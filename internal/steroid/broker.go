package steroid

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nat-on-steroids/internal/vpn"
)

type Request struct {
	Operation string `json:"operation"`
	Address   string `json:"address,omitempty"`
	Rules     []Rule `json:"rules,omitempty"`
}
type response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func readJSON(reader *bufio.Reader, value any) error {
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > MaxMessage {
		return errors.New("invalid or oversized broker message")
	}
	if err = json.Unmarshal(line, value); err != nil {
		return errors.New("invalid broker message")
	}
	return nil
}
func writeJSON(writer io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data)+1 > MaxMessage {
		return errors.New("broker message is too large")
	}
	_, err = writer.Write(append(data, '\n'))
	return err
}

type Client struct {
	Path       string
	Diagnostic bool
}

func (c *Client) request(ctx context.Context, request Request) (*brokerStream, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.Path)
	if err != nil {
		return nil, errors.New("direct connection helper is unavailable")
	}
	socket := conn.(*net.UnixConn)
	deadline := time.Now().Add(20 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	_ = socket.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { socket.Close() })
	failed := true
	defer func() {
		if failed {
			stop()
			socket.Close()
		}
	}()
	if err = writeJSON(socket, request); err != nil {
		return nil, err
	}
	reader := bufio.NewReaderSize(socket, MaxMessage+1)
	var reply response
	if err = readJSON(reader, &reply); err != nil {
		return nil, err
	}
	if !reply.OK {
		return nil, fmt.Errorf("direct helper: %s", reply.Error)
	}
	_ = socket.SetDeadline(time.Time{})
	failed = false
	return &brokerStream{UnixConn: socket, reader: reader, stop: stop}, nil
}
func (c *Client) Open(ctx context.Context, address string) (io.ReadWriteCloser, error) {
	op := "dial"
	if c.Diagnostic {
		op = "diagnostic"
	}
	return c.request(ctx, Request{Operation: op, Address: address})
}
func (c *Client) UpdateRules(ctx context.Context, rules []Rule) error {
	stream, err := c.request(ctx, Request{Operation: "rules", Rules: rules})
	if err != nil {
		return err
	}
	return stream.Close()
}

type brokerStream struct {
	*net.UnixConn
	reader *bufio.Reader
	stop   func() bool
}

func (s *brokerStream) Read(p []byte) (int, error) { return s.reader.Read(p) }
func (s *brokerStream) Close() error               { s.stop(); return s.UnixConn.Close() }

// The only elevated network operation is a marked TCP connection. No caller
// supplied command, filesystem path, network interface, or socket mark is used.
func MarkedDialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: func(network, address string, raw syscall.RawConn) error {
		var optionErr error
		err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, Mark) })
		if err != nil {
			return err
		}
		return optionErr
	}}
}

type Server struct {
	UID        uint32
	Resolve    func(context.Context, string) ([]netip.Addr, error)
	Dial       func(context.Context, string, string) (net.Conn, error)
	mu         sync.Mutex
	rules      []Rule
	generation uint64
	streams    map[net.Conn]net.Conn
}

func NewServer(uid uint32, rules []Rule, resolve func(context.Context, string) ([]netip.Addr, error), dial func(context.Context, string, string) (net.Conn, error)) *Server {
	return &Server{UID: uid, rules: append([]Rule(nil), rules...), Resolve: resolve, Dial: dial, streams: map[net.Conn]net.Conn{}}
}
func (s *Server) Serve(ctx context.Context, listener *net.UnixListener) error {
	ctx, cancel := context.WithCancel(ctx)
	var clients sync.Map
	stop := context.AfterFunc(ctx, func() {
		listener.Close()
		clients.Range(func(key, value any) bool { key.(net.Conn).Close(); return true })
	})
	defer stop()
	slots := make(chan struct{}, 64)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		listener.Close()
		clients.Range(func(key, value any) bool { key.(net.Conn).Close(); return true })
		workers.Wait()
	}()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !sameUser(conn, s.UID) {
			conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		clients.Store(conn, true)
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots; clients.Delete(conn); conn.Close() }()
			s.handle(ctx, conn)
		}()
	}
}
func sameUser(conn *net.UnixConn, uid uint32) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	var credential *unix.Ucred
	var optionErr error
	if err = raw.Control(func(fd uintptr) {
		credential, optionErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return false
	}
	return optionErr == nil && credential != nil && credential.Uid == uid
}
func (s *Server) handle(ctx context.Context, conn *net.UnixConn) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReaderSize(conn, MaxMessage+1)
	var request Request
	if err := readJSON(reader, &request); err != nil {
		return
	}
	reject := func(err error) { _ = writeJSON(conn, response{Error: err.Error()}) }
	if request.Operation == "rules" {
		rules, err := NormalizeRules(request.Rules)
		if err != nil {
			reject(err)
			return
		}
		s.mu.Lock()
		s.rules = rules
		s.generation++
		old := make(map[net.Conn]net.Conn, len(s.streams))
		for client, remote := range s.streams {
			old[client] = remote
		}
		s.mu.Unlock()
		for client, remote := range old {
			client.Close()
			remote.Close()
		}
		_ = writeJSON(conn, response{OK: true})
		return
	}
	if request.Operation != "dial" && request.Operation != "diagnostic" {
		reject(errors.New("unsupported broker operation"))
		return
	}
	host, portText, err := net.SplitHostPort(request.Address)
	port, _ := strconv.Atoi(portText)
	if err != nil || port != 80 && port != 443 {
		reject(errors.New("only HTTP/HTTPS ports 80 and 443 are allowed"))
		return
	}
	domain, err := NormalizeDomain(host)
	if err != nil {
		reject(err)
		return
	}
	s.mu.Lock()
	allowed := Decide(s.rules, domain) == "direct"
	generation := s.generation
	s.mu.Unlock()
	if request.Operation == "diagnostic" {
		allowed = request.Address == DiagnosticAddress
	}
	if !allowed {
		reject(errors.New("domain is not permitted for a direct connection"))
		return
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	addresses, err := s.Resolve(requestCtx, domain)
	if err != nil {
		reject(errors.New("direct DNS resolution failed"))
		return
	}
	var remote net.Conn
	for _, address := range addresses {
		if !PublicIPv4(address) {
			continue
		}
		// Dial the already validated address, never resolve the hostname again.
		remote, err = s.Dial(requestCtx, "tcp4", net.JoinHostPort(address.String(), portText))
		if err == nil {
			break
		}
	}
	if remote == nil {
		reject(errors.New("no reachable public IPv4 destination"))
		return
	}
	defer remote.Close()
	s.mu.Lock()
	if generation != s.generation {
		s.mu.Unlock()
		reject(errors.New("domain rules changed; retry"))
		return
	}
	s.streams[conn] = remote
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.streams, conn); s.mu.Unlock() }()
	if err = writeJSON(conn, response{OK: true}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	stop := context.AfterFunc(ctx, func() { conn.Close(); remote.Close() })
	defer stop()
	vpn.Relay(&bufferedSocket{Conn: conn, reader: reader}, remote)
}

type bufferedSocket struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedSocket) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *bufferedSocket) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return c.Conn.Close()
}
