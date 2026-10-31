package vpn

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Opener interface {
	Open(context.Context, string) (io.ReadWriteCloser, error)
}

type Proxy struct {
	ctx     context.Context
	cancel  context.CancelFunc
	opener  Opener
	socks   net.Listener
	http    *http.Server
	clients sync.Map
	doh     *http.Client
	slots   chan struct{}
}

func HTTPClient(opener Opener) *http.Client {
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: false, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 20 * time.Second, MaxIdleConns: 8, IdleConnTimeout: 60 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		remote, err := opener.Open(ctx, address)
		if err != nil {
			return nil, err
		}
		return &streamConn{ReadWriteCloser: remote}, nil
	}
	return &http.Client{Transport: transport, Timeout: 25 * time.Second}
}

type streamConn struct{ io.ReadWriteCloser }
type tunnelAddr string

func (a tunnelAddr) Network() string                   { return "tcp" }
func (a tunnelAddr) String() string                    { return string(a) }
func (c *streamConn) LocalAddr() net.Addr              { return tunnelAddr("tunnel:0") }
func (c *streamConn) RemoteAddr() net.Addr             { return tunnelAddr("upstream:0") }
func (c *streamConn) SetDeadline(time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }

func StartProxy(parent context.Context, opener Opener, socksAddress, httpAddress string) (*Proxy, error) {
	socks, err := net.Listen("tcp4", socksAddress)
	if err != nil {
		return nil, fmt.Errorf("SOCKS port is unavailable: %w", err)
	}
	httpListener, err := net.Listen("tcp4", httpAddress)
	if err != nil {
		socks.Close()
		return nil, fmt.Errorf("HTTP proxy port is unavailable: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	p := &Proxy{ctx: ctx, cancel: cancel, opener: opener, socks: socks, doh: HTTPClient(opener), slots: make(chan struct{}, 256)}
	p.http = &http.Server{Handler: http.HandlerFunc(p.handleHTTP), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	go p.http.Serve(httpListener)
	go func() {
		for {
			conn, err := socks.Accept()
			if err != nil {
				return
			}
			select {
			case p.slots <- struct{}{}:
				p.clients.Store(conn, true)
				go func() { defer func() { <-p.slots; p.clients.Delete(conn); conn.Close() }(); p.handleSOCKS(conn) }()
			default:
				conn.Close()
			}
		}
	}()
	return p, nil
}

func (p *Proxy) Port() int { return p.socks.Addr().(*net.TCPAddr).Port }
func (p *Proxy) Close() {
	p.cancel()
	p.socks.Close()
	p.http.Close()
	p.clients.Range(func(k, v any) bool { k.(net.Conn).Close(); return true })
	p.doh.CloseIdleConnections()
}

func readTarget(r io.Reader) (string, int, []byte, error) {
	typeByte := make([]byte, 1)
	if _, err := io.ReadFull(r, typeByte); err != nil {
		return "", 0, nil, err
	}
	header := append([]byte{}, typeByte...)
	var host string
	switch typeByte[0] {
	case 1, 4:
		n := 4
		if typeByte[0] == 4 {
			n = 16
		}
		ip := make([]byte, n)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0, nil, err
		}
		header = append(header, ip...)
		host = net.IP(ip).String()
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(r, length); err != nil {
			return "", 0, nil, err
		}
		if length[0] == 0 {
			return "", 0, nil, errors.New("empty hostname")
		}
		domain := make([]byte, int(length[0]))
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", 0, nil, err
		}
		header = append(append(header, length...), domain...)
		host = string(domain)
	default:
		return "", 0, nil, errors.New("unsupported address")
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, portBytes); err != nil {
		return "", 0, nil, err
	}
	header = append(header, portBytes...)
	return host, int(binary.BigEndian.Uint16(portBytes)), header, nil
}

func validDestination(host string, port int) bool {
	if port < 1 || port > 65535 || strings.ContainsAny(host, "\x00\r\n /\\") {
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	if name == "localhost" || strings.HasSuffix(name, ".localhost") || strings.HasSuffix(name, ".local") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
	}
	return host != ""
}

func (p *Proxy) handleSOCKS(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil || greeting[0] != 5 || greeting[1] == 0 {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if !bytes.Contains(methods, []byte{0}) {
		conn.Write([]byte{5, 255})
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	header := make([]byte, 3)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != 5 || header[2] != 0 {
		return
	}
	host, port, _, err := readTarget(conn)
	if err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	if header[1] == 3 {
		p.udpAssociation(conn)
		return
	}
	if header[1] != 1 {
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	if port == 53 {
		conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		p.dnsTCP(conn)
		return
	}
	if !validDestination(host, port) {
		conn.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	remote, err := p.opener.Open(p.ctx, net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	if _, err = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		remote.Close()
		return
	}
	Relay(conn, remote)
}

func (p *Proxy) resolveDNS(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) < 12 || len(query) > 65535 {
		return nil, errors.New("invalid DNS message")
	}
	for _, endpoint := range []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"} {
		req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(query))
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		resp, err := p.doh.Do(req)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
		resp.Body.Close()
		if err == nil && resp.StatusCode == 200 && len(data) >= 12 && len(data) <= 65535 && bytes.Equal(data[:2], query[:2]) {
			return data, nil
		}
	}
	return nil, errors.New("encrypted DNS is unavailable")
}

func (p *Proxy) dnsTCP(conn net.Conn) {
	for {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		length := make([]byte, 2)
		if _, err := io.ReadFull(conn, length); err != nil {
			return
		}
		query := make([]byte, int(binary.BigEndian.Uint16(length)))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(p.ctx, 20*time.Second)
		reply, err := p.resolveDNS(ctx, query)
		cancel()
		if err != nil {
			return
		}
		binary.BigEndian.PutUint16(length, uint16(len(reply)))
		if _, err = conn.Write(append(length, reply...)); err != nil {
			return
		}
	}
}

func (p *Proxy) udpAssociation(control net.Conn) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	defer socket.Close()
	port := socket.LocalAddr().(*net.UDPAddr).Port
	_, err = control.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()
	go func() { _, _ = io.Copy(io.Discard, control); cancel(); socket.Close() }()
	sem := make(chan struct{}, 32)
	var owner *net.UDPAddr
	for {
		buf := make([]byte, 65535)
		n, source, err := socket.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !source.IP.IsLoopback() {
			continue
		}
		if owner != nil && (owner.Port != source.Port || !owner.IP.Equal(source.IP)) {
			continue
		}
		if n < 10 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
			continue
		}
		r := bytes.NewReader(buf[3:n])
		_, targetPort, header, err := readTarget(r)
		if err != nil || targetPort != 53 {
			continue
		}
		if owner == nil {
			owner = source
		}
		query := append([]byte{}, buf[n-r.Len():n]...)
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				requestCtx, stop := context.WithTimeout(ctx, 20*time.Second)
				defer stop()
				reply, err := p.resolveDNS(requestCtx, query)
				if err == nil {
					packet := append(append([]byte{0, 0, 0}, header...), reply...)
					socket.WriteToUDP(packet, source)
				}
			}()
		default:
		}
	}
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		host, portText, err := net.SplitHostPort(r.Host)
		port, _ := strconv.Atoi(portText)
		if err != nil || !validDestination(host, port) {
			http.Error(w, "Destination is not supported", http.StatusForbidden)
			return
		}
		remote, err := p.opener.Open(p.ctx, r.Host)
		if err != nil {
			http.Error(w, "VPN service could not open this destination", http.StatusBadGateway)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			remote.Close()
			http.Error(w, "Cannot open tunnel", 500)
			return
		}
		conn, buffer, err := hijacker.Hijack()
		if err != nil {
			remote.Close()
			return
		}
		p.clients.Store(conn, true)
		defer p.clients.Delete(conn)
		_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if buffer.Flush() != nil {
			conn.Close()
			remote.Close()
			return
		}
		Relay(&bufferedConn{Conn: conn, reader: buffer.Reader}, remote)
		return
	}
	if !r.URL.IsAbs() || r.URL.Scheme != "http" {
		http.Error(w, "Use this endpoint as an HTTP proxy", 400)
		return
	}
	port := 80
	if r.URL.Port() != "" {
		port, _ = strconv.Atoi(r.URL.Port())
	}
	if !validDestination(r.URL.Hostname(), port) {
		http.Error(w, "Destination is not supported", 403)
		return
	}
	request := r.Clone(p.ctx)
	request.RequestURI = ""
	request.Header = request.Header.Clone()
	stripHopHeaders(request.Header)
	resp, err := p.doh.Do(request)
	if err != nil {
		http.Error(w, "VPN service could not reach this destination", 502)
		return
	}
	defer resp.Body.Close()
	stripHopHeaders(resp.Header)
	for k, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func stripHopHeaders(header http.Header) {
	for _, name := range strings.Split(header.Get("Connection"), ",") {
		header.Del(strings.TrimSpace(name))
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
