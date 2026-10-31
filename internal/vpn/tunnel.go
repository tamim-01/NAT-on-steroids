package vpn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

type Tunnel struct {
	mu               sync.Mutex
	conn             *http2.ClientConn
	socket           net.Conn
	server           Server
	ip, token        string
	closed           bool
	Upload, Download atomic.Int64
}

func NewTunnel(ctx context.Context, server Server, token string) (*Tunnel, error) {
	// Resolve once and pin the edge IPv4 address. TUN routing bypasses only this
	// address, so subsequent data and control requests cannot loop into themselves.
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", server.Host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("cannot resolve the selected VPN server")
	}
	t := &Tunnel{server: server, ip: ips[0].String(), token: token}
	if err = t.connect(ctx); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Tunnel) connect(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	d := net.Dialer{Timeout: 15 * time.Second, KeepAlive: 25 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(t.ip, strconv.Itoa(t.server.Port)))
	if err != nil {
		return errors.New("cannot reach this VPN server")
	}
	conn := tls.Client(raw, &tls.Config{ServerName: t.server.Host, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}})
	if err = conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return errors.New("VPN server TLS handshake failed")
	}
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		conn.Close()
		return errors.New("VPN server did not negotiate HTTP/2")
	}
	transport := &http2.Transport{ReadIdleTimeout: 25 * time.Second, PingTimeout: 15 * time.Second, StrictMaxConcurrentStreams: true}
	cc, err := transport.NewClientConn(conn)
	if err != nil {
		conn.Close()
		return err
	}
	oldConn, oldSocket := t.conn, t.socket
	t.conn = cc
	t.socket = conn
	if oldConn != nil {
		_ = oldConn.Close()
	}
	if oldSocket != nil {
		_ = oldSocket.Close()
	}
	return nil
}

func (t *Tunnel) UpdateToken(token string) { t.mu.Lock(); t.token = token; t.mu.Unlock() }
func (t *Tunnel) EdgeIP() string           { return t.ip }

// Latency measures the round trip to the existing HTTP/2 edge connection.
// It opens no destination stream and does not require ICMP support.
func (t *Tunnel) Latency(ctx context.Context) (time.Duration, error) {
	t.mu.Lock()
	cc, closed := t.conn, t.closed
	t.mu.Unlock()
	if closed || cc == nil {
		return 0, errors.New("VPN is disconnected")
	}
	started := time.Now()
	if err := cc.Ping(ctx); err != nil {
		return 0, errors.New("the VPN server did not answer the latency check")
	}
	return time.Since(started), nil
}

func (t *Tunnel) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	if t.conn != nil {
		t.conn.Close()
	}
	if t.socket != nil {
		t.socket.Close()
	}
}

func (t *Tunnel) Open(ctx context.Context, address string) (io.ReadWriteCloser, error) {
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, errors.New("invalid tunnel destination")
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, errors.New("VPN is disconnected")
	}
	if state := t.conn.State(); state.Closed || state.Closing {
		// Reconnect to the pinned edge, preserving the routing bypass rule.
		if err := t.connect(ctx); err != nil {
			t.mu.Unlock()
			return nil, err
		}
	}
	cc, token := t.conn, t.token
	t.mu.Unlock()
	streamCtx, cancel := context.WithCancel(ctx)
	reader, writer := io.Pipe()
	req := &http.Request{Method: "CONNECT", URL: &url.URL{Scheme: "https", Host: address}, Host: address, Header: make(http.Header), Body: reader, ContentLength: -1}
	req = req.WithContext(streamCtx)
	req.Header.Set("Proxy-Authorization", "Bearer "+token)
	// Bound CONNECT setup without imposing a deadline on established streams.
	timer := time.AfterFunc(20*time.Second, cancel)
	resp, err := cc.RoundTrip(req)
	timer.Stop()
	if err != nil {
		cancel()
		reader.Close()
		writer.Close()
		return nil, errors.New("VPN tunnel could not open the connection")
	}
	if resp.StatusCode != 200 {
		cancel()
		reader.Close()
		writer.Close()
		resp.Body.Close()
		return nil, fmt.Errorf("VPN service refused the destination (HTTP %d)", resp.StatusCode)
	}
	return &stream{reader: resp.Body, writer: writer, request: reader, cancel: cancel, up: &t.Upload, down: &t.Download}, nil
}

type stream struct {
	reader   io.ReadCloser
	writer   *io.PipeWriter
	request  *io.PipeReader
	cancel   context.CancelFunc
	up, down *atomic.Int64
}

func (s *stream) Read(b []byte) (int, error) {
	n, e := s.reader.Read(b)
	s.down.Add(int64(n))
	return n, e
}
func (s *stream) Write(b []byte) (int, error) {
	n, e := s.writer.Write(b)
	s.up.Add(int64(n))
	return n, e
}
func (s *stream) CloseWrite() error { return s.writer.Close() }
func (s *stream) Close() error {
	s.cancel()
	s.writer.Close()
	s.request.Close()
	return s.reader.Close()
}

// Relay preserves TCP half-closes, but caps the drain period after either end
// finishes to avoid stranded streams holding resources forever.
func Relay(client net.Conn, remote io.ReadWriteCloser) {
	defer client.Close()
	defer remote.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, err := io.Copy(remote, client)
		if cw, ok := remote.(interface{ CloseWrite() error }); ok && err == nil {
			_ = cw.CloseWrite()
		} else {
			remote.Close()
		}
		done <- struct{}{}
	}()
	go func() {
		_, err := io.Copy(client, remote)
		if cw, ok := client.(interface{ CloseWrite() error }); ok && err == nil {
			_ = cw.CloseWrite()
		} else {
			client.Close()
		}
		done <- struct{}{}
	}()
	<-done
	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}
}
