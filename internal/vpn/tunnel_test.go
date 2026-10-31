package vpn

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

type flushWriter struct{ w http.ResponseWriter }

func (w flushWriter) Write(p []byte) (int, error) {
	n, e := w.w.Write(p)
	w.w.(http.Flusher).Flush()
	return n, e
}

func mockTunnel(t *testing.T, destination string) *Tunnel {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Method != "CONNECT" {
			t.Errorf("expected HTTP/2 CONNECT, got %s %s", r.Proto, r.Method)
			w.WriteHeader(400)
			return
		}
		if r.Header.Get("Proxy-Authorization") != "Bearer test-pass" {
			w.WriteHeader(407)
			return
		}
		if strings.HasPrefix(r.Host, "refused.example:") {
			w.WriteHeader(403)
			return
		}
		if destination == "" {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			_, _ = io.Copy(flushWriter{w}, r.Body)
			return
		}
		remote, err := net.DialTimeout("tcp", destination, time.Second)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer remote.Close()
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		go func() { _, _ = io.Copy(remote, r.Body); _ = remote.(*net.TCPConn).CloseWrite() }()
		_, _ = io.Copy(flushWriter{w}, remote)
	}))
	server.EnableHTTP2 = true
	if err := http2.ConfigureServer(server.Config, &http2.Server{MaxConcurrentStreams: 2}); err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	address := strings.TrimPrefix(server.URL, "https://")
	conn, err := tls.Dial("tcp", address, &tls.Config{RootCAs: pool, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	transport := &http2.Transport{StrictMaxConcurrentStreams: true}
	cc, err := transport.NewClientConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	tunnel := &Tunnel{conn: cc, socket: conn, token: "test-pass"}
	t.Cleanup(tunnel.Close)
	return tunnel
}

func TestHTTP2TunnelDuplexRefusalAndCancel(t *testing.T) {
	tunnel := mockTunnel(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := tunnel.Open(ctx, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("tunnel-data-"), 8192)
	go func() { _, _ = stream.Write(payload); _ = stream.(interface{ CloseWrite() error }).CloseWrite() }()
	got, err := io.ReadAll(stream)
	stream.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("bidirectional payload was corrupted")
	}
	if tunnel.Upload.Load() != int64(len(payload)) || tunnel.Download.Load() != int64(len(payload)) {
		t.Fatal("traffic counters do not match actual relayed bytes")
	}
	if _, err = tunnel.Open(ctx, "refused.example:22"); err == nil {
		t.Fatal("edge refusal was ignored")
	}
	stream, err = tunnel.Open(ctx, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { b := make([]byte, 1); _, e := stream.Read(b); done <- e }()
	tunnel.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closing tunnel did not interrupt the stream")
		}
	case <-time.After(time.Second):
		t.Fatal("stream remained blocked after disconnect")
	}
}

func TestHTTP2StreamLimitDoesNotResetExistingTraffic(t *testing.T) {
	tunnel := mockTunnel(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := tunnel.Open(ctx, "first.example:443")
	if err != nil {
		t.Fatal(err)
	}
	second, err := tunnel.Open(ctx, "second.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	opened := make(chan io.ReadWriteCloser, 1)
	go func() { third, _ := tunnel.Open(ctx, "third.example:443"); opened <- third }()
	select {
	case third := <-opened:
		if third != nil {
			third.Close()
		}
		t.Fatal("third stream did not wait for a server slot")
	case <-time.After(100 * time.Millisecond):
	}
	first.Close()
	select {
	case third := <-opened:
		if third == nil {
			t.Fatal("queued stream failed after a slot was released")
		}
		third.Close()
	case <-time.After(time.Second):
		t.Fatal("queued stream did not resume")
	}
	go func() { second.Write([]byte("still alive")); second.(interface{ CloseWrite() error }).CloseWrite() }()
	got, err := io.ReadAll(second)
	if err != nil || string(got) != "still alive" {
		t.Fatal("reaching the stream limit reset an existing connection")
	}
}

func TestSOCKSAndHTTPProxyThroughRealHTTP2Tunnel(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hello" {
			t.Error("wrong origin path")
		}
		_, _ = io.WriteString(w, "verified through tunnel")
	}))
	defer origin.Close()
	tunnel := mockTunnel(t, strings.TrimPrefix(origin.URL, "https://"))
	p, err := StartProxy(context.Background(), tunnel, "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	pool := x509.NewCertPool()
	pool.AddCert(origin.Certificate())
	dialer, err := proxy.SOCKS5("tcp", p.socks.Addr().String(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
	}, TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}}}
	resp, err := client.Get("https://example.com/hello")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	client.CloseIdleConnections()
	if err != nil || string(body) != "verified through tunnel" {
		t.Fatal("SOCKS proxy failed to carry HTTPS")
	}
	// Exercise HTTP CONNECT using the same handler over an independently owned listener.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(p.handleHTTP)}
	go server.Serve(listener)
	defer server.Close()
	proxyURL, _ := url.Parse("http://" + listener.Addr().String())
	client = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}}}
	resp, err = client.Get("https://example.com/hello")
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	client.CloseIdleConnections()
	if err != nil || string(body) != "verified through tunnel" {
		t.Fatal("HTTP CONNECT proxy failed to carry HTTPS")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestDNSOnlyUDPRelayAndAssociationOwnership(t *testing.T) {
	tunnel := mockTunnel(t, "")
	p, err := StartProxy(context.Background(), tunnel, "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var calls atomic.Int32
	p.doh = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.String() != "https://1.1.1.1/dns-query" || r.Header.Get("Content-Type") != "application/dns-message" {
			t.Error("DNS was not sent through the encrypted DNS path")
		}
		body, _ := io.ReadAll(r.Body)
		body[2] |= 128
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})}
	control, err := net.Dial("tcp", p.socks.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	control.SetDeadline(time.Now().Add(3 * time.Second))
	control.Write([]byte{5, 1, 0})
	greeting := make([]byte, 2)
	io.ReadFull(control, greeting)
	control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 10)
	if _, err = io.ReadFull(control, reply); err != nil {
		t.Fatal(err)
	}
	address := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(reply[8])<<8 | int(reply[9])}
	socket, err := net.DialUDP("udp4", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	query := []byte{0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	packet := append([]byte{0, 0, 0, 1, 8, 8, 8, 8, 0, 53}, query...)
	socket.SetDeadline(time.Now().Add(time.Second))
	socket.Write(packet)
	buf := make([]byte, 1024)
	n, err := socket.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(packet) || buf[10] != 0x12 || buf[12]&128 == 0 {
		t.Fatal("invalid SOCKS UDP DNS reply")
	}
	packet[9] = 123 // Non-DNS UDP must never fall back to a direct socket.
	socket.SetDeadline(time.Now().Add(120 * time.Millisecond))
	socket.Write(packet)
	if _, err = socket.Read(buf); err == nil {
		t.Fatal("non-DNS UDP was forwarded")
	}
	foreign, _ := net.DialUDP("udp4", nil, address)
	defer foreign.Close()
	packet[9] = 53
	foreign.SetDeadline(time.Now().Add(120 * time.Millisecond))
	foreign.Write(packet)
	if _, err = foreign.Read(buf); err == nil {
		t.Fatal("another UDP source hijacked an association")
	}
	if calls.Load() != 1 {
		t.Fatal("unsupported or foreign traffic reached DNS transport")
	}
}

func TestPrivateDestinationsRejected(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "::1", "fe80::1", "localhost", "foo.local", "example.com\r\nX-Test: yes"} {
		if validDestination(host, 443) {
			t.Errorf("accepted unsupported destination %q", host)
		}
	}
	if !validDestination("example.com", 443) || !validDestination("1.1.1.1", 443) {
		t.Fatal("valid public destination was rejected")
	}
}

func TestLatencyUsesExistingHTTP2ConnectionWithoutDestinationTraffic(t *testing.T) {
	tunnel := mockTunnel(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		elapsed, err := tunnel.Latency(ctx)
		if err != nil || elapsed <= 0 {
			t.Fatalf("HTTP/2 latency check failed: %v", err)
		}
	}
	if tunnel.Upload.Load() != 0 || tunnel.Download.Load() != 0 {
		t.Fatal("latency probe opened application traffic")
	}
	stream, err := tunnel.Open(ctx, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	go func() {
		_, _ = stream.Write([]byte("after-ping"))
		_ = stream.(interface{ CloseWrite() error }).CloseWrite()
	}()
	data, err := io.ReadAll(stream)
	if err != nil || string(data) != "after-ping" {
		t.Fatal("latency probes disrupted the existing tunnel")
	}
	tunnel.Close()
	if _, err = tunnel.Latency(ctx); err == nil {
		t.Fatal("closed tunnel returned latency")
	}
}
