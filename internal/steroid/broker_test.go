package steroid

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func brokerFixture(t *testing.T, uid uint32, addresses []netip.Addr) (*Client, *atomic.Int32, context.CancelFunc) {
	t.Helper()
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	path := filepath.Join(t.TempDir(), "direct.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := NewServer(uid, []Rule{{Kind: "suffix", Domain: "ir", Action: "direct"}}, func(context.Context, string) ([]netip.Addr, error) { return addresses, nil }, func(ctx context.Context, network, address string) (net.Conn, error) {
		calls.Add(1)
		if address != "93.184.215.14:443" {
			t.Errorf("dial did not use validated pinned address: %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp4", echo.Addr().String())
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("broker did not stop")
		}
	})
	return &Client{Path: path}, &calls, cancel
}
func TestBrokerPinsPublicAddressesAndPreservesStreamHalfClose(t *testing.T) {
	client, calls, _ := brokerFixture(t, uint32(os.Getuid()), []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("93.184.215.14")})
	stream, err := client.Open(context.Background(), "example.ir:443")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err = stream.Write([]byte("hello-direct")); err != nil {
		t.Fatal(err)
	}
	if err = stream.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(stream)
	if err != nil || string(data) != "hello-direct" {
		t.Fatalf("direct stream failed: %q %v", data, err)
	}
	if calls.Load() != 1 {
		t.Fatal("private result was dialed or public result not dialed")
	}
}
func TestBrokerRejectsForeignUsersDisallowedHostsAndPrivateDNS(t *testing.T) {
	wrong, wrongCalls, _ := brokerFixture(t, uint32(os.Getuid()+1), []netip.Addr{netip.MustParseAddr("93.184.215.14")})
	if _, err := wrong.Open(context.Background(), "example.ir:443"); err == nil || wrongCalls.Load() != 0 {
		t.Fatal("foreign UID reached direct dialer")
	}
	private, privateCalls, _ := brokerFixture(t, uint32(os.Getuid()), []netip.Addr{netip.MustParseAddr("169.254.169.254")})
	if _, err := private.Open(context.Background(), "example.ir:443"); err == nil || privateCalls.Load() != 0 {
		t.Fatal("private DNS answer reached direct dialer")
	}
	client, calls, _ := brokerFixture(t, uint32(os.Getuid()), []netip.Addr{netip.MustParseAddr("93.184.215.14")})
	for _, address := range []string{"example.com:443", "example.ir:22", "127.0.0.1:443", "example.ir:0"} {
		if _, err := client.Open(context.Background(), address); err == nil {
			t.Fatalf("disallowed request accepted: %s", address)
		}
	}
	diagnostic := *client
	diagnostic.Diagnostic = true
	if _, err := diagnostic.Open(context.Background(), "example.ir:443"); err == nil {
		t.Fatal("diagnostic operation allowed arbitrary hostname")
	}
	stream, err := diagnostic.Open(context.Background(), DiagnosticAddress)
	if err != nil {
		t.Fatal(err)
	}
	stream.Close()
	if calls.Load() != 1 {
		t.Fatal("rejected requests reached the direct dialer")
	}
}
func TestBrokerRuleUpdatesRevokeExistingStreamsAndNeverDefaultDirect(t *testing.T) {
	client, _, _ := brokerFixture(t, uint32(os.Getuid()), []netip.Addr{netip.MustParseAddr("93.184.215.14")})
	stream, err := client.Open(context.Background(), "example.ir:443")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err = client.UpdateRules(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 1)
	if _, err = stream.Read(data); err == nil {
		t.Fatal("revoked stream remained open")
	}
	if _, err = client.Open(context.Background(), "example.ir:443"); err == nil {
		t.Fatal("empty rules allowed direct traffic")
	}
	if err = client.UpdateRules(context.Background(), []Rule{{Kind: "exact", Domain: "example.ir", Action: "direct"}}); err != nil {
		t.Fatal(err)
	}
	next, err := client.Open(context.Background(), "example.ir:443")
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}
func TestBrokerCancellationClosesActiveStreams(t *testing.T) {
	client, _, cancel := brokerFixture(t, uint32(os.Getuid()), []netip.Addr{netip.MustParseAddr("93.184.215.14")})
	stream, err := client.Open(context.Background(), "example.ir:443")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	cancel()
	done := make(chan error, 1)
	go func() { var b [1]byte; _, err := stream.Read(b[:]); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled stream read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled direct stream was stranded")
	}
}
