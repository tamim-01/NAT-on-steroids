package steroid

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
)

type fakeOpener struct {
	mu        sync.Mutex
	addresses []string
	fail      bool
	peers     []net.Conn
}

func (o *fakeOpener) Open(ctx context.Context, address string) (io.ReadWriteCloser, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.addresses = append(o.addresses, address)
	if o.fail {
		return nil, errors.New("test refusal")
	}
	client, server := net.Pipe()
	o.peers = append(o.peers, server)
	return client, nil
}
func (o *fakeOpener) close() {
	for _, peer := range o.peers {
		peer.Close()
	}
}
func TestRouterUsesOnlyExplicitDirectRulesAndHasNoFallback(t *testing.T) {
	tunneled, direct := &fakeOpener{}, &fakeOpener{}
	defer tunneled.close()
	defer direct.close()
	router := NewRouter(tunneled, direct, []Rule{{Kind: "suffix", Domain: "ir", Action: "direct"}})
	defer router.Close()
	for _, address := range []string{"example.ir:443", "example.com:443", "1.1.1.1:443"} {
		stream, err := router.Open(context.Background(), address)
		if err != nil {
			t.Fatal(err)
		}
		stream.Close()
	}
	if len(direct.addresses) != 1 || direct.addresses[0] != "example.ir:443" || len(tunneled.addresses) != 2 {
		t.Fatal("domain routing selected the wrong outbound")
	}
	direct.fail = true
	if _, err := router.Open(context.Background(), "other.ir:443"); err == nil {
		t.Fatal("direct refusal hidden")
	}
	if len(tunneled.addresses) != 2 {
		t.Fatal("failed direct connection fell back to VPN")
	}
	if _, err := router.Open(context.Background(), "example.ir:22"); err == nil {
		t.Fatal("non-web direct port accepted")
	}
	if len(direct.addresses) != 2 {
		t.Fatal("non-web direct port reached broker")
	}
	events := router.Events()
	if len(events) != 3 {
		t.Fatalf("IP-only requests should not appear as browser domains: %+v", events)
	}
	router.ClearEvents()
	if len(router.Events()) != 0 {
		t.Fatal("domain history not cleared")
	}
}
func TestRuleChangesCloseHostnameStreamsButKeepIPOnlyTUNStreams(t *testing.T) {
	tunneled, direct := &fakeOpener{}, &fakeOpener{}
	defer tunneled.close()
	defer direct.close()
	router := NewRouter(tunneled, direct, nil)
	defer router.Close()
	domain, err := router.Open(context.Background(), "example.ir:443")
	if err != nil {
		t.Fatal(err)
	}
	ip, err := router.Open(context.Background(), "1.1.1.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer ip.Close()
	router.SetRules([]Rule{{Kind: "suffix", Domain: "ir", Action: "direct"}})
	if _, err = domain.Write([]byte("x")); err == nil {
		t.Fatal("old hostname stream survived rule change")
	}
	done := make(chan error, 1)
	go func() { _, err := tunneled.peers[1].Write([]byte("ok")); done <- err }()
	data := make([]byte, 2)
	if _, err = io.ReadFull(ip, data); err != nil || string(data) != "ok" {
		t.Fatal("IP-only TUN stream was interrupted")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

type pausedOpener struct {
	started chan struct{}
	release chan struct{}
	peer    net.Conn
}

func (o *pausedOpener) Open(context.Context, string) (io.ReadWriteCloser, error) {
	close(o.started)
	<-o.release
	client, peer := net.Pipe()
	o.peer = peer
	return client, nil
}
func TestRulesDoNotCancelPendingIPOnlyTUNConnections(t *testing.T) {
	for _, address := range []string{"1.1.1.1:443", "example.com:443"} {
		t.Run(address, func(t *testing.T) {
			opener := &pausedOpener{started: make(chan struct{}), release: make(chan struct{})}
			router := NewRouter(opener, opener, nil)
			defer router.Close()
			type result struct {
				stream io.ReadWriteCloser
				err    error
			}
			done := make(chan result, 1)
			go func() { stream, err := router.Open(context.Background(), address); done <- result{stream, err} }()
			<-opener.started
			router.SetRules([]Rule{{Kind: "suffix", Domain: "ir", Action: "direct"}})
			close(opener.release)
			outcome := <-done
			defer opener.peer.Close()
			if address == "1.1.1.1:443" {
				if outcome.err != nil {
					t.Fatal("pending IP-only TUN connection was interrupted")
				}
				outcome.stream.Close()
			} else if outcome.err == nil {
				outcome.stream.Close()
				t.Fatal("pending hostname connection retained its stale routing decision")
			}
		})
	}
}
