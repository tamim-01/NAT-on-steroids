package steroid

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type dnsEntry struct {
	addresses []netip.Addr
	expires   time.Time
}
type DirectResolver struct {
	client *http.Client
	mu     sync.Mutex
	cache  map[string]dnsEntry
}

func NewDirectResolver() *DirectResolver {
	dialer := MarkedDialer()
	return &DirectResolver{client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second}}, cache: map[string]dnsEntry{}}
}
func (r *DirectResolver) Close() { r.client.CloseIdleConnections() }
func (r *DirectResolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	cached, ok := r.cache[host]
	r.mu.Unlock()
	if ok && time.Now().Before(cached.expires) {
		return append([]netip.Addr(nil), cached.addresses...), nil
	}
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil, err
	}
	var random [2]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(random[:])
	query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		return nil, err
	}
	for _, endpoint := range []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"} {
		request, _ := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(query))
		request.Header.Set("Content-Type", "application/dns-message")
		request.Header.Set("Accept", "application/dns-message")
		response, err := r.client.Do(request)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 65536))
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK || len(body) > 65535 {
			continue
		}
		addresses, ttl, err := parseAddresses(body, id, host)
		if err != nil {
			continue
		}
		r.mu.Lock()
		if len(r.cache) >= 256 {
			for key, value := range r.cache {
				if !time.Now().Before(value.expires) {
					delete(r.cache, key)
				}
			}
			if len(r.cache) >= 256 {
				r.cache = map[string]dnsEntry{}
			}
		}
		r.cache[host] = dnsEntry{addresses: addresses, expires: time.Now().Add(time.Duration(min(ttl, 300)) * time.Second)}
		r.mu.Unlock()
		return append([]netip.Addr(nil), addresses...), nil
	}
	return nil, errors.New("direct DNS did not return a public IPv4 address")
}
func parseAddresses(body []byte, id uint16, host string) ([]netip.Addr, uint32, error) {
	var message dnsmessage.Message
	if err := message.Unpack(body); err != nil {
		return nil, 0, err
	}
	if message.ID != id || !message.Response || message.RCode != dnsmessage.RCodeSuccess || len(message.Questions) != 1 || strings.TrimSuffix(strings.ToLower(message.Questions[0].Name.String()), ".") != host || message.Questions[0].Type != dnsmessage.TypeA || message.Questions[0].Class != dnsmessage.ClassINET {
		return nil, 0, errors.New("unexpected DNS response")
	}
	names := map[string]bool{host + ".": true}
	for range len(message.Answers) {
		changed := false
		for _, answer := range message.Answers {
			if cname, ok := answer.Body.(*dnsmessage.CNAMEResource); ok && names[strings.ToLower(answer.Header.Name.String())] && !names[strings.ToLower(cname.CNAME.String())] {
				names[strings.ToLower(cname.CNAME.String())] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	ttl := uint32(300)
	out := []netip.Addr{}
	seen := map[netip.Addr]bool{}
	for _, answer := range message.Answers {
		if !names[strings.ToLower(answer.Header.Name.String())] || answer.Header.Class != dnsmessage.ClassINET {
			continue
		}
		ttl = min(ttl, answer.Header.TTL)
		if resource, ok := answer.Body.(*dnsmessage.AResource); ok {
			address := netip.AddrFrom4(resource.A)
			if PublicIPv4(address) && !seen[address] {
				out = append(out, address)
				seen[address] = true
			}
		}
	}
	if len(out) == 0 {
		return nil, 0, errors.New("no public IPv4 answer")
	}
	return out, ttl, nil
}
