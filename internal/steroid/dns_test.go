package steroid

import (
	"context"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDNSAnswersBindToQuestionAndRejectPrivateRebinding(t *testing.T) {
	name := dnsmessage.MustNewName("example.ir.")
	alias := dnsmessage.MustNewName("cdn.example.com.")
	message := dnsmessage.Message{Header: dnsmessage.Header{ID: 42, Response: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}, Answers: []dnsmessage.Resource{
		{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 20}, Body: &dnsmessage.CNAMEResource{CNAME: alias}},
		{Header: dnsmessage.ResourceHeader{Name: alias, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}},
		{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("unrelated.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{8, 8, 8, 8}}},
	}}
	data, _ := message.Pack()
	addresses, ttl, err := parseAddresses(data, 42, "example.ir")
	if err != nil || len(addresses) != 1 || addresses[0].String() != "1.1.1.1" || ttl != 20 {
		t.Fatalf("bad canonical DNS result: %v %d %v", addresses, ttl, err)
	}
	if _, _, err = parseAddresses(data, 41, "example.ir"); err == nil {
		t.Fatal("mismatched DNS transaction accepted")
	}
	if _, _, err = parseAddresses(data, 42, "other.ir"); err == nil {
		t.Fatal("mismatched DNS question accepted")
	}
	message.Answers[1].Body = &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}
	data, _ = message.Pack()
	if _, _, err = parseAddresses(data, 42, "example.ir"); err == nil {
		t.Fatal("private DNS rebinding accepted")
	}
}

type dnsRoundTrip func(*http.Request) (*http.Response, error)

func (f dnsRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
func TestDirectDNSNeverFollowsRedirectsAwayFromFixedResolvers(t *testing.T) {
	resolver := NewDirectResolver()
	defer resolver.Close()
	requests := 0
	resolver.client.Transport = dnsRoundTrip(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.Host != "1.1.1.1" && request.URL.Host != "8.8.8.8" {
			t.Fatalf("direct resolver followed redirect to %s", request.URL.Host)
		}
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"http://169.254.169.254/metadata"}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})
	if _, err := resolver.Lookup(context.Background(), "example.ir"); err == nil || requests != 2 {
		t.Fatal("redirected DNS response was accepted")
	}
}
