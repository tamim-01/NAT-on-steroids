package steroid

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRulePrecedenceAndNormalization(t *testing.T) {
	rules, err := NormalizeRules([]Rule{{Kind: "suffix", Domain: "*.IR.", Action: "direct"}, {Kind: "suffix", Domain: "account.example.ir", Action: "vpn"}, {Kind: "exact", Domain: "Shop.Example.ir", Action: "vpn"}})
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{"example.ir": "direct", "x.example.ir": "direct", "shop.example.ir": "vpn", "x.shop.example.ir": "direct", "account.example.ir": "vpn", "a.account.example.ir": "vpn", "notir": "vpn", "example.ir.evil.com": "vpn", "example.com": "vpn"} {
		if got := Decide(rules, host); got != want {
			t.Errorf("%s: %s, want %s", host, got, want)
		}
	}
	unicode, err := NormalizeDomain("BÜCHER.de.")
	if err != nil || unicode != "xn--bcher-kva.de" {
		t.Fatal("IDNA canonicalization failed")
	}
	for _, bad := range []Rule{{Kind: "suffix", Domain: "https://example.ir/path", Action: "direct"}, {Kind: "exact", Domain: "127.0.0.1", Action: "direct"}, {Kind: "suffix", Domain: "bad..ir", Action: "direct"}, {Kind: "suffix", Domain: "a.ir:443", Action: "direct"}, {Kind: "suffix", Domain: "ir", Action: "unknown"}, {Kind: "unknown", Domain: "ir", Action: "direct"}, {Kind: "exact", Domain: strings.Repeat("a", 64) + ".ir", Action: "direct"}} {
		if _, err := NormalizeRules([]Rule{bad}); err == nil {
			t.Fatalf("bad rule accepted: %+v", bad)
		}
	}
	if _, err := NormalizeRules([]Rule{{Kind: "suffix", Domain: "ir", Action: "direct"}, {Kind: "suffix", Domain: ".IR", Action: "vpn"}}); err == nil {
		t.Fatal("duplicate canonical rule accepted")
	}
}
func TestDirectDestinationsMustBePublicIPv4(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.1.2.3", "100.100.100.100", "169.254.169.254", "172.16.4.3", "192.168.1.1", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.5", "224.0.0.1", "240.1.2.3", "0.0.0.1", "::1", "2606:4700:4700::1111", "::ffff:1.1.1.1"} {
		if PublicIPv4(netip.MustParseAddr(address)) {
			t.Fatalf("non-public destination accepted: %s", address)
		}
	}
	for _, address := range []string{"1.1.1.1", "8.8.8.8", "93.184.215.14"} {
		if !PublicIPv4(netip.MustParseAddr(address)) {
			t.Fatalf("public IPv4 rejected: %s", address)
		}
	}
}
