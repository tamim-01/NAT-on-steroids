package steroid

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

const MaxRules = 128
const Mark = 0x4e4f524d
const BypassPriority = 18575
const MaxMessage = 65536
const DiagnosticAddress = "www.cloudflare.com:443"

type Rule struct {
	Kind   string `json:"kind"`
	Domain string `json:"domain"`
	Action string `json:"action"`
}

type Config struct {
	PACPort int    `json:"pacPort"`
	Rules   []Rule `json:"rules"`
}

func DefaultConfig() Config { return Config{PACPort: 8099, Rules: []Rule{}} }

func NormalizeDomain(host string) (string, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || len(ascii) == 0 || len(ascii) > 253 {
		return "", errors.New("enter a domain name, without a URL, path, or port")
	}
	if _, err := netip.ParseAddr(ascii); err == nil {
		return "", errors.New("rules must use domain names, not IP addresses")
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid domain label")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", errors.New("invalid domain name")
			}
		}
	}
	return ascii, nil
}

func NormalizeRules(rules []Rule) ([]Rule, error) {
	if len(rules) > MaxRules {
		return nil, errors.New("at most 128 domain rules are supported")
	}
	out := make([]Rule, 0, len(rules))
	seen := map[string]bool{}
	for _, rule := range rules {
		if rule.Kind != "exact" && rule.Kind != "suffix" {
			return nil, errors.New("choose exact domain or domain suffix")
		}
		if rule.Action != "vpn" && rule.Action != "direct" {
			return nil, errors.New("choose VPN or Direct")
		}
		if rule.Kind == "suffix" {
			rule.Domain = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(rule.Domain), "*."), ".")
		}
		domain, err := NormalizeDomain(rule.Domain)
		if err != nil {
			return nil, err
		}
		rule.Domain = domain
		key := rule.Kind + ":" + domain
		if seen[key] {
			return nil, fmt.Errorf("a %s rule for %s already exists", rule.Kind, domain)
		}
		seen[key] = true
		out = append(out, rule)
	}
	return out, nil
}

func NormalizeConfig(config Config) (Config, error) {
	if config.PACPort < 1024 || config.PACPort > 65535 {
		return Config{}, errors.New("browser PAC port must be between 1024 and 65535")
	}
	rules, err := NormalizeRules(config.Rules)
	if err != nil {
		return Config{}, err
	}
	config.Rules = rules
	return config, nil
}

// Exact rules win; otherwise the longest suffix wins on a DNS-label boundary.
func Decide(rules []Rule, host string) string {
	best := -1
	action := "vpn"
	for _, rule := range rules {
		score := -1
		if rule.Kind == "exact" && host == rule.Domain {
			score = 1024 + len(rule.Domain)
		}
		if rule.Kind == "suffix" && (host == rule.Domain || strings.HasSuffix(host, "."+rule.Domain)) {
			score = len(rule.Domain)
		}
		if score > best {
			best = score
			action = rule.Action
		}
	}
	return action
}

func SocketPath(uid int) string { return fmt.Sprintf("/run/n-orm-steroid-%d/direct.sock", uid) }

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
}

func PublicIPv4(ip netip.Addr) bool {
	if !ip.Is4() || !ip.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
