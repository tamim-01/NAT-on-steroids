package vpn

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestHawkAuthenticatesPayloadPathAndPort(t *testing.T) {
	const session = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	body := []byte(`{"code":"123456"}`)
	header, err := hawk("POST", "https://api.example.com:8443/v1/session/verify_code?test=1", session, body)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{}
	for _, match := range regexp.MustCompile(`([a-z]+)="([^"]*)"`).FindAllStringSubmatch(header, -1) {
		fields[match[1]] = match[2]
	}
	secret, _ := hex.DecodeString(session)
	prk := hmac.New(sha256.New, make([]byte, 32))
	prk.Write(secret)
	block1 := hmac.New(sha256.New, prk.Sum(nil))
	block1.Write([]byte(protocol + "sessionToken"))
	block1.Write([]byte{1})
	block2 := hmac.New(sha256.New, prk.Sum(nil))
	block2.Write(block1.Sum(nil))
	block2.Write([]byte(protocol + "sessionToken"))
	block2.Write([]byte{2})
	if fields["id"] != hex.EncodeToString(block1.Sum(nil)) {
		t.Fatal("wrong Hawk credential identifier")
	}
	hash := sha256.Sum256(append(append([]byte("hawk.1.payload\napplication/json\n"), body...), '\n'))
	if fields["hash"] != base64.StdEncoding.EncodeToString(hash[:]) {
		t.Fatal("payload hash does not match body")
	}
	normalized := "hawk.1.header\n" + fields["ts"] + "\n" + fields["nonce"] + "\nPOST\n/v1/session/verify_code?test=1\napi.example.com\n8443\n" + fields["hash"] + "\n\n"
	mac := hmac.New(sha256.New, block2.Sum(nil))
	mac.Write([]byte(normalized))
	if fields["mac"] != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
		t.Fatal("Hawk signature does not authenticate the request")
	}
}

func TestPublicMozillaLocationsLive(t *testing.T) {
	if os.Getenv("FOXYVPN_LIVE_TEST") != "1" {
		t.Skip("set FOXYVPN_LIVE_TEST=1 for the read-only Mozilla endpoint check")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	locations, err := NewAPI().Locations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Mozilla returned %d usable locations", len(locations))
}

func TestFirefoxPasswordVector(t *testing.T) {
	// Independently computed with Python hashlib.pbkdf2_hmac and hmac (SHA-256).
	want := "fc3520482606245b8bf0401cb961a8555b736c3b40e1f7d1140f29881a007916"
	if got := AuthPassword("alice@example.com", "correct horse battery staple"); got != want {
		t.Fatalf("password stretching mismatch: got %s", got)
	}
}

func TestLoginVerificationRefreshAndQuota(t *testing.T) {
	const session = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	var loginCount, verificationCount, refreshCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch r.URL.Path {
		case "/account/login":
			loginCount++
			if body["email"] != "alice@example.com" || body["authPW"] != AuthPassword("alice@example.com", "password") {
				t.Error("login was not normalized/stretched")
			}
			if _, ok := body["password"]; ok {
				t.Error("raw password was sent")
			}
			if loginCount == 1 {
				w.WriteHeader(400)
				w.Write([]byte(`{"errno":107,"message":"Invalid parameter"}`))
				return
			}
			if _, exists := body["verificationMethod"]; exists {
				t.Error("invalid verification parameter was not removed")
			}
			json.NewEncoder(w).Encode(map[string]any{"sessionToken": session, "verified": false})
		case "/session/verify_code":
			verificationCount++
			if body["code"] != "123456" || !strings.HasPrefix(r.Header.Get("Authorization"), "Hawk ") {
				t.Error("verification was not authenticated")
			}
			w.Write([]byte(`{}`))
		case "/oauth/token":
			if body["grant_type"] == "refresh_token" {
				refreshCount++
				if body["refresh_token"] != "refresh-one" {
					t.Error("refresh token was not carried")
				}
				w.Write([]byte(`{"access_token":"access-two","expires_in":3600}`))
				return
			}
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Hawk ") {
				t.Error("token exchange missing Hawk authentication")
			}
			w.Write([]byte(`{"access_token":"access-one","refresh_token":"refresh-one","expires_in":3600}`))
		case "/api/v1/fpn/token":
			if r.Header.Get("Authorization") != "Bearer access-two" {
				t.Error("guardian missing renewed access token")
			}
			w.Header().Set("X-Quota-Remaining", "0")
			w.Header().Set("X-Quota-Limit", "50000000000")
			w.Write([]byte(`{"token":"proxy-pass"}`))
		default:
			t.Errorf("unexpected API path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	a := NewAPI()
	a.AuthURL = server.URL
	a.GuardianURL = server.URL
	auth, pending, err := a.Login(context.Background(), " Alice@Example.com ", "password")
	if err != nil || pending != session || auth.AccessToken != "" {
		t.Fatalf("verification flow failed: %v", err)
	}
	auth, err = a.Verify(context.Background(), auth.Email, pending, " 123456 ")
	if err != nil {
		t.Fatal(err)
	}
	auth.ExpiresAt = time.Now().Unix() - 1
	auth, err = a.Refresh(context.Background(), auth)
	if err != nil {
		t.Fatal(err)
	}
	if auth.RefreshToken != "refresh-one" || auth.AccessToken != "access-two" {
		t.Fatal("refresh rotation lost the existing refresh token")
	}
	if _, err = a.ProxyPass(context.Background(), auth); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatal("exhausted quota was accepted")
	}
	if loginCount != 2 || verificationCount != 1 || refreshCount != 1 {
		t.Fatal("authentication flow made unexpected calls")
	}
}

func TestLocationsExcludeQuarantinedAndUnsupportedProtocols(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[{"country":{"code":"US","name":"United States","cities":[{"servers":[{"hostname":"valid.example","port":443,"protocols":[{"name":"connect","port":2499}]},{"hostname":"bad.example","port":443,"quarantined":true},{"hostname":"h3.example","port":443,"protocols":[{"name":"connect-udp"}]}]}]}},{"code":"CA","name":"CatchAll Anycast","cities":[{"servers":[{"hostname":"any.example","port":443}]}]}]}`))
	}))
	defer server.Close()
	a := NewAPI()
	a.ServersURL = server.URL
	locations, err := a.Locations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(locations) != 1 || len(locations[0].Servers) != 1 || locations[0].Servers[0].Host != "valid.example" || locations[0].Servers[0].Port != 2499 {
		t.Fatalf("unexpected usable locations: %+v", locations)
	}
}

func TestMalformedQuotaIsUnknownRatherThanExhausted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Quota-Remaining", "unknown")
		w.Write([]byte(`{"token":"test-pass"}`))
	}))
	defer server.Close()
	a := NewAPI()
	a.GuardianURL = server.URL
	pass, err := a.ProxyPass(context.Background(), Auth{AccessToken: "test-access"})
	if err != nil || pass.Remaining != -1 {
		t.Fatalf("malformed quota was interpreted as exhausted: %v", err)
	}
}

func TestAccountQuotaHeadersAndFailures(t *testing.T) {
	for _, tc := range []struct {
		name, remaining, limit string
		status                 int
		want                   int64
		wantError              bool
	}{
		{"remaining", "24500000000", "50000000000", 200, 24500000000, false},
		{"exhausted", "0", "50000000000", 200, 0, false},
		{"exhausted429", "0", "50000000000", 429, 0, true},
		{"rateLimited", "", "", 429, -1, true},
		{"missing", "", "", 200, -1, false},
		{"invalid", "unknown", "invalid", 200, -1, false},
		{"negative", "-20", "-50", 200, -1, false},
		{"unauthorized", "0", "50000000000", 401, -1, true},
		{"serviceFailure", "0", "50000000000", 503, -1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" || r.URL.Path != "/api/v1/fpn/token" || r.Header.Get("Authorization") != "Bearer test-access" {
					t.Error("quota check activated an account or used incorrect authentication")
				}
				w.Header().Set("X-Quota-Remaining", tc.remaining)
				w.Header().Set("X-Quota-Limit", tc.limit)
				w.WriteHeader(tc.status)
				w.Write([]byte(`{"token":"test-proxy-pass"}`))
			}))
			defer server.Close()
			a := NewAPI()
			a.GuardianURL = server.URL
			q, err := a.AccountQuota(context.Background(), Auth{AccessToken: "test-access"})
			if q.Remaining != tc.want || (err != nil) != tc.wantError || calls != 1 {
				t.Fatalf("remaining=%d error=%v calls=%d", q.Remaining, err, calls)
			}
			if tc.want >= 0 && q.Limit != 50000000000 {
				t.Fatal("quota limit was lost")
			}
		})
	}
}
