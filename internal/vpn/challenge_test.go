package vpn

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

type challengeTransportFunc func(*http.Request) (*http.Response, error)

func (f challengeTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func challengeResponse(r *http.Request, status int, body string, cookies ...*http.Cookie) *http.Response {
	header := make(http.Header)
	for _, cookie := range cookies {
		header.Add("Set-Cookie", cookie.String())
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

func TestAccountChallengeIdentityCookiesAndBoundedRetry(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cookie      *http.Cookie
		reject      bool
		interactive bool
		wantStep    string
	}{
		{name: "success", cookie: &http.Cookie{Name: "_fs_ch_cp_fixture", Value: "new-cookie", Domain: "firefox.com", Path: "/", Secure: true, HttpOnly: true}},
		{name: "no completion cookie", wantStep: "completion-cookie"},
		{name: "site-only cookie", cookie: &http.Cookie{Name: "_fs_ch_cp_fixture", Value: "new-cookie", Path: "/"}, wantStep: "completion-cookie"},
		{name: "wrong path", cookie: &http.Cookie{Name: "_fs_ch_cp_fixture", Value: "new-cookie", Domain: "firefox.com", Path: "/other"}, wantStep: "completion-cookie"},
		{name: "expired cookie", cookie: &http.Cookie{Name: "_fs_ch_cp_fixture", Value: "new-cookie", Domain: "firefox.com", Path: "/", MaxAge: -1}, wantStep: "completion-cookie"},
		{name: "retry rejected", cookie: &http.Cookie{Name: "_fs_ch_cp_fixture", Value: "new-cookie", Domain: "firefox.com", Path: "/"}, reject: true},
		{name: "interactive required", interactive: true, wantStep: "interactive-required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAPI()
			apiURL, _ := url.Parse(a.AuthURL + "/")
			a.HTTP.Jar.SetCookies(apiURL, []*http.Cookie{
				{Name: "_fs_ch_cp_fixture", Value: "stale-cookie", Domain: "firefox.com", Path: "/"},
				{Name: "unrelated", Value: "preserved", Path: "/"},
			})
			calls, postbacks := 0, 0
			var firstBody string
			a.HTTP.Transport = challengeTransportFunc(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("User-Agent") != accountUserAgent {
					t.Error("account and challenge request identities differ")
				}
				switch r.URL.Host + r.URL.Path {
				case "api.accounts.firefox.com/v1/account/login":
					calls++
					body, _ := io.ReadAll(r.Body)
					if calls == 1 {
						firstBody = string(body)
						return challengeResponse(r, 406, ""), nil
					}
					if string(body) != firstBody {
						t.Error("challenge retry changed the request body")
					}
					cookie, e := r.Cookie("_fs_ch_cp_fixture")
					if e != nil || cookie.Value != "new-cookie" {
						t.Error("the old completion cookie shadowed the new one")
					}
					if len(r.Cookies()) != 2 {
						t.Error("a start cookie was copied, a duplicate was created, or an unrelated cookie was lost")
					}
					if tc.reject {
						return challengeResponse(r, 406, "<html>private response must not be exposed</html>"), nil
					}
					return challengeResponse(r, 200, `{}`), nil
				case "api.accounts.firefox.com/":
					return challengeResponse(r, 200, `{}`), nil
				case "accounts.firefox.com/":
					if len(r.Cookies()) != 0 {
						t.Error("the solver reused old cookies instead of starting a fresh challenge")
					}
					return challengeResponse(r, 200, `<script src="/_fs-ch-fixture/script.js"></script>`, &http.Cookie{Name: "_fs_ch_st_fixture", Value: "start", Path: "/", Secure: true}), nil
				case "accounts.firefox.com/_fs-ch-fixture/script.js":
					if tc.interactive {
						return challengeResponse(r, 200, `init([{"ty":"captcha","data":{}}], "fixture-token", "fixture-prefix")`), nil
					}
					hash := sha256.Sum256([]byte("fixture-baseaa"))
					return challengeResponse(r, 200, fmt.Sprintf(`init([{"ty":"pow","data":{"base":"fixture-base","hash":"%x"}}], "fixture-token", "fixture-prefix")`, hash)), nil
				case "accounts.firefox.com/_fs-ch-fixture/fst-post-back":
					postbacks++
					if tc.cookie != nil {
						return challengeResponse(r, 200, `{"status":"success"}`, tc.cookie), nil
					}
					return challengeResponse(r, 200, `{"status":"success"}`), nil
				default:
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					return nil, nil
				}
			})
			_, err := a.request(context.Background(), "POST", a.AuthURL+"/account/login", "", "", map[string]string{"fixture": "request-body"}, nil)
			if tc.wantStep != "" {
				var challengeErr *ChallengeError
				if !errors.As(err, &challengeErr) || challengeErr.Step != tc.wantStep || calls != 1 {
					t.Fatalf("expected challenge refusal at %s without resubmitting login, got %v (calls=%d)", tc.wantStep, err, calls)
				}
			} else if tc.reject {
				var apiErr *APIError
				if !errors.As(err, &apiErr) || apiErr.Status != 406 || !apiErr.Challenged || apiErr.Operation != "login" || strings.Contains(err.Error(), "private response") {
					t.Fatalf("expected a safe, classified rejection: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if calls > 2 || postbacks > 1 {
				t.Fatal("challenge handling retried indefinitely")
			}
		})
	}
}

func TestAccountErrorsAndGuardianIdentityRemainIntact(t *testing.T) {
	for _, tc := range []struct {
		name, endpoint, agent, body string
		status, errno               int
	}{
		{"invalid password", fxaURL + "/account/login", accountUserAgent, `{"errno":103,"message":"Incorrect password"}`, 400, 103},
		{"JSON 406", fxaURL + "/account/login", accountUserAgent, `{"errno":107,"message":"Invalid parameter"}`, 406, 107},
		{"guardian", guardianURL + "/api/v1/fpn/token", userAgent, `{}`, 406, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAPI()
			calls := 0
			a.HTTP.Transport = challengeTransportFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != tc.endpoint || r.Header.Get("User-Agent") != tc.agent {
					t.Error("unexpected endpoint or identity")
				}
				return challengeResponse(r, tc.status, tc.body), nil
			})
			_, err := a.request(context.Background(), "GET", tc.endpoint, "", "", nil, nil)
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Status != tc.status || apiErr.Errno != tc.errno || apiErr.Challenged || calls != 1 {
				t.Fatalf("ordinary API error was changed or started a challenge: %v (calls=%d)", err, calls)
			}
		})
	}
}

type challengeTraceTransport struct {
	base http.RoundTripper
	t    *testing.T
}

func (tr challengeTraceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	stage := req.URL.Path
	if strings.HasPrefix(stage, "/_fs-ch-") {
		stage = "challenge/" + stage[strings.LastIndex(stage, "/")+1:]
	}
	resp, err := tr.base.RoundTrip(req)
	if err != nil {
		tr.t.Logf("%s %s: transport failure", req.Method, stage)
		return nil, err
	}
	tr.t.Logf("%s %s: HTTP %d, protocol=%s, content-type=%q, request-cookies=%d, response-cookies=%d", req.Method, stage, resp.StatusCode, resp.Proto, resp.Header.Get("Content-Type"), len(req.Cookies()), len(resp.Cookies()))
	for _, cookie := range resp.Cookies() {
		kind := "other"
		if strings.HasPrefix(cookie.Name, "_fs_ch_cp_") {
			kind = "challenge-complete"
		} else if strings.HasPrefix(cookie.Name, "_fs_ch_st_") {
			kind = "challenge-start"
		}
		tr.t.Logf("cookie: type=%s, domain=%q, path=%q, secure=%t", kind, cookie.Domain, cookie.Path, cookie.Secure)
	}
	return resp, nil
}

// Sends no account identity or credential. A validation error proves the empty
// request reached the account API instead of being rejected by the edge.
func TestPublicAccountValidationLive(t *testing.T) {
	if os.Getenv("NATOS_ACCOUNT_LIVE_TEST") != "1" {
		t.Skip("set NATOS_ACCOUNT_LIVE_TEST=1 for the empty public validation probe")
	}
	a := NewAPI()
	a.HTTP.Transport = challengeTraceTransport{base: a.HTTP.Transport, t: t}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	_, err := a.request(ctx, http.MethodPost, a.AuthURL+"/account/login", "", "", map[string]string{}, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("empty validation request: %v", err)
	}
	if apiErr.Status != http.StatusBadRequest || apiErr.Errno != 108 {
		t.Fatalf("empty validation did not reach API: HTTP %d, errno %d", apiErr.Status, apiErr.Errno)
	}
}
