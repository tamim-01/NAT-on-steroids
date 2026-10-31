// Protocol behavior is ported from Vauth/FoxyVPN v1.0.7 (MIT).
package vpn

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/net/publicsuffix"
)

const (
	fxaURL        = "https://api.accounts.firefox.com/v1"
	guardianURL   = "https://vpn.mozilla.org"
	serverListURL = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"
	clientID      = "5882386c6d801776"
	scope         = "profile https://identity.mozilla.com/apps/vpn"
	protocol      = "identity.mozilla.com/picl/v1/"
	userAgent     = "MozillaVPN/2.35.0 (sys:linux; iap:true)"
	// Account requests must use the same identity as their challenge exchange.
	accountUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

type Auth struct {
	Email        string `json:"email"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    int64  `json:"expiresAt"`
}

type API struct {
	HTTP                             *http.Client
	AuthURL, GuardianURL, ServersURL string
}

func NewAPI() *API {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	return &API{HTTP: &http.Client{Timeout: 35 * time.Second, Jar: jar, Transport: &http.Transport{ForceAttemptHTTP2: true}}, AuthURL: fxaURL, GuardianURL: guardianURL, ServersURL: serverListURL}
}

type APIError struct {
	Status, Errno int
	Message       string
	Operation     string
	Challenged    bool
}

func (e *APIError) Error() string { return fmt.Sprintf("%s (HTTP %d)", e.Message, e.Status) }

func expand(secret []byte, info string, n int) []byte {
	out := make([]byte, n)
	_, _ = io.ReadFull(hkdf.New(sha256.New, secret, make([]byte, 32), []byte(protocol+info)), out)
	return out
}

func AuthPassword(email, password string) string {
	quick := pbkdf2.Key([]byte(password), []byte(protocol+"quickStretch:"+email), 1000, 32, sha256.New)
	return hex.EncodeToString(expand(quick, "authPW", 32))
}

func hawk(method, endpoint, session string, body []byte) (string, error) {
	secret, err := hex.DecodeString(session)
	if err != nil || len(secret) != 32 {
		return "", errors.New("invalid account session")
	}
	keys := expand(secret, "sessionToken", 64)
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	nonce := make([]byte, 6)
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	n := base64.RawURLEncoding.EncodeToString(nonce)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	hash := ""
	if len(body) > 0 {
		sum := sha256.Sum256(append(append([]byte("hawk.1.payload\napplication/json\n"), body...), '\n'))
		hash = base64.StdEncoding.EncodeToString(sum[:])
	}
	normalized := fmt.Sprintf("hawk.1.header\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n\n", ts, n, strings.ToUpper(method), u.RequestURI(), u.Hostname(), port, hash)
	m := hmac.New(sha256.New, keys[32:])
	m.Write([]byte(normalized))
	header := fmt.Sprintf(`Hawk id="%s", ts="%s", nonce="%s", mac="%s"`, hex.EncodeToString(keys[:32]), ts, n, base64.StdEncoding.EncodeToString(m.Sum(nil)))
	if hash != "" {
		header += fmt.Sprintf(`, hash="%s"`, hash)
	}
	return header, nil
}

func (a *API) request(ctx context.Context, method, endpoint, session, bearer string, input, output any) (http.Header, error) {
	accountRequest := strings.HasPrefix(endpoint, strings.TrimRight(a.AuthURL, "/")+"/")
	operation := "service"
	if accountRequest {
		switch strings.TrimPrefix(endpoint, strings.TrimRight(a.AuthURL, "/")+"/") {
		case "account/login":
			operation = "login"
		case "session/verify_code":
			operation = "email-verification"
		case "oauth/token":
			operation = "token-exchange"
		}
	}
	var data []byte
	var err error
	if input != nil {
		data, err = json.Marshal(input)
		if err != nil {
			return nil, err
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		if accountRequest {
			req.Header.Set("User-Agent", accountUserAgent)
		}
		req.Header.Set("Accept", "application/json")
		if input != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if session != "" {
			header, e := hawk(method, endpoint, session, data)
			if e != nil {
				return nil, e
			}
			req.Header.Set("Authorization", header)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := a.HTTP.Do(req)
		if err != nil {
			return nil, errors.New("cannot reach the account service; check your connection")
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if readErr != nil {
			return nil, errors.New("account service response was interrupted")
		}
		var api struct {
			Message string `json:"message"`
			Errno   int    `json:"errno"`
		}
		_ = json.Unmarshal(body, &api)
		if accountRequest && resp.StatusCode == 406 && api.Errno == 0 && api.Message == "" && attempt == 0 {
			if err := a.solveChallenge(ctx); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			// Only expose parsed API messages, never arbitrary response pages or tokens.
			if api.Message == "" {
				api.Message = "account service rejected the request"
			}
			if len(api.Message) > 220 {
				api.Message = "account service rejected the request"
			}
			if resp.StatusCode == 429 {
				api.Message = "account quota or request limit reached; try again later"
			}
			if accountRequest && resp.StatusCode == 406 && api.Errno == 0 {
				api.Message = "Mozilla's sign-in security check rejected the app"
			}
			return resp.Header, &APIError{Status: resp.StatusCode, Errno: api.Errno, Message: api.Message, Operation: operation, Challenged: attempt > 0}
		}
		if output != nil && len(body) > 0 {
			if err = json.Unmarshal(body, output); err != nil {
				return nil, errors.New("invalid response from the account service")
			}
		}
		return resp.Header, nil
	}
	return nil, errors.New("account service challenge was not accepted")
}

func (a *API) Login(ctx context.Context, email, password string) (Auth, string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || password == "" {
		return Auth{}, "", errors.New("enter your email and password")
	}
	body := map[string]any{"email": email, "authPW": AuthPassword(email, password), "verificationMethod": "email-2fa"}
	var result struct {
		Session  string `json:"sessionToken"`
		Verified bool   `json:"verified"`
	}
	_, err := a.request(ctx, "POST", a.AuthURL+"/account/login", "", "", body, &result)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Errno == 107 {
		delete(body, "verificationMethod")
		_, err = a.request(ctx, "POST", a.AuthURL+"/account/login", "", "", body, &result)
	}
	if err != nil {
		return Auth{}, "", err
	}
	if result.Session == "" {
		return Auth{}, "", errors.New("account service returned no session")
	}
	if !result.Verified {
		return Auth{Email: email}, result.Session, nil
	}
	auth, err := a.exchange(ctx, email, result.Session)
	return auth, "", err
}

func (a *API) Verify(ctx context.Context, email, session, code string) (Auth, error) {
	_, err := a.request(ctx, "POST", a.AuthURL+"/session/verify_code", session, "", map[string]string{"code": strings.TrimSpace(code)}, nil)
	if err != nil {
		return Auth{}, err
	}
	return a.exchange(ctx, email, session)
}

func (a *API) exchange(ctx context.Context, email, session string) (Auth, error) {
	return a.token(ctx, email, session, map[string]string{"client_id": clientID, "grant_type": "fxa-credentials", "scope": scope, "access_type": "offline"})
}

func (a *API) token(ctx context.Context, email, session string, body any) (Auth, error) {
	var r struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		Expires int64  `json:"expires_in"`
	}
	_, err := a.request(ctx, "POST", a.AuthURL+"/oauth/token", session, "", body, &r)
	if err != nil {
		return Auth{}, err
	}
	if r.Access == "" {
		return Auth{}, errors.New("account service returned no access token")
	}
	if r.Expires <= 0 {
		r.Expires = 86400
	}
	return Auth{email, r.Access, r.Refresh, time.Now().Unix() + r.Expires}, nil
}

func (a *API) Refresh(ctx context.Context, auth Auth) (Auth, error) {
	if auth.ExpiresAt > time.Now().Unix()+90 {
		return auth, nil
	}
	if auth.RefreshToken == "" {
		return Auth{}, errors.New("your session expired; sign in again")
	}
	next, err := a.token(ctx, auth.Email, "", map[string]string{"client_id": clientID, "grant_type": "refresh_token", "refresh_token": auth.RefreshToken, "scope": scope})
	if next.RefreshToken == "" {
		next.RefreshToken = auth.RefreshToken
	}
	return next, err
}

type Pass struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	Limit     int64  `json:"-"`
	Remaining int64  `json:"-"`
}

type Quota struct {
	Limit, Remaining int64
}

func quotaFromHeaders(headers http.Header) Quota {
	q := Quota{Remaining: -1}
	if limit, err := strconv.ParseInt(headers.Get("X-Quota-Limit"), 10, 64); err == nil && limit >= 0 {
		q.Limit = limit
	}
	if remaining, err := strconv.ParseInt(headers.Get("X-Quota-Remaining"), 10, 64); err == nil && remaining >= 0 {
		q.Remaining = remaining
	}
	return q
}

// Guardian exposes the remaining allowance on the token response, as used by
// the Android client. Checking it does not activate or select an account.
func (a *API) AccountQuota(ctx context.Context, auth Auth) (Quota, error) {
	headers, err := a.request(ctx, "GET", a.GuardianURL+"/api/v1/fpn/token", "", auth.AccessToken, nil, nil)
	var apiErr *APIError
	if err != nil && !(errors.As(err, &apiErr) && apiErr.Status == 429) {
		return Quota{Remaining: -1}, err
	}
	return quotaFromHeaders(headers), err
}

func (a *API) ProxyPass(ctx context.Context, auth Auth) (Pass, error) {
	p := Pass{Remaining: -1}
	headers, err := a.request(ctx, "GET", a.GuardianURL+"/api/v1/fpn/token", "", auth.AccessToken, nil, &p)
	var apiErr *APIError
	if errors.As(err, &apiErr) && (apiErr.Status == 401 || apiErr.Status == 403) {
		_, activationErr := a.request(ctx, "POST", a.GuardianURL+"/api/v1/fpn/activate", "", auth.AccessToken, map[string]string{}, nil)
		if activationErr != nil {
			return p, activationErr
		}
		headers, err = a.request(ctx, "GET", a.GuardianURL+"/api/v1/fpn/token", "", auth.AccessToken, nil, &p)
	}
	// A quota response can include an exhausted balance even when HTTP 429
	// prevents issuing a usable pass. Other failures are not quota evidence.
	if err == nil || (errors.As(err, &apiErr) && apiErr.Status == 429) {
		q := quotaFromHeaders(headers)
		p.Limit, p.Remaining = q.Limit, q.Remaining
	}
	if err != nil {
		return p, err
	}
	if p.Token == "" {
		return p, errors.New("Mozilla returned no proxy credential")
	}
	if p.Remaining == 0 {
		return p, errors.New("monthly VPN allowance is exhausted")
	}
	if p.ExpiresAt == 0 {
		parts := strings.Split(p.Token, ".")
		if len(parts) == 3 {
			payload, e := base64.RawURLEncoding.DecodeString(parts[1])
			if e == nil {
				var claims struct {
					Exp int64 `json:"exp"`
				}
				_ = json.Unmarshal(payload, &claims)
				p.ExpiresAt = claims.Exp
			}
		}
	}
	return p, nil
}

type Location struct {
	Code          string   `json:"code"`
	Name          string   `json:"name"`
	Servers       []Server `json:"-"`
	PingMS        int64    `json:"pingMs"`
	PingCheckedAt int64    `json:"pingCheckedAt"`
}
type Server struct {
	Host string
	Port int
}

func (a *API) Locations(ctx context.Context) ([]Location, error) {
	type node struct {
		Hostname    string `json:"hostname"`
		Port        int    `json:"port"`
		Quarantined bool   `json:"quarantined"`
		Protocols   []struct {
			Name, Host string
			Port       int
		} `json:"protocols"`
	}
	type country struct {
		Code, Name string
		Cities     []struct{ Servers []node }
	}
	var envelope struct {
		Data []json.RawMessage `json:"data"`
	}
	_, err := a.request(ctx, "GET", a.ServersURL, "", "", nil, &envelope)
	if err != nil {
		return nil, err
	}
	out := []Location{}
	for _, raw := range envelope.Data {
		var wrapped struct {
			Country *country `json:"country"`
		}
		var c country
		if json.Unmarshal(raw, &wrapped) != nil {
			continue
		}
		if wrapped.Country != nil {
			c = *wrapped.Country
		} else {
			_ = json.Unmarshal(raw, &c)
		}
		if c.Code == "" || strings.EqualFold(c.Name, "CatchAll Anycast") {
			continue
		}
		loc := Location{Code: c.Code, Name: c.Name, PingMS: -1}
		for _, city := range c.Cities {
			for _, n := range city.Servers {
				if n.Quarantined {
					continue
				}
				host, port := n.Hostname, n.Port
				if len(n.Protocols) > 0 {
					host = ""
					for _, p := range n.Protocols {
						if p.Name == "connect" {
							host = p.Host
							if host == "" {
								host = n.Hostname
							}
							port = p.Port
							if port == 0 {
								port = n.Port
							}
							break
						}
					}
				}
				if host != "" && port > 0 && port <= 65535 {
					loc.Servers = append(loc.Servers, Server{host, port})
				}
			}
		}
		if len(loc.Servers) > 0 {
			out = append(out, loc)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) == 0 {
		return nil, errors.New("Mozilla returned no usable VPN locations")
	}
	return out, nil
}
