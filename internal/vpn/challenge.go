package vpn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

var challengePrefix = regexp.MustCompile(`/_fs-ch-[A-Za-z0-9]+`)
var challengeInit = regexp.MustCompile(`init\((\[[^\]]*\]),\s*"([^"]+)",\s*"([^"]+)"`)

// Only fixed step names and HTTP status codes are retained for diagnostics.
type ChallengeError struct {
	Step   string
	Status int
}

func (e *ChallengeError) Error() string {
	if e.Step == "interactive-required" {
		return "Mozilla requires an interactive sign-in security check that this app cannot complete"
	}
	if e.Status == 0 {
		return fmt.Sprintf("Mozilla's sign-in security check could not be completed (%s)", e.Step)
	}
	return fmt.Sprintf("Mozilla's sign-in security check could not be completed (%s, HTTP %d)", e.Step, e.Status)
}

// This implements the bounded PoW/PAT exchange used by the Android client.
// Interactive challenges remain an explicit error rather than an infinite retry.
func (a *API) solveChallenge(ctx context.Context) error {
	// Re-solving must not reuse an old completion cookie, which can hide the
	// challenge page. Keep the same transport and request identity as the API.
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	client := *a.HTTP
	client.Jar = jar
	type issuedCookie struct {
		origin *url.URL
		cookie *http.Cookie
	}
	var issued []issuedCookie
	fetch := func(method, endpoint string, body []byte) ([]byte, int, error) {
		req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", accountUserAgent)
		req.Header.Set("Accept", "*/*")
		if method == "POST" {
			req.Header.Set("Content-Type", "application/json")
			u, _ := url.Parse(endpoint)
			req.Header.Set("Origin", u.Scheme+"://"+u.Host)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		issuer := req.URL
		if resp.Request != nil {
			issuer = resp.Request.URL
		}
		for _, cookie := range resp.Cookies() {
			if strings.HasPrefix(cookie.Name, "_fs_ch_cp_") {
				issued = append(issued, issuedCookie{issuer, cookie})
			}
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		return b, resp.StatusCode, err
	}
	for _, origin := range []string{"https://api.accounts.firefox.com", "https://accounts.firefox.com"} {
		page, _, err := fetch("GET", origin+"/", nil)
		if err != nil {
			continue
		}
		prefix := challengePrefix.Find(page)
		if len(prefix) == 0 {
			continue
		}
		base := origin + string(prefix)
		script, _, err := fetch("GET", base+"/script.js?reload=true", nil)
		if err != nil {
			continue
		}
		matches := challengeInit.FindAllSubmatch(script, -1)
		if len(matches) == 0 {
			continue
		}
		init := matches[len(matches)-1]
		token := string(init[2])
		list := init[1]
		for round := 0; round < 3; round++ {
			var challenges []struct {
				Type string            `json:"ty"`
				Data map[string]string `json:"data"`
			}
			if json.Unmarshal(list, &challenges) != nil || len(challenges) == 0 {
				break
			}
			answers := []any{}
			for _, ch := range challenges {
				switch ch.Type {
				case "pow":
					suffix := solvePOW(ch.Data["base"], ch.Data["hash"])
					if suffix == "" {
						return &ChallengeError{Step: "proof-of-work"}
					}
					answers = append(answers, map[string]string{"ty": "pow", "base": ch.Data["base"], "answer": suffix, "hmac": ch.Data["hmac"], "expires": ch.Data["expires"]})
				case "pat":
					body, status, e := fetch("POST", base+"/pat?token="+url.QueryEscape(token), nil)
					if e != nil {
						return &ChallengeError{Step: "private-access-token"}
					}
					var pat struct {
						Auth string `json:"auth"`
					}
					if status != 400 && status != 401 {
						if status != 200 {
							return &ChallengeError{Step: "private-access-token", Status: status}
						}
						_ = json.Unmarshal(body, &pat)
					}
					answers = append(answers, map[string]string{"ty": "pat", "auth": pat.Auth})
				case "clientmetrics":
					answers = append(answers, map[string]any{"ty": "clientmetrics", "webdriver": false, "bot_detection_result": map[string]any{"bot_detected": false, "bot_kind": nil}, "browser_metrics": map[string]any{"client_data": "{}", "error_trace": nil}, "detector_results": map[string]any{}, "v": 2})
				default:
					return &ChallengeError{Step: "interactive-required"}
				}
			}
			body, _ := json.Marshal(map[string]any{"token": token, "data": answers})
			result, status, err := fetch("POST", base+"/fst-post-back", body)
			if err != nil || status != 200 {
				break
			}
			var response struct {
				Status     string          `json:"status"`
				Challenges json.RawMessage `json:"ch"`
				Token      string          `json:"tok"`
			}
			if json.Unmarshal(result, &response) != nil {
				break
			}
			if response.Status == "success" {
				// A successful post-back alone is insufficient. Require a completed
				// challenge cookie whose original scope already covers the API.
				domain, _ := url.Parse(a.AuthURL + "/")
				complete := map[string]string{}
				for _, cookie := range jar.Cookies(domain) {
					if strings.HasPrefix(cookie.Name, "_fs_ch_cp_") {
						complete[cookie.Name] = cookie.Value
					}
				}
				if len(complete) == 0 {
					return &ChallengeError{Step: "completion-cookie", Status: status}
				}
				if a.HTTP.Jar == nil {
					a.HTTP.Jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
				}
				// Preserve issuer scope, expiry and flags so a new cookie replaces
				// the old entry instead of creating a shadowing duplicate.
				installed := false
				for _, item := range issued {
					if value, ok := complete[item.cookie.Name]; ok && value == item.cookie.Value {
						a.HTTP.Jar.SetCookies(item.origin, []*http.Cookie{item.cookie})
						installed = true
					}
				}
				if !installed {
					return &ChallengeError{Step: "completion-cookie", Status: status}
				}
				return nil
			}
			list = response.Challenges
			token = response.Token
			if token == "" {
				break
			}
		}
	}
	return &ChallengeError{Step: "challenge-exchange"}
}

func solvePOW(base, target string) string {
	if _, err := hex.DecodeString(target); err != nil || len(target) != 64 {
		return ""
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for _, x := range alphabet {
		for _, y := range alphabet {
			suffix := string([]rune{x, y})
			sum := sha256.Sum256([]byte(base + suffix))
			if strings.EqualFold(hex.EncodeToString(sum[:]), target) {
				return suffix
			}
		}
	}
	return ""
}
