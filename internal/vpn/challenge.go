package vpn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var challengePrefix = regexp.MustCompile(`/_fs-ch-[A-Za-z0-9]+`)
var challengeInit = regexp.MustCompile(`init\((\[[^\]]*\]),\s*"([^"]+)",\s*"([^"]+)"`)

// This implements the bounded PoW/PAT exchange used by the Android client.
// Interactive challenges remain an explicit error rather than an infinite retry.
func (a *API) solveChallenge(ctx context.Context) error {
	const agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
	fetch := func(method, endpoint string, body []byte) ([]byte, int, error) {
		req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", agent)
		req.Header.Set("Accept", "*/*")
		if method == "POST" {
			req.Header.Set("Content-Type", "application/json")
			u, _ := url.Parse(endpoint)
			req.Header.Set("Origin", u.Scheme+"://"+u.Host)
		}
		resp, err := a.HTTP.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
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
						return errors.New("account proof-of-work challenge failed")
					}
					answers = append(answers, map[string]string{"ty": "pow", "base": ch.Data["base"], "answer": suffix, "hmac": ch.Data["hmac"], "expires": ch.Data["expires"]})
				case "pat":
					body, status, e := fetch("POST", base+"/pat?token="+url.QueryEscape(token), nil)
					if e != nil {
						return errors.New("account challenge could not be completed")
					}
					var pat struct {
						Auth string `json:"auth"`
					}
					if status != 400 && status != 401 {
						if status != 200 {
							return errors.New("account challenge was rejected")
						}
						_ = json.Unmarshal(body, &pat)
					}
					answers = append(answers, map[string]string{"ty": "pat", "auth": pat.Auth})
				case "clientmetrics":
					answers = append(answers, map[string]any{"ty": "clientmetrics", "webdriver": false, "bot_detection_result": map[string]any{"bot_detected": false, "bot_kind": nil}, "browser_metrics": map[string]any{"client_data": "{}", "error_trace": nil}, "detector_results": map[string]any{}, "v": 2})
				default:
					return errors.New("account service requires an interactive challenge; try signing in to Firefox first")
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
				// The challenge hosts issue cookies consumed by the Firefox API host.
				u, _ := url.Parse(origin)
				cookies := a.HTTP.Jar.Cookies(u)
				domain, _ := url.Parse("https://api.accounts.firefox.com")
				for _, cookie := range cookies {
					cookie.Domain = ".firefox.com"
					cookie.Path = "/"
					cookie.Secure = true
				}
				a.HTTP.Jar.SetCookies(domain, cookies)
				return nil
			}
			list = response.Challenges
			token = response.Token
			if token == "" {
				break
			}
		}
	}
	return errors.New("account service challenge could not be completed; try again on a stable connection")
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
