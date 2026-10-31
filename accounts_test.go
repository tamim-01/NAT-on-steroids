package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"nat-on-steroids/internal/vpn"
)

type memoryVault struct {
	data              string
	locked, failWrite bool
}

func (m *memoryVault) operation(op, data string) (string, error) {
	if m.locked {
		return "", errKeyringLocked
	}
	if op == "get" {
		return m.data, nil
	}
	if m.failWrite {
		return "", errors.New("test write failure")
	}
	if op == "delete" {
		m.data = ""
	} else {
		m.data = data
	}
	return "", nil
}
func accountFixture(email string) vpn.Auth {
	return vpn.Auth{Email: email, AccessToken: "test-access-for-" + email, RefreshToken: "test-refresh-for-" + email, ExpiresAt: time.Now().Add(time.Hour).Unix()}
}
func accountApp() (*App, *memoryVault) {
	a := NewApp()
	m := &memoryVault{}
	a.store = m.operation
	return a, m
}

func TestAccountsSwitchClosesProxyAndPersistsSelection(t *testing.T) {
	a, m := accountApp()
	a.saveAuth(accountFixture("one@example.invalid"))
	a.saveAuth(accountFixture("two@example.invalid"))
	if len(a.GetState().Accounts) != 2 || a.GetState().Email != "two@example.invalid" {
		t.Fatal("adding accounts lost a sign-in")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := vpn.StartProxy(ctx, unusedOpener{}, "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(p.Port()))
	a.proxy = p
	a.cancel = cancel
	a.state.Status = "connected"
	a.state.QuotaRemaining = 123
	if err = a.SwitchAccount("ONE@example.invalid"); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == nil || a.proxy != nil || a.GetState().Status != "disconnected" {
		t.Fatal("switching accounts did not stop the old connection")
	}
	if conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("old proxy listener remained open")
	}
	if a.auth.Email != "one@example.invalid" || a.GetState().QuotaRemaining != -1 {
		t.Fatal("previous account state leaked into selected account")
	}
	vault, err := decodeVault(m.data)
	if err != nil || vault.ActiveEmail != "one@example.invalid" || len(vault.Accounts) != 2 {
		t.Fatal("selection was not persisted")
	}
	frontend, _ := json.Marshal(a.GetState())
	if strings.Contains(string(frontend), "test-access") || strings.Contains(string(frontend), "test-refresh") {
		t.Fatal("frontend state contains account credentials")
	}
}

type unusedOpener struct{}

func (unusedOpener) Open(context.Context, string) (io.ReadWriteCloser, error) {
	return nil, errors.New("unused test transport")
}

func TestLegacyAccountMigrationAndPendingLoginIsolation(t *testing.T) {
	a, m := accountApp()
	legacy := accountFixture("old@example.invalid")
	data, _ := json.Marshal(legacy)
	m.data = string(data)
	if err := a.ensureVault(); err != nil {
		t.Fatal(err)
	}
	a.publishAccounts()
	if a.GetState().Email != legacy.Email || len(a.accounts) != 1 {
		t.Fatal("legacy sign-in was not restored")
	}
	a.pending = "test-pending-session"
	a.pendingEmail = "new@example.invalid"
	a.publishAccounts()
	if a.GetState().Email != legacy.Email || a.GetState().PendingEmail != "new@example.invalid" {
		t.Fatal("pending sign-in overwrote the active account")
	}
	a.CancelVerification()
	if a.GetState().Email != legacy.Email || a.GetState().NeedsCode {
		t.Fatal("cancelling sign-in removed the active account")
	}
	a.saveAuth(accountFixture("new@example.invalid"))
	vault, err := decodeVault(m.data)
	if err != nil || len(vault.Accounts) != 2 || vault.Schema != 1 {
		t.Fatal("legacy session was not retained in the new vault")
	}
}

func TestLockedVaultIsMergedBeforeSavingNewAccounts(t *testing.T) {
	a, m := accountApp()
	old := accountFixture("saved@example.invalid")
	data, _ := json.Marshal(old)
	m.data = string(data)
	m.locked = true
	if err := a.ensureVault(); !errors.Is(err, errKeyringLocked) {
		t.Fatal("expected locked keyring")
	}
	a.saveAuth(accountFixture("new@example.invalid"))
	if m.data != string(data) {
		t.Fatal("locked saved account was overwritten")
	}
	m.locked = false
	a.saveAuth(accountFixture("new@example.invalid"))
	vault, err := decodeVault(m.data)
	if err != nil || len(vault.Accounts) != 2 || vault.ActiveEmail != "new@example.invalid" {
		t.Fatal("unseen saved accounts were not merged")
	}
}

func TestAccountRemovalAndWriteFailure(t *testing.T) {
	a, m := accountApp()
	a.saveAuth(accountFixture("one@example.invalid"))
	a.saveAuth(accountFixture("two@example.invalid"))
	m.failWrite = true
	if err := a.RemoveAccount("two@example.invalid"); err == nil {
		t.Fatal("saved account deletion failure was hidden")
	}
	if a.auth.Email != "two@example.invalid" || len(a.accounts) != 2 {
		t.Fatal("failed deletion lost in-memory accounts")
	}
	m.failWrite = false
	if err := a.RemoveAccount("two@example.invalid"); err != nil {
		t.Fatal(err)
	}
	if a.GetState().Email != "one@example.invalid" || !a.GetState().SignedIn {
		t.Fatal("remaining account was not selected")
	}
	if err := a.SignOut(); err != nil {
		t.Fatal(err)
	}
	if a.GetState().SignedIn || len(a.accounts) != 0 || m.data != "" {
		t.Fatal("last account was not removed from the keyring")
	}
}

func TestRemovingInactiveAccountDoesNotDisconnectActiveAccount(t *testing.T) {
	a, _ := accountApp()
	a.saveAuth(accountFixture("one@example.invalid"))
	a.saveAuth(accountFixture("two@example.invalid"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.cancel = cancel
	a.state.Status = "connected"
	if err := a.RemoveAccount("one@example.invalid"); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil || a.GetState().Status != "connected" || a.auth.Email != "two@example.invalid" {
		t.Fatal("removing an inactive account disturbed the active connection")
	}
}

func TestFailedTokenRenewalPreservesSelectedAccount(t *testing.T) {
	a, _ := accountApp()
	auth := accountFixture("one@example.invalid")
	auth.ExpiresAt = 0
	a.saveAuth(auth)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		w.Write([]byte(`{"message":"temporarily unavailable"}`))
	}))
	defer server.Close()
	a.api.AuthURL = server.URL
	if err := a.Connect("US", "proxy"); err == nil {
		t.Fatal("expected token renewal failure")
	}
	if a.auth != auth || len(a.accounts) != 1 || a.accounts[0] != auth || a.GetState().Email != auth.Email {
		t.Fatal("transient renewal failure erased the selected account")
	}
}

func TestUnrecognizedVaultIsNotOverwritten(t *testing.T) {
	for _, data := range []string{`{"schema":2,"accounts":[]}`, `{"schema":1}`, `{"schema":1,"accounts":null}`, `{broken`} {
		a, m := accountApp()
		m.data = data
		a.saveAuth(accountFixture("one@example.invalid"))
		if m.data != data || a.GetState().Notice == "" {
			t.Fatal("invalid or newer saved data was overwritten without warning")
		}
	}
}

func TestPerAccountQuotaRefreshIsolationAndStaleBalances(t *testing.T) {
	a, _ := accountApp()
	one, two := accountFixture("one@example.invalid"), accountFixture("two@example.invalid")
	a.saveAuth(one)
	a.saveAuth(two)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.cancel = cancel
	a.state.Status = "connected"
	a.pass = vpn.Pass{Token: "active-test-pass", Remaining: 800}
	a.pending, a.pendingEmail = "test-pending", "new@example.invalid"
	fail := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/fpn/token" {
			t.Error("quota refresh made an unexpected request")
		}
		if fail {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("X-Quota-Limit", "50000000000")
		switch r.Header.Get("Authorization") {
		case "Bearer " + one.AccessToken:
			w.Header().Set("X-Quota-Remaining", "12000000000")
		case "Bearer " + two.AccessToken:
			w.Header().Set("X-Quota-Remaining", "0")
		default:
			t.Error("quota request used the wrong account")
		}
		w.Write([]byte(`{"token":"unused-test-pass"}`))
	}))
	defer server.Close()
	a.api.GuardianURL = server.URL
	for _, email := range []string{one.Email, two.Email} {
		if err := a.RefreshAccountQuota(email); err != nil {
			t.Fatal(err)
		}
	}
	state := a.GetState()
	if state.Accounts[0].QuotaRemaining != 12000000000 || state.Accounts[1].QuotaRemaining != 0 || state.QuotaRemaining != 0 {
		t.Fatal("per-account balances were mixed or exhausted balance was hidden")
	}
	if ctx.Err() != nil || state.Status != "connected" || a.auth != two || a.pass.Token != "active-test-pass" || a.pending != "test-pending" || state.PendingEmail != "new@example.invalid" {
		t.Fatal("quota refresh changed selection, connection, credential, or pending verification")
	}
	checked := state.Accounts[0].QuotaCheckedAt
	if checked == 0 {
		t.Fatal("successful balance has no timestamp")
	}
	fail = true
	if err := a.RefreshAccountQuota(one.Email); err != nil {
		t.Fatal(err)
	}
	state = a.GetState()
	if state.Accounts[0].QuotaRemaining != 12000000000 || state.Accounts[0].QuotaCheckedAt != checked || state.Accounts[0].QuotaError == "" || state.Accounts[1].QuotaError != "" {
		t.Fatal("failed refresh lost the last known balance or affected another account")
	}
	if err := a.SwitchAccount(one.Email); err != nil {
		t.Fatal(err)
	}
	if a.GetState().QuotaRemaining != 12000000000 {
		t.Fatal("switch did not display the selected account's cached allowance")
	}
	if err := a.RemoveAccount(one.Email); err != nil {
		t.Fatal(err)
	}
	if _, exists := a.accountQuotas[one.Email]; exists {
		t.Fatal("removed account retained cached traffic")
	}
}

func TestQuotaRefreshPersistsRotatedInactiveCredentialsBeforeQuotaFailure(t *testing.T) {
	a, m := accountApp()
	one, two := accountFixture("one@example.invalid"), accountFixture("two@example.invalid")
	one.ExpiresAt = 0
	a.saveAuth(one)
	a.saveAuth(two)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Write([]byte(`{"access_token":"rotated-test-access","refresh_token":"rotated-test-refresh","expires_in":3600}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer rotated-test-access" {
			t.Error("quota used stale access token")
		}
		w.WriteHeader(503)
	}))
	defer server.Close()
	a.api.AuthURL, a.api.GuardianURL = server.URL, server.URL
	if err := a.RefreshAccountQuota(one.Email); err != nil {
		t.Fatal(err)
	}
	vault, err := decodeVault(m.data)
	if err != nil || vault.ActiveEmail != two.Email || vault.Accounts[0].RefreshToken != "rotated-test-refresh" || a.auth != two {
		t.Fatal("quota failure lost rotated credentials or changed active account")
	}
	if a.GetState().Accounts[0].QuotaRemaining != -1 || a.GetState().Accounts[0].QuotaError == "" {
		t.Fatal("failed quota appeared as exhausted or hid the failure")
	}
	frontend, _ := json.Marshal(a.GetState())
	if strings.Contains(string(frontend), "rotated-test") {
		t.Fatal("quota state exposed tokens")
	}
}

func TestQuotaRefreshFailurePreservesCredentials(t *testing.T) {
	a, _ := accountApp()
	auth := accountFixture("one@example.invalid")
	auth.ExpiresAt = 0
	a.saveAuth(auth)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer server.Close()
	a.api.AuthURL = server.URL
	if err := a.RefreshAccountQuota(auth.Email); err != nil {
		t.Fatal(err)
	}
	if a.auth != auth || a.accounts[0] != auth || a.GetState().Accounts[0].QuotaRemaining != -1 || a.GetState().Accounts[0].QuotaError == "" {
		t.Fatal("failed renewal erased credentials or displayed a false zero balance")
	}
	if err := a.RefreshAccountQuota("missing@example.invalid"); err == nil {
		t.Fatal("missing account was accepted")
	}
}

func TestConnectPublishesExhaustedAccountQuota(t *testing.T) {
	for _, status := range []int{200, 429} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			a, _ := accountApp()
			a.saveAuth(accountFixture("one@example.invalid"))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Quota-Limit", "50000000000")
				w.Header().Set("X-Quota-Remaining", "0")
				w.WriteHeader(status)
				w.Write([]byte(`{"token":"test-pass"}`))
			}))
			defer server.Close()
			a.api.GuardianURL = server.URL
			if err := a.Connect("US", "proxy"); err == nil {
				t.Fatal("exhausted account connected")
			}
			state := a.GetState()
			if state.QuotaRemaining != 0 || state.Accounts[0].QuotaRemaining != 0 || state.Accounts[0].QuotaCheckedAt == 0 {
				t.Fatal("failed connection hid the confirmed exhausted balance")
			}
		})
	}
}
