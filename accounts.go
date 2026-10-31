package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"nat-on-steroids/internal/vpn"
)

type Account struct {
	Email          string `json:"email"`
	QuotaLimit     int64  `json:"quotaLimit"`
	QuotaRemaining int64  `json:"quotaRemaining"`
	QuotaCheckedAt int64  `json:"quotaCheckedAt"`
	QuotaError     string `json:"quotaError"`
}
type accountVault struct {
	Schema      int        `json:"schema"`
	ActiveEmail string     `json:"activeEmail"`
	Accounts    []vpn.Auth `json:"accounts"`
}

func decodeVault(data string) (accountVault, error) {
	vault := accountVault{Schema: 1, Accounts: []vpn.Auth{}}
	if data == "" {
		return vault, nil
	}
	var header struct {
		Schema *int `json:"schema"`
	}
	if json.Unmarshal([]byte(data), &header) != nil {
		return vault, errors.New("saved account data is invalid; it has not been overwritten")
	}
	if header.Schema == nil {
		var legacy vpn.Auth
		if json.Unmarshal([]byte(data), &legacy) != nil || legacy.AccessToken == "" || legacy.Email == "" {
			return vault, errors.New("saved account data is invalid; it has not been overwritten")
		}
		vault.Accounts = []vpn.Auth{legacy}
		vault.ActiveEmail = legacy.Email
	} else {
		if *header.Schema != 1 {
			return vault, errors.New("saved accounts use an unsupported format; they have not been overwritten")
		}
		vault = accountVault{}
		if json.Unmarshal([]byte(data), &vault) != nil || vault.Accounts == nil {
			return vault, errors.New("saved account data is invalid; it has not been overwritten")
		}
	}
	seen := map[string]bool{}
	for i := range vault.Accounts {
		account := &vault.Accounts[i]
		account.Email = strings.ToLower(strings.TrimSpace(account.Email))
		if account.Email == "" || account.AccessToken == "" || seen[account.Email] {
			return vault, errors.New("saved account data is invalid; it has not been overwritten")
		}
		seen[account.Email] = true
	}
	vault.ActiveEmail = strings.ToLower(strings.TrimSpace(vault.ActiveEmail))
	return vault, nil
}

func mergeAccounts(stored, current []vpn.Auth) []vpn.Auth {
	merged := append([]vpn.Auth{}, stored...)
	for _, account := range current {
		found := false
		for i := range merged {
			if merged[i].Email == account.Email {
				merged[i] = account
				found = true
				break
			}
		}
		if !found {
			merged = append(merged, account)
		}
	}
	return merged
}

// If the keyring was locked at startup, read and merge it before any write.
// Otherwise adding an account after unlocking could erase unseen saved accounts.
func (a *App) ensureVault() error {
	if a.vaultReady {
		return nil
	}
	data, err := a.store("get", "")
	if err != nil {
		if errors.Is(err, errKeyringLocked) {
			a.savedSession = true
		}
		return err
	}
	vault, err := decodeVault(data)
	if err != nil {
		a.savedSession = true
		return err
	}
	a.accounts = mergeAccounts(vault.Accounts, a.accounts)
	a.vaultReady = true
	a.savedSession = data != ""
	if a.auth.AccessToken == "" && len(a.accounts) > 0 {
		a.auth = a.accounts[0]
		for _, account := range a.accounts {
			if account.Email == vault.ActiveEmail {
				a.auth = account
				break
			}
		}
	}
	return nil
}

func (a *App) publishAccounts() {
	accounts := make([]Account, 0, len(a.accounts))
	for _, account := range a.accounts {
		info, ok := a.accountQuotas[account.Email]
		if !ok {
			info = Account{QuotaRemaining: -1}
		}
		info.Email = account.Email
		accounts = append(accounts, info)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state.Accounts = accounts
	a.state.SignedIn = a.auth.AccessToken != ""
	a.state.Email = a.auth.Email
	a.state.NeedsCode = a.pending != ""
	a.state.PendingEmail = a.pendingEmail
	a.state.QuotaLimit, a.state.QuotaRemaining = 0, -1
	if quota, ok := a.accountQuotas[a.auth.Email]; ok {
		a.state.QuotaLimit, a.state.QuotaRemaining = quota.QuotaLimit, quota.QuotaRemaining
	}
}

func (a *App) recordQuota(email string, quota vpn.Quota, err error) {
	info, ok := a.accountQuotas[email]
	if !ok {
		info = Account{QuotaRemaining: -1}
	}
	info.QuotaError = ""
	if quota.Remaining >= 0 {
		info.QuotaLimit, info.QuotaRemaining = quota.Limit, quota.Remaining
		info.QuotaCheckedAt = time.Now().Unix()
	} else if err == nil {
		info.QuotaError = "Mozilla did not return a remaining allowance."
	}
	if err != nil && quota.Remaining < 0 {
		info.QuotaError = "Could not refresh traffic. Try again."
		var apiErr *vpn.APIError
		if errors.As(err, &apiErr) {
			if apiErr.Status == 401 || apiErr.Status == 403 {
				info.QuotaError = "Account access was rejected. Reconnect or sign in again."
			} else if apiErr.Status == 429 {
				info.QuotaError = "Request limit reached. Try again later."
			}
		}
	}
	if a.accountQuotas == nil {
		a.accountQuotas = make(map[string]Account)
	}
	a.accountQuotas[email] = info
	if a.quotaAttemptedAt == nil {
		a.quotaAttemptedAt = make(map[string]time.Time)
	}
	a.quotaAttemptedAt[email] = time.Now()
	a.publishAccounts()
}

func (a *App) RefreshAccountQuota(email string) error {
	a.cancelQuotaRefresh()
	a.operation.Lock()
	defer a.operation.Unlock()
	ctx, cancel := context.WithTimeout(a.ctx, 25*time.Second)
	defer cancel()
	return a.refreshAccountQuota(ctx, email)
}

// Caller holds operation so refresh-token rotation cannot race a sign-in,
// account removal, or connection renewal.
func (a *App) refreshAccountQuota(ctx context.Context, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	for i, account := range a.accounts {
		if account.Email != email {
			continue
		}
		auth, err := a.api.Refresh(ctx, account)
		if err != nil {
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil
			}
			a.recordQuota(email, vpn.Quota{Remaining: -1}, err)
			return nil // The failure belongs to this account's traffic display.
		}
		if auth != account {
			// Persist rotated credentials without selecting this account or
			// disturbing an in-progress verification for a different account.
			a.accounts[i] = auth
			if a.auth.Email == email {
				a.auth = auth
			}
			a.accountSaveNotice(a.persistAccounts())
		}
		quota, err := a.api.AccountQuota(ctx, auth)
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil
		}
		a.recordQuota(email, quota, err)
		return nil
	}
	return errors.New("this account is not signed in")
}

func (a *App) persistAccounts() error {
	if err := a.ensureVault(); err != nil {
		return err
	}
	if len(a.accounts) == 0 {
		if _, err := a.store("delete", ""); err != nil {
			return err
		}
		a.savedSession = false
		return nil
	}
	data, err := json.Marshal(accountVault{Schema: 1, ActiveEmail: a.auth.Email, Accounts: a.accounts})
	if err != nil {
		return err
	}
	if _, err = a.store("set", string(data)); err != nil {
		return err
	}
	a.savedSession = true
	return nil
}

func (a *App) accountSaveNotice(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state.Notice = ""
	if err != nil {
		a.state.Notice = "Account changes could not be saved to your desktop keyring. They apply to this app session only. Unlock the keyring to remember them."
	}
}

func (a *App) saveAuth(auth vpn.Auth) {
	auth.Email = strings.ToLower(strings.TrimSpace(auth.Email))
	if auth.Email != a.auth.Email {
		a.resetAccountQuota()
	}
	a.accounts = mergeAccounts(a.accounts, []vpn.Auth{auth})
	a.auth = auth
	a.pending = ""
	a.pendingEmail = ""
	err := a.persistAccounts()
	a.publishAccounts()
	a.accountSaveNotice(err)
	a.mu.Lock()
	a.state.Error = ""
	a.mu.Unlock()
}

func (a *App) resetAccountQuota() {
	a.pass = vpn.Pass{}
	a.mu.Lock()
	a.state.QuotaLimit = 0
	a.state.QuotaRemaining = -1
	a.mu.Unlock()
}

func (a *App) SwitchAccount(email string) error {
	a.cancelQuotaRefresh()
	a.operation.Lock()
	defer a.operation.Unlock()
	email = strings.ToLower(strings.TrimSpace(email))
	var selected *vpn.Auth
	for _, account := range a.accounts {
		if account.Email == email {
			copy := account
			selected = &copy
			break
		}
	}
	if selected == nil {
		return errors.New("this account is not signed in")
	}
	if email == a.auth.Email {
		return nil
	}
	if err := a.disconnect(); err != nil {
		return err
	}
	a.resetAccountQuota()
	a.saveAuth(*selected)
	return nil
}

func (a *App) RemoveAccount(email string) error {
	a.cancelQuotaRefresh()
	a.operation.Lock()
	defer a.operation.Unlock()
	loadErr := a.ensureVault()
	if loadErr != nil && a.savedSession {
		return errors.New("unlock your desktop keyring before removing saved accounts")
	}
	email = strings.ToLower(strings.TrimSpace(email))
	remaining := make([]vpn.Auth, 0, len(a.accounts))
	found := false
	for _, account := range a.accounts {
		if account.Email == email {
			found = true
		} else {
			remaining = append(remaining, account)
		}
	}
	if !found {
		return errors.New("this account is not signed in")
	}
	wasActive := email == a.auth.Email
	if wasActive {
		if err := a.disconnect(); err != nil {
			return err
		}
	}
	oldAccounts, oldAuth := a.accounts, a.auth
	a.accounts = remaining
	if wasActive {
		a.auth = vpn.Auth{}
		if len(remaining) > 0 {
			a.auth = remaining[0]
		}
	}
	var saveErr error
	if loadErr == nil {
		saveErr = a.persistAccounts()
	} else {
		saveErr = loadErr
	}
	if saveErr != nil && a.savedSession {
		a.accounts, a.auth = oldAccounts, oldAuth
		return errors.New("the saved account could not be removed; unlock your desktop keyring and try again")
	}
	a.pending = ""
	a.pendingEmail = ""
	if wasActive {
		a.resetAccountQuota()
	}
	delete(a.accountQuotas, email)
	delete(a.quotaAttemptedAt, email)
	a.publishAccounts()
	a.accountSaveNotice(saveErr)
	a.mu.Lock()
	a.state.Error = ""
	a.mu.Unlock()
	return nil
}

func (a *App) SignOut() error { return a.RemoveAccount(a.GetState().Email) }
