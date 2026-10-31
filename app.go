package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nat-on-steroids/internal/steroid"
	"nat-on-steroids/internal/vpn"
)

type State struct {
	SteroidConfig        steroid.Config        `json:"steroidConfig"`
	ObservedDomains      []steroid.DomainEvent `json:"observedDomains"`
	DirectIP             string                `json:"directIp"`
	DirectUpload         int64                 `json:"directUpload"`
	DirectDownload       int64                 `json:"directDownload"`
	Preferences          Preferences           `json:"preferences"`
	Accounts             []Account             `json:"accounts"`
	PendingEmail         string                `json:"pendingEmail"`
	SOCKSPort            int                   `json:"socksPort"`
	HTTPPort             int                   `json:"httpPort"`
	Status               string                `json:"status"`
	SignedIn             bool                  `json:"signedIn"`
	NeedsCode            bool                  `json:"needsCode"`
	Email                string                `json:"email"`
	Locations            []vpn.Location        `json:"locations"`
	ServerPingsChecking  bool                  `json:"serverPingsChecking"`
	ServerPingsCompleted int                   `json:"serverPingsCompleted"`
	ServerPingsTotal     int                   `json:"serverPingsTotal"`
	ServerPingsCheckedAt int64                 `json:"serverPingsCheckedAt"`
	ServerPingsError     string                `json:"serverPingsError"`
	Country              string                `json:"country"`
	Mode                 string                `json:"mode"`
	IP                   string                `json:"ip"`
	Since                int64                 `json:"since"`
	Upload               int64                 `json:"upload"`
	Download             int64                 `json:"download"`
	UploadSpeed          int64                 `json:"uploadSpeed"`
	DownloadSpeed        int64                 `json:"downloadSpeed"`
	LatencyMS            int64                 `json:"latencyMs"`
	LatencyCheckedAt     int64                 `json:"latencyCheckedAt"`
	LatencyChecking      bool                  `json:"latencyChecking"`
	LatencyError         string                `json:"latencyError"`
	QuotaLimit           int64                 `json:"quotaLimit"`
	QuotaRemaining       int64                 `json:"quotaRemaining"`
	Error                string                `json:"error"`
	Notice               string                `json:"notice"`
}

type App struct {
	mu, operation     sync.Mutex
	ctx               context.Context
	api               *vpn.API
	state             State
	auth              vpn.Auth
	pending           string
	cancel            context.CancelFunc
	stopMonitoring    context.CancelFunc
	quotaCancel       context.CancelFunc
	serverPingsCancel context.CancelFunc
	tunnel            *vpn.Tunnel
	proxy             *vpn.Proxy
	helper            *tunHelper
	steroid           *steroidSession
	pass              vpn.Pass
	savedSession      bool
	vaultReady        bool
	accounts          []vpn.Auth
	accountQuotas     map[string]Account
	quotaAttemptedAt  map[string]time.Time
	speedSample       speedSample
	pendingEmail      string
	store             func(string, string) (string, error)
	settings          proxySettings
	settingsPath      string
	probeServer       func(context.Context, vpn.Server) (time.Duration, error)
	probeLatency      func(context.Context, *vpn.Tunnel) (time.Duration, error)
	latencyStartedAt  time.Time
	latencyChanged    chan struct{}
}

func NewApp() *App {
	config, _ := os.UserConfigDir()
	path := ""
	if config != "" {
		path = filepath.Join(config, "n-orm-proxy", "settings.json")
	}
	return &App{api: vpn.NewAPI(), ctx: context.Background(), store: keyringOperation, settings: proxySettings{SOCKSPort: 1088, HTTPPort: 8088, Preferences: defaultPreferences()}, settingsPath: path, latencyChanged: make(chan struct{}, 1), state: State{SteroidConfig: steroid.DefaultConfig(), ObservedDomains: []steroid.DomainEvent{}, Preferences: defaultPreferences(), Status: "disconnected", Mode: "tun", Locations: []vpn.Location{}, Accounts: []Account{}, SOCKSPort: 1088, HTTPPort: 8088, QuotaRemaining: -1, LatencyMS: -1}}
}

func (a *App) startup(ctx context.Context) {
	a.ctx, a.stopMonitoring = context.WithCancel(ctx)
	go a.restore()
	go a.monitorSpeeds(a.ctx)
	go a.monitorLatency(a.ctx)
	go a.monitorBalances(a.ctx)
}
func (a *App) shutdown(ctx context.Context) {
	if a.stopMonitoring != nil {
		a.stopMonitoring()
	}
	_ = a.Disconnect()
}
func (a *App) GetState() State {
	a.mu.Lock()
	defer a.mu.Unlock()
	state := a.state
	if a.tunnel != nil {
		state.Upload = a.tunnel.Upload.Load()
		state.Download = a.tunnel.Download.Load()
	}
	if a.steroid != nil {
		state.ObservedDomains = a.steroid.router.Events()
		state.DirectUpload = a.steroid.router.DirectUpload.Load()
		state.DirectDownload = a.steroid.router.DirectDownload.Load()
	}
	return state
}
func (a *App) setError(err error) { a.mu.Lock(); a.state.Error = err.Error(); a.mu.Unlock() }

func (a *App) restore() {
	a.operation.Lock()
	a.loadSettings()
	if err := a.ensureVault(); err != nil {
		a.mu.Lock()
		a.state.Notice = "Saved accounts could not be loaded. Unlock your desktop keyring; you can still sign in for this app session."
		a.mu.Unlock()
	}
	a.publishAccounts()
	a.operation.Unlock()
	ctx, cancel := context.WithTimeout(a.ctx, 40*time.Second)
	defer cancel()
	locations, err := a.api.Locations(ctx)
	if err != nil {
		a.setError(fmt.Errorf("Could not load locations: %w. Use Refresh to retry", err))
		return
	}
	a.mu.Lock()
	a.state.Locations = locations
	a.mu.Unlock()
}

func (a *App) Login(email, password string) error {
	a.cancelQuotaRefresh()
	a.operation.Lock()
	defer a.operation.Unlock()
	if err := a.disconnect(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(a.ctx, 100*time.Second)
	defer cancel()
	auth, pending, err := a.api.Login(ctx, email, password)
	if err != nil {
		a.setError(err)
		return err
	}
	a.pending = pending
	if pending != "" {
		a.mu.Lock()
		a.state.NeedsCode = true
		a.pendingEmail = auth.Email
		a.state.PendingEmail = auth.Email
		a.state.Error = ""
		a.mu.Unlock()
		return nil
	}
	a.saveAuth(auth)
	return nil
}

func (a *App) Verify(code string) error {
	a.cancelQuotaRefresh()
	a.operation.Lock()
	defer a.operation.Unlock()
	if a.pending == "" {
		return errors.New("start sign-in again")
	}
	ctx, cancel := context.WithTimeout(a.ctx, 100*time.Second)
	defer cancel()
	auth, err := a.api.Verify(ctx, a.pendingEmail, a.pending, code)
	if err != nil {
		a.setError(err)
		return err
	}
	a.pending = ""
	a.saveAuth(auth)
	return nil
}

func (a *App) CancelVerification() {
	a.operation.Lock()
	defer a.operation.Unlock()
	a.pending = ""
	a.mu.Lock()
	a.state.NeedsCode = false
	a.pendingEmail = ""
	a.state.PendingEmail = ""
	a.state.Error = ""
	a.mu.Unlock()
}

func (a *App) RefreshLocations() error {
	a.operation.Lock()
	defer a.operation.Unlock()
	if a.GetState().Status == "connected" {
		return errors.New("disconnect before refreshing locations")
	}
	ctx, cancel := context.WithTimeout(a.ctx, 40*time.Second)
	defer cancel()
	locations, err := a.api.Locations(ctx)
	if err != nil {
		a.setError(err)
		return err
	}
	a.mu.Lock()
	a.state.Locations = locations
	a.state.Error = ""
	a.state.ServerPingsCheckedAt = 0
	a.state.ServerPingsError = ""
	a.state.ServerPingsCompleted, a.state.ServerPingsTotal = 0, 0
	a.mu.Unlock()
	return nil
}

func (a *App) Connect(country, mode string) (err error) {
	a.cancelQuotaRefresh()
	a.operation.Lock()
	defer a.operation.Unlock()
	if !a.GetState().SignedIn {
		return errors.New("sign in with your Mozilla account first")
	}
	if mode != "tun" && mode != "proxy" && mode != "steroid" {
		return errors.New("choose TUN, TUN on steroid, or proxy mode")
	}
	if err = a.disconnect(); err != nil {
		return err
	}
	if mode == "steroid" {
		config := a.GetState().SteroidConfig
		if _, validationErr := steroid.NormalizeConfig(config); validationErr != nil {
			return validationErr
		}
		if config.PACPort == a.settings.HTTPPort || config.PACPort == a.settings.SOCKSPort {
			return errors.New("browser PAC port conflicts with a proxy port; change the experimental mode settings")
		}
	}
	ctx, cancel := context.WithCancel(a.ctx)
	a.mu.Lock()
	a.cancel = cancel
	a.state.Status = "connecting"
	a.state.Mode = mode
	a.state.Country = country
	a.state.IP = ""
	a.state.Error = ""
	a.mu.Unlock()
	timeout := time.AfterFunc(110*time.Second, cancel)
	defer timeout.Stop()
	defer func() {
		if err != nil {
			if cleanupErr := a.disconnect(); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
			a.mu.Lock()
			a.state.Status = "error"
			a.state.Error = err.Error()
			a.mu.Unlock()
		}
	}()
	auth, refreshErr := a.api.Refresh(ctx, a.auth)
	if refreshErr != nil {
		return refreshErr
	}
	a.saveAuth(auth)
	a.pass, err = a.api.ProxyPass(ctx, a.auth)
	a.recordQuota(a.auth.Email, vpn.Quota{Limit: a.pass.Limit, Remaining: a.pass.Remaining}, err)
	if err != nil {
		return err
	}
	var location *vpn.Location
	state := a.GetState()
	for _, l := range state.Locations {
		if l.Code == country {
			copy := l
			location = &copy
			break
		}
	}
	if location == nil {
		return errors.New("select an available location; refresh locations if needed")
	}
	// Try a few nodes in the requested country. Never silently switch countries.
	var tunnel *vpn.Tunnel
	var ip string
	for i, server := range location.Servers {
		if i >= 3 {
			break
		}
		tunnel, err = vpn.NewTunnel(ctx, server, a.pass.Token)
		if err != nil {
			continue
		}
		ip, err = verifyExit(ctx, tunnel)
		if err == nil {
			break
		}
		tunnel.Close()
		tunnel = nil
	}
	if tunnel == nil {
		if err == nil {
			err = errors.New("no usable servers in this location")
		}
		return err
	}
	a.mu.Lock()
	a.tunnel = tunnel
	a.mu.Unlock()
	var opener vpn.Opener = tunnel
	if mode == "steroid" {
		session, sessionErr := newSteroidSession(ctx, tunnel, a.GetState().SteroidConfig, a.settings.HTTPPort)
		if sessionErr != nil {
			return sessionErr
		}
		a.mu.Lock()
		a.steroid = session
		a.state.ObservedDomains = []steroid.DomainEvent{}
		a.state.DirectIP = ""
		a.state.DirectUpload = 0
		a.state.DirectDownload = 0
		a.mu.Unlock()
		opener = session.router
	}
	proxy, err := vpn.StartProxy(ctx, opener, net.JoinHostPort("127.0.0.1", strconv.Itoa(a.settings.SOCKSPort)), net.JoinHostPort("127.0.0.1", strconv.Itoa(a.settings.HTTPPort)))
	if err != nil {
		return err
	}
	a.proxy = proxy
	if mode == "tun" {
		helper, helperErr := startTUN(ctx, proxy.Port(), tunnel.EdgeIP())
		if helperErr != nil {
			return helperErr
		}
		a.helper = helper
		go a.watchHelper(ctx, helper, cancel)
		// Verify actual OS routing, not just that the helper created an interface.
		direct := &http.Client{Timeout: 25 * time.Second, Transport: &http.Transport{Proxy: nil}}
		defer direct.CloseIdleConnections()
		if _, err = traceIP(ctx, direct); err != nil {
			return errors.New("TUN started, but system traffic verification failed")
		}
	}
	if mode == "steroid" {
		helper, helperErr := startSteroidTUN(ctx, proxy.Port(), tunnel.EdgeIP(), a.GetState().SteroidConfig.Rules)
		if helper != nil {
			a.helper = helper
		}
		if helperErr != nil {
			return helperErr
		}
		go a.watchHelper(ctx, helper, cancel)
		systemClient := &http.Client{Timeout: 25 * time.Second, Transport: &http.Transport{Proxy: nil}}
		defer systemClient.CloseIdleConnections()
		if _, err = traceIP(ctx, systemClient); err != nil {
			return errors.New("experimental TUN started, but system traffic verification failed")
		}
		diagnosticClient := vpn.HTTPClient(&steroid.Client{Path: steroid.SocketPath(os.Getuid()), Diagnostic: true})
		defer diagnosticClient.CloseIdleConnections()
		directIP, directErr := traceIP(ctx, diagnosticClient)
		if directErr != nil {
			return errors.New("experimental TUN started, but the direct connection could not be verified")
		}
		if directIP == ip {
			return errors.New("VPN and Direct returned the same exit IP; check other VPNs before using domain exceptions")
		}
		a.mu.Lock()
		a.state.DirectIP = directIP
		a.mu.Unlock()
	}
	if ctx.Err() != nil {
		return errors.New("connection was cancelled or timed out")
	}
	a.mu.Lock()
	a.state.Status = "connected"
	a.state.IP = ip
	a.state.Since = time.Now().Unix()
	a.speedSample = speedSample{tunnel: tunnel, at: time.Now(), upload: tunnel.Upload.Load(), download: tunnel.Download.Load()}
	a.mu.Unlock()
	a.notifyLatencyChanged()
	go a.measureLatency(ctx, tunnel)
	go a.maintain(ctx, tunnel)
	return nil
}

func (a *App) watchHelper(ctx context.Context, helper *tunHelper, cancel context.CancelFunc) {
	select {
	case <-ctx.Done():
		return
	case <-helper.done:
	}
	if ctx.Err() != nil {
		return
	}
	cancel()
	a.operation.Lock()
	defer a.operation.Unlock()
	if a.helper != helper {
		return
	}
	cleanupErr := a.disconnect()
	a.mu.Lock()
	a.state.Status = "error"
	if cleanupErr == nil {
		a.state.Error = "The system tunnel stopped. Reconnect to try again."
	}
	a.mu.Unlock()
}

func verifyExit(ctx context.Context, tunnel *vpn.Tunnel) (string, error) {
	client := vpn.HTTPClient(tunnel)
	defer client.CloseIdleConnections()
	return traceIP(ctx, client)
}
func traceIP(ctx context.Context, client *http.Client) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.cloudflare.com/cdn-cgi/trace", nil)
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("the VPN could not pass an encrypted traffic check")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("VPN traffic check was rejected")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return "", errors.New("VPN traffic check was interrupted")
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ip=") {
			ip := strings.TrimSpace(strings.TrimPrefix(line, "ip="))
			if net.ParseIP(ip) != nil {
				return ip, nil
			}
		}
	}
	return "", errors.New("VPN traffic check returned no exit address")
}

func (a *App) maintain(ctx context.Context, tunnel *vpn.Tunnel) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	failures := 0
	nextPass := time.Now().Add(5 * time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		a.operation.Lock()
		if ctx.Err() != nil {
			a.operation.Unlock()
			return
		}
		var err error
		if a.helper != nil {
			select {
			case <-a.helper.done:
				err = errors.New("the system tunnel stopped unexpectedly")
			default:
			}
		}
		if err == nil && (time.Now().After(nextPass) || (a.pass.ExpiresAt > 0 && a.pass.ExpiresAt < time.Now().Unix()+120)) {
			var auth vpn.Auth
			auth, err = a.api.Refresh(ctx, a.auth)
			if err == nil {
				a.saveAuth(auth)
				var pass vpn.Pass
				pass, err = a.api.ProxyPass(ctx, auth)
				a.recordQuota(auth.Email, vpn.Quota{Limit: pass.Limit, Remaining: pass.Remaining}, err)
				if err == nil {
					a.pass = pass
					tunnel.UpdateToken(pass.Token)
					nextPass = time.Now().Add(5 * time.Minute)
				}
			}
		}
		if err == nil {
			_, err = verifyExit(ctx, tunnel)
		}
		if err != nil {
			failures++
		} else {
			failures = 0
		}
		if failures >= 3 {
			_ = a.disconnect()
			a.mu.Lock()
			a.state.Status = "error"
			a.state.Error = "The connection stopped passing traffic. Reconnect to try again."
			a.mu.Unlock()
			a.operation.Unlock()
			return
		}
		a.operation.Unlock()
	}
}

func (a *App) Disconnect() error {
	// Cancel before taking the operation lock so pending network calls unblock.
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
	}
	if a.quotaCancel != nil {
		a.quotaCancel()
	}
	if a.serverPingsCancel != nil {
		a.serverPingsCancel()
	}
	a.mu.Unlock()
	a.operation.Lock()
	defer a.operation.Unlock()
	return a.disconnect()
}
func (a *App) disconnect() error {
	a.mu.Lock()
	cancel, tunnel := a.cancel, a.tunnel
	session := a.steroid
	if session != nil {
		a.state.ObservedDomains = session.router.Events()
		a.state.DirectUpload = session.router.DirectUpload.Load()
		a.state.DirectDownload = session.router.DirectDownload.Load()
	}
	a.steroid = nil
	a.state.DirectIP = ""
	a.cancel = nil
	a.tunnel = nil
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	var err error
	if session != nil {
		session.Close()
	}
	if a.helper != nil {
		err = a.helper.Close()
		if err == nil {
			a.helper = nil
		}
	}
	if a.proxy != nil {
		a.proxy.Close()
		a.proxy = nil
	}
	if tunnel != nil {
		tunnel.Close()
	}
	a.mu.Lock()
	a.state.Status = "disconnected"
	a.state.IP = ""
	a.state.Since = 0
	a.state.Upload = 0
	a.state.Download = 0
	a.state.UploadSpeed, a.state.DownloadSpeed = 0, 0
	a.speedSample = speedSample{}
	a.state.LatencyMS, a.state.LatencyCheckedAt = -1, 0
	a.state.LatencyChecking, a.state.LatencyError = false, ""
	a.latencyStartedAt = time.Time{}
	if err != nil {
		a.state.Status = "error"
		a.state.Error = err.Error()
	}
	a.mu.Unlock()
	return err
}

type tunHelper struct {
	input   io.WriteCloser
	cmd     *exec.Cmd
	done    chan struct{}
	err     error
	cleaned atomic.Bool
}

func startTUN(ctx context.Context, port int, edge string) (*tunHelper, error) {
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return nil, errors.New("TUN is unavailable on this system. Use proxy mode, or enable /dev/net/tun")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(filepath.Dir(exe), "n-orm-helper")
	if _, err = os.Stat(path); err != nil {
		return nil, errors.New("n-orm-helper is missing beside the app")
	}
	cmd := exec.Command("/usr/bin/pkexec", path, strconv.Itoa(port), edge)
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	// Capture only helper diagnostics; it has no account credentials.
	var diagnostic limitedBuffer
	cmd.Stderr = &diagnostic
	if err = cmd.Start(); err != nil {
		return nil, errors.New("cannot request administrator authorization; install polkit")
	}
	h := &tunHelper{input: input, cmd: cmd, done: make(chan struct{})}
	ready := make(chan bool, 1)
	go func() {
		sentReady := false
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			if scanner.Text() == "READY" {
				ready <- true
				sentReady = true
			}
			if scanner.Text() == "CLEAN" {
				h.cleaned.Store(true)
			}
		}
		if !sentReady {
			ready <- false
		}
		h.err = cmd.Wait()
		close(h.done)
	}()
	select {
	case ok := <-ready:
		if ok {
			return h, nil
		}
		_ = h.Close()
		message := strings.TrimSpace(diagnostic.String())
		if message == "" {
			message = "administrator authorization was cancelled"
		}
		return nil, fmt.Errorf("TUN could not start: %s", message)
	case <-ctx.Done():
		_ = h.Close()
		return nil, errors.New("TUN startup was cancelled or timed out")
	}
}
func (h *tunHelper) Close() error {
	_ = h.input.Close()
	select {
	case <-h.done:
		if h.cleaned.Load() {
			return nil
		}
		return errors.New("TUN helper exited without confirming route cleanup; check routing before reconnecting")
	case <-time.After(7 * time.Second):
		return errors.New("TUN helper did not confirm route cleanup; check the helper process before reconnecting")
	}
}

type limitedBuffer struct {
	mu   sync.Mutex
	data []byte
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.data) < 4096 {
		n := 4096 - len(b.data)
		if n > len(p) {
			n = len(p)
		}
		b.data = append(b.data, p[:n]...)
	}
	return len(p), nil
}
func (b *limitedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return string(b.data) }
