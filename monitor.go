package main

import (
	"context"
	"errors"
	"time"

	"nat-on-steroids/internal/vpn"
)

const balanceRefreshInterval = 5 * time.Minute

type speedSample struct {
	tunnel           *vpn.Tunnel
	at               time.Time
	upload, download int64
}

func (a *App) monitorSpeeds(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.sampleSpeeds(time.Now())
		}
	}
}

func (a *App) sampleSpeeds(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.Status != "connected" || a.tunnel == nil {
		a.speedSample = speedSample{}
		a.state.UploadSpeed, a.state.DownloadSpeed = 0, 0
		return
	}
	upload, download := a.tunnel.Upload.Load(), a.tunnel.Download.Load()
	previous := a.speedSample
	if previous.tunnel == a.tunnel && now.After(previous.at) {
		seconds := now.Sub(previous.at).Seconds()
		a.state.UploadSpeed = int64(float64(max(0, upload-previous.upload)) / seconds)
		a.state.DownloadSpeed = int64(float64(max(0, download-previous.download)) / seconds)
	} else {
		a.state.UploadSpeed, a.state.DownloadSpeed = 0, 0
	}
	a.speedSample = speedSample{tunnel: a.tunnel, at: now, upload: upload, download: download}
}

func (a *App) monitorBalances(ctx context.Context) {
	// Poll for newly restored/signed-in accounts; each account is requested at
	// most once per interval, including failures, to avoid hammering Guardian.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.refreshDueAccountQuotas(ctx)
		}
	}
}

func (a *App) cancelQuotaRefresh() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.quotaCancel != nil {
		a.quotaCancel()
	}
}

func (a *App) quotaDue(email string) bool {
	// The active connection already refreshes its pass and balance in maintain.
	if a.GetState().Status == "connected" && email == a.auth.Email {
		return false
	}
	return time.Since(a.quotaAttemptedAt[email]) >= balanceRefreshInterval
}

func (a *App) refreshDueAccountQuotas(ctx context.Context) {
	if ctx.Err() != nil || !a.operation.TryLock() {
		return
	}
	emails := make([]string, 0, len(a.accounts))
	for _, account := range a.accounts {
		if a.quotaDue(account.Email) {
			emails = append(emails, account.Email)
		}
	}
	a.operation.Unlock()
	for _, email := range emails {
		if ctx.Err() != nil || !a.operation.TryLock() {
			return // Interactive work takes priority; retry at the next tick.
		}
		if a.quotaDue(email) {
			requestCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
			a.mu.Lock()
			a.quotaCancel = cancel
			a.mu.Unlock()
			_ = a.refreshAccountQuota(requestCtx, email)
			cancel()
			a.mu.Lock()
			a.quotaCancel = nil
			a.mu.Unlock()
		}
		a.operation.Unlock()
	}
}

func (a *App) MeasureLatency() error {
	a.mu.Lock()
	tunnel, connected := a.tunnel, a.state.Status == "connected"
	a.mu.Unlock()
	if tunnel == nil || !connected {
		return errors.New("connect before testing latency")
	}
	a.measureLatency(a.ctx, tunnel)
	return nil
}

func (a *App) measureLatency(ctx context.Context, tunnel *vpn.Tunnel) {
	a.mu.Lock()
	if a.tunnel != tunnel || a.state.Status != "connected" || a.state.LatencyChecking {
		a.mu.Unlock()
		return
	}
	a.state.LatencyChecking = true
	a.latencyStartedAt = time.Now()
	a.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	probe := a.probeLatency
	if probe == nil {
		probe = func(ctx context.Context, tunnel *vpn.Tunnel) (time.Duration, error) { return tunnel.Latency(ctx) }
	}
	elapsed, err := probe(ctx, tunnel)
	a.recordLatency(tunnel, elapsed, err)
}

func (a *App) recordLatency(tunnel *vpn.Tunnel, elapsed time.Duration, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// A delayed response from a disconnected tunnel must not reach a new session.
	if a.tunnel != tunnel || a.state.Status != "connected" {
		return
	}
	a.state.LatencyChecking = false
	a.notifyLatencyChanged()
	a.state.LatencyCheckedAt = time.Now().Unix()
	a.state.LatencyError = ""
	a.state.LatencyMS = -1
	if err == nil {
		a.state.LatencyMS = max(1, elapsed.Milliseconds())
	} else {
		a.state.LatencyError = "Server latency unavailable. Try again."
	}
}

// Wake at the actual due time, rather than a polling tick that can round a
// one-second interval up to two seconds after goroutine scheduling jitter.
func (a *App) monitorLatency(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		a.mu.Lock()
		tunnel := a.tunnel
		wait := time.Second
		if a.state.Status == "connected" && tunnel != nil && !a.state.LatencyChecking {
			wait = time.Until(a.latencyStartedAt.Add(time.Duration(a.state.Preferences.LatencyRefreshSeconds) * time.Second))
		}
		a.mu.Unlock()
		if wait <= 0 {
			a.measureLatency(ctx, tunnel)
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-a.latencyChanged:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (a *App) notifyLatencyChanged() {
	select {
	case a.latencyChanged <- struct{}{}:
	default:
	}
}
