package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"nat-on-steroids/internal/vpn"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAutomaticBalancesRefreshAllAccountsWithoutNotificationsOrRapidRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, _ := accountApp()
		one, two := accountFixture("one@example.invalid"), accountFixture("two@example.invalid")
		a.saveAuth(one)
		a.saveAuth(two)
		a.pending, a.pendingEmail = "pending-test", "pending@example.invalid"
		var calls atomic.Int32
		a.api.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			if r.URL.Path != "/api/v1/fpn/token" || r.Method != "GET" {
				t.Error("background refresh made an unexpected request")
			}
			headers := make(http.Header)
			headers.Set("X-Quota-Limit", "50000000000")
			remaining := "12000000000"
			status := 200
			if r.Header.Get("Authorization") == "Bearer "+two.AccessToken {
				status = 429
				remaining = ""
			}
			headers.Set("X-Quota-Remaining", remaining)
			return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
		})}
		ctx, cancel := context.WithCancel(context.Background())
		go a.monitorBalances(ctx)
		synctest.Wait()
		time.Sleep(30 * time.Second)
		synctest.Wait()
		state := a.GetState()
		if calls.Load() != 2 || state.Accounts[0].QuotaRemaining != 12000000000 || state.Accounts[1].QuotaRemaining != -1 || state.Accounts[1].QuotaError == "" {
			t.Fatal("automatic refresh missed an account or invented an exhausted balance")
		}
		if state.Error != "" || state.Notice != "" || a.auth.Email != two.Email || a.pending != "pending-test" {
			t.Fatal("automatic balance refresh interrupted the account or raised an alert")
		}
		time.Sleep(balanceRefreshInterval - 30*time.Second)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatal("failed refresh was retried before the refresh interval")
		}
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if calls.Load() != 4 {
			t.Fatal("balances did not refresh again after five minutes")
		}
		cancel()
		synctest.Wait()
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		if calls.Load() != 4 {
			t.Fatal("balance monitoring continued after shutdown")
		}
	})
}

func TestAutomaticBalancesSkipInteractiveWorkAndConnectedAccount(t *testing.T) {
	a, _ := accountApp()
	one, two := accountFixture("one@example.invalid"), accountFixture("two@example.invalid")
	a.saveAuth(one)
	a.saveAuth(two)
	a.state.Status = "connected"
	var calls atomic.Int32
	a.api.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+one.AccessToken {
			t.Error("active account was needlessly refreshed outside connection maintenance")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"X-Quota-Remaining": []string{"500"}}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	a.operation.Lock()
	a.refreshDueAccountQuotas(context.Background())
	a.operation.Unlock()
	if calls.Load() != 0 {
		t.Fatal("background refresh competed with interactive work")
	}
	a.refreshDueAccountQuotas(context.Background())
	if calls.Load() != 1 || a.auth != two || a.GetState().Status != "connected" {
		t.Fatal("background refresh disturbed connection or missed inactive account")
	}
}

func TestDisconnectCancelsBackgroundBalanceRequest(t *testing.T) {
	a, _ := accountApp()
	a.saveAuth(accountFixture("one@example.invalid"))
	started := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	a.api.GuardianURL = server.URL
	done := make(chan struct{})
	go func() { a.refreshDueAccountQuotas(context.Background()); close(done) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("background request did not start")
	}
	disconnected := make(chan error, 1)
	go func() { disconnected <- a.Disconnect() }()
	select {
	case err := <-disconnected:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("disconnect waited for a background request timeout")
	}
	<-done
	if a.GetState().Accounts[0].QuotaError != "" {
		t.Fatal("cancelled background work displayed a spurious quota failure")
	}
}

func TestLiveSpeedsUseElapsedTimeAndResetAcrossConnections(t *testing.T) {
	a := NewApp()
	tunnel := &vpn.Tunnel{}
	a.tunnel = tunnel
	a.state.Status = "connected"
	now := time.Now()
	a.sampleSpeeds(now)
	tunnel.Upload.Add(6000)
	tunnel.Download.Add(15000)
	a.sampleSpeeds(now.Add(3 * time.Second))
	state := a.GetState()
	if state.UploadSpeed != 2000 || state.DownloadSpeed != 5000 || state.Upload != 6000 || state.Download != 15000 {
		t.Fatal("rates did not use elapsed time independently of totals")
	}
	a.sampleSpeeds(now.Add(4 * time.Second))
	if a.GetState().UploadSpeed != 0 || a.GetState().DownloadSpeed != 0 {
		t.Fatal("idle connection retained stale speeds")
	}
	next := &vpn.Tunnel{}
	next.Upload.Store(900000)
	a.tunnel = next
	a.sampleSpeeds(now.Add(5 * time.Second))
	if a.GetState().UploadSpeed != 0 {
		t.Fatal("new tunnel inherited the old speed sample")
	}
	next.Upload.Store(1)
	a.sampleSpeeds(now.Add(6 * time.Second))
	if a.GetState().UploadSpeed < 0 {
		t.Fatal("counter reset produced a negative speed")
	}
	a.state.Status = "disconnected"
	a.sampleSpeeds(now.Add(7 * time.Second))
	if a.GetState().UploadSpeed != 0 || a.GetState().DownloadSpeed != 0 {
		t.Fatal("disconnected speeds were not cleared")
	}
}

func TestSpeedMonitorTicksAndStops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := NewApp()
		a.tunnel = &vpn.Tunnel{}
		a.state.Status = "connected"
		ctx, cancel := context.WithCancel(context.Background())
		go a.monitorSpeeds(ctx)
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()
		a.tunnel.Download.Add(1234)
		time.Sleep(time.Second)
		synctest.Wait()
		if a.GetState().DownloadSpeed != 1234 {
			t.Fatal("monitor did not sample speed once per second")
		}
		cancel()
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if a.GetState().DownloadSpeed != 1234 {
			t.Fatal("speed monitor continued after cancellation")
		}
	})
}

func TestLatencyResultsDoNotAffectConnectionAndIgnoreOldTunnel(t *testing.T) {
	a := NewApp()
	if err := a.MeasureLatency(); err == nil {
		t.Fatal("disconnected latency test was accepted")
	}
	old, current := &vpn.Tunnel{}, &vpn.Tunnel{}
	a.tunnel = current
	a.state.Status = "connected"
	a.recordLatency(current, 42*time.Millisecond, nil)
	state := a.GetState()
	if state.LatencyMS != 42 || state.LatencyCheckedAt == 0 || state.LatencyError != "" {
		t.Fatal("successful latency was not published")
	}
	a.recordLatency(old, time.Second, errors.New("old connection"))
	if a.GetState().LatencyMS != 42 {
		t.Fatal("old connection overwrote current latency")
	}
	a.measureLatency(context.Background(), current) // No HTTP/2 socket: a failed probe.
	state = a.GetState()
	if state.LatencyChecking || state.LatencyMS != -1 || state.LatencyError == "" || state.Status != "connected" || state.Error != "" {
		t.Fatal("failed latency probe changed connectivity or displayed stale latency")
	}
	if err := a.Disconnect(); err != nil {
		t.Fatal(err)
	}
	state = a.GetState()
	if state.LatencyChecking || state.LatencyMS != -1 || state.LatencyCheckedAt != 0 || state.LatencyError != "" {
		t.Fatal("disconnect retained old latency metadata")
	}
	a.recordLatency(current, time.Second, nil)
	if a.GetState().LatencyMS != -1 {
		t.Fatal("late measurement repopulated disconnected latency")
	}
}
