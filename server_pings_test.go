package main

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"nat-on-steroids/internal/vpn"
)

func TestServerPingsSortLocationsAndConnectionCandidates(t *testing.T) {
	a := NewApp()
	a.state.Locations = []vpn.Location{
		{Code: "US", Name: "United States", PingMS: -1, Servers: []vpn.Server{{Host: "slow"}, {Host: "fast"}, {Host: "failed"}}},
		{Code: "DE", Name: "Germany", PingMS: -1, Servers: []vpn.Server{{Host: "fastest"}}},
		{Code: "FR", Name: "France", PingMS: -1, Servers: []vpn.Server{{Host: "failed"}}},
	}
	a.state.Country = "US"
	previous := a.GetState()
	a.probeServer = func(ctx context.Context, s vpn.Server) (time.Duration, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second {
			t.Error("probe has no bounded deadline")
		}
		if s.Host == "failed" {
			return 0, errors.New("unreachable")
		}
		return map[string]time.Duration{"slow": 90 * time.Millisecond, "fast": 40 * time.Millisecond, "fastest": time.Microsecond}[s.Host], nil
	}
	if err := a.RefreshServerPings(); err != nil {
		t.Fatal(err)
	}
	s := a.GetState()
	if s.Locations[0].Code != "DE" || s.Locations[0].PingMS != 1 || s.Locations[1].Code != "US" || s.Locations[1].PingMS != 40 || s.Locations[2].PingMS != -1 {
		t.Fatalf("wrong fastest-first location order: %+v", s.Locations)
	}
	if s.Locations[1].Servers[0].Host != "fast" || s.Locations[1].Servers[2].Host != "failed" {
		t.Fatal("connection candidates were not sorted")
	}
	if s.Country != "US" || s.Status != "disconnected" || s.ServerPingsCompleted != 5 || s.ServerPingsTotal != 5 || s.ServerPingsChecking || s.ServerPingsCheckedAt == 0 || s.ServerPingsError != "" {
		t.Fatal("scan altered connection or missed completion metadata")
	}
	if previous.Locations[0].Code != "US" || previous.Locations[0].Servers[0].Host != "slow" || previous.Locations[0].PingCheckedAt != 0 {
		t.Fatal("scan mutated an earlier GetState snapshot")
	}
	// A failed refresh must clear the old ping rather than retain a misleading result.
	a.probeServer = func(context.Context, vpn.Server) (time.Duration, error) { return 0, errors.New("offline") }
	if err := a.RefreshServerPings(); err != nil {
		t.Fatal(err)
	}
	s = a.GetState()
	if s.ServerPingsError == "" || s.Locations[0].PingMS != -1 || s.Error != "" {
		t.Fatal("offline scan retained stale results or raised a global error")
	}
}

func TestServerPingsRejectConnectedEmptyAndConcurrentOperations(t *testing.T) {
	a := NewApp()
	if a.RefreshServerPings() == nil {
		t.Fatal("empty scan accepted")
	}
	a.state.Locations = []vpn.Location{{Code: "US", Servers: []vpn.Server{{Host: "edge"}}}}
	for _, status := range []string{"connected", "connecting"} {
		a.state.Status = status
		if a.RefreshServerPings() == nil {
			t.Fatalf("scan accepted while %s", status)
		}
	}
	a.state.Status = "disconnected"
	a.operation.Lock()
	err := a.RefreshServerPings()
	a.operation.Unlock()
	if err == nil {
		t.Fatal("scan competed with another operation")
	}
}

func TestServerPingsBoundConcurrencyAndOverallTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := NewApp()
		location := vpn.Location{Code: "US", PingMS: -1}
		for i := 0; i < 100; i++ {
			location.Servers = append(location.Servers, vpn.Server{Host: fmt.Sprint(i)})
		}
		a.state.Locations = []vpn.Location{location, {Code: "DE", Servers: []vpn.Server{{Host: "small-country"}}}}
		var active, maximum atomic.Int32
		var smallCountryTested atomic.Bool
		a.probeServer = func(ctx context.Context, s vpn.Server) (time.Duration, error) {
			if s.Host == "small-country" {
				smallCountryTested.Store(true)
			}
			n := active.Add(1)
			for old := maximum.Load(); n > old; old = maximum.Load() {
				if maximum.CompareAndSwap(old, n) {
					break
				}
			}
			defer active.Add(-1)
			<-ctx.Done()
			return 0, ctx.Err()
		}
		started := time.Now()
		if err := a.RefreshServerPings(); err != nil {
			t.Fatal(err)
		}
		s := a.GetState()
		if maximum.Load() > 6 || maximum.Load() < 2 || active.Load() != 0 || time.Since(started) > 60*time.Second {
			t.Fatal("scan exceeded concurrency or deadline bounds")
		}
		if !smallCountryTested.Load() {
			t.Fatal("large country starved another location before timeout")
		}
		if s.ServerPingsChecking || s.ServerPingsError == "" || s.ServerPingsCompleted >= 101 {
			t.Fatal("partial scan did not finish with a retry message")
		}
	})
}

func TestDisconnectCancelsServerPingScan(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := NewApp()
		a.state.Locations = []vpn.Location{{Code: "US", Servers: []vpn.Server{{Host: "edge"}}}}
		a.probeServer = func(ctx context.Context, s vpn.Server) (time.Duration, error) { <-ctx.Done(); return 0, ctx.Err() }
		done := make(chan error, 1)
		go func() { done <- a.RefreshServerPings() }()
		synctest.Wait()
		if !a.GetState().ServerPingsChecking {
			t.Fatal("scan did not start")
		}
		if err := a.RefreshServerPings(); err == nil {
			t.Fatal("duplicate scan accepted")
		}
		if err := a.Disconnect(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if a.GetState().ServerPingsChecking || a.GetState().Status != "disconnected" {
			t.Fatal("cancelled scan remained active")
		}
	})
}
