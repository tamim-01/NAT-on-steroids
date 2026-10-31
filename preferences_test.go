package main

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"nat-on-steroids/internal/vpn"
)

func TestPreferencesMigrateAndPreservePorts(t *testing.T) {
	a := NewApp()
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(a.settingsPath, []byte(`{"socksPort":2080,"httpPort":2081}`), 0600); err != nil {
		t.Fatal(err)
	}
	a.loadSettings()
	if a.GetState().SOCKSPort != 2080 || a.GetState().Preferences != defaultPreferences() {
		t.Fatal("legacy ports or default preferences were lost")
	}
	p := defaultPreferences()
	p.Theme, p.SpeedVisualization, p.RemainingVisualization, p.TotalsVisualization, p.LatencyRefreshSeconds = "daylight", "bars", "blocks", "ring", 40
	a.state.Status = "connected"
	a.state.Error = "existing connection error"
	if err := a.SavePreferences(p); err != nil {
		t.Fatal(err)
	}
	if a.GetState().Preferences != p || a.GetState().Status != "connected" || a.settings.SOCKSPort != 2080 {
		t.Fatal("saving preferences disturbed the active connection or ports")
	}
	if a.GetState().Error != "existing connection error" {
		t.Fatal("preference changes hid a connection error")
	}
	a.state.Status = "disconnected"
	if err := a.SavePorts(3080, 3081); err != nil {
		t.Fatal(err)
	}
	b := NewApp()
	b.settingsPath = a.settingsPath
	b.loadSettings()
	if b.GetState().Preferences != p || b.GetState().SOCKSPort != 3080 || b.GetState().HTTPPort != 3081 {
		t.Fatal("preferences and ports did not survive save and reload together")
	}
}

func TestPreferencesRejectInvalidValuesAndSaveFailures(t *testing.T) {
	a := NewApp()
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	if err := a.SavePreferences(defaultPreferences()); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(a.settingsPath)
	for _, change := range []func(*Preferences){
		func(p *Preferences) { p.Theme = "unknown" }, func(p *Preferences) { p.SpeedVisualization = "unknown" }, func(p *Preferences) { p.RemainingVisualization = "unknown" }, func(p *Preferences) { p.TotalsVisualization = "unknown" }, func(p *Preferences) { p.LatencyRefreshSeconds = 0 }, func(p *Preferences) { p.LatencyRefreshSeconds = 901 },
	} {
		p := defaultPreferences()
		change(&p)
		if a.SavePreferences(p) == nil {
			t.Fatalf("invalid preference accepted: %+v", p)
		}
		data, _ := os.ReadFile(a.settingsPath)
		if string(data) != string(original) || a.GetState().Preferences != defaultPreferences() {
			t.Fatal("invalid preference changed saved or active settings")
		}
	}
	a.settingsPath = t.TempDir()
	p := defaultPreferences()
	p.Theme = "forest"
	if a.SavePreferences(p) == nil || a.GetState().Preferences.Theme != "midnight" {
		t.Fatal("failed save silently applied preferences")
	}
}

func TestLatencySchedulerUsesAllIntervalsAndStops(t *testing.T) {
	for _, seconds := range []int{1, 15, 30, 40, 45, 60, 600, 900} {
		t.Run((time.Duration(seconds) * time.Second).String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a := NewApp()
				tunnel := &vpn.Tunnel{}
				a.tunnel = tunnel
				a.state.Status = "connected"
				a.state.Preferences.LatencyRefreshSeconds = seconds
				var calls atomic.Int32
				a.probeLatency = func(context.Context, *vpn.Tunnel) (time.Duration, error) {
					calls.Add(1)
					return 12 * time.Millisecond, nil
				}
				ctx, cancel := context.WithCancel(context.Background())
				a.measureLatency(ctx, tunnel)
				go a.monitorLatency(ctx)
				synctest.Wait()
				if seconds > 1 {
					time.Sleep(time.Duration(seconds-1) * time.Second)
					synctest.Wait()
				}
				if calls.Load() != 1 {
					t.Fatal("latency refreshed before configured interval")
				}
				time.Sleep(time.Second)
				synctest.Wait()
				if calls.Load() != 2 || a.GetState().LatencyMS != 12 {
					t.Fatal("latency did not refresh at configured interval")
				}
				cancel()
				synctest.Wait()
				time.Sleep(time.Duration(seconds) * time.Second)
				synctest.Wait()
				if calls.Load() != 2 {
					t.Fatal("latency monitoring continued after shutdown")
				}
			})
		})
	}
}

func TestLatencyIntervalChangesDoNotOverlapSlowProbes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := NewApp()
		tunnel := &vpn.Tunnel{}
		a.tunnel = tunnel
		a.state.Status = "connected"
		var calls, active, maximum atomic.Int32
		a.probeLatency = func(ctx context.Context, _ *vpn.Tunnel) (time.Duration, error) {
			calls.Add(1)
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
		ctx, cancel := context.WithCancel(context.Background())
		go a.monitorLatency(ctx)
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatal("initial latency probe did not start")
		}
		a.mu.Lock()
		a.state.Preferences.LatencyRefreshSeconds = 1
		a.mu.Unlock()
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatal("short interval overlapped a slow probe")
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if calls.Load() != 2 || maximum.Load() != 1 {
			t.Fatal("changed interval was not applied without overlapping probes")
		}
		cancel()
		synctest.Wait()
		if active.Load() != 0 {
			t.Fatal("probe survived monitor cancellation")
		}
	})
}

func TestSavedIntervalChangeReschedulesWaitingMonitor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := NewApp()
		a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
		a.state.Status = "connected"
		tunnel := &vpn.Tunnel{}
		a.tunnel = tunnel
		a.state.Preferences.LatencyRefreshSeconds = 900
		var calls atomic.Int32
		a.probeLatency = func(context.Context, *vpn.Tunnel) (time.Duration, error) { calls.Add(1); return time.Millisecond, nil }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		a.measureLatency(ctx, tunnel)
		go a.monitorLatency(ctx)
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatal("long interval was not respected")
		}
		p := defaultPreferences()
		p.LatencyRefreshSeconds = 1
		if err := a.SavePreferences(p); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if calls.Load() != 2 || a.GetState().Status != "connected" {
			t.Fatal("saving a shorter interval did not wake the active monitor")
		}
	})
}
