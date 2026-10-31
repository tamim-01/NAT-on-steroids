package main

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"nat-on-steroids/internal/vpn"
)

// Probe the edge without a proxy pass: HTTP/2 PING opens no destination stream.
func probeServerLatency(ctx context.Context, server vpn.Server) (time.Duration, error) {
	tunnel, err := vpn.NewTunnel(ctx, server, "")
	if err != nil {
		return 0, err
	}
	defer tunnel.Close()
	return tunnel.Latency(ctx)
}

func (a *App) RefreshServerPings() error {
	if !a.operation.TryLock() {
		return errors.New("wait for the current operation before refreshing pings")
	}
	defer a.operation.Unlock()
	a.mu.Lock()
	if a.state.Status == "connected" || a.state.Status == "connecting" || a.helper != nil {
		a.mu.Unlock()
		return errors.New("disconnect before refreshing server pings")
	}
	if len(a.state.Locations) == 0 {
		a.mu.Unlock()
		return errors.New("refresh locations before testing server pings")
	}
	// Results are published as a new snapshot so GetState readers never race a sort.
	locations := append([]vpn.Location(nil), a.state.Locations...)
	for i := range locations {
		locations[i].Servers = append([]vpn.Server(nil), locations[i].Servers...)
		locations[i].PingMS, locations[i].PingCheckedAt = -1, 0
	}
	ctx, cancel := context.WithTimeout(a.ctx, 60*time.Second)
	a.serverPingsCancel = cancel
	a.state.ServerPingsChecking = true
	a.state.ServerPingsCompleted, a.state.ServerPingsTotal = 0, 0
	a.state.ServerPingsError = ""
	for _, location := range locations {
		a.state.ServerPingsTotal += len(location.Servers)
	}
	a.mu.Unlock()
	defer cancel()
	probe := a.probeServer
	if probe == nil {
		probe = probeServerLatency
	}
	type job struct{ location, server int }
	jobs := make(chan job)
	results := make([][]int64, len(locations))
	for i, location := range locations {
		results[i] = make([]int64, len(location.Servers))
		for j := range results[i] {
			results[i][j] = -1
		}
	}
	var workers sync.WaitGroup
	for range 6 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for task := range jobs {
				requestCtx, stop := context.WithTimeout(ctx, 5*time.Second)
				elapsed, err := probe(requestCtx, locations[task.location].Servers[task.server])
				stop()
				if err == nil {
					results[task.location][task.server] = max(1, elapsed.Milliseconds())
				}
				a.mu.Lock()
				a.state.ServerPingsCompleted++
				a.mu.Unlock()
			}
		}()
	}
enqueue:
	// Visit countries in rounds so a large country cannot starve later ones
	// if the overall deadline is reached.
	for j := 0; ; j++ {
		found := false
		for i, location := range locations {
			if j >= len(location.Servers) {
				continue
			}
			found = true
			if ctx.Err() != nil {
				break enqueue
			}
			select {
			case jobs <- job{i, j}:
			case <-ctx.Done():
				break enqueue
			}
		}
		if !found {
			break
		}
	}
	close(jobs)
	workers.Wait()
	checkedAt := time.Now().Unix()
	for i := range locations {
		location, pings := &locations[i], results[i]
		order := make([]int, len(pings))
		for j := range order {
			order[j] = j
		}
		sort.SliceStable(order, func(j, k int) bool { return pingLess(pings[order[j]], pings[order[k]]) })
		servers := make([]vpn.Server, len(order))
		for j, index := range order {
			servers[j] = location.Servers[index]
		}
		location.Servers = servers
		location.PingCheckedAt = checkedAt
		if len(order) > 0 {
			location.PingMS = pings[order[0]]
		}
	}
	sort.SliceStable(locations, func(i, j int) bool { return pingLess(locations[i].PingMS, locations[j].PingMS) })
	a.mu.Lock()
	a.state.Locations = locations
	a.state.ServerPingsChecking = false
	a.state.ServerPingsCheckedAt = checkedAt
	a.serverPingsCancel = nil
	if ctx.Err() != nil {
		a.state.ServerPingsError = "Scan stopped before all servers finished. Refresh pings to retry."
	} else if len(locations) > 0 && locations[0].PingMS < 0 {
		a.state.ServerPingsError = "No servers answered. Check your network and refresh pings to retry."
	}
	a.mu.Unlock()
	return nil
}

func pingLess(a, b int64) bool {
	return a >= 0 && (b < 0 || a < b)
}
