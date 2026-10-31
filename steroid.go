package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"nat-on-steroids/internal/steroid"
	"nat-on-steroids/internal/vpn"
)

type steroidSession struct {
	router   *steroid.Router
	client   *steroid.Client
	pac      *http.Server
	listener net.Listener
}

func newSteroidSession(ctx context.Context, tunnel vpn.Opener, config steroid.Config, httpPort int) (*steroidSession, error) {
	if config.PACPort == httpPort {
		return nil, errors.New("browser PAC and HTTP proxy ports must differ")
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(config.PACPort)))
	if err != nil {
		return nil, errors.New("browser PAC port is unavailable; change it in TUN on steroid settings")
	}
	client := &steroid.Client{Path: steroid.SocketPath(os.Getuid())}
	session := &steroidSession{client: client, router: steroid.NewRouter(tunnel, client, config.Rules), listener: listener}
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy.pac", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprint(w, browserPAC(httpPort))
	})
	session.pac = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192}
	go session.pac.Serve(listener)
	return session, nil
}
func browserPAC(port int) string {
	return fmt.Sprintf("function FindProxyForURL(url, host) {\n  if (host === 'localhost' || host.slice(-10) === '.localhost' || /^127(?:\\.\\d{1,3}){3}$/.test(host) || host === '::1' || host === '[::1]') return 'DIRECT';\n  return 'PROXY 127.0.0.1:%d';\n}\n", port)
}
func (s *steroidSession) Close() { s.router.Close(); _ = s.pac.Close(); _ = s.listener.Close() }

func (a *App) SaveSteroidConfig(config steroid.Config) error {
	a.operation.Lock()
	defer a.operation.Unlock()
	normalized, err := steroid.NormalizeConfig(config)
	if err != nil {
		return err
	}
	if normalized.PACPort == a.settings.HTTPPort || normalized.PACPort == a.settings.SOCKSPort {
		return errors.New("browser PAC port must differ from both local proxy ports")
	}
	a.mu.Lock()
	session := a.steroid
	previous := a.state.SteroidConfig
	a.mu.Unlock()
	if session != nil && normalized.PACPort != previous.PACPort {
		return errors.New("disconnect before changing the browser PAC port")
	}
	settings := a.settings
	settings.Steroid = &normalized
	if err = a.saveSettings(settings); err != nil {
		return err
	}
	if session != nil {
		// Stop hostname streams before allowing them to reopen under new decisions.
		session.router.SetRules(normalized.Rules)
		ctx, cancel := context.WithTimeout(a.ctx, 3*time.Second)
		defer cancel()
		if err = session.client.UpdateRules(ctx, normalized.Rules); err != nil {
			return errors.New("rules were saved but the direct helper could not apply them; disconnect and reconnect before browsing")
		}
	}
	return nil
}
func (a *App) ClearObservedDomains() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.steroid != nil {
		a.steroid.router.ClearEvents()
	}
	a.state.ObservedDomains = []steroid.DomainEvent{}
}

// This launcher is deliberately separate from startTUN. Its helper supervises
// the installed original helper and confirms cleanup of both routing layers.
func startSteroidTUN(ctx context.Context, port int, edge string, rules []steroid.Rule) (*tunHelper, error) {
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return nil, errors.New("TUN is unavailable on this system")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(filepath.Dir(exe), "n-orm-steroid-helper")
	if _, err = os.Stat(path); err != nil {
		return nil, errors.New("install the updated Debian package to use TUN on steroid")
	}
	command := exec.Command("/usr/bin/pkexec", path, strconv.Itoa(port), edge)
	input, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var diagnostic limitedBuffer
	command.Stderr = &diagnostic
	if err = command.Start(); err != nil {
		input.Close()
		return nil, errors.New("cannot request administrator authorization")
	}
	helper := &tunHelper{input: input, cmd: command, done: make(chan struct{})}
	ready := make(chan bool, 1)
	var routing atomic.Bool
	go func() {
		sent := false
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			switch scanner.Text() {
			case "ROUTING":
				routing.Store(true)
			case "READY":
				if !sent {
					ready <- true
					sent = true
				}
			case "CLEAN":
				helper.cleaned.Store(true)
			}
		}
		helper.err = command.Wait()
		close(helper.done)
		if !sent {
			ready <- false
		}
	}()
	if err = json.NewEncoder(input).Encode(rules); err != nil {
		_ = helper.Close()
		if routing.Load() && !helper.cleaned.Load() {
			return helper, err
		}
		return nil, err
	}
	fail := func(reason error) (*tunHelper, error) {
		cleanupErr := helper.Close()
		if routing.Load() && !helper.cleaned.Load() {
			return helper, errors.Join(reason, cleanupErr)
		}
		select {
		case <-helper.done:
			return nil, reason
		default:
			return helper, errors.Join(reason, cleanupErr)
		}
	}
	select {
	case ok := <-ready:
		if ok {
			return helper, nil
		}
		text := diagnostic.String()
		if text == "" {
			text = "administrator authorization was cancelled or the helper could not start"
		}
		return fail(fmt.Errorf("TUN on steroid could not start: %s", text))
	case <-ctx.Done():
		return fail(errors.New("TUN on steroid startup was cancelled or timed out"))
	}
}
