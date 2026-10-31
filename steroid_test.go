package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nat-on-steroids/internal/steroid"
	"nat-on-steroids/internal/vpn"
)

func TestSteroidSettingsPreserveExistingPreferencesAndAreOptional(t *testing.T) {
	a := NewApp()
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	if err := a.SavePorts(2080, 2081); err != nil {
		t.Fatal(err)
	}
	config := steroid.Config{PACPort: 8099, Rules: []steroid.Rule{{Kind: "suffix", Domain: ".IR", Action: "direct"}}}
	if err := a.SaveSteroidConfig(config); err != nil {
		t.Fatal(err)
	}
	if a.GetState().SteroidConfig.Rules[0].Domain != "ir" || a.GetState().SOCKSPort != 2080 || a.GetState().Preferences != defaultPreferences() {
		t.Fatal("experimental settings altered normal settings")
	}
	preferences := defaultPreferences()
	preferences.Theme = "forest"
	if err := a.SavePreferences(preferences); err != nil {
		t.Fatal(err)
	}
	if err := a.SavePorts(3080, 3081); err != nil {
		t.Fatal(err)
	}
	b := NewApp()
	b.settingsPath = a.settingsPath
	b.loadSettings()
	if b.GetState().SteroidConfig.PACPort != 8099 || len(b.GetState().SteroidConfig.Rules) != 1 || b.GetState().Preferences.Theme != "forest" || b.GetState().SOCKSPort != 3080 {
		t.Fatal("experimental rules did not persist")
	}
	config.PACPort = 3080
	if a.SaveSteroidConfig(config) == nil {
		t.Fatal("PAC and SOCKS port collision accepted")
	}
	data, _ := os.ReadFile(a.settingsPath)
	var saved map[string]any
	if json.Unmarshal(data, &saved) != nil || len(saved) != 4 {
		t.Fatal("experimental configuration not isolated in its own settings key")
	}
}
func TestPACIsLoopbackOnlyAndHasNoExternalDirectFallback(t *testing.T) {
	session, err := newSteroidSession(context.Background(), &vpn.Tunnel{}, steroid.Config{PACPort: 0}, 8088)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	address := session.listener.Addr().String()
	if !strings.HasPrefix(address, "127.0.0.1:") {
		t.Fatal("PAC server is not loopback-only")
	}
	response, err := http.Get("http://" + address + "/proxy.pac")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	text := string(data)
	if !strings.Contains(response.Header.Get("Content-Type"), "proxy-autoconfig") || !strings.Contains(text, "PROXY 127.0.0.1:8088") || strings.Contains(text, "; DIRECT") {
		t.Fatal("PAC has an unexpected destination or direct fallback")
	}
	if strings.Count(text, "DIRECT") != 1 || !strings.Contains(text, "host === 'localhost'") {
		t.Fatal("unexpected global direct bypass")
	}
}
func TestNormalTUNNeverCreatesExperimentalSession(t *testing.T) {
	a := NewApp()
	if a.steroid != nil || a.settings.Steroid != nil || a.GetState().Mode != "tun" {
		t.Fatal("experimental routing is enabled by default")
	}
	if err := a.Disconnect(); err != nil {
		t.Fatal(err)
	}
	if a.steroid != nil {
		t.Fatal("normal disconnect created experimental state")
	}
}
