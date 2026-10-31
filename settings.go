package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"

	"nat-on-steroids/internal/steroid"
)

type Preferences struct {
	Theme                  string `json:"theme"`
	SpeedVisualization     string `json:"speedVisualization"`
	RemainingVisualization string `json:"remainingVisualization"`
	TotalsVisualization    string `json:"totalsVisualization"`
	LatencyRefreshSeconds  int    `json:"latencyRefreshSeconds"`
}

type proxySettings struct {
	Steroid     *steroid.Config `json:"steroid,omitempty"`
	SOCKSPort   int             `json:"socksPort"`
	HTTPPort    int             `json:"httpPort"`
	Preferences Preferences     `json:"preferences"`
}

func defaultPreferences() Preferences {
	return Preferences{Theme: "midnight", SpeedVisualization: "graph", RemainingVisualization: "ring", TotalsVisualization: "bars", LatencyRefreshSeconds: 30}
}

func validatePreferences(p Preferences) error {
	if !slices.Contains([]string{"midnight", "nord", "dracula", "forest", "ember", "daylight"}, p.Theme) ||
		!slices.Contains([]string{"graph", "bars", "numbers"}, p.SpeedVisualization) ||
		!slices.Contains([]string{"ring", "blocks", "bar"}, p.RemainingVisualization) ||
		!slices.Contains([]string{"bars", "ring", "numbers"}, p.TotalsVisualization) {
		return errors.New("choose an available theme and visualization")
	}
	if p.LatencyRefreshSeconds < 1 || p.LatencyRefreshSeconds > 900 {
		return errors.New("latency refresh interval must be between 1 and 900 seconds")
	}
	return nil
}

func validatePorts(socks, http int) error {
	if socks < 1024 || socks > 65535 || http < 1024 || http > 65535 {
		return errors.New("proxy ports must be between 1024 and 65535")
	}
	if socks == http {
		return errors.New("SOCKS5 and HTTP must use different ports")
	}
	return nil
}

func (a *App) loadSettings() {
	data, err := os.ReadFile(a.settingsPath)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	// Initializing first keeps older port-only files compatible with new settings.
	settings := proxySettings{SOCKSPort: 1088, HTTPPort: 8088, Preferences: defaultPreferences()}
	if err != nil || json.Unmarshal(data, &settings) != nil || validatePorts(settings.SOCKSPort, settings.HTTPPort) != nil || validatePreferences(settings.Preferences) != nil {
		a.setError(errors.New("saved settings could not be loaded; defaults are in use"))
		return
	}
	if settings.Steroid != nil {
		config, validationErr := steroid.NormalizeConfig(*settings.Steroid)
		if validationErr != nil {
			a.setError(errors.New("saved experimental routing settings are invalid; default VPN-only rules are in use"))
			settings.Steroid = nil
		} else {
			settings.Steroid = &config
		}
	}
	a.settings = settings
	a.publishSettings()
}

func (a *App) publishSettings() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state.SOCKSPort = a.settings.SOCKSPort
	a.state.HTTPPort = a.settings.HTTPPort
	a.state.Preferences = a.settings.Preferences
	a.state.SteroidConfig = steroid.DefaultConfig()
	if a.settings.Steroid != nil {
		a.state.SteroidConfig = *a.settings.Steroid
	}
}

func (a *App) SavePorts(socks, http int) error {
	a.operation.Lock()
	defer a.operation.Unlock()
	if err := validatePorts(socks, http); err != nil {
		return err
	}
	if status := a.GetState().Status; status == "connected" || status == "connecting" || a.proxy != nil {
		return errors.New("disconnect before changing local proxy ports")
	}
	settings := a.settings
	settings.SOCKSPort, settings.HTTPPort = socks, http
	if err := a.saveSettings(settings); err != nil {
		return err
	}
	a.mu.Lock()
	a.state.Error = ""
	a.mu.Unlock()
	return nil
}

func (a *App) SavePreferences(preferences Preferences) error {
	a.operation.Lock()
	defer a.operation.Unlock()
	if err := validatePreferences(preferences); err != nil {
		return err
	}
	settings := a.settings
	settings.Preferences = preferences
	return a.saveSettings(settings)
}

func (a *App) saveSettings(settings proxySettings) error {
	if a.settingsPath == "" {
		return errors.New("your user configuration directory is unavailable")
	}
	data, _ := json.MarshalIndent(settings, "", "  ")
	dir := filepath.Dir(a.settingsPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("cannot create the settings directory")
	}
	file, err := os.CreateTemp(dir, ".settings-*")
	if err != nil {
		return errors.New("cannot save settings")
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(append(data, '\n')); err != nil {
		file.Close()
		return errors.New("cannot save settings")
	}
	if err = file.Close(); err != nil {
		return errors.New("cannot save settings")
	}
	if err = os.Rename(name, a.settingsPath); err != nil {
		return errors.New("cannot save settings")
	}
	a.settings = settings
	a.publishSettings()
	a.notifyLatencyChanged()
	return nil
}
