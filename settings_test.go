package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPortSettingsPersistAndRejectLiveChanges(t *testing.T) {
	a := NewApp()
	a.settingsPath = filepath.Join(t.TempDir(), "n-orm-proxy", "settings.json")
	if err := a.SavePorts(2080, 2081); err != nil {
		t.Fatal(err)
	}
	if a.GetState().SOCKSPort != 2080 || a.GetState().HTTPPort != 2081 {
		t.Fatal("ports were not applied")
	}
	info, err := os.Stat(a.settingsPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("settings file is not private")
	}
	data, _ := os.ReadFile(a.settingsPath)
	var saved map[string]any
	if json.Unmarshal(data, &saved) != nil || len(saved) != 3 {
		t.Fatal("settings should contain proxy ports and preferences")
	}
	b := NewApp()
	b.settingsPath = a.settingsPath
	b.loadSettings()
	if b.settings != a.settings {
		t.Fatal("saved ports did not survive restart")
	}
	a.state.Status = "connected"
	if err := a.SavePorts(3080, 3081); err == nil {
		t.Fatal("ports were changed during an active connection")
	}
	after, _ := os.ReadFile(a.settingsPath)
	if string(after) != string(data) {
		t.Fatal("rejected port change altered saved settings")
	}
}

func TestPortValidationAndSaveFailure(t *testing.T) {
	a := NewApp()
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	for _, pair := range [][2]int{{1023, 8080}, {65536, 8080}, {1080, 1080}, {1080, 0}} {
		if err := a.SavePorts(pair[0], pair[1]); err == nil {
			t.Fatalf("invalid port pair accepted: %v", pair)
		}
	}
	if err := os.Mkdir(a.settingsPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := a.SavePorts(2080, 2081); err == nil {
		t.Fatal("file save failure was hidden")
	}
	if a.settings.SOCKSPort != 1088 || a.GetState().SOCKSPort != 1088 {
		t.Fatal("failed save altered active configuration")
	}
}
