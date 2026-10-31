package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakePolicy(t *testing.T) (*policyRunner, string, string) {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	log := filepath.Join(dir, "log")
	path := filepath.Join(dir, "ip")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + log + "'\ncase \"$*\" in\n '-4 -json rule show') if test -e '" + state + "'; then cat '" + state + "'; else printf '[]'; fi;;\n '-4 rule add '*) printf '[{\"priority\":18575}]' > '" + state + "';;\n '-4 rule del '*) printf '[]' > '" + state + "';;\n '-4 -json route get '*) printf '[{\"dev\":\"eth0\"}]';;\n esac\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return &policyRunner{ip: path}, state, log
}
func TestMarkedPolicyAddsAndRemovesOnlyItsOwnRule(t *testing.T) {
	r, _, log := fakePolicy(t)
	if err := r.add(); err != nil {
		t.Fatal(err)
	}
	if err := r.verify(); err != nil {
		t.Fatal(err)
	}
	if err := r.cleanup(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log)
	text := string(data)
	if !strings.Contains(text, "fwmark 0x4e4f524d/0xffffffff lookup main") || !strings.Contains(text, "rule del priority 18575") || strings.Contains(text, "flush") || strings.Contains(text, "18577") {
		t.Fatal("direct policy touched unrelated TUN routing")
	}
}
func TestMarkedPolicyRefusesOccupiedPriorityWithoutDeletingIt(t *testing.T) {
	r, state, log := fakePolicy(t)
	if err := os.WriteFile(state, []byte(`[{"priority":18575}]`), 0600); err != nil {
		t.Fatal(err)
	}
	if r.add() == nil {
		t.Fatal("occupied priority was overwritten")
	}
	if err := r.cleanup(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log)
	if strings.Contains(string(data), "rule add") || strings.Contains(string(data), "rule del") {
		t.Fatal("existing routing policy was modified")
	}
}
