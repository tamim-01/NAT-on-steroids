package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRollbackReversesOnlySuccessfulChanges(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	fake := filepath.Join(dir, "ip")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + log + "'\ncase \"$*\" in\n  *FAIL*) exit 1;;\n  *'rule show') printf '[]';;\nesac\n"
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	r := &runner{ip: fake}
	if err := r.add([]string{"add", "first"}, []string{"del", "first"}); err != nil {
		t.Fatal(err)
	}
	if err := r.add([]string{"add", "second"}, []string{"del", "second"}); err != nil {
		t.Fatal(err)
	}
	if err := r.add([]string{"add", "FAIL"}, []string{"del", "FAIL"}); err == nil {
		t.Fatal("failed change was accepted")
	}
	if err := r.cleanup(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log)
	calls := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(calls) < 5 || calls[3] != "del second" || calls[4] != "del first" {
		t.Fatalf("rollback did not reverse successful changes: %v", calls)
	}
	if strings.Contains(string(data), "del FAIL") || strings.Contains(string(data), "flush") {
		t.Fatal("cleanup touched an unowned change")
	}
}

func TestCleanupReportsResidualRules(t *testing.T) {
	fake := filepath.Join(t.TempDir(), "ip")
	script := "#!/bin/sh\ncase \"$*\" in\n  *'rule show') printf '[{\"priority\":18577}]';;\nesac\n"
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	r := &runner{ip: fake}
	if err := r.cleanup(); err == nil || !strings.Contains(err.Error(), "remain") {
		t.Fatal("residual routing rule was not reported")
	}
}
