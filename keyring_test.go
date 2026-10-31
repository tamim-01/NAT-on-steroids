package main

import (
	"bufio"
	"context"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type fakeSecretService struct {
	mu     sync.Mutex
	value  string
	locked bool
}

func (s *fakeSecretService) SearchItems(attrs map[string]string) ([]dbus.ObjectPath, []dbus.ObjectPath, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlocked, locked := []dbus.ObjectPath{}, []dbus.ObjectPath{}
	if attrs["service"] != "foxyvpn-linux" || attrs["username"] != "default" {
		return unlocked, locked, nil
	}
	if s.value != "" {
		if s.locked {
			locked = append(locked, "/test/item")
		} else {
			unlocked = append(unlocked, "/test/item")
		}
	}
	return unlocked, locked, nil
}
func (s *fakeSecretService) ReadAlias(alias string) (dbus.ObjectPath, *dbus.Error) {
	return "/test/collection", nil
}
func (s *fakeSecretService) OpenSession(algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	return dbus.MakeVariant(""), "/test/session", nil
}
func (s *fakeSecretService) Get(iface, property string) (dbus.Variant, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return dbus.MakeVariant(s.locked), nil
}
func (s *fakeSecretService) CreateItem(props map[string]dbus.Variant, secret secretValue, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.value = string(secret.Value)
	return "/test/item", "/", nil
}
func (s *fakeSecretService) GetSecret(session dbus.ObjectPath) (secretValue, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return secretValue{session, []byte{}, []byte(s.value), "text/plain; charset=utf8"}, nil
}
func (s *fakeSecretService) Delete() (dbus.ObjectPath, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.value = ""
	return "/", nil
}

func TestKeyringRoundTripAndLockedSession(t *testing.T) {
	// Own an isolated bus, so tests never inspect or change the user's keyring.
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address=1")
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() {
		t.Fatal("private DBus failed to start")
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", scanner.Text())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dbus.ConnectSessionBus(dbus.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	service := &fakeSecretService{}
	for _, item := range []struct {
		path  dbus.ObjectPath
		iface string
	}{{"/org/freedesktop/secrets", secretService}, {"/test/collection", "org.freedesktop.Secret.Collection"}, {"/test/collection", "org.freedesktop.DBus.Properties"}, {"/test/item", "org.freedesktop.Secret.Item"}} {
		if err = conn.Export(service, item.path, item.iface); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = conn.RequestName(secretName, dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	if value, err := keyringOperation("get", ""); err != nil || value != "" {
		t.Fatalf("missing session failed: %v", err)
	}
	if _, err = keyringOperation("set", "test-only-session"); err != nil {
		t.Fatal(err)
	}
	if value, err := keyringOperation("get", ""); err != nil || value != "test-only-session" {
		t.Fatalf("saved session failed: %v", err)
	}
	service.mu.Lock()
	service.locked = true
	service.mu.Unlock()
	if _, err = keyringOperation("get", ""); err != errKeyringLocked {
		t.Fatalf("locked session should not prompt: %v", err)
	}
	service.mu.Lock()
	service.locked = false
	service.mu.Unlock()
	if _, err = keyringOperation("delete", ""); err != nil {
		t.Fatal(err)
	}
	if value, err := keyringOperation("get", ""); err != nil || value != "" {
		t.Fatalf("session was not removed: %v", err)
	}
}
