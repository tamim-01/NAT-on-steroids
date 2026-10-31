// The privileged helper only configures a fixed TUN setup and supervises hev.
// It never receives Firefox credentials or executes caller-provided commands.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const table = "18577"
const bypassPriority = "18576"
const routePriority = "18577"

type runner struct {
	ip   string
	undo [][]string
}

func (r *runner) run(args ...string) ([]byte, error) {
	cmd := exec.Command(r.ip, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ip %s: %s", strings.Join(args, " "), strings.TrimSpace(string(output)))
	}
	return output, nil
}
func (r *runner) add(add, undo []string) error {
	if _, err := r.run(add...); err != nil {
		return err
	}
	r.undo = append(r.undo, undo)
	return nil
}
func (r *runner) cleanup() error {
	for i := len(r.undo) - 1; i >= 0; i-- {
		_, _ = r.run(r.undo[i]...)
	}
	for _, family := range []string{"-4", "-6"} {
		data, err := r.run(family, "-json", "rule", "show")
		if err != nil {
			return errors.New("could not verify route cleanup")
		}
		var rules []struct {
			Priority int `json:"priority"`
		}
		if json.Unmarshal(data, &rules) != nil {
			return errors.New("could not verify route cleanup")
		}
		for _, rule := range rules {
			if rule.Priority == 18576 || rule.Priority == 18577 {
				return errors.New("N-orm proxy routing rules remain; check priorities 18576 and 18577")
			}
		}
		data, err = r.run(family, "route", "show", "table", table)
		if err != nil && !strings.Contains(err.Error(), "FIB table does not exist") {
			return errors.New("could not verify routing table cleanup")
		}
		if err == nil && len(strings.TrimSpace(string(data))) > 0 {
			return errors.New("N-orm proxy routing table 18577 was not cleared")
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() (result error) {
	if os.Geteuid() != 0 {
		return errors.New("TUN setup needs administrator authorization through pkexec")
	}
	uid, err := strconv.ParseUint(os.Getenv("PKEXEC_UID"), 10, 32)
	if err != nil || uid == 0 {
		return errors.New("launch this helper from the desktop app")
	}
	if len(os.Args) != 3 {
		return errors.New("expected a SOCKS port and an edge IPv4 address")
	}
	port, err := strconv.Atoi(os.Args[1])
	if err != nil || port < 1024 || port > 65535 {
		return errors.New("invalid local SOCKS port")
	}
	edge := net.ParseIP(os.Args[2])
	if edge == nil || edge.To4() == nil || !edge.IsGlobalUnicast() || edge.IsPrivate() {
		return errors.New("invalid edge IPv4 address")
	}
	if info, err := os.Stat("/dev/net/tun"); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return errors.New("/dev/net/tun is unavailable; enable the Linux TUN driver")
	}
	stop := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, bufio.NewReader(os.Stdin)); close(stop) }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(signals)
	stopping := func() bool {
		select {
		case <-stop:
			return true
		case <-signals:
			return true
		default:
			return false
		}
	}
	ip := "/usr/sbin/ip"
	if _, err = os.Stat(ip); err != nil {
		ip = "/usr/bin/ip"
	}
	if _, err = os.Stat(ip); err != nil {
		return errors.New("install iproute2 to use TUN mode")
	}
	// A fixed lock and exclusive interface prevent parallel helpers from touching
	// each other's rules. Existing rules are rejected, never flushed.
	lock, err := os.OpenFile("/run/n-orm-proxy.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return errors.New("another N-orm proxy TUN session is active")
	}
	r := &runner{ip: ip}
	for _, family := range []string{"-4", "-6"} {
		data, e := r.run(family, "-json", "rule", "show")
		if e != nil {
			return e
		}
		var rules []map[string]any
		if json.Unmarshal(data, &rules) != nil {
			return errors.New("cannot inspect existing routing rules")
		}
		for _, rule := range rules {
			p, _ := rule["priority"].(float64)
			if p == 18576 || p == 18577 {
				return errors.New("routing priorities 18576–18577 are already in use")
			}
		}
		data, e = r.run(family, "route", "show", "table", table)
		// ip reports an absent routing table as an error; that is the expected state.
		if e == nil && len(strings.TrimSpace(string(data))) > 0 {
			return errors.New("routing table 18577 is already in use")
		}
	}
	name := "fxvpn" + strconv.FormatUint(uid, 10)
	if _, e := r.run("link", "show", "dev", name); e == nil {
		return errors.New("a N-orm proxy interface already exists; check an earlier session before reconnecting")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	engine := filepath.Join(filepath.Dir(exe), "hev-socks5-tunnel")
	if info, e := os.Stat(engine); e != nil || !info.Mode().IsRegular() {
		return errors.New("hev-socks5-tunnel is missing beside the helper")
	}
	dir, err := os.MkdirTemp("/run", "n-orm-proxy-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	config := fmt.Sprintf("tunnel:\n  name: '%s'\n  mtu: 1400\n  ipv4: '198.18.0.1'\n  icmp: 'off'\nsocks5:\n  address: '127.0.0.1'\n  port: %d\n  udp: 'udp'\nmisc:\n  log-level: 'error'\n  connect-timeout: 20000\n  tcp-read-write-timeout: 300000\n", name, port)
	path := filepath.Join(dir, "tunnel.yaml")
	if err = os.WriteFile(path, []byte(config), 0600); err != nil {
		return err
	}
	cmd := exec.Command(engine, path)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if stopping() {
		return nil
	}
	if err = cmd.Start(); err != nil {
		return errors.New("cannot start the TUN engine")
	}
	finished := make(chan struct{})
	go func() { _ = cmd.Wait(); close(finished) }()
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
		}
	}()
	// Undo routes before terminating hev. Closing hev's non-persistent TUN file
	// descriptor removes the interface in the kernel, including partial startup.
	cleanupDNS := func() error { return nil }
	defer func() {
		if err := errors.Join(cleanupDNS(), r.cleanup()); err != nil {
			result = errors.Join(result, err)
		} else {
			fmt.Println("CLEAN")
		}
	}()
	ready := false
	for i := 0; i < 60; i++ {
		if stopping() {
			return nil
		}
		select {
		case <-finished:
			return errors.New("TUN engine exited during startup")
		default:
		}
		data, e := r.run("-json", "link", "show", "dev", name)
		if e == nil {
			var links []struct {
				Flags []string `json:"flags"`
				MTU   int      `json:"mtu"`
			}
			_ = json.Unmarshal(data, &links)
			if len(links) > 0 && links[0].MTU == 1400 {
				for _, flag := range links[0].Flags {
					if flag == "UP" {
						ready = true
					}
				}
			}
		}
		if ready {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		return errors.New("TUN interface did not become ready")
	}
	changes := []struct{ add, del []string }{
		{[]string{"-4", "route", "add", "table", table, "default", "dev", name}, []string{"-4", "route", "del", "table", table, "default", "dev", name}},
		{[]string{"-6", "route", "add", "blackhole", "default", "table", table}, []string{"-6", "route", "del", "blackhole", "default", "table", table}},
		{[]string{"-4", "rule", "add", "priority", bypassPriority, "to", edge.String() + "/32", "lookup", "main"}, []string{"-4", "rule", "del", "priority", bypassPriority, "to", edge.String() + "/32", "lookup", "main"}},
		{[]string{"-6", "rule", "add", "priority", routePriority, "lookup", table}, []string{"-6", "rule", "del", "priority", routePriority, "lookup", table}},
		{[]string{"-4", "rule", "add", "priority", routePriority, "lookup", table}, []string{"-4", "rule", "del", "priority", routePriority, "lookup", table}},
	}
	for _, change := range changes {
		if stopping() {
			return nil
		}
		if err = r.add(change.add, change.del); err != nil {
			return err
		}
	}
	// systemd-resolved binds DNS sockets to individual links. Point its stub at
	// the TUN link explicitly rather than depending on capture of physical-link DNS.
	resolverConfig, _ := os.ReadFile("/etc/resolv.conf")
	if strings.Contains(string(resolverConfig), "127.0.0.53") || strings.Contains(string(resolverConfig), "127.0.0.54") {
		const resolvectl = "/usr/bin/resolvectl"
		if _, err := os.Stat(resolvectl); err != nil {
			return errors.New("systemd-resolved is active but resolvectl is missing")
		}
		resolve := func(args ...string) error {
			cmd := exec.Command(resolvectl, args...)
			cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
			if err := cmd.Run(); err != nil {
				return errors.New("could not configure systemd-resolved for the TUN link")
			}
			return nil
		}
		cleanupDNS = func() error {
			if err := resolve("revert", name); err != nil {
				if _, linkErr := r.run("link", "show", "dev", name); linkErr == nil {
					return err
				}
			}
			return nil
		}
		for _, args := range [][]string{{"dns", name, "1.1.1.1"}, {"domain", name, "~."}, {"default-route", name, "yes"}} {
			if stopping() {
				return nil
			}
			if err := resolve(args...); err != nil {
				return err
			}
		}
	}
	probe := "1.1.1.1"
	if edge.String() == probe {
		probe = "8.8.8.8"
	}
	data, err := r.run("-4", "-json", "route", "get", probe)
	if err != nil {
		return errors.New("cannot verify TUN routing")
	}
	var routes []struct {
		Dev string `json:"dev"`
	}
	if json.Unmarshal(data, &routes) != nil || len(routes) == 0 || routes[0].Dev != name {
		return errors.New("another routing policy overrides TUN; disconnect other VPNs first")
	}
	if stopping() {
		return nil
	}
	fmt.Println("READY")
	// EOF means the GUI died or disconnected. Drop routes even after a GUI crash.
	select {
	case <-stop:
		return nil
	case <-signals:
		return nil
	case <-finished:
		return errors.New("TUN engine stopped unexpectedly")
	}
}
