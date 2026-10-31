// Experimental orchestration: the original TUN helper runs unmodified. Only
// this process's explicitly marked direct sockets get an additional bypass.
package main

import (
	"bufio"
	"context"
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

	"nat-on-steroids/internal/steroid"
)

const originalHelper = "/usr/lib/n-orm-proxy/n-orm-helper"
const socketMark = "0x4e4f524d/0xffffffff"

type policyRunner struct {
	ip    string
	owned bool
}

func (r *policyRunner) call(args ...string) ([]byte, error) {
	command := exec.Command(r.ip, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	data, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("direct routing: ip %s: %s", strings.Join(args, " "), strings.TrimSpace(string(data)))
	}
	return data, nil
}
func (r *policyRunner) vacant() error {
	data, err := r.call("-4", "-json", "rule", "show")
	if err != nil {
		return err
	}
	var rules []struct {
		Priority int `json:"priority"`
	}
	if json.Unmarshal(data, &rules) != nil {
		return errors.New("cannot inspect direct routing policy")
	}
	for _, rule := range rules {
		if rule.Priority == steroid.BypassPriority {
			return errors.New("routing priority 18575 is already in use")
		}
	}
	return nil
}
func (r *policyRunner) add() error {
	if err := r.vacant(); err != nil {
		return err
	}
	_, err := r.call("-4", "rule", "add", "priority", "18575", "fwmark", socketMark, "lookup", "main")
	if err == nil {
		r.owned = true
	}
	return err
}
func (r *policyRunner) cleanup() error {
	if !r.owned {
		return nil
	}
	if _, err := r.call("-4", "rule", "del", "priority", "18575", "fwmark", socketMark, "lookup", "main"); err != nil {
		return err
	}
	if err := r.vacant(); err != nil {
		return errors.New("direct routing cleanup was not confirmed; check priority 18575")
	}
	r.owned = false
	return nil
}
func (r *policyRunner) verify() error {
	data, err := r.call("-4", "-json", "route", "get", "1.1.1.1", "mark", "0x4e4f524d")
	if err != nil {
		return err
	}
	var routes []struct {
		Dev string `json:"dev"`
	}
	if json.Unmarshal(data, &routes) != nil || len(routes) == 0 || routes[0].Dev == "" || routes[0].Dev == "lo" || strings.HasPrefix(routes[0].Dev, "fxvpn") {
		return errors.New("the marked direct route still points into TUN")
	}
	return nil
}

func trustedOriginal() error {
	for _, path := range []string{filepath.Dir(originalHelper), originalHelper, "/usr/lib/n-orm-proxy/hev-socks5-tunnel"} {
		info, err := os.Lstat(path)
		if err != nil {
			return errors.New("install the Debian package before using TUN on steroid")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 || !(info.IsDir() || info.Mode().IsRegular()) {
			return errors.New("installed TUN components must be root-owned and not writable by other users")
		}
	}
	return nil
}

type childResult struct {
	err   error
	clean bool
}
type originalProcess struct {
	input io.WriteCloser
	ready chan struct{}
	done  chan childResult
}

func startOriginal(uid string, port, edge string) (*originalProcess, error) {
	cmd := exec.Command(originalHelper, port, edge)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "PKEXEC_UID=" + uid}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		input.Close()
		return nil, err
	}
	process := &originalProcess{input: input, ready: make(chan struct{}, 1), done: make(chan childResult, 1)}
	go func() {
		clean := false
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			switch scanner.Text() {
			case "READY":
				select {
				case process.ready <- struct{}{}:
				default:
				}
			case "CLEAN":
				clean = true
			}
		}
		process.done <- childResult{err: cmd.Wait(), clean: clean}
		close(process.done)
	}()
	return process, nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() (result error) {
	if os.Geteuid() != 0 {
		return errors.New("TUN on steroid needs administrator authorization")
	}
	uid, err := strconv.ParseUint(os.Getenv("PKEXEC_UID"), 10, 32)
	if err != nil || uid == 0 {
		return errors.New("launch this helper from N-orm proxy")
	}
	if len(os.Args) != 3 {
		return errors.New("expected a SOCKS port and VPN edge IPv4 address")
	}
	port, err := strconv.Atoi(os.Args[1])
	if err != nil || port < 1024 || port > 65535 {
		return errors.New("invalid SOCKS port")
	}
	edge := net.ParseIP(os.Args[2])
	if edge == nil || edge.To4() == nil || !edge.IsGlobalUnicast() || edge.IsPrivate() {
		return errors.New("invalid VPN edge")
	}
	if err = trustedOriginal(); err != nil {
		return err
	}
	if info, err := os.Stat("/dev/net/tun"); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return errors.New("/dev/net/tun is unavailable")
	}
	// Only a bounded initial rule list crosses the privileged control pipe.
	reader := bufio.NewReaderSize(os.Stdin, steroid.MaxMessage+1)
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > steroid.MaxMessage {
		return errors.New("invalid initial domain rules")
	}
	var requested []steroid.Rule
	if json.Unmarshal(line, &requested) != nil {
		return errors.New("invalid initial domain rules")
	}
	rules, err := steroid.NormalizeRules(requested)
	if err != nil {
		return err
	}
	lock, err := os.OpenFile("/run/n-orm-steroid.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return errors.New("another TUN on steroid session is active")
	}
	ip := "/usr/sbin/ip"
	if _, err = os.Stat(ip); err != nil {
		ip = "/usr/bin/ip"
	}
	if _, err = os.Stat(ip); err != nil {
		return errors.New("install iproute2")
	}
	routing := &policyRunner{ip: ip}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	var listener *net.UnixListener
	var resolver *steroid.DirectResolver
	var child *originalProcess
	var finished *childResult
	var serverDone chan error
	socket := ""
	directory := ""
	ownSocket := false
	ownDirectory := false
	// The app only treats missing CLEAN as a routing failure after this marker.
	fmt.Println("ROUTING")
	defer func() {
		cleanupErr := error(nil)
		cancel()
		if listener != nil {
			listener.Close()
		}
		if serverDone != nil {
			select {
			case <-serverDone:
			case <-time.After(3 * time.Second):
				cleanupErr = errors.Join(cleanupErr, errors.New("direct streams did not stop"))
			}
		}
		if resolver != nil {
			resolver.Close()
		}
		if child != nil {
			child.input.Close()
			if finished == nil {
				select {
				case ended := <-child.done:
					finished = &ended
				case <-time.After(8 * time.Second):
					cleanupErr = errors.New("original TUN helper did not finish cleanup")
				}
			}
			if finished != nil && !finished.clean {
				cleanupErr = errors.Join(cleanupErr, errors.New("original TUN helper did not confirm cleanup"))
			}
		}
		cleanupErr = errors.Join(cleanupErr, routing.cleanup())
		if ownSocket {
			_ = os.Remove(socket)
		}
		if ownDirectory {
			_ = os.Remove(directory)
		}
		if cleanupErr == nil {
			fmt.Println("CLEAN")
		} else {
			result = errors.Join(result, cleanupErr)
		}
	}()
	go func() { _, _ = io.Copy(io.Discard, reader); cancel() }()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err = routing.add(); err != nil {
		return err
	}
	socket = steroid.SocketPath(int(uid))
	directory = filepath.Dir(socket)
	if err = os.Mkdir(directory, 0701); err != nil {
		return errors.New("direct helper directory already exists; inspect the earlier session before retrying")
	}
	ownDirectory = true
	listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return err
	}
	ownSocket = true
	listener.SetUnlinkOnClose(false)
	if err = os.Chown(socket, int(uid), -1); err != nil {
		return err
	}
	if err = os.Chmod(socket, 0600); err != nil {
		return err
	}
	resolver = steroid.NewDirectResolver()
	server := steroid.NewServer(uint32(uid), rules, resolver.Lookup, steroid.MarkedDialer().DialContext)
	serverDone = make(chan error, 1)
	go func() { serverDone <- server.Serve(ctx, listener) }()
	child, err = startOriginal(strconv.FormatUint(uid, 10), strconv.Itoa(port), edge.String())
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return nil
	case ended := <-child.done:
		finished = &ended
		return errors.New("the original TUN helper could not start")
	case err := <-serverDone:
		serverDone = nil
		return fmt.Errorf("direct helper stopped: %v", err)
	case <-child.ready:
	}
	if err = routing.verify(); err != nil {
		return err
	}
	fmt.Println("READY")
	select {
	case <-ctx.Done():
		return nil
	case ended := <-child.done:
		finished = &ended
		return errors.New("the original TUN helper stopped")
	case err := <-serverDone:
		serverDone = nil
		return fmt.Errorf("direct helper stopped: %v", err)
	}
}
