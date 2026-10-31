package steroid

import (
	"context"
	"errors"
	"io"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"nat-on-steroids/internal/vpn"
)

type DomainEvent struct {
	Domain      string `json:"domain"`
	Action      string `json:"action"`
	Connections int    `json:"connections"`
	LastSeen    int64  `json:"lastSeen"`
	Error       string `json:"error"`
}

type Router struct {
	mu                           sync.Mutex
	rules                        []Rule
	generation                   uint64
	vpn, direct                  vpn.Opener
	active                       map[*routedStream]struct{}
	events                       map[string]DomainEvent
	closed                       bool
	DirectUpload, DirectDownload atomic.Int64
}

func NewRouter(tunnel, direct vpn.Opener, rules []Rule) *Router {
	return &Router{vpn: tunnel, direct: direct, rules: append([]Rule(nil), rules...), active: map[*routedStream]struct{}{}, events: map[string]DomainEvent{}}
}

func (r *Router) Open(ctx context.Context, address string) (io.ReadWriteCloser, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid destination")
	}
	domain, domainErr := NormalizeDomain(host)
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, errors.New("domain router is closed")
	}
	action := "vpn"
	if domainErr == nil {
		action = Decide(r.rules, domain)
	}
	generation := r.generation
	r.mu.Unlock()
	opener := r.vpn
	if action == "direct" {
		opener = r.direct
	}
	var remote io.ReadWriteCloser
	port, _ := strconv.Atoi(portText)
	if action == "direct" && port != 80 && port != 443 {
		err = errors.New("Direct domain rules support HTTP/HTTPS on ports 80 and 443")
	} else {
		remote, err = opener.Open(ctx, address)
	}
	r.mu.Lock()
	if domainErr == nil {
		if len(r.events) >= 256 {
			if _, exists := r.events[domain]; !exists {
				oldest := ""
				at := int64(1<<63 - 1)
				for key, event := range r.events {
					if event.LastSeen < at {
						oldest, at = key, event.LastSeen
					}
				}
				delete(r.events, oldest)
			}
		}
		event := r.events[domain]
		event.Domain = domain
		event.Action = action
		event.Connections++
		event.LastSeen = time.Now().Unix()
		event.Error = ""
		if err != nil {
			event.Error = err.Error()
		}
		r.events[domain] = event
	}
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	if r.closed || domainErr == nil && generation != r.generation {
		r.mu.Unlock()
		remote.Close()
		return nil, errors.New("routing rules changed; reload this connection")
	}
	stream := &routedStream{ReadWriteCloser: remote, owner: r, direct: action == "direct", domain: domainErr == nil}
	r.active[stream] = struct{}{}
	r.mu.Unlock()
	return stream, nil
}

// Rule changes close existing hostname-based proxy streams. IP-only TUN
// connections retain their existing VPN route and are not interrupted.
func (r *Router) SetRules(rules []Rule) {
	r.mu.Lock()
	r.rules = append([]Rule(nil), rules...)
	r.generation++
	active := make([]*routedStream, 0, len(r.active))
	for stream := range r.active {
		if stream.domain {
			active = append(active, stream)
		}
	}
	r.mu.Unlock()
	for _, stream := range active {
		stream.Close()
	}
}

func (r *Router) Events() []DomainEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]DomainEvent, 0, len(r.events))
	for _, event := range r.events {
		out = append(out, event)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen == out[j].LastSeen {
			return out[i].Domain < out[j].Domain
		}
		return out[i].LastSeen > out[j].LastSeen
	})
	return out
}
func (r *Router) ClearEvents() { r.mu.Lock(); r.events = map[string]DomainEvent{}; r.mu.Unlock() }
func (r *Router) Close() {
	r.mu.Lock()
	r.closed = true
	r.generation++
	active := make([]*routedStream, 0, len(r.active))
	for stream := range r.active {
		active = append(active, stream)
	}
	r.mu.Unlock()
	for _, stream := range active {
		stream.Close()
	}
}

type routedStream struct {
	io.ReadWriteCloser
	owner          *Router
	direct, domain bool
	once           sync.Once
}

func (s *routedStream) Read(p []byte) (int, error) {
	n, err := s.ReadWriteCloser.Read(p)
	if s.direct {
		s.owner.DirectDownload.Add(int64(n))
	}
	return n, err
}
func (s *routedStream) Write(p []byte) (int, error) {
	n, err := s.ReadWriteCloser.Write(p)
	if s.direct {
		s.owner.DirectUpload.Add(int64(n))
	}
	return n, err
}
func (s *routedStream) Close() error {
	var err error
	s.once.Do(func() {
		err = s.ReadWriteCloser.Close()
		s.owner.mu.Lock()
		delete(s.owner.active, s)
		s.owner.mu.Unlock()
	})
	return err
}
func (s *routedStream) CloseWrite() error {
	if closer, ok := s.ReadWriteCloser.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return s.Close()
}
