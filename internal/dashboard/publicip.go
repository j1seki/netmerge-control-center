// Package dashboard's publicip resolves the public (WAN) IP address that each uplink actually
// uses, by making one outbound request per uplink that is pinned to that uplink's interface.
//
// This is opt-in and disclosed. It runs only when the user presses "Check public IPs"; nothing
// contacts the network on load or on a timer. The endpoint it asks is shown in the UI and is
// configurable, because a request to a third-party echo service reveals the caller's public IP
// to that service — a fact the user is entitled to see before it happens.
//
// Pinning is the whole point. A single un-pinned request would only report the default route's
// egress IP, which is worthless when the question is "which public IP does THIS uplink use".
// ForceEgress binds the socket to one interface index so the reply reflects that uplink's path,
// which is what makes multi-WAN bonding verifiable.

package dashboard

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"net-merge/internal/inventory"
	"net-merge/internal/logx"
	"net-merge/internal/nics"
)

// DefaultPublicIPEcho is the endpoint used when the user has not configured one. It returns the
// caller's public IP as plain text on success. The choice is disclosed in the UI and the whole
// request is opt-in.
const DefaultPublicIPEcho = "https://api.ipify.org"

// maxEchoBody bounds how much of the reply is read, so a hostile or broken endpoint cannot make
// the resolver buffer an unbounded response.
const maxEchoBody = 64

// PublicIPResult is the outcome for one uplink. Exactly one of IP or Error is meaningful; a
// result with neither would be a bug, so Error is always populated when IP is empty.
type PublicIPResult struct {
	// Name is the adapter's display name, matching the rest of the dashboard.
	Name string `json:"name"`
	// Index is the interface index the request was pinned to.
	Index int `json:"index"`
	// Family is "ipv4" or "ipv6", naming which stack was used for this uplink's request.
	Family string `json:"family"`
	// IP is the public address the echo service saw for this uplink, empty on failure.
	IP string `json:"ip,omitempty"`
	// Error explains a failure in user-facing terms; empty on success.
	Error string `json:"error,omitempty"`
}

// PublicIPProbe resolves one uplink's public IP. It is an interface so the dashboard can be
// driven by a fake in tests without opening a socket. The echo endpoint is passed per call
// because it is user configuration (Privacy.PublicIPEcho); an empty endpoint means the build's
// default.
type PublicIPProbe interface {
	// ResolvePublicIP reports the public IP for the given interface index, asked over endpoint.
	// index <= 0 means the interface is unknown and cannot be pinned.
	ResolvePublicIP(ctx context.Context, endpoint string, index int, family string) (string, error)
}

// EchoPublicIP is the real PublicIPProbe. It asks a plain-text echo endpoint for the caller's
// address, with the socket bound to one interface so the answer reflects that uplink's path.
type EchoPublicIP struct {
	// Client is injectable for tests; Defaults to a client with ResolveTimeout.
	Client *http.Client
	// ResolveTimeout bounds one uplink's request; Defaults to ResolveTimeout when zero.
	ResolveTimeout time.Duration
}

// ResolveTimeout is the per-uplink deadline. It is generous enough for a cold path and short
// enough that a dead uplink does not make the whole check feel hung.
const ResolveTimeout = 8 * time.Second

// ResolvePublicIP implements PublicIPProbe.
func (e *EchoPublicIP) ResolvePublicIP(ctx context.Context, endpoint string, index int, family string) (string, error) {
	if endpoint == "" {
		endpoint = DefaultPublicIPEcho
	}
	if !strings.HasPrefix(endpoint, "https://") && !strings.HasPrefix(endpoint, "http://") {
		return "", fmt.Errorf("the public-IP endpoint must be an http(s) URL, got %q", endpoint)
	}
	if index <= 0 {
		return "", fmt.Errorf("this uplink has no usable interface index, so its traffic cannot be pinned")
	}

	v6 := family == "ipv6"
	timeout := e.ResolveTimeout
	if timeout <= 0 {
		timeout = ResolveTimeout
	}
	client := e.Client
	if client == nil {
		// ForceEgress runs in the dialer's Control hook, which net/http exposes only through a
		// custom DialContext; Transport.Control would pin every dial on the shared client.
		client = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					d := net.Dialer{Control: nics.ForceEgress(index, v6)}
					return d.DialContext(ctx, network, addr)
				},
				// A fresh client per call must not reuse pooled connections, or a later uplink
				// could be answered over an earlier uplink's pinned socket.
				DisableKeepAlives: true,
			},
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("the public-IP endpoint URL could not be used: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("no reply from the public-IP endpoint over this uplink: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxEchoBody))
	if err != nil {
		return "", fmt.Errorf("the public-IP endpoint's reply could not be read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the public-IP endpoint answered HTTP %d over this uplink", resp.StatusCode)
	}

	ip := strings.TrimSpace(string(body))
	if parsed := net.ParseIP(ip); parsed == nil {
		// A non-IP reply usually means a captive portal intercepted the request, which is
		// exactly the signal a bonding user needs, so it is reported as such rather than as a
		// generic parse failure.
		if looksLikeHTML(ip) {
			return "", fmt.Errorf("this uplink did not reach the public-IP endpoint: something else answered, which often means a captive portal or hotspot login is intercepting traffic")
		}
		return "", fmt.Errorf("the public-IP endpoint did not return an IP address over this uplink")
	}
	return ip, nil
}

// looksLikeHTML reports whether a reply looks like a web page rather than a bare address.
func looksLikeHTML(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "<html") || strings.Contains(l, "<!doctype") || strings.Contains(l, "<head")
}

// eligibleUplinks picks the adapters worth asking an echo service about: those the inventory
// considers usable (active or eligible, not excluded) and that have an interface index to pin
// to. Asking about a virtual or excluded adapter would produce a public IP that misrepresents
// the link, so those are skipped and simply never appear in the result.
func eligibleUplinks(adapters []inventory.Adapter) []PublicIPResult {
	out := make([]PublicIPResult, 0, len(adapters))
	for _, a := range adapters {
		if a.Status != inventory.StateActive && a.Status != inventory.StateEligible {
			continue
		}
		if a.Index <= 0 {
			continue
		}
		out = append(out, PublicIPResult{Name: a.Name, Index: a.Index, Family: "ipv4"})
	}
	return out
}

// publicIPCheckResponse is what the check endpoint returns. It always names the endpoint that
// was asked, so the user can see exactly which third party was contacted for this check.
type publicIPCheckResponse struct {
	// Endpoint is the echo service actually asked, after applying any user configuration. It is
	// echoed back so the UI (and the user) can confirm what was contacted.
	Endpoint string `json:"endpoint"`
	// Results holds one entry per eligible uplink, in snapshot order.
	Results []PublicIPResult `json:"results"`
	// Skipped names uplinks that were not asked because they are excluded, virtual, or have no
	// usable interface — reported so an absent row is never mistaken for an oversight.
	Skipped []string `json:"skipped,omitempty"`
}

// maxConcurrentEcho bounds how many uplinks are asked at once. Uplinks are independent, but an
// unbounded fan-out against a dead network would open one socket per link with no backpressure.
const maxConcurrentEcho = 8

// handlePublicIPCheck runs the opt-in public-IP check. It is a POST on purpose: it makes a real
// outbound request to a third-party echo service, so it must never run on page load or a poll.
// The endpoint is disclosed in the response, and every uplink is resolved independently so one
// dead link does not hide the others.
func (s *Server) handlePublicIPCheck(w http.ResponseWriter, r *http.Request) {
	if s.deps.PublicIP == nil {
		fail(w, http.StatusServiceUnavailable, "dashboard_publicip_unavailable",
			"public-IP resolution is not available in this context", nil)
		return
	}

	snap, _, _ := s.cached()
	if snap == nil {
		fail(w, http.StatusServiceUnavailable, "dashboard_no_snapshot",
			"no adapter inventory is available yet, so there are no uplinks to check", nil)
		return
	}

	targets := eligibleUplinks(snap.Adapters)
	asked := make(map[string]bool, len(targets))
	for _, t := range targets {
		asked[t.Name] = true
	}
	var skipped []string
	for _, a := range snap.Adapters {
		if !asked[a.Name] {
			skipped = append(skipped, a.Name)
		}
	}

	endpoint := s.echoEndpoint()
	results := make([]PublicIPResult, len(targets))

	// Resolve concurrently but bound the fan-out. Each result slot is written by exactly one
	// goroutine, so no lock is needed; the WaitGroup only orders completion.
	sem := make(chan struct{}, maxConcurrentEcho)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t PublicIPResult) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(r.Context(), ResolveTimeout)
			defer cancel()
			ip, err := s.deps.PublicIP.ResolvePublicIP(ctx, endpoint, t.Index, t.Family)
			if err != nil {
				t.Error = err.Error()
			} else {
				t.IP = ip
			}
			results[i] = t
		}(i, t)
	}
	wg.Wait()

	logx.Eventf(logx.LevelInfo, "dashboard.publicip",
		"public-IP check asked %s (%d uplink(s), %d skipped)", endpoint, len(results), len(skipped))
	writeJSON(w, http.StatusOK, publicIPCheckResponse{Endpoint: endpoint, Results: results, Skipped: skipped})
}

// echoEndpoint returns the configured echo service, or the build default when unset. It is
// resolved here so the disclosure the UI shows matches exactly what was contacted.
func (s *Server) echoEndpoint() string {
	cfg, _, _ := s.loadSettings()
	if e := strings.TrimSpace(cfg.Privacy.PublicIPEcho); e != "" {
		return e
	}
	return DefaultPublicIPEcho
}
