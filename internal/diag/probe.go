package diag

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Prober is the in-process counterpart of execx.Runner: everything a check does with sockets
// goes through it, so checks are testable without a network and without a Windows host.
//
// The methods return the error rather than a boolean because *why* a probe failed is the
// diagnosis: a refusal proves the path works and the port is closed, while a timeout proves
// nothing about the far end at all.
type Prober interface {
	// TCPConnect dials addr (host:port) optionally from a specific local IP. It returns the
	// time the handshake took.
	TCPConnect(ctx context.Context, addr string, localIP net.IP) (time.Duration, error)
	// UDPExchange sends payload to addr and reads up to want bytes. It returns the reply and
	// the round-trip time.
	UDPExchange(ctx context.Context, addr string, payload []byte, want int) ([]byte, time.Duration, error)
	// LookupIP resolves a name using the host's configured resolvers.
	LookupIP(ctx context.Context, name string) ([]net.IP, error)
	// LookupAtServer resolves a name by asking one specific DNS server.
	LookupAtServer(ctx context.Context, name, server string) ([]net.IP, error)
	// PortFree reports whether a TCP listen on addr is possible right now. A successful bind
	// proves nothing else is listening there; it is closed again immediately.
	PortFree(ctx context.Context, addr string) (bool, error)
}

// SystemProber is the real implementation.
type SystemProber struct{}

func (SystemProber) TCPConnect(ctx context.Context, addr string, localIP net.IP) (time.Duration, error) {
	d := &net.Dialer{}
	if localIP != nil {
		d.LocalAddr = &net.TCPAddr{IP: localIP}
	}
	if dl, ok := ctx.Deadline(); ok {
		d.Timeout = time.Until(dl)
	} else {
		d.Timeout = 5 * time.Second
	}
	start := time.Now()
	c, err := d.DialContext(ctx, "tcp", addr)
	took := time.Since(start)
	if err != nil {
		return took, err
	}
	_ = c.Close()
	return took, nil
}

func (SystemProber) UDPExchange(ctx context.Context, addr string, payload []byte, want int) ([]byte, time.Duration, error) {
	d := &net.Dialer{}
	if dl, ok := ctx.Deadline(); ok {
		d.Timeout = time.Until(dl)
	} else {
		d.Timeout = 5 * time.Second
	}
	network := "udp"
	if strings.HasPrefix(addr, "[") {
		network = "udp6"
	}
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, 0, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	}
	start := time.Now()
	if _, err := c.Write(payload); err != nil {
		return nil, 0, fmt.Errorf("sending: %w", err)
	}
	buf := make([]byte, want)
	n, err := c.Read(buf)
	took := time.Since(start)
	if err != nil {
		return nil, took, err
	}
	return buf[:n], took, nil
}

func (SystemProber) LookupIP(ctx context.Context, name string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, name)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	if len(out) == 0 {
		return nil, errors.New("the resolver returned no addresses")
	}
	return out, nil
}

func (SystemProber) LookupAtServer(ctx context.Context, name, server string) ([]net.IP, error) {
	host := server
	// A bare address means the default DNS port; anything else is taken as host[:port].
	if !strings.Contains(host, ":") || net.ParseIP(host) != nil {
		host = net.JoinHostPort(host, "53")
	} else if h, p, err := net.SplitHostPort(host); err == nil {
		host = net.JoinHostPort(h, p)
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{}
			if dl, ok := ctx.Deadline(); ok {
				d.Timeout = time.Until(dl)
			}
			return d.DialContext(ctx, "udp", host)
		},
	}
	addrs, err := r.LookupIPAddr(ctx, name)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	if len(out) == 0 {
		return nil, errors.New("the server returned no addresses")
	}
	return out, nil
}

func (SystemProber) PortFree(ctx context.Context, addr string) (bool, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		// A bind failure is the finding, not a transport error.
		return false, nil
	}
	_ = ln.Close()
	return true, nil
}
