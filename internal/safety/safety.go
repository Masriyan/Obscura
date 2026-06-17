// Package safety provides target intake validation and an SSRF-guarded dialer.
//
// AEGIS fetches user-supplied targets and crawls discovered links; without
// guards it is an SSRF cannon. The guard works at the transport layer (the
// dialer Control hook), so it re-validates the resolved IP on every dial —
// including every redirect hop — which defeats DNS-rebinding and redirect-based
// bypasses. Default is deny; an explicit opt-in (AllowInternal) permits
// internal targets for authorized engagements.
package safety

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
)

// ErrBlockedTarget is returned when a connection to a disallowed IP is refused.
var ErrBlockedTarget = errors.New("connection to internal/reserved IP blocked (use --allow-internal to override)")

// TargetKind classifies a normalized scan target.
type TargetKind string

const (
	KindDomain TargetKind = "domain"
	KindIP     TargetKind = "ip"
	KindURL    TargetKind = "url"
	KindEmail  TargetKind = "email"
)

// Target is a validated, normalized scan target.
type Target struct {
	Raw    string     // original user input
	Kind   TargetKind // domain | ip | url | email
	Host   string     // hostname or IP (no scheme/port)
	URL    string     // canonical http(s) URL form, when applicable
	Scheme string     // http | https (for URL/domain targets)
}

// blockedCIDRs enumerates the ranges refused by default (§16).
var blockedCIDRs = func() []*net.IPNet {
	cidrs := []string{
		// loopback
		"127.0.0.0/8", "::1/128",
		// link-local (incl. cloud metadata 169.254.169.254)
		"169.254.0.0/16", "fe80::/10",
		// private
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
		// unspecified / reserved / special-use
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"240.0.0.0/4", "::/128",
	}
	var nets []*net.IPNet
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// IsBlockedIP reports whether ip falls in a denied range or is otherwise not a
// safe public destination (multicast, unspecified, loopback, link-local).
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, n := range blockedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateTarget validates and normalizes raw user input into a Target.
// It rejects malformed input before any module runs.
func ValidateTarget(raw string) (Target, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Target{}, errors.New("empty target")
	}

	// Email target.
	if strings.Contains(s, "@") && !strings.Contains(s, "/") {
		at := strings.LastIndex(s, "@")
		domain := s[at+1:]
		if !isValidHostname(domain) {
			return Target{}, fmt.Errorf("invalid email domain: %q", domain)
		}
		return Target{Raw: raw, Kind: KindEmail, Host: strings.ToLower(domain)}, nil
	}

	// URL target (has a scheme).
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return Target{}, fmt.Errorf("invalid URL: %w", err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return Target{}, fmt.Errorf("unsupported scheme: %q", u.Scheme)
		}
		host := u.Hostname()
		if host == "" {
			return Target{}, errors.New("URL has no host")
		}
		t := Target{Raw: raw, Kind: KindURL, Host: strings.ToLower(host), Scheme: u.Scheme, URL: u.String()}
		if net.ParseIP(host) == nil && !isValidHostname(host) {
			return Target{}, fmt.Errorf("invalid URL host: %q", host)
		}
		return t, nil
	}

	// Bare IP.
	if ip := net.ParseIP(s); ip != nil {
		return Target{Raw: raw, Kind: KindIP, Host: s, Scheme: "https", URL: "https://" + s}, nil
	}

	// Bare domain (optionally host:port).
	host := s
	if h, _, err := net.SplitHostPort(s); err == nil {
		host = h
	}
	if !isValidHostname(host) {
		return Target{}, fmt.Errorf("invalid target: %q", raw)
	}
	host = strings.ToLower(host)
	return Target{Raw: raw, Kind: KindDomain, Host: host, Scheme: "https", URL: "https://" + host}, nil
}

// isValidHostname performs a conservative RFC-1123-ish hostname check.
func isValidHostname(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-'
			if !ok {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// NewDialer returns a *net.Dialer whose Control hook refuses connections to
// blocked IPs at CONNECT time. When allowInternal is true the guard is disabled.
func NewDialer(allowInternal bool) *net.Dialer {
	d := &net.Dialer{}
	if !allowInternal {
		d.Control = guardControl
	}
	return d
}

// guardControl is the net.Dialer.Control callback: address is the resolved
// "ip:port" the stack is about to connect to, so checking it here covers every
// hop (DNS rebinding / redirects re-dial and re-validate).
func guardControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if IsBlockedIP(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedTarget, host)
	}
	return nil
}

// CheckHostPort resolves host and verifies no resolved IP is blocked. It is a
// pre-dial convenience for callers that want to reject early (the dialer still
// enforces at connect time regardless). allowInternal disables the check.
func CheckHostPort(ctx context.Context, host string, allowInternal bool) error {
	if allowInternal {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) {
			return fmt.Errorf("%w: %s", ErrBlockedTarget, host)
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", host, err)
	}
	for _, ip := range ips {
		if IsBlockedIP(ip) {
			return fmt.Errorf("%w: %s resolves to %s", ErrBlockedTarget, host, ip)
		}
	}
	return nil
}
