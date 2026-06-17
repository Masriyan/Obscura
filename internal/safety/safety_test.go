package safety

import (
	"net"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.5.5.5", "::1",
		"169.254.169.254", // cloud metadata
		"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"0.0.0.0", "100.64.0.1", "240.0.0.1",
		"fc00::1", "fe80::1",
	}
	for _, s := range blocked {
		if ip := net.ParseIP(s); !IsBlockedIP(ip) {
			t.Errorf("IsBlockedIP(%s) = false, want true (must be refused)", s)
		}
	}

	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1::"}
	for _, s := range allowed {
		if ip := net.ParseIP(s); IsBlockedIP(ip) {
			t.Errorf("IsBlockedIP(%s) = true, want false (public should be allowed)", s)
		}
	}

	if !IsBlockedIP(nil) {
		t.Error("IsBlockedIP(nil) must be true (fail closed)")
	}
}

func TestGuardControlRefusesInternal(t *testing.T) {
	// guardControl is the dialer hook; address is the resolved ip:port.
	if err := guardControl("tcp", "169.254.169.254:80", nil); err == nil {
		t.Error("guardControl should refuse the cloud metadata IP")
	}
	if err := guardControl("tcp", "127.0.0.1:8080", nil); err == nil {
		t.Error("guardControl should refuse loopback")
	}
	if err := guardControl("tcp", "8.8.8.8:443", nil); err != nil {
		t.Errorf("guardControl should allow a public IP, got %v", err)
	}
}

func TestNewDialerAllowInternal(t *testing.T) {
	if d := NewDialer(false); d.Control == nil {
		t.Error("default dialer must install the SSRF Control guard")
	}
	if d := NewDialer(true); d.Control != nil {
		t.Error("--allow-internal dialer must NOT install the guard")
	}
}

func TestValidateTarget(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
		kind    TargetKind
		host    string
	}{
		{"example.com", false, KindDomain, "example.com"},
		{"https://sub.example.com/path", false, KindURL, "sub.example.com"},
		{"8.8.8.8", false, KindIP, "8.8.8.8"},
		{"user@example.com", false, KindEmail, "example.com"},
		{"EXAMPLE.COM", false, KindDomain, "example.com"},
		{"", true, "", ""},
		{"not a domain", true, "", ""},
		{"ftp://example.com", true, "", ""},
	}
	for _, c := range cases {
		got, err := ValidateTarget(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ValidateTarget(%q) expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ValidateTarget(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got.Kind != c.kind {
			t.Errorf("ValidateTarget(%q).Kind = %s, want %s", c.in, got.Kind, c.kind)
		}
		if got.Host != c.host {
			t.Errorf("ValidateTarget(%q).Host = %s, want %s", c.in, got.Host, c.host)
		}
	}
}
