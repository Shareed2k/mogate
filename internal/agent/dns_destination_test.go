package agent

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestRewriteDNSDestination(t *testing.T) {
	t.Parallel()
	configPath := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(configPath, []byte("search local\nnameserver 10.96.0.10\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := newServer(Config{DNSConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := server.rewriteDNSAddrPort(netip.MustParseAddrPort("192.0.2.53:53")), netip.MustParseAddrPort("10.96.0.10:53"); got != want {
		t.Fatalf("DNS destination=%s, want %s", got, want)
	}
	unchanged := netip.MustParseAddrPort("192.0.2.53:5353")
	if got := server.rewriteDNSAddrPort(unchanged); got != unchanged {
		t.Fatalf("non-DNS destination=%s, want %s", got, unchanged)
	}
}
