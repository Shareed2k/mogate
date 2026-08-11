package protocol_test

import (
	"net/netip"
	"testing"

	"github.com/shareed2k/mogate/internal/protocol"
)

func TestCanonicalAddressRoundTrip(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"192.0.2.1:8080", "[2001:db8::1]:5353"} {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			want := netip.MustParseAddrPort(input)
			payload, err := protocol.AppendAddress(nil, want)
			if err != nil {
				t.Fatal(err)
			}
			got, consumed, err := protocol.ParseAddress(payload)
			if err != nil {
				t.Fatal(err)
			}
			if got != want || consumed != len(payload) {
				t.Fatalf("got %v/%d, want %v/%d", got, consumed, want, len(payload))
			}
		})
	}
}
