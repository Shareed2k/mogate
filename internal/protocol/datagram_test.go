package protocol_test

import (
	"net/netip"
	"testing"

	"github.com/shareed2k/mogate/internal/protocol"
)

func TestDatagramMetadataRoundTrip(t *testing.T) {
	t.Parallel()
	want := protocol.DatagramMetadata{
		Destination:  netip.MustParseAddr("2001:db8::42"),
		Interface:    7,
		HopLimit:     61,
		TrafficClass: 0x2e,
		TimestampNS:  1_725_000_000_123_456_789,
	}
	payload, err := protocol.AppendDatagramMetadata(nil, want)
	if err != nil {
		t.Fatal(err)
	}
	got, consumed, err := protocol.ParseDatagramMetadata(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got != want || consumed != protocol.DatagramMetadataSize {
		t.Fatalf("got %+v/%d, want %+v/%d", got, consumed, want, protocol.DatagramMetadataSize)
	}
}
