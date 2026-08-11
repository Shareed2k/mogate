package protocol_test

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/shareed2k/mogate/internal/protocol"
)

// FuzzReadFrame feeds arbitrary bytes to ReadFrame and asserts it never panics.
// Any frame it accepts must survive a WriteFrame -> ReadFrame round trip.
func FuzzReadFrame(f *testing.F) {
	var valid bytes.Buffer
	if err := protocol.WriteFrame(&valid, protocol.Frame{Operation: protocol.OpTCPConnect, Flags: 1, Payload: []byte("example.com:80")}); err != nil {
		f.Fatalf("seed frame: %v", err)
	}
	f.Add(valid.Bytes())
	f.Add([]byte{})
	f.Add(make([]byte, protocol.HeaderSize))

	f.Fuzz(func(t *testing.T, data []byte) {
		frame, err := protocol.ReadFrame(bytes.NewReader(data))
		if err != nil {
			return
		}
		var round bytes.Buffer
		if err := protocol.WriteFrame(&round, frame); err != nil {
			t.Fatalf("re-encode accepted frame: %v", err)
		}
		got, err := protocol.ReadFrame(&round)
		if err != nil {
			t.Fatalf("re-read re-encoded frame: %v", err)
		}
		if got.Operation != frame.Operation || got.Flags != frame.Flags || !bytes.Equal(got.Payload, frame.Payload) {
			t.Fatalf("round-trip mismatch: got %+v, want %+v", got, frame)
		}
	})
}

// FuzzParseAddress feeds arbitrary bytes to the canonical address decoder and
// asserts it never panics and never reports consuming more than it was given.
func FuzzParseAddress(f *testing.F) {
	for _, input := range []string{"192.0.2.1:8080", "[2001:db8::1]:53"} {
		encoded, err := protocol.AppendAddress(nil, netip.MustParseAddrPort(input))
		if err != nil {
			f.Fatalf("seed address %q: %v", input, err)
		}
		f.Add(encoded)
	}
	f.Add([]byte{})
	f.Add([]byte{protocol.AddressFamilyIPv4})
	f.Add([]byte{protocol.AddressFamilyIPv6, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, consumed, err := protocol.ParseAddress(data)
		if err != nil {
			return
		}
		if consumed < 0 || consumed > len(data) {
			t.Fatalf("consumed %d out of range for %d bytes", consumed, len(data))
		}
	})
}

// FuzzParseDatagramMetadata feeds arbitrary bytes to the datagram metadata
// decoder and asserts it never panics on short or truncated payloads.
func FuzzParseDatagramMetadata(f *testing.F) {
	seed, err := protocol.AppendDatagramMetadata(nil, protocol.DatagramMetadata{
		Destination:  netip.MustParseAddr("2001:db8::42"),
		Interface:    7,
		HopLimit:     61,
		TrafficClass: 0x2e,
		TimestampNS:  1_725_000_000_123_456_789,
	})
	if err != nil {
		f.Fatalf("seed datagram metadata: %v", err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Add(make([]byte, protocol.DatagramMetadataSize))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, consumed, err := protocol.ParseDatagramMetadata(data)
		if err != nil {
			return
		}
		if consumed < 0 || consumed > len(data) {
			t.Fatalf("consumed %d out of range for %d bytes", consumed, len(data))
		}
	})
}

// FuzzParseStatus feeds arbitrary bytes to the status decoder and asserts it
// never panics on short payloads.
func FuzzParseStatus(f *testing.F) {
	f.Add(protocol.StatusPayload(0, []byte("ok")))
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, rest, err := protocol.ParseStatus(data)
		if err != nil {
			return
		}
		if len(rest) > len(data) {
			t.Fatalf("rest length %d exceeds input %d", len(rest), len(data))
		}
	})
}
