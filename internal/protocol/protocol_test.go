package protocol_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/shareed2k/mogate/internal/protocol"
)

func TestFrameRoundTrip(t *testing.T) {
	t.Parallel()

	want := protocol.Frame{Operation: protocol.OpDNSLookup, Flags: 42, Payload: []byte("example.com")}
	var buffer bytes.Buffer
	if err := protocol.WriteFrame(&buffer, want); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := protocol.ReadFrame(&buffer)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Operation != want.Operation || got.Flags != want.Flags || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("frame mismatch: got %+v, want %+v", got, want)
	}
}

func TestReadFrameRejectsBadMagic(t *testing.T) {
	t.Parallel()

	data := make([]byte, protocol.HeaderSize)
	_, err := protocol.ReadFrame(bytes.NewReader(data))
	if !errors.Is(err, protocol.ErrBadMagic) {
		t.Fatalf("got %v, want ErrBadMagic", err)
	}
}
