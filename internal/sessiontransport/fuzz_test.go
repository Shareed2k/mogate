package sessiontransport

import (
	"bytes"
	"testing"
)

// FuzzReadMessage feeds arbitrary bytes to ReadMessage and asserts it never
// panics. Any message it accepts must survive a WriteMessage -> ReadMessage
// round trip.
func FuzzReadMessage(f *testing.F) {
	var valid bytes.Buffer
	if err := WriteMessage(&valid, Message{Type: MessageIncoming, Flags: 3, StreamID: 42, Payload: []byte("payload")}); err != nil {
		f.Fatalf("seed message: %v", err)
	}
	f.Add(valid.Bytes())
	f.Add([]byte{})
	f.Add(make([]byte, messageHeaderSize))

	f.Fuzz(func(t *testing.T, data []byte) {
		message, err := ReadMessage(bytes.NewReader(data))
		if err != nil {
			return
		}
		var round bytes.Buffer
		if err := WriteMessage(&round, message); err != nil {
			t.Fatalf("re-encode accepted message: %v", err)
		}
		got, err := ReadMessage(&round)
		if err != nil {
			t.Fatalf("re-read re-encoded message: %v", err)
		}
		if got.Type != message.Type || got.Flags != message.Flags || got.StreamID != message.StreamID || !bytes.Equal(got.Payload, message.Payload) {
			t.Fatalf("round-trip mismatch: got %+v, want %+v", got, message)
		}
	})
}
