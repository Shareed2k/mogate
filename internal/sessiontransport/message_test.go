package sessiontransport

import (
	"bytes"
	"testing"
)

func TestMessageRoundTrip(t *testing.T) {
	want := Message{Type: MessageIncoming, Flags: 3, StreamID: 42, Payload: []byte("payload")}
	var buffer bytes.Buffer
	if err := WriteMessage(&buffer, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMessage(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.Flags != want.Flags || got.StreamID != want.StreamID || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
