package session_test

import (
	"context"
	"errors"
	"testing"

	"github.com/shareed2k/mogate/internal/session"
)

func TestRunCancelsAndDrainsTasks(t *testing.T) {
	stopped := make(chan struct{})
	err := session.Run(context.Background(),
		session.Task{Name: "command", Run: func(context.Context) error { return nil }},
		session.Task{Name: "relay", Run: func(ctx context.Context) error {
			<-ctx.Done()
			close(stopped)
			return ctx.Err()
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	<-stopped
}

func TestRunNamesTaskError(t *testing.T) {
	want := errors.New("failed")
	err := session.Run(context.Background(), session.Task{Name: "relay", Run: func(context.Context) error { return want }})
	if !errors.Is(err, want) || err.Error() != "relay: failed" {
		t.Fatalf("got %v", err)
	}
}
