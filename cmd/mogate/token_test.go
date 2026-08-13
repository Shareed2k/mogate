package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const validCLIToken = "0123456789abcdef-cli-token"

func writeTokenFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

// writeFileLater writes content to path after delay, atomically (temp + rename)
// so a concurrent reader never observes a partially written token. It mimics an
// orchestrator delivering the token a moment after the agent starts waiting.
func writeFileLater(t *testing.T, path, content string, delay time.Duration) {
	t.Helper()
	go func() {
		time.Sleep(delay)
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
			return
		}
		_ = os.Rename(tmp, path)
	}()
}

func TestResolveSessionToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("file wins over flag", func(t *testing.T) {
		t.Parallel()
		path := writeTokenFile(t, validCLIToken)
		got, err := resolveSessionToken(ctx, "0123456789abcdef-flag-token", path)
		if err != nil {
			t.Fatalf("resolveSessionToken: %v", err)
		}
		if got != validCLIToken {
			t.Fatalf("token=%q, want file token %q", got, validCLIToken)
		}
	})

	t.Run("trailing newline trimmed", func(t *testing.T) {
		t.Parallel()
		path := writeTokenFile(t, validCLIToken+"\n")
		got, err := resolveSessionToken(ctx, "", path)
		if err != nil {
			t.Fatalf("resolveSessionToken: %v", err)
		}
		if got != validCLIToken {
			t.Fatalf("token=%q, want trimmed %q", got, validCLIToken)
		}
	})

	t.Run("waits for a delayed token file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "token")
		writeFileLater(t, path, validCLIToken, 150*time.Millisecond)
		got, err := resolveSessionToken(ctx, "", path)
		if err != nil {
			t.Fatalf("resolveSessionToken: %v", err)
		}
		if got != validCLIToken {
			t.Fatalf("token=%q, want delayed file token %q", got, validCLIToken)
		}
	})

	t.Run("waits past an initially empty token file", func(t *testing.T) {
		t.Parallel()
		path := writeTokenFile(t, "") // exists but empty, like `cat >` before the write
		writeFileLater(t, path, validCLIToken, 150*time.Millisecond)
		got, err := resolveSessionToken(ctx, "", path)
		if err != nil {
			t.Fatalf("resolveSessionToken: %v", err)
		}
		if got != validCLIToken {
			t.Fatalf("token=%q, want filled file token %q", got, validCLIToken)
		}
	})

	t.Run("missing file times out", func(t *testing.T) {
		t.Parallel()
		missing := filepath.Join(t.TempDir(), "absent")
		// A short parent deadline bounds the wait so the test does not block for
		// the full tokenFileWaitTimeout; the effective wait is the shorter of the
		// two.
		tctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		if _, err := resolveSessionToken(tctx, validCLIToken, missing); err == nil {
			t.Fatal("resolveSessionToken succeeded, want timeout for missing token file")
		}
	})

	t.Run("short file token errors", func(t *testing.T) {
		t.Parallel()
		path := writeTokenFile(t, "short\n")
		if _, err := resolveSessionToken(ctx, "", path); err == nil {
			t.Fatal("resolveSessionToken succeeded, want error for short file token")
		}
	})

	t.Run("flag used when no file", func(t *testing.T) {
		t.Parallel()
		got, err := resolveSessionToken(ctx, validCLIToken, "")
		if err != nil {
			t.Fatalf("resolveSessionToken: %v", err)
		}
		if got != validCLIToken {
			t.Fatalf("token=%q, want flag token %q", got, validCLIToken)
		}
	})

	t.Run("short flag token errors", func(t *testing.T) {
		t.Parallel()
		if _, err := resolveSessionToken(ctx, "short", ""); err == nil {
			t.Fatal("resolveSessionToken succeeded, want error for short flag token")
		}
	})
}

// TestWaitReadTokenFile exercises the polling primitive directly: an immediate
// read when present, a bounded error when the file never appears, and an
// immediate non-timeout error on a non-ENOENT read failure.
func TestWaitReadTokenFile(t *testing.T) {
	t.Parallel()

	t.Run("returns immediately when present", func(t *testing.T) {
		t.Parallel()
		path := writeTokenFile(t, validCLIToken)
		start := time.Now()
		data, err := waitReadTokenFile(context.Background(), path, time.Minute)
		if err != nil {
			t.Fatalf("waitReadTokenFile: %v", err)
		}
		if string(data) != validCLIToken {
			t.Fatalf("data=%q, want %q", data, validCLIToken)
		}
		// The fast path reads before the first tick: an already-present file must
		// not cost a poll interval. Guards against a regression that polls first.
		if elapsed := time.Since(start); elapsed > 25*time.Millisecond {
			t.Fatalf("took %v for a present file, want an immediate read (< one 50ms tick)", elapsed)
		}
	})

	t.Run("times out when never present", func(t *testing.T) {
		t.Parallel()
		missing := filepath.Join(t.TempDir(), "absent")
		start := time.Now()
		if _, err := waitReadTokenFile(context.Background(), missing, 150*time.Millisecond); err == nil {
			t.Fatal("waitReadTokenFile succeeded, want timeout")
		}
		if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
			t.Fatalf("returned after %v, want at least the 150ms timeout", elapsed)
		}
	})

	t.Run("fails fast on a non-ENOENT read error", func(t *testing.T) {
		t.Parallel()
		// A directory at the path makes os.ReadFile fail with a non-ENOENT error,
		// which must return immediately rather than poll until timeout.
		dir := t.TempDir()
		start := time.Now()
		if _, err := waitReadTokenFile(context.Background(), dir, time.Minute); err == nil {
			t.Fatal("waitReadTokenFile succeeded on a directory, want error")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("took %v, want an immediate non-ENOENT error", elapsed)
		}
	})
}
