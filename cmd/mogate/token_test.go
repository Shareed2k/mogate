package main

import (
	"os"
	"path/filepath"
	"testing"
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

func TestResolveSessionToken(t *testing.T) {
	t.Parallel()

	t.Run("file wins over flag", func(t *testing.T) {
		t.Parallel()
		path := writeTokenFile(t, validCLIToken)
		got, err := resolveSessionToken("0123456789abcdef-flag-token", path)
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
		got, err := resolveSessionToken("", path)
		if err != nil {
			t.Fatalf("resolveSessionToken: %v", err)
		}
		if got != validCLIToken {
			t.Fatalf("token=%q, want trimmed %q", got, validCLIToken)
		}
	})

	t.Run("missing file errors", func(t *testing.T) {
		t.Parallel()
		missing := filepath.Join(t.TempDir(), "absent")
		if _, err := resolveSessionToken(validCLIToken, missing); err == nil {
			t.Fatal("resolveSessionToken succeeded, want error for missing token file")
		}
	})

	t.Run("short file token errors", func(t *testing.T) {
		t.Parallel()
		path := writeTokenFile(t, "short\n")
		if _, err := resolveSessionToken("", path); err == nil {
			t.Fatal("resolveSessionToken succeeded, want error for short file token")
		}
	})

	t.Run("flag used when no file", func(t *testing.T) {
		t.Parallel()
		got, err := resolveSessionToken(validCLIToken, "")
		if err != nil {
			t.Fatalf("resolveSessionToken: %v", err)
		}
		if got != validCLIToken {
			t.Fatalf("token=%q, want flag token %q", got, validCLIToken)
		}
	})

	t.Run("short flag token errors", func(t *testing.T) {
		t.Parallel()
		if _, err := resolveSessionToken("short", ""); err == nil {
			t.Fatal("resolveSessionToken succeeded, want error for short flag token")
		}
	})
}
