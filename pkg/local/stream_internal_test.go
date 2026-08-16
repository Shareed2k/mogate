package local

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// TestResolveStreams asserts the stream defaulting that keeps the CLI/default
// path byte-identical: a nil stream resolves to the matching os.Std* file, while
// a caller-supplied stream is passed through untouched.
func TestResolveStreams(t *testing.T) {
	customIn := strings.NewReader("in")
	customOut := &bytes.Buffer{}
	customErr := &bytes.Buffer{}

	tests := []struct {
		name       string
		options    injectionOptions
		wantStdin  io.Reader
		wantStdout io.Writer
		wantStderr io.Writer
	}{
		{
			name:       "all nil resolves to os.Std*",
			options:    injectionOptions{},
			wantStdin:  os.Stdin,
			wantStdout: os.Stdout,
			wantStderr: os.Stderr,
		},
		{
			name:       "custom streams pass through",
			options:    injectionOptions{stdin: customIn, stdout: customOut, stderr: customErr},
			wantStdin:  customIn,
			wantStdout: customOut,
			wantStderr: customErr,
		},
		{
			name:       "only stdout overridden, rest default",
			options:    injectionOptions{stdout: customOut},
			wantStdin:  os.Stdin,
			wantStdout: customOut,
			wantStderr: os.Stderr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdin, stdout, stderr := resolveStreams(tt.options)
			if stdin != tt.wantStdin {
				t.Errorf("stdin = %p, want %p", stdin, tt.wantStdin)
			}
			if stdout != tt.wantStdout {
				t.Errorf("stdout = %p, want %p", stdout, tt.wantStdout)
			}
			if stderr != tt.wantStderr {
				t.Errorf("stderr = %p, want %p", stderr, tt.wantStderr)
			}
		})
	}
}

// TestRunWithPty exercises the pty pump orchestration directly against a plain
// command (no injector, no SIP patching), so it runs on every platform. It
// covers output capture, exit-status propagation, and draining a window-size on
// ResizeCh without deadlock -- and asserts no goroutine outlives the child.
func TestRunWithPty(t *testing.T) {
	tests := []struct {
		name       string
		command    []string
		resize     chan Winsize
		wantOutput string
		wantExit   int // -1 when a clean (nil) exit is expected
	}{
		{
			name:       "captures output over the provided stdout",
			command:    []string{"sh", "-c", "echo hi"},
			wantOutput: "hi",
			wantExit:   -1,
		},
		{
			name:     "propagates a non-zero exit as an ExitError",
			command:  []string{"sh", "-c", "exit 3"},
			wantExit: 3,
		},
		{
			name:       "drains a resize without deadlock",
			command:    []string{"sh", "-c", "echo sized"},
			resize:     resizeChan(Winsize{Rows: 24, Cols: 80}),
			wantOutput: "sized",
			wantExit:   -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer goleak.VerifyNone(t)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var out bytes.Buffer
			cmd := exec.CommandContext(ctx, tt.command[0], tt.command[1:]...)
			var resize <-chan Winsize
			if tt.resize != nil {
				resize = tt.resize
			}

			err := runWithPty(ctx, cmd, bytes.NewReader(nil), &out, resize)

			switch {
			case tt.wantExit < 0:
				if err != nil {
					t.Fatalf("runWithPty returned %v, want nil", err)
				}
			default:
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Fatalf("runWithPty returned %v, want *exec.ExitError", err)
				}
				if exitErr.ExitCode() != tt.wantExit {
					t.Fatalf("exit code = %d, want %d", exitErr.ExitCode(), tt.wantExit)
				}
			}
			if tt.wantOutput != "" && !strings.Contains(out.String(), tt.wantOutput) {
				t.Fatalf("output = %q, want it to contain %q", out.String(), tt.wantOutput)
			}
		})
	}
}

// TestRunWithPty_CtxCancel asserts that cancelling ctx tears down a long-running
// child promptly and leaves no pump goroutine behind.
func TestRunWithPty_CtxCancel(t *testing.T) {
	defer goleak.VerifyNone(t)

	ctx, cancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(ctx, "sleep", "60")
	done := make(chan error, 1)
	go func() {
		done <- runWithPty(ctx, cmd, bytes.NewReader(nil), io.Discard, nil)
	}()

	// Give the child a moment to reach its pty before cancelling.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Returned; goleak asserts the pumps are gone.
	case <-time.After(10 * time.Second):
		t.Fatal("runWithPty did not return promptly after ctx cancel")
	}
}

// resizeChan returns a buffered channel preloaded with size, so a test can feed
// exactly one window size to the resize pump without blocking.
func resizeChan(size Winsize) chan Winsize {
	ch := make(chan Winsize, 1)
	ch <- size
	return ch
}
