package incoming

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

const testToken = "0123456789abcdef-test-token"

func TestIncoming_Steal(t *testing.T) {
	t.Parallel()

	localAddr, localReceived := startResponder(t, "local-response")
	capture, captureAddr, controlAddr := newTestCapture(t, ModeSteal, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	captureResult := make(chan error, 1)
	go func() { captureResult <- capture.Serve(ctx) }()
	waitForTCP(t, controlAddr)
	forwardResult := make(chan error, 1)
	go func() {
		forwardResult <- Forward(ctx, ForwardConfig{
			ControlAddr: controlAddr,
			TargetAddr:  localAddr,
			Token:       testToken,
		})
	}()
	waitForWatcher(t, capture)

	response := exchange(t, captureAddr, "steal-request")
	if response != "local-response" {
		t.Fatalf("response=%q, want local-response", response)
	}
	if got := <-localReceived; got != "steal-request" {
		t.Fatalf("local received %q", got)
	}

	cancel()
	assertStops(t, "capture", captureResult)
	assertStops(t, "forward", forwardResult)
}

func TestIncoming_Mirror(t *testing.T) {
	t.Parallel()

	upstreamAddr, upstreamReceived := startResponder(t, "upstream-response")
	localAddr, localReceived := startResponder(t, "ignored-local-response")
	capture, captureAddr, controlAddr := newTestCapture(t, ModeMirror, upstreamAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	captureResult := make(chan error, 1)
	go func() { captureResult <- capture.Serve(ctx) }()
	waitForTCP(t, controlAddr)
	forwardResult := make(chan error, 1)
	go func() {
		forwardResult <- Forward(ctx, ForwardConfig{
			ControlAddr: controlAddr,
			TargetAddr:  localAddr,
			Token:       testToken,
		})
	}()
	waitForWatcher(t, capture)

	response := exchange(t, captureAddr, "mirror-request")
	if response != "upstream-response" {
		t.Fatalf("response=%q, want upstream-response", response)
	}
	if got := <-upstreamReceived; got != "mirror-request" {
		t.Fatalf("upstream received %q", got)
	}
	if got := <-localReceived; got != "mirror-request" {
		t.Fatalf("local received %q", got)
	}

	cancel()
	assertStops(t, "capture", captureResult)
	assertStops(t, "forward", forwardResult)
}

func TestIncoming_StealPassesThroughWithoutWatcher(t *testing.T) {
	t.Parallel()

	upstreamAddr, upstreamReceived := startResponder(t, "upstream-response")
	capture, captureAddr, controlAddr := newTestCapture(t, ModeSteal, upstreamAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	captureResult := make(chan error, 1)
	go func() { captureResult <- capture.Serve(ctx) }()
	waitForTCP(t, controlAddr)

	response := exchange(t, captureAddr, "passthrough-request")
	if response != "upstream-response" {
		t.Fatalf("response=%q, want upstream-response", response)
	}
	if got := <-upstreamReceived; got != "passthrough-request" {
		t.Fatalf("upstream received %q", got)
	}

	cancel()
	assertStops(t, "capture", captureResult)
}

func TestIncoming_WatcherCanReconnectAfterDisconnect(t *testing.T) {
	capture, _, controlAddress := newTestCapture(t, ModeSteal, "127.0.0.1:1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- capture.Serve(ctx) }()
	waitForTCP(t, controlAddress)

	first, err := net.Dial("tcp", controlAddress)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(first, "WATCH %s\n", testToken); err != nil {
		t.Fatal(err)
	}
	if err := expectOK(bufio.NewReader(first)); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		second, dialErr := net.Dial("tcp", controlAddress)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		_, _ = fmt.Fprintf(second, "WATCH %s\n", testToken)
		line, readErr := bufio.NewReader(second).ReadString('\n')
		_ = second.Close()
		if readErr == nil && line == "OK\n" {
			cancel()
			assertStops(t, "capture", result)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("watcher did not become available after disconnect")
}

func TestNewCapture_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config CaptureConfig
	}{
		{name: "missing addresses", config: CaptureConfig{Mode: ModeSteal, Token: testToken}},
		{name: "short token", config: CaptureConfig{ListenAddr: ":1", ControlAddr: ":2", Mode: ModeSteal, Token: "short"}},
		{name: "mirror without upstream", config: CaptureConfig{ListenAddr: ":1", ControlAddr: ":2", Mode: ModeMirror, Token: testToken}},
		{name: "invalid mode", config: CaptureConfig{ListenAddr: ":1", ControlAddr: ":2", Mode: "invalid", Token: testToken}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewCapture(test.config); err == nil {
				t.Fatal("NewCapture succeeded, want error")
			}
		})
	}
}

func newTestCapture(t *testing.T, mode Mode, upstream string) (*Capture, string, string) {
	t.Helper()
	captureAddr := freeAddress(t)
	controlAddr := freeAddress(t)
	capture, err := NewCapture(CaptureConfig{
		ListenAddr:   captureAddr,
		ControlAddr:  controlAddr,
		UpstreamAddr: upstream,
		Token:        testToken,
		Mode:         mode,
		ClaimTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewCapture: %v", err)
	}
	return capture, captureAddr, controlAddr
}

func startResponder(t *testing.T, response string) (string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen responder: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	received := make(chan string, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buffer := make([]byte, 128)
		count, _ := conn.Read(buffer)
		received <- string(buffer[:count])
		_, _ = io.WriteString(conn, response)
	}()
	return listener.Addr().String(), received
}

func exchange(t *testing.T, address, request string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("dial capture: %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 128)
	count, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return string(buffer[:count])
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve address: %v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func waitForTCP(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("listener %s not ready: %v", address, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForWatcher(t *testing.T, capture *Capture) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		capture.mu.Lock()
		ready := capture.watcher != nil
		capture.mu.Unlock()
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("watcher not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertStops(t *testing.T, name string, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("%s stopped with error: %v", name, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not stop", name)
	}
}
