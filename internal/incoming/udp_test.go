package incoming

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestIncomingUDP_Steal(t *testing.T) {
	t.Parallel()

	localAddr, localReceived := startUDPResponder(t, "local-response")
	capture, captureAddr, controlAddr := newUDPTestCapture(t, ModeSteal, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	captureResult := make(chan error, 1)
	go func() { captureResult <- capture.Serve(ctx) }()
	waitForTCP(t, controlAddr)
	forwardResult := make(chan error, 1)
	go func() {
		forwardResult <- ForwardUDP(ctx, ForwardConfig{
			ControlAddr: controlAddr,
			TargetAddr:  localAddr,
			Token:       testToken,
		})
	}()
	waitForUDPTunnel(t, capture)

	response := exchangeUDP(t, captureAddr, "steal-request")
	if response != "local-response" {
		t.Fatalf("response=%q, want local-response", response)
	}
	if got := <-localReceived; got != "steal-request" {
		t.Fatalf("local received %q", got)
	}

	cancel()
	assertStops(t, "capture", captureResult)
	assertStops(t, "udp forward", forwardResult)
}

func TestIncomingUDP_Mirror(t *testing.T) {
	t.Parallel()

	upstreamAddr, upstreamReceived := startUDPResponder(t, "upstream-response")
	localAddr, localReceived := startUDPResponder(t, "ignored-local-response")
	capture, captureAddr, controlAddr := newUDPTestCapture(t, ModeMirror, upstreamAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	captureResult := make(chan error, 1)
	go func() { captureResult <- capture.Serve(ctx) }()
	waitForTCP(t, controlAddr)
	forwardResult := make(chan error, 1)
	go func() {
		forwardResult <- ForwardUDP(ctx, ForwardConfig{
			ControlAddr: controlAddr,
			TargetAddr:  localAddr,
			Token:       testToken,
		})
	}()
	waitForUDPTunnel(t, capture)

	response := exchangeUDP(t, captureAddr, "mirror-request")
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
	assertStops(t, "udp forward", forwardResult)
}

func TestIncomingUDP_StealPassesThroughWithoutTunnel(t *testing.T) {
	t.Parallel()

	upstreamAddr, upstreamReceived := startUDPResponder(t, "upstream-response")
	capture, captureAddr, controlAddr := newUDPTestCapture(t, ModeSteal, upstreamAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	captureResult := make(chan error, 1)
	go func() { captureResult <- capture.Serve(ctx) }()
	waitForTCP(t, controlAddr)

	response := exchangeUDP(t, captureAddr, "passthrough-request")
	if response != "upstream-response" {
		t.Fatalf("response=%q, want upstream-response", response)
	}
	if got := <-upstreamReceived; got != "passthrough-request" {
		t.Fatalf("upstream received %q", got)
	}

	cancel()
	assertStops(t, "capture", captureResult)
}

func TestDatagramFrameRoundTrip(t *testing.T) {
	t.Parallel()

	first, second := net.Pipe()
	defer first.Close()
	defer second.Close()
	written := make(chan error, 1)
	go func() { written <- writeDatagramFrame(first, 42, []byte("payload")) }()
	id, payload, err := readDatagramFrame(second)
	if err != nil {
		t.Fatalf("readDatagramFrame: %v", err)
	}
	if err := <-written; err != nil {
		t.Fatalf("writeDatagramFrame: %v", err)
	}
	if id != 42 || string(payload) != "payload" {
		t.Fatalf("frame=(%d, %q), want (42, payload)", id, payload)
	}
}

func newUDPTestCapture(t *testing.T, mode Mode, upstream string) (*Capture, string, string) {
	t.Helper()
	captureAddr := freeAddress(t)
	controlAddr := freeAddress(t)
	capture, err := NewCapture(CaptureConfig{
		ListenAddr:     captureAddr,
		ControlAddr:    controlAddr,
		UpstreamAddr:   upstream,
		Token:          testToken,
		Mode:           mode,
		ClaimTimeout:   time.Second,
		EnableUDP:      true,
		UDPIdleTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewCapture: %v", err)
	}
	return capture, captureAddr, controlAddr
}

func startUDPResponder(t *testing.T, response string) (string, <-chan string) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen udp responder: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	received := make(chan string, 1)
	go func() {
		buffer := make([]byte, 128)
		count, client, readErr := conn.ReadFromUDP(buffer)
		if readErr != nil {
			return
		}
		received <- string(buffer[:count])
		_, _ = conn.WriteToUDP([]byte(response), client)
	}()
	return conn.LocalAddr().String(), received
}

func exchangeUDP(t *testing.T, address, request string) string {
	t.Helper()
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		t.Fatalf("resolve udp capture: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		t.Fatalf("dial udp capture: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("write udp request: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 128)
	count, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("read udp response: %v", err)
	}
	return string(buffer[:count])
}

func waitForUDPTunnel(t *testing.T, capture *Capture) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		capture.udpMu.Lock()
		ready := capture.udpTunnel != nil
		capture.udpMu.Unlock()
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("udp tunnel not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
