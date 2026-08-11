package egress_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/shareed2k/mogate/internal/agent"
	"github.com/shareed2k/mogate/internal/egress"
	"github.com/shareed2k/mogate/internal/protocol"
)

const testToken = "0123456789abcdef-egress-token"

func TestRelayRoutesProtocolToRemoteAgent(t *testing.T) {
	t.Parallel()

	targetAddr := startTCPEcho(t)
	remoteAddr := freeTCPAddress(t)
	socketPath := shortSocketPath(t)
	handler, err := agent.NewHandler(agent.Config{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	server, err := egress.NewServer(egress.ServerConfig{
		ListenAddr: remoteAddr,
		Token:      testToken,
	}, handler)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	relay, err := egress.NewRelay(egress.RelayConfig{
		SocketPath: socketPath,
		RemoteAddr: remoteAddr,
		Token:      testToken,
	})
	if err != nil {
		t.Fatalf("NewRelay: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Serve(ctx) }()
	waitForTCP(t, remoteAddr)
	relayResult := make(chan error, 1)
	go func() { relayResult <- relay.Serve(ctx) }()
	waitForUnix(t, socketPath)

	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer conn.Close()
	if err := protocol.WriteFrame(conn, protocol.Frame{
		Operation: protocol.OpTCPConnect,
		Payload:   []byte(targetAddr),
	}); err != nil {
		t.Fatalf("write connect frame: %v", err)
	}
	response, err := protocol.ReadFrame(conn)
	if err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	if response.Operation != protocol.OpTCPConnect || len(response.Payload) < 4 || binary.BigEndian.Uint32(response.Payload[:4]) != 0 {
		t.Fatalf("connect response=%+v, want success", response)
	}
	if _, err := io.WriteString(conn, "through-cluster-agent"); err != nil {
		t.Fatalf("write tunneled data: %v", err)
	}
	buffer := make([]byte, len("through-cluster-agent"))
	if _, err := io.ReadFull(conn, buffer); err != nil {
		t.Fatalf("read tunneled data: %v", err)
	}
	if string(buffer) != "through-cluster-agent" {
		t.Fatalf("echo=%q", buffer)
	}

	_ = conn.Close()
	dnsConn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		t.Fatalf("dial relay for dns: %v", err)
	}
	if err := protocol.WriteFrame(dnsConn, protocol.Frame{
		Operation: protocol.OpDNSLookup,
		Payload:   []byte("localhost"),
	}); err != nil {
		t.Fatalf("write dns frame: %v", err)
	}
	dnsResponse, err := protocol.ReadFrame(dnsConn)
	if err != nil {
		t.Fatalf("read dns response: %v", err)
	}
	_ = dnsConn.Close()
	if dnsResponse.Operation != protocol.OpDNSLookup || len(dnsResponse.Payload) <= 4 || binary.BigEndian.Uint32(dnsResponse.Payload[:4]) != 0 {
		t.Fatalf("dns response=%+v, want resolved addresses", dnsResponse)
	}

	cancel()
	assertStops(t, "server", serverResult)
	assertStops(t, "relay", relayResult)
}

// TestNewServer_RejectsWeakToken ensures the egress server and relay fail
// closed at construction when configured with an empty or too-short token,
// so an operator sees the error at startup instead of per accepted connection.
func TestNewServer_RejectsWeakToken(t *testing.T) {
	t.Parallel()

	handler, err := agent.NewHandler(agent.Config{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	weak := []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "short", token: "short"},
		{name: "fifteen characters", token: "0123456789abcde"},
	}
	for _, test := range weak {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := egress.NewServer(egress.ServerConfig{ListenAddr: "127.0.0.1:0", Token: test.token}, handler); err == nil {
				t.Fatalf("NewServer accepted weak token %q, want error", test.token)
			}
			if _, err := egress.NewRelay(egress.RelayConfig{SocketPath: "/tmp/mogate-weak.sock", RemoteAddr: "127.0.0.1:0", Token: test.token}); err == nil {
				t.Fatalf("NewRelay accepted weak token %q, want error", test.token)
			}
		})
	}
}

func shortSocketPath(t *testing.T) string {
	t.Helper()
	file, err := os.CreateTemp("/tmp", "mogate-egress-")
	if err != nil {
		t.Fatalf("create temporary socket path: %v", err)
	}
	path := file.Name()
	_ = file.Close()
	_ = os.Remove(path)
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

func startTCPEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	return listener.Addr().String()
}

func freeTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp address: %v", err)
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
			t.Fatalf("tcp listener not ready: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForUnix(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("unix", path, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("unix listener not ready: %v", err)
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
