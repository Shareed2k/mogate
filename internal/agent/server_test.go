package agent

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shareed2k/mogate/internal/protocol"
)

func TestServer_RemoteFileRead(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	const content = "read through the agent"
	if err := os.WriteFile(filepath.Join(root, "message.txt"), []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	socketDir, err := os.MkdirTemp("", "mga-")
	if err != nil {
		t.Fatalf("create socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "agent.sock")
	server, err := New(Config{SocketPath: socket, Root: root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-result:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Serve did not stop")
		}
	})

	conn := dialUnix(t, socket)
	defer conn.Close()
	openPayload := make([]byte, 8+len("/message.txt"))
	copy(openPayload[8:], "/message.txt")
	if err := protocol.WriteFrame(conn, protocol.Frame{Operation: protocol.OpFileOpen, Payload: openPayload}); err != nil {
		t.Fatalf("open request: %v", err)
	}
	assertOK(t, conn, protocol.OpFileOpen)

	readPayload := make([]byte, 4)
	binary.BigEndian.PutUint32(readPayload, 64)
	if err := protocol.WriteFrame(conn, protocol.Frame{Operation: protocol.OpFileRead, Payload: readPayload}); err != nil {
		t.Fatalf("read request: %v", err)
	}
	frame, err := protocol.ReadFrame(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	errno, data, err := protocol.ParseStatus(frame.Payload)
	if err != nil || errno != 0 {
		t.Fatalf("read status: errno=%d err=%v", errno, err)
	}
	if string(data) != content {
		t.Fatalf("got %q, want %q", data, content)
	}
}

func TestServer_UnconnectedUDPRoundTrip(t *testing.T) {
	t.Parallel()

	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP echo: %v", err)
	}
	defer echo.Close()
	go func() {
		buffer := make([]byte, 1024)
		count, source, readErr := echo.ReadFromUDPAddrPort(buffer)
		if readErr == nil {
			_, _ = echo.WriteToUDPAddrPort(append([]byte("echo:"), buffer[:count]...), source)
		}
	}()

	socketDir, err := os.MkdirTemp("", "mga-")
	if err != nil {
		t.Fatalf("create socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "agent.sock")
	server, err := New(Config{SocketPath: socket})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case serveErr := <-result:
			if serveErr != nil {
				t.Errorf("Serve: %v", serveErr)
			}
		case <-time.After(2 * time.Second):
			t.Error("Serve did not stop")
		}
	})

	conn := dialUnix(t, socket)
	defer conn.Close()
	if err := protocol.WriteFrame(conn, protocol.Frame{Operation: protocol.OpUDPOpen}); err != nil {
		t.Fatalf("UDP open request: %v", err)
	}
	assertOK(t, conn, protocol.OpUDPOpen)

	destination := echo.LocalAddr().(*net.UDPAddr).AddrPort()
	payload, err := protocol.AppendAddress(nil, netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port()))
	if err != nil {
		t.Fatalf("encode destination: %v", err)
	}
	payload = append(payload, "probe"...)
	if err := protocol.WriteFrame(conn, protocol.Frame{Operation: protocol.OpUDPSendTo, Payload: payload}); err != nil {
		t.Fatalf("UDP send request: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	frame, err := protocol.ReadFrame(conn)
	if err != nil {
		t.Fatalf("UDP receive response: %v", err)
	}
	if frame.Operation != protocol.OpUDPReceiveFrom {
		t.Fatalf("operation=%d, want %d", frame.Operation, protocol.OpUDPReceiveFrom)
	}
	source, consumed, err := protocol.ParseAddress(frame.Payload)
	if err != nil {
		t.Fatalf("decode source: %v", err)
	}
	if source != destination {
		t.Fatalf("source=%s, want %s", source, destination)
	}
	if got := string(frame.Payload[consumed:]); got != "echo:probe" {
		t.Fatalf("payload=%q, want %q", got, "echo:probe")
	}
}

func TestServer_ResolvePath(t *testing.T) {
	t.Parallel()

	server := &Server{config: Config{Root: "/sandbox"}}
	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{name: "absolute", path: "/etc/hosts", want: filepath.Join("etc", "hosts")},
		{name: "relative", path: "tmp/file", want: filepath.Join("tmp", "file")},
		{name: "empty", path: "", wantErr: true},
		{name: "nul byte", path: "bad\x00path", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := server.resolvePath(test.path)
			if (err != nil) != test.wantErr {
				t.Fatalf("resolvePath(%q): err=%v, wantErr=%v", test.path, err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("resolvePath(%q)=%q, want %q", test.path, got, test.want)
			}
		})
	}
}

func dialUnix(t *testing.T, socket string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.Dial("unix", socket)
		if err == nil {
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial agent: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertOK(t *testing.T, conn net.Conn, operation protocol.Operation) {
	t.Helper()
	frame, err := protocol.ReadFrame(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if frame.Operation != operation {
		t.Fatalf("operation=%d, want %d", frame.Operation, operation)
	}
	errno, _, err := protocol.ParseStatus(frame.Payload)
	if err != nil || errno != 0 {
		t.Fatalf("status: errno=%d err=%v", errno, err)
	}
}
