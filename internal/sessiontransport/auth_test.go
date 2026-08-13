package sessiontransport

import (
	"bufio"
	"errors"
	"net"
	"testing"
)

const token = "0123456789abcdef-session"

func TestBinaryHandshake(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	serverResult := make(chan error, 1)
	go func() {
		binary, acceptErr := Accept(server, bufio.NewReader(server), token, KindEgress)
		if acceptErr == nil && !binary {
			acceptErr = errors.New("binary handshake detected as legacy")
		}
		serverResult <- acceptErr
	}()
	if err := clientHandshake(client, token, KindEgress); err != nil {
		t.Fatal(err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestAcceptLeavesLegacyInputBuffered(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	go func() { _, _ = client.Write([]byte("EGRESS " + token + "\n")) }()
	reader := bufio.NewReader(server)
	binary, err := Accept(server, reader, token, KindEgress)
	if err != nil || binary {
		t.Fatalf("binary=%v err=%v", binary, err)
	}
	line, err := reader.ReadString('\n')
	if err != nil || line != "EGRESS "+token+"\n" {
		t.Fatalf("legacy input=%q err=%v", line, err)
	}
}
