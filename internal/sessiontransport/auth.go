package sessiontransport

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode"
)

const (
	Version           = 1
	maxTokenSize      = 256
	handshakeSize     = 8
	handshakeDeadline = 5 * time.Second
)

var (
	handshakeMagic  = [4]byte{'M', 'G', 'S', 'T'}
	okMagic         = [4]byte{'M', 'G', 'O', 'K'}
	errorMagic      = [4]byte{'M', 'G', 'E', 'R'}
	ErrUnauthorized = errors.New("session transport unauthorized")
	ErrVersion      = errors.New("unsupported session transport version")
	ErrKind         = errors.New("unexpected session transport kind")
)

type Kind byte

const (
	KindIncoming Kind = 1
	KindEgress   Kind = 2
)

func ValidateToken(token string) error {
	if len(token) < 16 || len(token) > maxTokenSize {
		return errors.New("token must contain 16 to 256 characters")
	}
	if strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return errors.New("token must not contain whitespace")
	}
	return nil
}

func SecureEqual(first, second string) bool {
	if len(first) != len(second) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(first), []byte(second)) == 1
}

func Dial(ctx context.Context, address, token string, kind Kind, timeout time.Duration) (net.Conn, error) {
	if err := ValidateToken(token); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if err := clientHandshake(conn, token, kind); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func clientHandshake(conn net.Conn, token string, kind Kind) error {
	_ = conn.SetDeadline(time.Now().Add(handshakeDeadline))
	defer conn.SetDeadline(time.Time{})
	var header [handshakeSize]byte
	copy(header[:4], handshakeMagic[:])
	header[4] = Version
	header[5] = byte(kind)
	binary.BigEndian.PutUint16(header[6:8], uint16(len(token)))
	if err := writeAll(conn, header[:]); err != nil {
		return err
	}
	if err := writeAll(conn, []byte(token)); err != nil {
		return err
	}
	var response [4]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	switch response {
	case okMagic:
		return nil
	case errorMagic:
		return ErrUnauthorized
	default:
		return errors.New("invalid session transport handshake response")
	}
}

// Accept authenticates a binary Session Transport connection. It returns
// binary=false without consuming input when the peer is a legacy text client.
func Accept(conn net.Conn, reader *bufio.Reader, token string, expected Kind) (binaryProtocol bool, err error) {
	if err := ValidateToken(token); err != nil {
		return false, err
	}
	prefix, err := reader.Peek(len(handshakeMagic))
	if err != nil {
		return false, err
	}
	if [4]byte(prefix) != handshakeMagic {
		return false, nil
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeDeadline))
	defer conn.SetDeadline(time.Time{})
	var header [handshakeSize]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return true, err
	}
	if header[4] != Version {
		_, _ = conn.Write(errorMagic[:])
		return true, fmt.Errorf("%w: %d", ErrVersion, header[4])
	}
	if Kind(header[5]) != expected {
		_, _ = conn.Write(errorMagic[:])
		return true, fmt.Errorf("%w: %d", ErrKind, header[5])
	}
	size := binary.BigEndian.Uint16(header[6:8])
	if size < 16 || size > maxTokenSize {
		_, _ = conn.Write(errorMagic[:])
		return true, ErrUnauthorized
	}
	presented := make([]byte, size)
	if _, err := io.ReadFull(reader, presented); err != nil {
		return true, err
	}
	if len(presented) != len(token) || subtle.ConstantTimeCompare(presented, []byte(token)) != 1 {
		_, _ = conn.Write(errorMagic[:])
		return true, ErrUnauthorized
	}
	if err := writeAll(conn, okMagic[:]); err != nil {
		return true, err
	}
	return true, nil
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		count, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		payload = payload[count:]
	}
	return nil
}
