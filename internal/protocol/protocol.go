package protocol

//go:generate go run ../cmd/protocolgen

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type Operation uint8

var (
	ErrBadMagic   = errors.New("invalid protocol magic")
	ErrBadVersion = errors.New("unsupported protocol version")
	ErrTooLarge   = errors.New("protocol payload too large")
)

type Frame struct {
	Operation Operation
	Flags     uint16
	Payload   []byte
}

func ReadFrame(r io.Reader) (Frame, error) {
	var header [HeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Frame{}, err
	}
	if [4]byte(header[:4]) != magic {
		return Frame{}, ErrBadMagic
	}
	if header[4] != Version {
		return Frame{}, fmt.Errorf("%w: %d", ErrBadVersion, header[4])
	}
	size := binary.BigEndian.Uint32(header[8:12])
	if size > MaxPayloadSize {
		return Frame{}, fmt.Errorf("%w: %d", ErrTooLarge, size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, err
	}
	return Frame{
		Operation: Operation(header[5]),
		Flags:     binary.BigEndian.Uint16(header[6:8]),
		Payload:   payload,
	}, nil
}

func WriteFrame(w io.Writer, frame Frame) error {
	if len(frame.Payload) > MaxPayloadSize {
		return fmt.Errorf("%w: %d", ErrTooLarge, len(frame.Payload))
	}
	var header [HeaderSize]byte
	copy(header[:4], magic[:])
	header[4] = Version
	header[5] = byte(frame.Operation)
	binary.BigEndian.PutUint16(header[6:8], frame.Flags)
	binary.BigEndian.PutUint32(header[8:12], uint32(len(frame.Payload)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, frame.Payload)
}

func StatusPayload(errno int32, data []byte) []byte {
	payload := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(payload[:4], uint32(errno))
	copy(payload[4:], data)
	return payload
}

func ParseStatus(payload []byte) (int32, []byte, error) {
	if len(payload) < 4 {
		return 0, nil, io.ErrUnexpectedEOF
	}
	return int32(binary.BigEndian.Uint32(payload[:4])), payload[4:], nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
