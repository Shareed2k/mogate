package sessiontransport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	messageHeaderSize = 16
	MaxMessageSize    = 1 << 20
)

type MessageType byte

const (
	MessageWatch    MessageType = 1
	MessageClaim    MessageType = 2
	MessageUDP      MessageType = 3
	MessageIncoming MessageType = 4
	MessageOK       MessageType = 5
	MessageError    MessageType = 6
	MessageDatagram MessageType = 7
	MessageEgress   MessageType = 8
)

type Message struct {
	Type     MessageType
	Flags    byte
	StreamID uint64
	Payload  []byte
}

func WriteMessage(writer io.Writer, message Message) error {
	if len(message.Payload) > MaxMessageSize {
		return errors.New("session transport message is too large")
	}
	var header [messageHeaderSize]byte
	header[0] = byte(message.Type)
	header[1] = message.Flags
	binary.BigEndian.PutUint64(header[4:12], message.StreamID)
	binary.BigEndian.PutUint32(header[12:16], uint32(len(message.Payload)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, message.Payload)
}

func ReadMessage(reader io.Reader) (Message, error) {
	var header [messageHeaderSize]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return Message{}, err
	}
	if header[2] != 0 || header[3] != 0 {
		return Message{}, errors.New("session transport reserved bits are non-zero")
	}
	size := binary.BigEndian.Uint32(header[12:16])
	if size > MaxMessageSize {
		return Message{}, fmt.Errorf("session transport message is too large: %d", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return Message{}, err
	}
	return Message{
		Type:     MessageType(header[0]),
		Flags:    header[1],
		StreamID: binary.BigEndian.Uint64(header[4:12]),
		Payload:  payload,
	}, nil
}

func ExpectOK(reader io.Reader) error {
	message, err := ReadMessage(reader)
	if err != nil {
		return err
	}
	if message.Type == MessageOK {
		return nil
	}
	if message.Type == MessageError {
		return fmt.Errorf("session transport rejected request: %s", message.Payload)
	}
	return fmt.Errorf("unexpected session transport response %d", message.Type)
}
