package protocol

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// DatagramMetadata is the OS-independent subset of UDP ancillary data that
// can be represented consistently across Linux and macOS.
type DatagramMetadata struct {
	Destination  netip.Addr
	Interface    uint32
	HopLimit     int32
	TrafficClass int32
	TimestampNS  int64
}

func AppendDatagramMetadata(payload []byte, metadata DatagramMetadata) ([]byte, error) {
	start := len(payload)
	payload = append(payload, make([]byte, DatagramMetadataSize)...)
	var flags uint32
	if metadata.Destination.IsValid() {
		flags |= DatagramDestination
		encoded, err := AppendAddress(nil, netip.AddrPortFrom(metadata.Destination, 0))
		if err != nil {
			return nil, fmt.Errorf("encode datagram destination: %w", err)
		}
		copy(payload[start+24:], encoded)
	}
	if metadata.Interface != 0 {
		flags |= DatagramInterface
		binary.BigEndian.PutUint32(payload[start+4:start+8], metadata.Interface)
	}
	if metadata.HopLimit != 0 {
		flags |= DatagramHopLimit
		binary.BigEndian.PutUint32(payload[start+8:start+12], uint32(metadata.HopLimit))
	}
	if metadata.TrafficClass != 0 {
		flags |= DatagramTrafficClass
		binary.BigEndian.PutUint32(payload[start+12:start+16], uint32(metadata.TrafficClass))
	}
	if metadata.TimestampNS != 0 {
		flags |= DatagramTimestamp
		binary.BigEndian.PutUint64(payload[start+16:start+24], uint64(metadata.TimestampNS))
	}
	binary.BigEndian.PutUint32(payload[start:start+4], flags)
	return payload, nil
}

func ParseDatagramMetadata(payload []byte) (DatagramMetadata, int, error) {
	if len(payload) < DatagramMetadataSize {
		return DatagramMetadata{}, 0, fmt.Errorf("datagram metadata: %w", ErrBadAddress)
	}
	flags := binary.BigEndian.Uint32(payload[:4])
	metadata := DatagramMetadata{}
	if flags&DatagramDestination != 0 {
		destination, _, err := ParseAddress(payload[24:])
		if err != nil {
			return DatagramMetadata{}, 0, err
		}
		metadata.Destination = destination.Addr()
	}
	if flags&DatagramInterface != 0 {
		metadata.Interface = binary.BigEndian.Uint32(payload[4:8])
	}
	if flags&DatagramHopLimit != 0 {
		metadata.HopLimit = int32(binary.BigEndian.Uint32(payload[8:12]))
	}
	if flags&DatagramTrafficClass != 0 {
		metadata.TrafficClass = int32(binary.BigEndian.Uint32(payload[12:16]))
	}
	if flags&DatagramTimestamp != 0 {
		metadata.TimestampNS = int64(binary.BigEndian.Uint64(payload[16:24]))
	}
	return metadata, DatagramMetadataSize, nil
}
