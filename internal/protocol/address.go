package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

var ErrBadAddress = errors.New("invalid canonical address")

func AppendAddress(payload []byte, address netip.AddrPort) ([]byte, error) {
	address = netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
	if !address.IsValid() {
		return nil, ErrBadAddress
	}
	if address.Addr().Is4() {
		start := len(payload)
		payload = append(payload, make([]byte, AddressIPv4Size)...)
		payload[start] = AddressFamilyIPv4
		binary.BigEndian.PutUint16(payload[start+2:start+4], address.Port())
		ipv4 := address.Addr().As4()
		copy(payload[start+AddressHeaderSize:], ipv4[:])
		return payload, nil
	}
	start := len(payload)
	payload = append(payload, make([]byte, AddressIPv6Size)...)
	payload[start] = AddressFamilyIPv6
	binary.BigEndian.PutUint16(payload[start+2:start+4], address.Port())
	ipv6 := address.Addr().As16()
	copy(payload[start+AddressHeaderSize:], ipv6[:])
	return payload, nil
}

func ParseAddress(payload []byte) (netip.AddrPort, int, error) {
	if len(payload) < AddressHeaderSize {
		return netip.AddrPort{}, 0, ErrBadAddress
	}
	port := binary.BigEndian.Uint16(payload[2:4])
	switch payload[0] {
	case AddressFamilyIPv4:
		if len(payload) < AddressIPv4Size {
			return netip.AddrPort{}, 0, ErrBadAddress
		}
		var raw [4]byte
		copy(raw[:], payload[AddressHeaderSize:AddressIPv4Size])
		return netip.AddrPortFrom(netip.AddrFrom4(raw), port), AddressIPv4Size, nil
	case AddressFamilyIPv6:
		if len(payload) < AddressIPv6Size {
			return netip.AddrPort{}, 0, ErrBadAddress
		}
		var raw [16]byte
		copy(raw[:], payload[AddressHeaderSize:AddressIPv6Size])
		address := netip.AddrFrom16(raw)
		scope := binary.BigEndian.Uint32(payload[4:8])
		if scope != 0 {
			return netip.AddrPort{}, 0, fmt.Errorf("%w: IPv6 scope %d is not supported", ErrBadAddress, scope)
		}
		return netip.AddrPortFrom(address, port), AddressIPv6Size, nil
	default:
		return netip.AddrPort{}, 0, ErrBadAddress
	}
}
