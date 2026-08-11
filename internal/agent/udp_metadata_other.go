//go:build !linux

package agent

import (
	"net"
	"net/netip"
	"time"

	"github.com/shareed2k/mogate/internal/protocol"
)

func configureUDPMetadata(*net.UDPConn) {}

func readUDPMetadata(packet *net.UDPConn, buffer []byte) (int, netip.AddrPort, protocol.DatagramMetadata, error) {
	count, source, err := packet.ReadFromUDPAddrPort(buffer)
	return count, source, protocol.DatagramMetadata{TimestampNS: time.Now().UnixNano()}, err
}

func writeUDPMetadata(packet *net.UDPConn, payload []byte, destination netip.AddrPort, _ protocol.DatagramMetadata) error {
	if !destination.IsValid() {
		_, err := packet.Write(payload)
		return err
	}
	_, err := packet.WriteToUDPAddrPort(payload, destination)
	return err
}
