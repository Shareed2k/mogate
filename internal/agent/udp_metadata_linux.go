//go:build linux

package agent

import (
	"encoding/binary"
	"net"
	"net/netip"
	"time"
	"unsafe"

	"github.com/shareed2k/mogate/internal/protocol"
	"golang.org/x/sys/unix"
)

func configureUDPMetadata(packet *net.UDPConn) {
	raw, err := packet.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		for _, option := range []struct{ level, name int }{
			{unix.IPPROTO_IP, unix.IP_PKTINFO},
			{unix.IPPROTO_IP, unix.IP_RECVTTL},
			{unix.IPPROTO_IP, unix.IP_RECVTOS},
			{unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO},
			{unix.IPPROTO_IPV6, unix.IPV6_RECVHOPLIMIT},
			{unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS},
			{unix.SOL_SOCKET, unix.SO_TIMESTAMPNS},
		} {
			_ = unix.SetsockoptInt(int(fd), option.level, option.name, 1)
		}
	})
}

func readUDPMetadata(packet *net.UDPConn, buffer []byte) (int, netip.AddrPort, protocol.DatagramMetadata, error) {
	oob := make([]byte, 256)
	count, oobCount, _, source, err := packet.ReadMsgUDPAddrPort(buffer, oob)
	if err != nil {
		return 0, netip.AddrPort{}, protocol.DatagramMetadata{}, err
	}
	metadata := protocol.DatagramMetadata{TimestampNS: time.Now().UnixNano()}
	messages, _ := unix.ParseSocketControlMessage(oob[:oobCount])
	for index := range messages {
		message := &messages[index]
		switch {
		case message.Header.Level == unix.IPPROTO_IP && message.Header.Type == unix.IP_PKTINFO && len(message.Data) >= unix.SizeofInet4Pktinfo:
			info := *(*unix.Inet4Pktinfo)(unsafe.Pointer(&message.Data[0]))
			metadata.Destination = netip.AddrFrom4(info.Addr)
			metadata.Interface = uint32(info.Ifindex)
		case message.Header.Level == unix.IPPROTO_IPV6 && message.Header.Type == unix.IPV6_PKTINFO && len(message.Data) >= unix.SizeofInet6Pktinfo:
			info := *(*unix.Inet6Pktinfo)(unsafe.Pointer(&message.Data[0]))
			metadata.Destination = netip.AddrFrom16(info.Addr)
			metadata.Interface = info.Ifindex
		case message.Header.Level == unix.IPPROTO_IP && message.Header.Type == unix.IP_TTL && len(message.Data) >= 4:
			metadata.HopLimit = int32(binary.NativeEndian.Uint32(message.Data))
		case message.Header.Level == unix.IPPROTO_IPV6 && message.Header.Type == unix.IPV6_HOPLIMIT && len(message.Data) >= 4:
			metadata.HopLimit = int32(binary.NativeEndian.Uint32(message.Data))
		case message.Header.Level == unix.IPPROTO_IP && message.Header.Type == unix.IP_TOS && len(message.Data) >= 1:
			metadata.TrafficClass = int32(message.Data[0])
		case message.Header.Level == unix.IPPROTO_IPV6 && message.Header.Type == unix.IPV6_TCLASS && len(message.Data) >= 4:
			metadata.TrafficClass = int32(binary.NativeEndian.Uint32(message.Data))
		case message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_TIMESTAMPNS && len(message.Data) >= int(unsafe.Sizeof(unix.Timespec{})):
			timestamp := *(*unix.Timespec)(unsafe.Pointer(&message.Data[0]))
			metadata.TimestampNS = timestamp.Nano()
		}
	}
	return count, source, metadata, nil
}

func writeUDPMetadata(packet *net.UDPConn, payload []byte, destination netip.AddrPort, metadata protocol.DatagramMetadata) error {
	var oob []byte
	if metadata.Destination.Is4() {
		info := unix.Inet4Pktinfo{Ifindex: int32(metadata.Interface), Spec_dst: metadata.Destination.As4()}
		oob = append(oob, unix.PktInfo4(&info)...)
	} else if metadata.Destination.Is6() {
		info := unix.Inet6Pktinfo{Ifindex: metadata.Interface, Addr: metadata.Destination.As16()}
		oob = append(oob, unix.PktInfo6(&info)...)
	}
	if metadata.HopLimit != 0 {
		level, kind := unix.IPPROTO_IP, unix.IP_TTL
		if destination.Addr().Is6() {
			level, kind = unix.IPPROTO_IPV6, unix.IPV6_HOPLIMIT
		}
		oob = append(oob, integerControlMessage(level, kind, metadata.HopLimit)...)
	}
	if metadata.TrafficClass != 0 {
		level, kind := unix.IPPROTO_IP, unix.IP_TOS
		if destination.Addr().Is6() {
			level, kind = unix.IPPROTO_IPV6, unix.IPV6_TCLASS
		}
		oob = append(oob, integerControlMessage(level, kind, metadata.TrafficClass)...)
	}
	if !destination.IsValid() {
		_, _, err := packet.WriteMsgUDP(payload, oob, nil)
		return err
	}
	_, _, err := packet.WriteMsgUDPAddrPort(payload, oob, destination)
	return err
}

func integerControlMessage(level, kind int, value int32) []byte {
	result := make([]byte, unix.CmsgSpace(4))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&result[0]))
	header.Level = int32(level)
	header.Type = int32(kind)
	header.SetLen(unix.CmsgLen(4))
	binary.NativeEndian.PutUint32(result[unix.CmsgLen(0):], uint32(value))
	return result
}
