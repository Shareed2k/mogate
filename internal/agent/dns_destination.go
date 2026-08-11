package agent

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"strings"
)

func (s *Server) rewriteDNSAddress(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "53" {
		return address
	}
	parsedHost, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return address
	}
	destination := netip.AddrPortFrom(parsedHost, 53)
	rewritten := s.rewriteDNSAddrPort(destination)
	return rewritten.String()
}

func (s *Server) rewriteDNSAddrPort(destination netip.AddrPort) netip.AddrPort {
	if destination.Port() != 53 {
		return destination
	}
	s.dnsOnce.Do(func() {
		file, err := os.Open(s.config.DNSConfigPath)
		if err != nil {
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) == 2 && fields[0] == "nameserver" {
				if address, parseErr := netip.ParseAddr(fields[1]); parseErr == nil {
					s.dnsServer = address.Unmap()
					return
				}
			}
		}
	})
	if !s.dnsServer.IsValid() {
		return destination
	}
	return netip.AddrPortFrom(s.dnsServer, 53)
}
