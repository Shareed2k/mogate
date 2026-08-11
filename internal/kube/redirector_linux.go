//go:build linux

package kube

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	preroutingPriority = -99
	outputPriority     = -101
)

type Redirector struct {
	config RedirectConfig
}

func NewRedirector(config RedirectConfig) (*Redirector, error) {
	if config.TableName == "" {
		config.TableName = DefaultTableName
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &Redirector{config: config}, nil
}

func (r *Redirector) Install() error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("open nftables netlink connection: %w", err)
	}
	existing, err := conn.ListTableOfFamily(r.config.TableName, nftables.TableFamilyINet)
	if err == nil {
		conn.DelTable(existing)
	}

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   r.config.TableName,
	})
	prerouting := conn.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(preroutingPriority),
	})
	output := conn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityRef(outputPriority),
	})

	// External traffic for the application is delivered to the agent.
	conn.AddRule(redirectRule(table, prerouting, unix.IPPROTO_TCP, r.config.AppPort, r.config.AgentPort, "capture inbound tcp"))
	// The agent uses the reserved proxy port to reach the real application. This
	// NAT decision happens before the capture rule and prevents a redirect loop.
	conn.AddRule(redirectRule(table, output, unix.IPPROTO_TCP, r.config.ProxyPort, r.config.AppPort, "pass through tcp to application"))
	if r.config.EnableUDP {
		conn.AddRule(redirectRule(table, output, unix.IPPROTO_UDP, r.config.ProxyPort, r.config.AppPort, "pass through udp to application"))
	}
	conn.AddRule(ownerBypassRule(table, output, r.config.AgentGID))
	// Capture loopback and pod-IP dials made by service-mesh proxies.
	conn.AddRule(loopbackRedirectRule(table, output, unix.IPPROTO_TCP, r.config.AppPort, r.config.AgentPort, "capture loopback tcp"))
	if r.config.PodIP != "" {
		conn.AddRule(podIPRedirectRule(table, output, unix.IPPROTO_TCP, r.config.AppPort, r.config.AgentPort, r.config.PodIP, "capture pod-ip tcp"))
	}
	if r.config.EnableUDP {
		conn.AddRule(redirectRule(table, prerouting, unix.IPPROTO_UDP, r.config.AppPort, r.config.AgentPort, "capture inbound udp"))
		conn.AddRule(loopbackRedirectRule(table, output, unix.IPPROTO_UDP, r.config.AppPort, r.config.AgentPort, "capture loopback udp"))
		if r.config.PodIP != "" {
			conn.AddRule(podIPRedirectRule(table, output, unix.IPPROTO_UDP, r.config.AppPort, r.config.AgentPort, r.config.PodIP, "capture pod-ip udp"))
		}
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("install nftables table %q: %w", r.config.TableName, err)
	}
	return nil
}

func podIPRedirectRule(table *nftables.Table, chain *nftables.Chain, protocol byte, fromPort, toPort uint16, podIP, comment string) *nftables.Rule {
	rule := redirectRule(table, chain, protocol, fromPort, toPort, comment)
	address := netip.MustParseAddr(podIP)
	networkProtocol := byte(unix.NFPROTO_IPV6)
	offset := uint32(24)
	addressBytes := address.As16()
	data := addressBytes[:]
	if address.Is4() {
		networkProtocol = byte(unix.NFPROTO_IPV4)
		offset = 16
		ipv4 := address.As4()
		data = ipv4[:]
	}
	rule.Exprs = append([]expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{networkProtocol}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(data))},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
	}, rule.Exprs...)
	return rule
}

func loopbackRedirectRule(table *nftables.Table, chain *nftables.Chain, protocol byte, fromPort, toPort uint16, comment string) *nftables.Rule {
	rule := redirectRule(table, chain, protocol, fromPort, toPort, comment)
	interfaceName := make([]byte, 16)
	copy(interfaceName, "lo\x00")
	rule.Exprs = append([]expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: interfaceName},
	}, rule.Exprs...)
	return rule
}

func ownerBypassRule(table *nftables.Table, chain *nftables.Chain, gid uint32) *nftables.Rule {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, gid)
	return &nftables.Rule{
		Table:    table,
		Chain:    chain,
		UserData: []byte("bypass agent egress\x00"),
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeySKGID, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	}
}

func (r *Redirector) Cleanup() error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("open nftables netlink connection: %w", err)
	}
	table, err := conn.ListTableOfFamily(r.config.TableName, nftables.TableFamilyINet)
	if err != nil {
		return nil
	}
	conn.DelTable(table)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("remove nftables table %q: %w", r.config.TableName, err)
	}
	return nil
}

func redirectRule(table *nftables.Table, chain *nftables.Chain, protocol byte, fromPort, toPort uint16, comment string) *nftables.Rule {
	return &nftables.Rule{
		Table:    table,
		Chain:    chain,
		UserData: append([]byte(comment), 0),
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: portBytes(fromPort)},
			&expr.Immediate{Register: 1, Data: portBytes(toPort)},
			&expr.Redir{RegisterProtoMin: 1},
		},
	}
}

func portBytes(port uint16) []byte {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, port)
	return data
}
