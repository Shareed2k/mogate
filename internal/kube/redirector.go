package kube

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
)

const DefaultTableName = "mogate"

var tableNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type RedirectConfig struct {
	TableName string
	AppPort   uint16
	AgentPort uint16
	ProxyPort uint16
	EnableUDP bool
	AgentGID  uint32
	PodIP     string
}

func (c RedirectConfig) validate() error {
	if c.TableName == "" {
		return errors.New("table name is required")
	}
	if len(c.TableName) > 64 || !tableNamePattern.MatchString(c.TableName) {
		return fmt.Errorf("invalid nftables table name %q", c.TableName)
	}
	if c.AppPort == 0 || c.AgentPort == 0 || c.ProxyPort == 0 {
		return errors.New("application, agent, and proxy ports must be non-zero")
	}
	if c.AppPort == c.AgentPort || c.AppPort == c.ProxyPort || c.AgentPort == c.ProxyPort {
		return errors.New("application, agent, and proxy ports must be distinct")
	}
	if c.PodIP != "" {
		if _, err := netip.ParseAddr(c.PodIP); err != nil {
			return fmt.Errorf("invalid pod ip %q: %w", c.PodIP, err)
		}
	}
	return nil
}
