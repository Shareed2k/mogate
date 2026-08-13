package incoming

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/shareed2k/mogate/internal/sessiontransport"
)

const (
	datagramHeaderSize = 12
	maxDatagramSize    = 65507
)

type datagramTunnel struct {
	conn    net.Conn
	writeMu sync.Mutex
}

type remoteUDPSession struct {
	id       uint64
	client   *net.UDPAddr
	upstream *net.UDPConn
	lastSeen time.Time
}

func (c *Capture) serveUDP(ctx context.Context, capture *net.UDPConn) error {
	buffer := make([]byte, maxDatagramSize)
	for {
		count, client, err := capture.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read captured udp: %w", err)
		}
		payload := append([]byte(nil), buffer[:count]...)
		session := c.remoteUDPSession(ctx, capture, client)
		if session == nil {
			continue
		}
		if c.config.Mode == ModeMirror {
			c.writeUDPUpstream(session, payload)
			_ = c.writeUDPToLocal(session.id, payload)
			continue
		}
		if err := c.writeUDPToLocal(session.id, payload); err != nil {
			c.writeUDPUpstream(session, payload)
		}
	}
}

func (c *Capture) remoteUDPSession(ctx context.Context, capture *net.UDPConn, client *net.UDPAddr) *remoteUDPSession {
	now := time.Now()
	key := client.String()
	c.udpMu.Lock()
	if id, ok := c.udpByAddr[key]; ok {
		session := c.udpSessions[id]
		session.lastSeen = now
		if session.upstream != nil {
			_ = session.upstream.SetReadDeadline(now.Add(c.config.UDPIdleTimeout))
		}
		c.udpMu.Unlock()
		return session
	}
	c.pruneUDPSessionsLocked(now)
	if len(c.udpSessions) >= c.config.MaxConnections {
		c.udpMu.Unlock()
		return nil
	}
	id := c.nextID.Add(1)
	session := &remoteUDPSession{id: id, client: cloneUDPAddr(client), lastSeen: now}
	c.udpSessions[id] = session
	c.udpByAddr[key] = id
	c.udpMu.Unlock()

	if c.config.UpstreamAddr != "" {
		upstreamAddress, err := net.ResolveUDPAddr("udp", c.config.UpstreamAddr)
		if err == nil {
			upstream, dialErr := net.DialUDP("udp", nil, upstreamAddress)
			if dialErr == nil {
				c.udpMu.Lock()
				session.upstream = upstream
				c.udpMu.Unlock()
				go c.readUDPUpstream(ctx, capture, session)
			}
		}
	}
	return session
}

func (c *Capture) readUDPUpstream(ctx context.Context, capture *net.UDPConn, session *remoteUDPSession) {
	buffer := make([]byte, maxDatagramSize)
	for {
		_ = session.upstream.SetReadDeadline(time.Now().Add(c.config.UDPIdleTimeout))
		count, err := session.upstream.Read(buffer)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				c.udpMu.Lock()
				isIdle := time.Since(session.lastSeen) >= c.config.UDPIdleTimeout
				c.udpMu.Unlock()
				if !isIdle {
					continue
				}
			}
			c.removeRemoteUDPSession(session)
			return
		}
		if _, err := capture.WriteToUDP(buffer[:count], session.client); err != nil || ctx.Err() != nil {
			return
		}
	}
}

func (c *Capture) removeRemoteUDPSession(session *remoteUDPSession) {
	c.udpMu.Lock()
	defer c.udpMu.Unlock()
	if c.udpSessions[session.id] != session {
		return
	}
	delete(c.udpSessions, session.id)
	delete(c.udpByAddr, session.client.String())
	if session.upstream != nil {
		_ = session.upstream.Close()
	}
}

func (c *Capture) writeUDPUpstream(session *remoteUDPSession, payload []byte) {
	c.udpMu.Lock()
	upstream := session.upstream
	c.udpMu.Unlock()
	if upstream != nil {
		_, _ = upstream.Write(payload)
	}
}

func (c *Capture) installUDPTunnel(ctx context.Context, conn net.Conn, binaryProtocol bool) {
	tunnel := &datagramTunnel{conn: conn}
	c.udpMu.Lock()
	if c.udpTunnel != nil {
		c.udpMu.Unlock()
		if binaryProtocol {
			_ = sessiontransport.WriteMessage(conn, sessiontransport.Message{Type: sessiontransport.MessageError, Payload: []byte("udp-watcher-active")})
		} else {
			_, _ = io.WriteString(conn, "ERR udp-watcher-active\n")
		}
		return
	}
	c.udpTunnel = tunnel
	c.udpMu.Unlock()
	defer func() {
		c.udpMu.Lock()
		if c.udpTunnel == tunnel {
			c.udpTunnel = nil
		}
		c.udpMu.Unlock()
	}()
	if err := writeControlOK(conn, binaryProtocol); err != nil {
		return
	}
	for {
		id, payload, err := readDatagramFrame(conn)
		if err != nil {
			return
		}
		if c.config.Mode == ModeMirror {
			continue
		}
		c.udpMu.Lock()
		session := c.udpSessions[id]
		c.udpMu.Unlock()
		if session == nil {
			continue
		}
		c.udpMu.Lock()
		udpConn := c.udpCapture
		c.udpMu.Unlock()
		if udpConn == nil {
			return
		}
		if _, err := udpConn.WriteToUDP(payload, session.client); err != nil || ctx.Err() != nil {
			return
		}
	}
}

func (c *Capture) writeUDPToLocal(id uint64, payload []byte) error {
	c.udpMu.Lock()
	tunnel := c.udpTunnel
	c.udpMu.Unlock()
	if tunnel == nil {
		return errors.New("udp tunnel is not connected")
	}
	tunnel.writeMu.Lock()
	defer tunnel.writeMu.Unlock()
	if err := writeDatagramFrame(tunnel.conn, id, payload); err != nil {
		_ = tunnel.conn.Close()
		return err
	}
	return nil
}

func (c *Capture) pruneUDPSessionsLocked(now time.Time) {
	for id, session := range c.udpSessions {
		if now.Sub(session.lastSeen) < c.config.UDPIdleTimeout {
			continue
		}
		delete(c.udpSessions, id)
		delete(c.udpByAddr, session.client.String())
		if session.upstream != nil {
			_ = session.upstream.Close()
		}
	}
}

func (c *Capture) closeUDPSessions() {
	c.udpMu.Lock()
	defer c.udpMu.Unlock()
	c.udpCapture = nil
	if c.udpTunnel != nil {
		_ = c.udpTunnel.conn.Close()
		c.udpTunnel = nil
	}
	for _, session := range c.udpSessions {
		if session.upstream != nil {
			_ = session.upstream.Close()
		}
	}
	c.udpSessions = make(map[uint64]*remoteUDPSession)
	c.udpByAddr = make(map[string]uint64)
}

func forwardUDP(ctx context.Context, config ForwardConfig) error {
	if config.ControlAddr == "" || config.TargetAddr == "" {
		return errors.New("control and target addresses are required")
	}
	if err := sessiontransport.ValidateToken(config.Token); err != nil {
		return err
	}
	if config.DialTimeout <= 0 {
		config.DialTimeout = 5 * time.Second
	}
	if config.MaxConnections <= 0 {
		config.MaxConnections = 256
	}
	if config.UDPIdleTimeout <= 0 {
		config.UDPIdleTimeout = time.Minute
	}
	tunnelConn, err := sessiontransport.Dial(ctx, config.ControlAddr, config.Token, sessiontransport.KindIncoming, config.DialTimeout)
	if err != nil {
		return fmt.Errorf("dial udp control: %w", err)
	}
	defer func() { _ = tunnelConn.Close() }()
	if err := sessiontransport.WriteMessage(tunnelConn, sessiontransport.Message{Type: sessiontransport.MessageUDP}); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(tunnelConn, 4096)
	if err := sessiontransport.ExpectOK(reader); err != nil {
		return err
	}
	tunnel := &datagramTunnel{conn: tunnelConn}
	tunnelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-tunnelCtx.Done()
		_ = tunnelConn.Close()
	}()

	target, err := net.ResolveUDPAddr("udp", config.TargetAddr)
	if err != nil {
		return fmt.Errorf("resolve local udp target: %w", err)
	}
	sessions := make(map[uint64]*net.UDPConn)
	var sessionsMu sync.Mutex
	defer func() {
		sessionsMu.Lock()
		defer sessionsMu.Unlock()
		for _, session := range sessions {
			_ = session.Close()
		}
	}()

	for {
		id, payload, err := readDatagramFrame(reader)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read udp tunnel: %w", err)
		}
		sessionsMu.Lock()
		session := sessions[id]
		if session == nil && len(sessions) < config.MaxConnections {
			session, err = net.DialUDP("udp", nil, target)
			if err == nil {
				sessions[id] = session
				go relayLocalUDP(tunnelCtx, tunnel, id, session, config.UDPIdleTimeout, &sessionsMu, sessions)
			}
		}
		sessionsMu.Unlock()
		if session != nil {
			_ = session.SetReadDeadline(time.Now().Add(config.UDPIdleTimeout))
			_, _ = session.Write(payload)
		}
	}
}

func relayLocalUDP(ctx context.Context, tunnel *datagramTunnel, id uint64, session *net.UDPConn, idleTimeout time.Duration, sessionsMu *sync.Mutex, sessions map[uint64]*net.UDPConn) {
	defer func() {
		_ = session.Close()
		sessionsMu.Lock()
		if sessions[id] == session {
			delete(sessions, id)
		}
		sessionsMu.Unlock()
	}()
	buffer := make([]byte, maxDatagramSize)
	for {
		_ = session.SetReadDeadline(time.Now().Add(idleTimeout))
		count, err := session.Read(buffer)
		if err != nil || ctx.Err() != nil {
			return
		}
		tunnel.writeMu.Lock()
		err = writeDatagramFrame(tunnel.conn, id, buffer[:count])
		tunnel.writeMu.Unlock()
		if err != nil {
			_ = tunnel.conn.Close()
			return
		}
	}
}

func writeDatagramFrame(writer io.Writer, id uint64, payload []byte) error {
	if len(payload) > maxDatagramSize {
		return errors.New("udp datagram is too large")
	}
	header := make([]byte, datagramHeaderSize)
	binary.BigEndian.PutUint64(header[:8], id)
	binary.BigEndian.PutUint32(header[8:], uint32(len(payload)))
	if err := writeAll(writer, header); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		payload = payload[written:]
	}
	return nil
}

func readDatagramFrame(reader io.Reader) (uint64, []byte, error) {
	header := make([]byte, datagramHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return 0, nil, err
	}
	size := binary.BigEndian.Uint32(header[8:])
	if size > maxDatagramSize {
		return 0, nil, errors.New("udp datagram is too large")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	return binary.BigEndian.Uint64(header[:8]), payload, nil
}

func cloneUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}
