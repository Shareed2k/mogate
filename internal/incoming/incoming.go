package incoming

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shareed2k/mogate/internal/sessiontransport"
)

type Mode string

const (
	ModeSteal  Mode = "steal"
	ModeMirror Mode = "mirror"
)

type CaptureConfig struct {
	ListenAddr     string
	ControlAddr    string
	UpstreamAddr   string
	Token          string
	Mode           Mode
	ClaimTimeout   time.Duration
	DialTimeout    time.Duration
	MaxConnections int
	EnableUDP      bool
	UDPIdleTimeout time.Duration
	Logger         *slog.Logger
}

type Capture struct {
	config CaptureConfig
	nextID atomic.Uint64

	mu      sync.Mutex
	pending map[uint64]chan net.Conn
	watcher chan uint64

	udpMu       sync.Mutex
	udpTunnel   *datagramTunnel
	udpCapture  *net.UDPConn
	udpSessions map[uint64]*remoteUDPSession
	udpByAddr   map[string]uint64
}

func NewCapture(config CaptureConfig) (*Capture, error) {
	if config.ListenAddr == "" || config.ControlAddr == "" {
		return nil, errors.New("listen and control addresses are required")
	}
	if config.Mode != ModeSteal && config.Mode != ModeMirror {
		return nil, fmt.Errorf("invalid incoming mode %q", config.Mode)
	}
	if config.Mode == ModeMirror && config.UpstreamAddr == "" {
		return nil, errors.New("upstream address is required in mirror mode")
	}
	if err := sessiontransport.ValidateToken(config.Token); err != nil {
		return nil, err
	}
	if config.ClaimTimeout <= 0 {
		config.ClaimTimeout = 2 * time.Second
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
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Capture{
		config:      config,
		pending:     make(map[uint64]chan net.Conn),
		udpSessions: make(map[uint64]*remoteUDPSession),
		udpByAddr:   make(map[string]uint64),
	}, nil
}

func (c *Capture) Serve(ctx context.Context) error {
	incomingListener, err := net.Listen("tcp", c.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen for incoming traffic: %w", err)
	}
	defer incomingListener.Close()
	controlListener, err := net.Listen("tcp", c.config.ControlAddr)
	if err != nil {
		return fmt.Errorf("listen for control traffic: %w", err)
	}
	defer controlListener.Close()
	var udpConn *net.UDPConn
	if c.config.EnableUDP {
		udpAddress, resolveErr := net.ResolveUDPAddr("udp", c.config.ListenAddr)
		if resolveErr != nil {
			return fmt.Errorf("resolve udp capture address: %w", resolveErr)
		}
		udpConn, err = net.ListenUDP("udp", udpAddress)
		if err != nil {
			return fmt.Errorf("listen for incoming udp traffic: %w", err)
		}
		defer udpConn.Close()
		c.udpMu.Lock()
		c.udpCapture = udpConn
		c.udpMu.Unlock()
	}

	go func() {
		<-ctx.Done()
		_ = incomingListener.Close()
		_ = controlListener.Close()
		if udpConn != nil {
			_ = udpConn.Close()
		}
	}()

	errorsChannel := make(chan error, 3)
	var clients sync.WaitGroup
	go func() { errorsChannel <- c.acceptIncoming(ctx, incomingListener, &clients) }()
	go func() { errorsChannel <- c.acceptControl(ctx, controlListener, &clients) }()
	if udpConn != nil {
		go func() { errorsChannel <- c.serveUDP(ctx, udpConn) }()
	}

	select {
	case <-ctx.Done():
		_ = incomingListener.Close()
		_ = controlListener.Close()
		if udpConn != nil {
			_ = udpConn.Close()
		}
		c.closeUDPSessions()
		clients.Wait()
		return nil
	case serveErr := <-errorsChannel:
		_ = incomingListener.Close()
		_ = controlListener.Close()
		if udpConn != nil {
			_ = udpConn.Close()
		}
		c.closeUDPSessions()
		clients.Wait()
		if ctx.Err() != nil {
			return nil
		}
		return serveErr
	}
}

func (c *Capture) acceptIncoming(ctx context.Context, listener net.Listener, clients *sync.WaitGroup) error {
	sem := make(chan struct{}, c.config.MaxConnections)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case sem <- struct{}{}:
			clients.Add(1)
			go func() {
				defer clients.Done()
				defer func() { <-sem }()
				defer conn.Close()
				if handleErr := c.handleIncoming(ctx, conn); handleErr != nil && ctx.Err() == nil {
					c.config.Logger.Debug("incoming connection failed", "error", handleErr)
				}
			}()
		case <-ctx.Done():
			_ = conn.Close()
			return nil
		}
	}
}

func (c *Capture) acceptControl(ctx context.Context, listener net.Listener, clients *sync.WaitGroup) error {
	sem := make(chan struct{}, c.config.MaxConnections+1)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case sem <- struct{}{}:
			clients.Add(1)
			go func() {
				defer clients.Done()
				defer func() { <-sem }()
				c.handleControl(ctx, conn)
			}()
		case <-ctx.Done():
			_ = conn.Close()
			return nil
		}
	}
}

func (c *Capture) handleControl(ctx context.Context, conn net.Conn) {
	owned := true
	defer func() {
		if owned {
			_ = conn.Close()
		}
	}()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReaderSize(conn, 4096)
	binaryProtocol, err := sessiontransport.Accept(conn, reader, c.config.Token, sessiontransport.KindIncoming)
	if err != nil {
		return
	}
	if binaryProtocol {
		_ = conn.SetReadDeadline(time.Time{})
		if c.handleBinaryControl(ctx, conn, reader) {
			owned = false
		}
		return
	}
	line, err := reader.ReadString('\n')
	if err != nil || len(line) > 4096 {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	parts := strings.Fields(line)
	if len(parts) < 2 || !sessiontransport.SecureEqual(parts[1], c.config.Token) {
		_, _ = io.WriteString(conn, "ERR unauthorized\n")
		return
	}
	switch parts[0] {
	case "WATCH":
		if len(parts) != 2 || !c.installWatcher(ctx, conn, false) {
			_, _ = io.WriteString(conn, "ERR watcher-active\n")
			return
		}
	case "CLAIM":
		if len(parts) != 3 {
			_, _ = io.WriteString(conn, "ERR bad-claim\n")
			return
		}
		id, parseErr := strconv.ParseUint(parts[2], 10, 64)
		if parseErr != nil {
			_, _ = io.WriteString(conn, "ERR bad-id\n")
			return
		}
		claim := c.claimChannel(id)
		if claim == nil {
			_, _ = io.WriteString(conn, "ERR unknown-id\n")
			return
		}
		if _, err := io.WriteString(conn, "OK\n"); err != nil {
			return
		}
		select {
		case claim <- conn:
			owned = false
		case <-ctx.Done():
		}
	case "UDP":
		if len(parts) != 2 || !c.config.EnableUDP {
			_, _ = io.WriteString(conn, "ERR udp-disabled\n")
			return
		}
		c.installUDPTunnel(ctx, conn, false)
	default:
		_, _ = io.WriteString(conn, "ERR bad-command\n")
	}
}

func (c *Capture) handleBinaryControl(ctx context.Context, conn net.Conn, reader *bufio.Reader) bool {
	message, err := sessiontransport.ReadMessage(reader)
	if err != nil {
		return false
	}
	switch message.Type {
	case sessiontransport.MessageWatch:
		if !c.installWatcher(ctx, conn, true) {
			_ = sessiontransport.WriteMessage(conn, sessiontransport.Message{Type: sessiontransport.MessageError, Payload: []byte("watcher-active")})
		}
	case sessiontransport.MessageClaim:
		claim := c.claimChannel(message.StreamID)
		if claim == nil {
			_ = sessiontransport.WriteMessage(conn, sessiontransport.Message{Type: sessiontransport.MessageError, Payload: []byte("unknown-id")})
			return false
		}
		if err := sessiontransport.WriteMessage(conn, sessiontransport.Message{Type: sessiontransport.MessageOK}); err != nil {
			return false
		}
		select {
		case claim <- &bufferedConn{Conn: conn, reader: reader}:
			return true
		case <-ctx.Done():
		}
	case sessiontransport.MessageUDP:
		if !c.config.EnableUDP {
			_ = sessiontransport.WriteMessage(conn, sessiontransport.Message{Type: sessiontransport.MessageError, Payload: []byte("udp-disabled")})
			return false
		}
		c.installUDPTunnel(ctx, &bufferedConn{Conn: conn, reader: reader}, true)
	default:
		_ = sessiontransport.WriteMessage(conn, sessiontransport.Message{Type: sessiontransport.MessageError, Payload: []byte("bad-command")})
	}
	return false
}

func (c *Capture) installWatcher(ctx context.Context, conn net.Conn, binaryProtocol bool) bool {
	updates := make(chan uint64, c.config.MaxConnections)
	c.mu.Lock()
	if c.watcher != nil {
		c.mu.Unlock()
		return false
	}
	c.watcher = updates
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.watcher == updates {
			c.watcher = nil
		}
		c.mu.Unlock()
	}()
	if err := writeControlOK(conn, binaryProtocol); err != nil {
		return true
	}
	disconnected := make(chan error, 1)
	go func() {
		var probe [1]byte
		_, err := conn.Read(probe[:])
		disconnected <- err
	}()
	for {
		select {
		case id := <-updates:
			var err error
			if binaryProtocol {
				err = sessiontransport.WriteMessage(conn, sessiontransport.Message{Type: sessiontransport.MessageIncoming, StreamID: id})
			} else {
				_, err = fmt.Fprintf(conn, "%d\n", id)
			}
			if err != nil {
				return true
			}
		case <-disconnected:
			return true
		case <-ctx.Done():
			return true
		}
	}
}

func (c *Capture) handleIncoming(ctx context.Context, client net.Conn) error {
	id := c.nextID.Add(1)
	claim := make(chan net.Conn, 1)
	c.mu.Lock()
	c.pending[id] = claim
	watcher := c.watcher
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()

	if watcher != nil {
		select {
		case watcher <- id:
		default:
			watcher = nil
		}
	}

	if c.config.Mode == ModeSteal {
		if watcher == nil {
			return c.passThrough(ctx, client)
		}
		local, err := waitForClaim(ctx, claim, c.config.ClaimTimeout)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			return c.passThrough(ctx, client)
		}
		defer local.Close()
		return bridge(ctx, client, local)
	}

	dialer := net.Dialer{Timeout: c.config.DialTimeout}
	upstream, err := dialer.DialContext(ctx, "tcp", c.config.UpstreamAddr)
	if err != nil {
		return fmt.Errorf("dial upstream: %w", err)
	}
	defer upstream.Close()
	if watcher == nil {
		return bridge(ctx, client, upstream)
	}
	local, claimErr := waitForClaim(ctx, claim, min(c.config.ClaimTimeout, 200*time.Millisecond))
	if claimErr != nil {
		return bridge(ctx, client, upstream)
	}
	defer local.Close()
	return mirror(ctx, client, upstream, local)
}

func (c *Capture) passThrough(ctx context.Context, client net.Conn) error {
	if c.config.UpstreamAddr == "" {
		return errors.New("no local watcher or passthrough upstream")
	}
	dialer := net.Dialer{Timeout: c.config.DialTimeout}
	upstream, err := dialer.DialContext(ctx, "tcp", c.config.UpstreamAddr)
	if err != nil {
		return fmt.Errorf("dial passthrough upstream: %w", err)
	}
	defer upstream.Close()
	return bridge(ctx, client, upstream)
}

func (c *Capture) claimChannel(id uint64) chan net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pending[id]
}

type ForwardConfig struct {
	ControlAddr    string
	TargetAddr     string
	Token          string
	DialTimeout    time.Duration
	MaxConnections int
	UDPIdleTimeout time.Duration
	Logger         *slog.Logger
}

func ForwardUDP(ctx context.Context, config ForwardConfig) error {
	return forwardUDP(ctx, config)
}

func Forward(ctx context.Context, config ForwardConfig) error {
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
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	dialer := net.Dialer{Timeout: config.DialTimeout}
	watch, err := sessiontransport.Dial(ctx, config.ControlAddr, config.Token, sessiontransport.KindIncoming, config.DialTimeout)
	if err != nil {
		return fmt.Errorf("dial control: %w", err)
	}
	defer watch.Close()
	watchStopped := make(chan struct{})
	defer close(watchStopped)
	go func() {
		select {
		case <-ctx.Done():
			_ = watch.Close()
		case <-watchStopped:
		}
	}()
	if err := sessiontransport.WriteMessage(watch, sessiontransport.Message{Type: sessiontransport.MessageWatch}); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(watch, 4096)
	if err := sessiontransport.ExpectOK(reader); err != nil {
		return err
	}

	sem := make(chan struct{}, config.MaxConnections)
	var connections sync.WaitGroup
	defer connections.Wait()
	for {
		message, readErr := sessiontransport.ReadMessage(reader)
		if readErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("watch control: %w", readErr)
		}
		if message.Type != sessiontransport.MessageIncoming {
			return fmt.Errorf("unexpected incoming message %d", message.Type)
		}
		id := message.StreamID
		select {
		case sem <- struct{}{}:
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer func() { <-sem }()
				if claimErr := claimAndForward(ctx, dialer, config, id); claimErr != nil && ctx.Err() == nil {
					config.Logger.Debug("claim failed", "id", id, "error", claimErr)
				}
			}()
		case <-ctx.Done():
			return nil
		}
	}
}

func claimAndForward(ctx context.Context, dialer net.Dialer, config ForwardConfig, id uint64) error {
	local, err := dialer.DialContext(ctx, "tcp", config.TargetAddr)
	if err != nil {
		return fmt.Errorf("dial local target: %w", err)
	}
	defer local.Close()
	claim, err := sessiontransport.Dial(ctx, config.ControlAddr, config.Token, sessiontransport.KindIncoming, config.DialTimeout)
	if err != nil {
		return fmt.Errorf("dial claim control: %w", err)
	}
	defer claim.Close()
	if err := sessiontransport.WriteMessage(claim, sessiontransport.Message{Type: sessiontransport.MessageClaim, StreamID: id}); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(claim, 4096)
	if err := sessiontransport.ExpectOK(reader); err != nil {
		return err
	}
	return bridge(ctx, local, &bufferedConn{Conn: claim, reader: reader})
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(buffer []byte) (int, error) {
	return c.reader.Read(buffer)
}

func expectOK(reader *bufio.Reader) error {
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if line != "OK\n" {
		return fmt.Errorf("control rejected request: %s", strings.TrimSpace(line))
	}
	return nil
}

func waitForClaim(ctx context.Context, claim <-chan net.Conn, timeout time.Duration) (net.Conn, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case conn := <-claim:
		return conn, nil
	case <-timer.C:
		return nil, errors.New("local claim timed out")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func bridge(ctx context.Context, first, second net.Conn) error {
	done := make(chan error, 2)
	go copyHalf(done, first, second)
	go copyHalf(done, second, first)
	select {
	case <-ctx.Done():
		_ = first.Close()
		_ = second.Close()
		<-done
		<-done
		return ctx.Err()
	case err := <-done:
		_ = first.Close()
		_ = second.Close()
		<-done
		return err
	}
}

func copyHalf(done chan<- error, destination, source net.Conn) {
	_, err := io.Copy(destination, source)
	if tcp, ok := destination.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	done <- err
}

func mirror(ctx context.Context, client, upstream, local net.Conn) error {
	chunks := make(chan []byte, 64)
	localDone := make(chan struct{})
	go func() {
		defer close(localDone)
		for chunk := range chunks {
			if _, err := local.Write(chunk); err != nil {
				return
			}
		}
	}()
	go func() { _, _ = io.Copy(io.Discard, local) }()

	done := make(chan error, 2)
	go func() {
		defer close(chunks)
		buffer := make([]byte, 32<<10)
		for {
			count, err := client.Read(buffer)
			if count > 0 {
				if _, writeErr := upstream.Write(buffer[:count]); writeErr != nil {
					done <- writeErr
					return
				}
				copyForLocal := append([]byte(nil), buffer[:count]...)
				select {
				case chunks <- copyForLocal:
				default:
				}
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	go func() {
		_, err := io.Copy(client, upstream)
		done <- err
	}()
	select {
	case <-ctx.Done():
		_ = client.Close()
		_ = upstream.Close()
		_ = local.Close()
		<-done
		<-done
		<-localDone
		return ctx.Err()
	case err := <-done:
		_ = client.Close()
		_ = upstream.Close()
		_ = local.Close()
		<-done
		<-localDone
		return err
	}
}

func writeControlOK(conn net.Conn, binaryProtocol bool) error {
	if binaryProtocol {
		return sessiontransport.WriteMessage(conn, sessiontransport.Message{Type: sessiontransport.MessageOK})
	}
	_, err := io.WriteString(conn, "OK\n")
	return err
}
