package egress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shareed2k/mogate/internal/sessiontransport"
)

type Handler interface {
	ServeConn(ctx context.Context, conn net.Conn) error
}

type ServerConfig struct {
	ListenAddr     string
	Token          string
	MaxConnections int
	Logger         *slog.Logger
}

type Server struct {
	config  ServerConfig
	handler Handler
}

func NewServer(config ServerConfig, handler Handler) (*Server, error) {
	if config.ListenAddr == "" {
		return nil, errors.New("listen address is required")
	}
	if handler == nil {
		return nil, errors.New("handler is required")
	}
	if err := sessiontransport.ValidateToken(config.Token); err != nil {
		return nil, err
	}
	if config.MaxConnections <= 0 {
		config.MaxConnections = 256
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Server{config: config, handler: handler}, nil
}

func (s *Server) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen for remote egress: %w", err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	sem := make(chan struct{}, s.config.MaxConnections)
	var clients sync.WaitGroup
	defer clients.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept remote egress: %w", err)
		}
		select {
		case sem <- struct{}{}:
			clients.Add(1)
			go func() {
				defer clients.Done()
				defer func() { <-sem }()
				defer func() { _ = conn.Close() }()
				stopped := make(chan struct{})
				go func() {
					select {
					case <-ctx.Done():
						_ = conn.Close()
					case <-stopped:
					}
				}()
				if err := s.serveConn(ctx, conn); err != nil && ctx.Err() == nil {
					s.config.Logger.Debug("remote egress connection failed", "error", err)
				}
				close(stopped)
			}()
		case <-ctx.Done():
			_ = conn.Close()
			return nil
		}
	}
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn) error {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReaderSize(conn, 4096)
	binaryProtocol, err := sessiontransport.Accept(conn, reader, s.config.Token, sessiontransport.KindEgress)
	if err != nil {
		return err
	}
	if binaryProtocol {
		_ = conn.SetReadDeadline(time.Time{})
		return s.handler.ServeConn(ctx, &bufferedConn{Conn: conn, reader: reader})
	}
	line, err := reader.ReadString('\n')
	if err != nil || len(line) > 4096 {
		return errors.New("read egress authentication")
	}
	parts := strings.Fields(line)
	if len(parts) != 2 || parts[0] != "EGRESS" || !sessiontransport.SecureEqual(parts[1], s.config.Token) {
		_, _ = io.WriteString(conn, "ERR unauthorized\n")
		return errors.New("unauthorized egress connection")
	}
	_ = conn.SetReadDeadline(time.Time{})
	if _, err := io.WriteString(conn, "OK\n"); err != nil {
		return err
	}
	return s.handler.ServeConn(ctx, &bufferedConn{Conn: conn, reader: reader})
}

type RelayConfig struct {
	SocketPath     string
	RemoteAddr     string
	Token          string
	DialTimeout    time.Duration
	MaxConnections int
	Logger         *slog.Logger
}

type Relay struct {
	config RelayConfig
}

func NewRelay(config RelayConfig) (*Relay, error) {
	if config.SocketPath == "" || config.RemoteAddr == "" {
		return nil, errors.New("socket path and remote address are required")
	}
	if err := sessiontransport.ValidateToken(config.Token); err != nil {
		return nil, err
	}
	if config.DialTimeout <= 0 {
		config.DialTimeout = 10 * time.Second
	}
	if config.MaxConnections <= 0 {
		config.MaxConnections = 256
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Relay{config: config}, nil
}

func (r *Relay) Serve(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(r.config.SocketPath), 0o700); err != nil {
		return fmt.Errorf("create relay socket directory: %w", err)
	}
	if err := removeStaleSocket(r.config.SocketPath); err != nil {
		return err
	}
	listener, err := net.Listen("unix", r.config.SocketPath)
	if err != nil {
		return fmt.Errorf("listen on relay socket: %w", err)
	}
	defer func() { _ = listener.Close() }()
	defer func() { _ = os.Remove(r.config.SocketPath) }()
	if err := os.Chmod(r.config.SocketPath, 0o600); err != nil {
		return fmt.Errorf("protect relay socket: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	sem := make(chan struct{}, r.config.MaxConnections)
	var clients sync.WaitGroup
	defer clients.Wait()
	for {
		local, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept relay connection: %w", err)
		}
		select {
		case sem <- struct{}{}:
			clients.Add(1)
			go func() {
				defer clients.Done()
				defer func() { <-sem }()
				defer func() { _ = local.Close() }()
				if err := r.relay(ctx, local); err != nil && ctx.Err() == nil {
					r.config.Logger.Debug("egress relay failed", "error", err)
				}
			}()
		case <-ctx.Done():
			_ = local.Close()
			return nil
		}
	}
}

func (r *Relay) relay(ctx context.Context, local net.Conn) error {
	remote, err := sessiontransport.Dial(ctx, r.config.RemoteAddr, r.config.Token, sessiontransport.KindEgress, r.config.DialTimeout)
	if err != nil {
		return fmt.Errorf("dial remote egress: %w", err)
	}
	defer func() { _ = remote.Close() }()
	return bridge(ctx, local, remote)
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(buffer []byte) (int, error) {
	return c.reader.Read(buffer)
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

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect relay socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket path %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale relay socket: %w", err)
	}
	return nil
}
