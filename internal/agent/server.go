package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shareed2k/mogate/internal/protocol"
)

const (
	fileAccessMask = 3
	fileWriteOnly  = 1
	fileReadWrite  = 2
	fileCreate     = 1 << 2
	fileTruncate   = 1 << 3
	fileAppend     = 1 << 4
	fileExclusive  = 1 << 5
)

type Config struct {
	SocketPath     string
	Root           string
	DialTimeout    time.Duration
	MaxConnections int
	Logger         *slog.Logger
	DNSConfigPath  string
}

type Server struct {
	config    Config
	dnsOnce   sync.Once
	dnsServer netip.Addr
}

func New(config Config) (*Server, error) {
	if config.SocketPath == "" {
		return nil, errors.New("socket path is required")
	}
	return newServer(config)
}

func NewHandler(config Config) (*Server, error) {
	return newServer(config)
}

func newServer(config Config) (*Server, error) {
	if config.Root == "" {
		config.Root = "/"
	}
	absRoot, err := filepath.Abs(config.Root)
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}
	config.Root = filepath.Clean(absRoot)
	if config.DialTimeout <= 0 {
		config.DialTimeout = 10 * time.Second
	}
	if config.MaxConnections <= 0 {
		config.MaxConnections = 256
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.DNSConfigPath == "" {
		config.DNSConfigPath = "/etc/resolv.conf"
	}
	return &Server{config: config}, nil
}

func (s *Server) ServeConn(ctx context.Context, conn net.Conn) error {
	return s.handle(ctx, conn)
}

func (s *Server) Serve(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(s.config.SocketPath), 0o700); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}
	if err := removeStaleSocket(s.config.SocketPath); err != nil {
		return err
	}
	listener, err := net.Listen("unix", s.config.SocketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.config.SocketPath, err)
	}
	defer listener.Close()
	defer os.Remove(s.config.SocketPath)
	if err := os.Chmod(s.config.SocketPath, 0o600); err != nil {
		return fmt.Errorf("protect socket: %w", err)
	}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	sem := make(chan struct{}, s.config.MaxConnections)
	var clients sync.WaitGroup
	defer clients.Wait()
	for {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", acceptErr)
		}
		select {
		case sem <- struct{}{}:
			clients.Add(1)
			go func() {
				defer clients.Done()
				defer func() { <-sem }()
				defer conn.Close()
				if handleErr := s.handle(ctx, conn); handleErr != nil && ctx.Err() == nil {
					s.config.Logger.Debug("client failed", "error", handleErr)
				}
			}()
		case <-ctx.Done():
			_ = conn.Close()
			return nil
		}
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) error {
	frame, err := protocol.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	switch frame.Operation {
	case protocol.OpTCPConnect:
		return s.handleTCP(ctx, conn, string(frame.Payload))
	case protocol.OpDNSLookup:
		return s.handleDNS(ctx, conn, string(frame.Payload))
	case protocol.OpUDPConnect:
		return s.handleUDP(ctx, conn, string(frame.Payload))
	case protocol.OpUDPOpen:
		return s.handleUnconnectedUDP(ctx, conn, false)
	case protocol.OpUDPOpenMetadata:
		return s.handleUnconnectedUDP(ctx, conn, true)
	case protocol.OpUDPConnectMetadata:
		return s.handleUDPMetadata(ctx, conn, string(frame.Payload))
	case protocol.OpFileOpen:
		return s.handleFile(conn, frame)
	default:
		return s.respond(conn, frame.Operation, int32(syscall.ENOSYS), nil)
	}
}

func (s *Server) handleUnconnectedUDP(ctx context.Context, client net.Conn, withMetadata bool) error {
	packet, err := net.ListenUDP("udp", nil)
	if err != nil {
		operation := protocol.OpUDPOpen
		if withMetadata {
			operation = protocol.OpUDPOpenMetadata
		}
		return s.respond(client, operation, errnoOf(err), nil)
	}
	defer packet.Close()
	configureUDPMetadata(packet)
	openOperation := protocol.OpUDPOpen
	if withMetadata {
		openOperation = protocol.OpUDPOpenMetadata
	}
	if err := s.respond(client, openOperation, 0, nil); err != nil {
		return err
	}

	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
			_ = packet.Close()
		case <-stopped:
		}
	}()
	defer close(stopped)

	receiveResult := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64<<10)
		for {
			count, source, metadata, readErr := readUDPMetadata(packet, buffer)
			if readErr != nil {
				receiveResult <- readErr
				return
			}
			payload, encodeErr := protocol.AppendAddress(nil, source)
			if encodeErr != nil {
				receiveResult <- encodeErr
				return
			}
			operation := protocol.OpUDPReceiveFrom
			if withMetadata {
				payload, encodeErr = protocol.AppendDatagramMetadata(payload, metadata)
				if encodeErr != nil {
					receiveResult <- encodeErr
					return
				}
				operation = protocol.OpUDPReceiveMsg
			}
			payload = append(payload, buffer[:count]...)
			if writeErr := protocol.WriteFrame(client, protocol.Frame{Operation: operation, Payload: payload}); writeErr != nil {
				receiveResult <- writeErr
				return
			}
		}
	}()

	for {
		frame, readErr := protocol.ReadFrame(client)
		if readErr != nil {
			return readErr
		}
		if frame.Operation != protocol.OpUDPSendTo && !(withMetadata && frame.Operation == protocol.OpUDPSendMsg) {
			return fmt.Errorf("unexpected unconnected UDP operation %d", frame.Operation)
		}
		destination, consumed, parseErr := protocol.ParseAddress(frame.Payload)
		if parseErr != nil {
			return parseErr
		}
		destination = s.rewriteDNSAddrPort(destination)
		metadata := protocol.DatagramMetadata{}
		if frame.Operation == protocol.OpUDPSendMsg {
			parsedMetadata, consumedMetadata, metadataErr := protocol.ParseDatagramMetadata(frame.Payload[consumed:])
			if metadataErr != nil {
				return metadataErr
			}
			metadata = parsedMetadata
			consumed += consumedMetadata
		}
		if writeErr := writeUDPMetadata(packet, frame.Payload[consumed:], destination, metadata); writeErr != nil {
			return writeErr
		}
		select {
		case receiveErr := <-receiveResult:
			return receiveErr
		default:
		}
	}
}

func (s *Server) handleUDPMetadata(ctx context.Context, client net.Conn, address string) error {
	address = s.rewriteDNSAddress(address)
	remoteAddress, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return s.respond(client, protocol.OpUDPConnectMetadata, errnoOf(err), nil)
	}
	packet, err := net.DialUDP("udp", nil, remoteAddress)
	if err != nil {
		return s.respond(client, protocol.OpUDPConnectMetadata, errnoOf(err), nil)
	}
	defer packet.Close()
	configureUDPMetadata(packet)
	if err := s.respond(client, protocol.OpUDPConnectMetadata, 0, nil); err != nil {
		return err
	}

	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
			_ = packet.Close()
		case <-stopped:
		}
	}()
	defer close(stopped)

	receiveResult := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64<<10)
		for {
			count, source, metadata, readErr := readUDPMetadata(packet, buffer)
			if readErr != nil {
				receiveResult <- readErr
				return
			}
			payload, encodeErr := protocol.AppendAddress(nil, source)
			if encodeErr == nil {
				payload, encodeErr = protocol.AppendDatagramMetadata(payload, metadata)
			}
			if encodeErr != nil {
				receiveResult <- encodeErr
				return
			}
			payload = append(payload, buffer[:count]...)
			if writeErr := protocol.WriteFrame(client, protocol.Frame{Operation: protocol.OpUDPReceiveMsg, Payload: payload}); writeErr != nil {
				receiveResult <- writeErr
				return
			}
		}
	}()

	for {
		frame, readErr := protocol.ReadFrame(client)
		if readErr != nil {
			return readErr
		}
		if frame.Operation != protocol.OpUDPSendMsg {
			return fmt.Errorf("unexpected metadata UDP operation %d", frame.Operation)
		}
		metadata, consumed, parseErr := protocol.ParseDatagramMetadata(frame.Payload)
		if parseErr != nil {
			return parseErr
		}
		if writeErr := writeUDPMetadata(packet, frame.Payload[consumed:], netip.AddrPort{}, metadata); writeErr != nil {
			return writeErr
		}
		select {
		case receiveErr := <-receiveResult:
			return receiveErr
		default:
		}
	}
}

func (s *Server) handleUDP(ctx context.Context, client net.Conn, address string) error {
	address = s.rewriteDNSAddress(address)
	dialer := net.Dialer{Timeout: s.config.DialTimeout}
	remote, err := dialer.DialContext(ctx, "udp", address)
	if err != nil {
		return s.respond(client, protocol.OpUDPConnect, errnoOf(err), nil)
	}
	defer remote.Close()
	if err := s.respond(client, protocol.OpUDPConnect, 0, nil); err != nil {
		return err
	}

	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
			_ = remote.Close()
		case <-stopped:
		}
	}()
	defer close(stopped)

	receiveResult := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64<<10)
		for {
			count, readErr := remote.Read(buffer)
			if readErr != nil {
				receiveResult <- readErr
				return
			}
			if writeErr := protocol.WriteFrame(client, protocol.Frame{
				Operation: protocol.OpUDPReceive,
				Payload:   buffer[:count],
			}); writeErr != nil {
				receiveResult <- writeErr
				return
			}
		}
	}()

	for {
		frame, readErr := protocol.ReadFrame(client)
		if readErr != nil {
			return readErr
		}
		if frame.Operation != protocol.OpUDPSend {
			return fmt.Errorf("unexpected UDP operation %d", frame.Operation)
		}
		if _, writeErr := remote.Write(frame.Payload); writeErr != nil {
			return writeErr
		}
		select {
		case receiveErr := <-receiveResult:
			return receiveErr
		default:
		}
	}
}

func (s *Server) handleTCP(ctx context.Context, client net.Conn, address string) error {
	address = s.rewriteDNSAddress(address)
	dialer := net.Dialer{Timeout: s.config.DialTimeout}
	remote, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return s.respond(client, protocol.OpTCPConnect, errnoOf(err), nil)
	}
	defer remote.Close()
	if err := s.respond(client, protocol.OpTCPConnect, 0, nil); err != nil {
		return err
	}

	done := make(chan error, 2)
	go copyStream(done, remote, client)
	go copyStream(done, client, remote)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func (s *Server) handleDNS(ctx context.Context, conn net.Conn, host string) error {
	lookupCtx, cancel := context.WithTimeout(ctx, s.config.DialTimeout)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	if err != nil {
		return s.respond(conn, protocol.OpDNSLookup, errnoOf(err), nil)
	}
	lines := make([]string, 0, len(addresses))
	for _, address := range addresses {
		lines = append(lines, address.IP.String())
	}
	return s.respond(conn, protocol.OpDNSLookup, 0, []byte(strings.Join(lines, "\n")))
}

func (s *Server) handleFile(conn net.Conn, openFrame protocol.Frame) error {
	if len(openFrame.Payload) < 8 {
		return s.respond(conn, protocol.OpFileOpen, int32(syscall.EINVAL), nil)
	}
	flags := binary.BigEndian.Uint32(openFrame.Payload[:4])
	mode := binary.BigEndian.Uint32(openFrame.Payload[4:8])
	path, err := s.resolvePath(string(openFrame.Payload[8:]))
	if err != nil {
		return s.respond(conn, protocol.OpFileOpen, int32(syscall.EACCES), nil)
	}
	root, err := os.OpenRoot(s.config.Root)
	if err != nil {
		return s.respond(conn, protocol.OpFileOpen, errnoOf(err), nil)
	}
	defer root.Close()
	file, err := root.OpenFile(path, osFlags(flags), os.FileMode(mode)&0o777)
	if err != nil {
		return s.respond(conn, protocol.OpFileOpen, errnoOf(err), nil)
	}
	defer file.Close()
	if err := s.respond(conn, protocol.OpFileOpen, 0, nil); err != nil {
		return err
	}
	for {
		frame, readErr := protocol.ReadFrame(conn)
		if readErr != nil {
			return readErr
		}
		switch frame.Operation {
		case protocol.OpFileRead:
			if err := s.fileRead(conn, file, frame.Payload); err != nil {
				return err
			}
		case protocol.OpFileWrite:
			n, writeErr := file.Write(frame.Payload)
			payload := make([]byte, 4)
			binary.BigEndian.PutUint32(payload, uint32(n))
			if err := s.respond(conn, frame.Operation, errnoOf(writeErr), payload); err != nil {
				return err
			}
		case protocol.OpFileSeek:
			if err := s.fileSeek(conn, file, frame.Payload); err != nil {
				return err
			}
		case protocol.OpFileStat:
			if err := s.fileStat(conn, file); err != nil {
				return err
			}
		case protocol.OpFileClose:
			return s.respond(conn, frame.Operation, errnoOf(file.Close()), nil)
		default:
			if err := s.respond(conn, frame.Operation, int32(syscall.ENOSYS), nil); err != nil {
				return err
			}
		}
	}
}

func (s *Server) fileRead(conn net.Conn, file *os.File, payload []byte) error {
	if len(payload) != 4 {
		return s.respond(conn, protocol.OpFileRead, int32(syscall.EINVAL), nil)
	}
	size := binary.BigEndian.Uint32(payload)
	if size > protocol.MaxPayloadSize-4 {
		return s.respond(conn, protocol.OpFileRead, int32(syscall.E2BIG), nil)
	}
	data := make([]byte, size)
	n, err := file.Read(data)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return s.respond(conn, protocol.OpFileRead, errnoOf(err), data[:n])
}

func (s *Server) fileSeek(conn net.Conn, file *os.File, payload []byte) error {
	if len(payload) != 12 {
		return s.respond(conn, protocol.OpFileSeek, int32(syscall.EINVAL), nil)
	}
	offset := int64(binary.BigEndian.Uint64(payload[:8]))
	whence := int32(binary.BigEndian.Uint32(payload[8:]))
	position, err := file.Seek(offset, int(whence))
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(position))
	return s.respond(conn, protocol.OpFileSeek, errnoOf(err), data)
}

func (s *Server) fileStat(conn net.Conn, file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return s.respond(conn, protocol.OpFileStat, errnoOf(err), nil)
	}
	data := make([]byte, 24)
	mode := uint32(info.Mode().Perm())
	switch {
	case info.Mode().IsRegular():
		mode |= 0o100000
	case info.IsDir():
		mode |= 0o040000
	case info.Mode()&os.ModeSymlink != 0:
		mode |= 0o120000
	}
	binary.BigEndian.PutUint32(data[:4], mode)
	binary.BigEndian.PutUint64(data[8:16], uint64(info.Size()))
	binary.BigEndian.PutUint64(data[16:24], uint64(info.ModTime().UnixNano()))
	return s.respond(conn, protocol.OpFileStat, 0, data)
}

func (s *Server) resolvePath(requested string) (string, error) {
	if requested == "" || strings.IndexByte(requested, 0) >= 0 {
		return "", errors.New("invalid path")
	}
	relative := strings.TrimPrefix(filepath.Clean("/"+requested), string(filepath.Separator))
	if !filepath.IsLocal(relative) {
		return "", errors.New("path escapes root")
	}
	return relative, nil
}

func (s *Server) respond(conn net.Conn, operation protocol.Operation, errno int32, data []byte) error {
	return protocol.WriteFrame(conn, protocol.Frame{
		Operation: operation,
		Payload:   protocol.StatusPayload(errno, data),
	})
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket path %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	return nil
}

func copyStream(done chan<- error, dst io.Writer, src io.Reader) {
	_, err := io.Copy(dst, src)
	done <- err
}

func errnoOf(err error) int32 {
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return int32(errno)
	}
	return int32(syscall.EIO)
}

func osFlags(flags uint32) int {
	result := os.O_RDONLY
	switch flags & fileAccessMask {
	case fileWriteOnly:
		result = os.O_WRONLY
	case fileReadWrite:
		result = os.O_RDWR
	}
	if flags&fileCreate != 0 {
		result |= os.O_CREATE
	}
	if flags&fileTruncate != 0 {
		result |= os.O_TRUNC
	}
	if flags&fileAppend != 0 {
		result |= os.O_APPEND
	}
	if flags&fileExclusive != 0 {
		result |= os.O_EXCL
	}
	return result
}
