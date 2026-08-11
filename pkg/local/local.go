// Package local exposes the mogate local interception control plane as a small,
// stable API. A caller (such as honey) that has already port-forwarded the
// in-Pod agent's control and egress ports drives a single Injection Session
// through Run: it establishes the local egress relay, attaches the incoming
// steal/mirror tunnels, and runs a command with the injector loaded.
//
// The public surface is intentionally minimal: Config, Modes, and Run. It is
// the compatibility contract embedders pin, so it changes rarely and never
// silently.
package local

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/shareed2k/mogate/internal/egress"
	"github.com/shareed2k/mogate/internal/incoming"
	"github.com/shareed2k/mogate/internal/session"
	"github.com/shareed2k/mogate/internal/sessiontransport"
)

// Config describes a single local Injection Session. The addresses are the
// LOCAL endpoints the caller has already port-forwarded to the in-Pod agent.
type Config struct {
	// ControlAddr is the local address port-forwarded to the agent control port.
	ControlAddr string
	// EgressAddr is the local address port-forwarded to the agent egress port.
	EgressAddr string
	// Target is the local application address that incoming steal/mirror traffic
	// is forwarded to. It is required when Modes.Incoming is set.
	Target string
	// TokenFile is the path to the session token file (mode 0600). The token is
	// read from this file and never taken from argv or the environment.
	TokenFile string
	// Socket is the relay Unix socket path (created 0600 inside a 0700 directory).
	Socket string
	// InjectorLib is the path to the injector .so/.dylib loaded through
	// LD_PRELOAD (Linux) or DYLD_INSERT_LIBRARIES (macOS).
	InjectorLib string
	// Root is the filesystem root offered to remote file operations. An empty
	// root disables file redirection.
	Root string
	// UDP includes the UDP tunnels alongside TCP for the incoming path.
	UDP bool
	// MaxConnections bounds concurrent connections. A value of zero or less
	// selects the internal default of 256.
	MaxConnections int
	// Modes selects which capabilities are active for the session.
	Modes Modes
	// Logger receives session diagnostics. A nil logger writes to stderr.
	Logger *slog.Logger
}

// Modes selects which capabilities participate in an Injection Session.
type Modes struct {
	// Egress enables the local egress relay to the remote agent.
	Egress bool
	// Incoming enables the incoming steal/mirror tunnels toward Target.
	Incoming bool
	// Files enables remote file redirection for the injected command.
	Files bool
}

// Run establishes the local egress relay, attaches the incoming tunnels when
// Modes.Incoming is set, and runs command with the injector loaded. It returns
// when command exits or ctx is cancelled, draining every task before returning.
// It is the extracted, parameterized form of the dev command flow.
func Run(ctx context.Context, cfg Config, command []string) error {
	if len(command) == 0 {
		return errors.New("a command is required")
	}
	if cfg.Modes.Incoming && cfg.Target == "" {
		return errors.New("incoming target address is required when incoming mode is enabled")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	token, err := readToken(cfg.TokenFile)
	if err != nil {
		return err
	}

	relay, err := egress.NewRelay(egress.RelayConfig{
		SocketPath:     cfg.Socket,
		RemoteAddr:     cfg.EgressAddr,
		Token:          token,
		MaxConnections: cfg.MaxConnections,
		Logger:         logger,
	})
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	relayResult := make(chan error, 1)
	go func() { relayResult <- relay.Serve(runCtx) }()
	if err := session.WaitForSocket(runCtx, cfg.Socket, relayResult); err != nil {
		return err
	}

	tasks := []session.Task{
		{Name: "outbound relay", Run: func(taskCtx context.Context) error {
			stopped := make(chan struct{})
			defer close(stopped)
			go func() {
				select {
				case <-taskCtx.Done():
					cancel()
				case <-stopped:
				}
			}()
			return <-relayResult
		}},
	}
	if cfg.Modes.Incoming {
		forwardConfig := incoming.ForwardConfig{
			ControlAddr:    cfg.ControlAddr,
			TargetAddr:     cfg.Target,
			Token:          token,
			MaxConnections: cfg.MaxConnections,
			Logger:         logger,
		}
		tasks = append(tasks, session.Task{Name: "incoming tunnel", Run: func(taskCtx context.Context) error {
			return incoming.Forward(taskCtx, forwardConfig)
		}})
		if cfg.UDP {
			tasks = append(tasks, session.Task{Name: "incoming udp tunnel", Run: func(taskCtx context.Context) error {
				return incoming.ForwardUDP(taskCtx, forwardConfig)
			}})
		}
	}
	tasks = append(tasks, session.Task{Name: "command", Run: func(taskCtx context.Context) error {
		return execute(taskCtx, injectionOptions{
			socket:  cfg.Socket,
			library: cfg.InjectorLib,
			files:   cfg.Modes.Files && cfg.Root != "",
		}, command)
	}})
	return session.Run(runCtx, tasks...)
}

// readToken reads and validates the shared session token from a file. Keeping
// the secret in a file keeps it out of argv (visible in ps) and out of the
// process environment (readable via /proc/<pid>/environ).
func readToken(path string) (string, error) {
	if path == "" {
		return "", errors.New("token file path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read token file %q: %w", path, err)
	}
	token := strings.TrimRight(string(data), " \t\r\n")
	if err := sessiontransport.ValidateToken(token); err != nil {
		return "", fmt.Errorf("session token: %w", err)
	}
	return token, nil
}

// injectionOptions configures how the injector is loaded into a command.
type injectionOptions struct {
	socket  string
	library string
	files   bool
}

// execute runs command with the injector loaded through the platform loader
// variable. It returns a descriptive error for a non-zero command exit.
func execute(ctx context.Context, options injectionOptions, command []string) error {
	library, err := filepath.Abs(options.library)
	if err != nil {
		return fmt.Errorf("resolve injector path: %w", err)
	}
	if _, err := os.Stat(library); err != nil {
		return fmt.Errorf("injector library: %w", err)
	}
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = injectedEnvironment(os.Environ(), options, library)
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("command exited with status %d", exitErr.ExitCode())
		}
		return fmt.Errorf("run command: %w", err)
	}
	return nil
}

// injectedEnvironment returns base extended with the relay socket, file mode,
// and platform loader variable pointing at library.
func injectedEnvironment(base []string, options injectionOptions, library string) []string {
	env := append([]string(nil), base...)
	env = setEnv(env, "MOGATE_SOCKET", options.socket)
	if options.files {
		env = setEnv(env, "MOGATE_FILE_MODE", "remote")
	} else {
		env = setEnv(env, "MOGATE_FILE_MODE", "local")
	}
	loaderVariable := "LD_PRELOAD"
	if runtime.GOOS == "darwin" {
		loaderVariable = "DYLD_INSERT_LIBRARIES"
	}
	existing := envValue(env, loaderVariable)
	if existing != "" {
		library += string(os.PathListSeparator) + existing
	}
	return setEnv(env, loaderVariable, library)
}

// setEnv sets key to value in env, replacing any existing entry.
func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	for index, item := range env {
		if strings.HasPrefix(item, prefix) {
			env[index] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

// envValue returns the value of key in env, or the empty string when absent.
func envValue(env []string, key string) string {
	prefix := key + "="
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			return strings.TrimPrefix(item, prefix)
		}
	}
	return ""
}
