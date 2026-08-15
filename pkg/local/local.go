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
	// InjectorLibRosetta is the path to the x86_64 build of the injector,
	// loaded for a command thinned to its x86_64 slice that runs under Rosetta.
	// It is required on Apple Silicon for restricted system binaries; on other
	// platforms it is unused.
	InjectorLibRosetta string
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
			socket:         cfg.Socket,
			library:        cfg.InjectorLib,
			libraryRosetta: cfg.InjectorLibRosetta,
			files:          cfg.Modes.Files && cfg.Root != "",
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
	socket         string
	library        string
	libraryRosetta string
	files          bool
}

// selectInjector picks the injector matching the slice command[0] was thinned
// to. A binary run natively (or any platform without SIP patching) takes the
// primary library; one thinned to x86_64 under Rosetta takes the x86_64
// library, and it is fail-loud when that path was not configured.
func selectInjector(options injectionOptions, res sipResult) (string, error) {
	if res.arch == sipArchRosetta {
		if options.libraryRosetta == "" {
			return "", fmt.Errorf("sip: %s needs the x86_64 injector but InjectorLibRosetta is unset", res.path)
		}
		return options.libraryRosetta, nil
	}
	return options.library, nil
}

// resolveExecutable resolves a bare command name to a concrete path via PATH,
// mirroring what a shell (and exec.Command at spawn time) does. A name that
// already contains a path separator is a path, not a PATH lookup, and is
// returned unchanged. It exists so the darwin SIP-patch step opens the real
// binary that would run, not a same-named file in the current directory.
func resolveExecutable(name string) (string, error) {
	if strings.ContainsRune(name, filepath.Separator) {
		return name, nil
	}
	resolved, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("resolve executable %q: %w", name, err)
	}
	return resolved, nil
}

// execute runs command with the injector loaded through the platform loader
// variable. On macOS it first PATH-resolves a bare command[0] to the real
// binary, then patches it when it is a restricted system binary, running the
// patched copy (or the patched interpreter, for a "#!" script) so
// DYLD_INSERT_LIBRARIES is honored. For the non-script case it preserves the
// caller's original argv[0], matching the C child detour. It returns a
// descriptive error for a non-zero command exit.
func execute(ctx context.Context, options injectionOptions, command []string) error {
	// Preserve the name the user passed as argv[0]. The C child detour execs the
	// patched path but passes the caller's argv through unchanged
	// (injector/sip_darwin.h), so a program that inspects argv[0] -- a
	// login/multi-call shell, os.Args[0] self-location -- must see the same value
	// whether it is spawned here at the Go top level or re-exec'd by a child.
	// Capture it before the darwin resolve and res.path replacement below rewrite
	// command[0].
	origArg0 := command[0]

	// On darwin the SIP-patch step below opens command[0] directly, so a bare
	// name must first be resolved to the binary PATH would run. Off darwin
	// exec.Command still resolves at spawn, so this is darwin-only and the
	// non-darwin path stays byte-identical.
	if runtime.GOOS == "darwin" {
		resolved, err := resolveExecutable(command[0])
		if err != nil {
			return err
		}
		command[0] = resolved
	}
	res, err := patchIfRestricted(command[0])
	if err != nil {
		return err
	}
	execPath, argv := assembleExec(origArg0, command, res)

	lib, err := selectInjector(options, res)
	if err != nil {
		return err
	}
	library, err := filepath.Abs(lib)
	if err != nil {
		return fmt.Errorf("resolve injector path: %w", err)
	}
	if _, err := os.Stat(library); err != nil {
		return fmt.Errorf("injector library: %w", err)
	}
	cmd := exec.CommandContext(ctx, execPath)
	cmd.Args = argv
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

// assembleExec builds the (execPath, argv) pair execute runs. For the non-script
// case it runs the PATCHED binary (res.path) while keeping the caller's original
// argv[0] (origArg0), matching the C child detour, which execs the patched path
// but passes the caller's argv through unchanged (injector/sip_darwin.h). For a
// "#!" script the (possibly patched) interpreter is both the program and argv[0],
// followed by the shebang args, the script path, and the original args -- how a
// shebang exec works; command[0] here is the resolved script path. The returned
// argv never aliases command.
func assembleExec(origArg0 string, command []string, res sipResult) (execPath string, argv []string) {
	if res.scriptInterp != "" {
		argv = make([]string, 0, 1+len(res.scriptArgs)+len(command))
		argv = append(argv, res.scriptInterp)
		argv = append(argv, res.scriptArgs...)
		argv = append(argv, command[0])
		argv = append(argv, command[1:]...)
		return res.scriptInterp, argv
	}
	argv = make([]string, len(command))
	copy(argv, command)
	argv[0] = origArg0
	return res.path, argv
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
