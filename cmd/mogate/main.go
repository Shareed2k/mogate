package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/shareed2k/mogate/internal/agent"
	"github.com/shareed2k/mogate/internal/egress"
	"github.com/shareed2k/mogate/internal/incoming"
	"github.com/shareed2k/mogate/internal/kube"
	"github.com/shareed2k/mogate/internal/session"
	"github.com/shareed2k/mogate/internal/sessiontransport"
	"github.com/shareed2k/mogate/pkg/local"
)

const (
	tokenFlagUsage     = "shared session token (or MOGATE_TOKEN); visible in ps, prefer --token-file"
	tokenFileFlagUsage = "read the session token from a file (or MOGATE_TOKEN_FILE); preferred over --token"
)

const rootLong = `mogate is a prototype of a local interception layer. It injects a native shim into a process and proxies selected libc
operations to a Go relay over a protected Unix socket.`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newRootCommand().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "mogate:", err)
		os.Exit(1)
	}
}

// newRootCommand assembles the mogate command tree.
func newRootCommand() *cobra.Command {
	cobra.EnableCommandSorting = false
	root := &cobra.Command{
		Use:           "mogate",
		Short:         "local process I/O redirection prototype",
		Long:          rootLong,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.AddCommand(
		newAgentCommand(),
		newExecCommand(),
		newRunCommand(),
		newDevCommand(),
		newIncomingAgentCommand(),
		newIncomingCommand(),
		newKubeAgentCommand(),
	)
	return root
}

// newAgentCommand serves proxy requests on a Unix socket.
func newAgentCommand() *cobra.Command {
	var (
		socket         string
		root           string
		maxConnections int
		dialTimeout    time.Duration
	)
	cmd := &cobra.Command{
		Use:   "agent [flags]",
		Short: "serve proxy requests on a Unix socket",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			server, err := agent.New(agent.Config{
				SocketPath:     socket,
				Root:           root,
				MaxConnections: maxConnections,
				DialTimeout:    dialTimeout,
				Logger:         stderrLogger(),
			})
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "mogate agent listening on", socket)
			return server.Serve(cmd.Context())
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&socket, "socket", defaultSocket(), "Unix socket path")
	flags.StringVar(&root, "root", "/", "root visible to remote file operations")
	flags.IntVar(&maxConnections, "max-connections", 256, "maximum concurrent clients")
	flags.DurationVar(&dialTimeout, "dial-timeout", 10*time.Second, "outbound connect and DNS timeout")
	return cmd
}

// newExecCommand injects the hook library into a command whose agent is running.
func newExecCommand() *cobra.Command {
	options := execOptions{}
	cmd := &cobra.Command{
		Use:   "exec [flags] -- command [args...]",
		Short: "inject the hook library into a command (agent already running)",
		RunE: func(cmd *cobra.Command, args []string) error {
			command := commandAfterDash(cmd, args)
			if len(command) == 0 {
				return errors.New("missing command after --")
			}
			return execute(cmd.Context(), options, command)
		},
	}
	flags := cmd.Flags()
	flags.SetInterspersed(false)
	flags.StringVar(&options.socket, "socket", defaultSocket(), "agent Unix socket path")
	flags.StringVar(&options.library, "library", defaultLibrary(), "injector shared library")
	flags.BoolVar(&options.files, "files", true, "redirect absolute file paths")
	return cmd
}

// newRunCommand starts an in-process agent, then injects and runs a command.
func newRunCommand() *cobra.Command {
	var (
		socket  string
		root    string
		library string
		files   bool
	)
	cmd := &cobra.Command{
		Use:   "run [flags] -- command [args...]",
		Short: "start an in-process agent, then inject and run a command",
		RunE: func(cmd *cobra.Command, args []string) error {
			command := commandAfterDash(cmd, args)
			if len(command) == 0 {
				return errors.New("missing command after --")
			}
			return runCombinedSession(cmd.Context(), socket, root, library, files, command)
		},
	}
	flags := cmd.Flags()
	flags.SetInterspersed(false)
	flags.StringVar(&socket, "socket", defaultSocket(), "Unix socket path")
	flags.StringVar(&root, "root", "/", "root visible to remote file operations")
	flags.StringVar(&library, "library", defaultLibrary(), "injector shared library")
	flags.BoolVar(&files, "files", true, "redirect absolute file paths")
	return cmd
}

// newDevCommand runs an injected command and attaches incoming Kubernetes
// traffic through the shared pkg/local session flow.
func newDevCommand() *cobra.Command {
	var (
		socket          string
		library         string
		files           bool
		control         string
		egressControl   string
		target          string
		token           string
		tokenFile       string
		maxConnections  int
		incomingEnabled bool
		udp             bool
	)
	cmd := &cobra.Command{
		Use:   "dev [flags] -- command [args...]",
		Short: "run an injected command and attach incoming Kubernetes traffic",
		RunE: func(cmd *cobra.Command, args []string) error {
			command := commandAfterDash(cmd, args)
			if len(command) == 0 {
				return errors.New("missing command after --")
			}
			sessionToken, err := resolveSessionToken(token, tokenFile)
			if err != nil {
				return err
			}
			// pkg/local reads the token from a file only, keeping it out of argv
			// and the environment. Bridge the resolved token (which may have come
			// from --token or $MOGATE_TOKEN) through a private 0600 file removed
			// when dev returns.
			tokenPath, cleanup, err := writeTempTokenFile(sessionToken)
			if err != nil {
				return err
			}
			defer cleanup()

			root := ""
			if files {
				root = "/"
			}
			return local.Run(cmd.Context(), local.Config{
				ControlAddr:    control,
				EgressAddr:     egressControl,
				Target:         target,
				TokenFile:      tokenPath,
				Socket:         socket,
				InjectorLib:    library,
				Root:           root,
				UDP:            udp,
				MaxConnections: maxConnections,
				Modes: local.Modes{
					Egress:   true,
					Incoming: incomingEnabled,
					Files:    files,
				},
				Logger: stderrLogger(),
			}, command)
		},
	}
	flags := cmd.Flags()
	flags.SetInterspersed(false)
	flags.StringVar(&socket, "socket", defaultSocket(), "Unix socket path")
	flags.StringVar(&library, "library", defaultLibrary(), "injector shared library")
	flags.BoolVar(&files, "files", true, "redirect absolute file paths")
	flags.StringVar(&control, "control", "127.0.0.1:30000", "Kubernetes traffic-agent control address")
	flags.StringVar(&egressControl, "egress-control", "127.0.0.1:30001", "Kubernetes remote-egress address")
	flags.StringVar(&target, "target", "127.0.0.1:8080", "local application address")
	flags.StringVar(&token, "token", os.Getenv("MOGATE_TOKEN"), tokenFlagUsage)
	flags.StringVar(&tokenFile, "token-file", os.Getenv("MOGATE_TOKEN_FILE"), tokenFileFlagUsage)
	flags.IntVar(&maxConnections, "max-connections", 256, "maximum concurrent incoming connections")
	flags.BoolVar(&incomingEnabled, "incoming", true, "attach incoming TCP traffic")
	flags.BoolVar(&udp, "udp", true, "attach incoming UDP traffic")
	return cmd
}

// newIncomingAgentCommand captures remote TCP/UDP traffic for steal or mirror.
func newIncomingAgentCommand() *cobra.Command {
	var (
		listen            string
		control           string
		upstream          string
		mode              string
		token             string
		tokenFile         string
		claimTimeout      time.Duration
		mirrorClaimWindow time.Duration
		maxConnections    int
		udp               bool
	)
	cmd := &cobra.Command{
		Use:   "incoming-agent [flags]",
		Short: "capture remote TCP/UDP traffic for steal/mirror",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sessionToken, err := resolveSessionToken(token, tokenFile)
			if err != nil {
				return err
			}
			capture, err := incoming.NewCapture(incoming.CaptureConfig{
				ListenAddr:        listen,
				ControlAddr:       control,
				UpstreamAddr:      upstream,
				Token:             sessionToken,
				Mode:              incoming.Mode(mode),
				ClaimTimeout:      claimTimeout,
				MirrorClaimWindow: mirrorClaimWindow,
				MaxConnections:    maxConnections,
				EnableUDP:         udp,
				Logger:            stderrLogger(),
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "mogate incoming-agent: capture=%s control=%s mode=%s\n", listen, control, mode)
			return capture.Serve(cmd.Context())
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&listen, "listen", "0.0.0.0:15080", "captured traffic listen address")
	flags.StringVar(&control, "control", "127.0.0.1:30000", "control listen address")
	flags.StringVar(&upstream, "upstream", "", "original service address, required for mirror")
	flags.StringVar(&mode, "mode", string(incoming.ModeSteal), "incoming mode: steal or mirror")
	flags.StringVar(&token, "token", os.Getenv("MOGATE_TOKEN"), tokenFlagUsage)
	flags.StringVar(&tokenFile, "token-file", os.Getenv("MOGATE_TOKEN_FILE"), tokenFileFlagUsage)
	flags.DurationVar(&claimTimeout, "claim-timeout", 2*time.Second, "maximum wait for a local claim")
	flags.DurationVar(&mirrorClaimWindow, "mirror-claim-window", 200*time.Millisecond, "mirror-mode cap on waiting for a local claim; raise for high-latency transports since it bounds the added delay to the real response")
	flags.IntVar(&maxConnections, "max-connections", 256, "maximum concurrent connections")
	flags.BoolVar(&udp, "udp", false, "also capture UDP on the listen address")
	return cmd
}

// newIncomingCommand forwards captured traffic to a local process.
func newIncomingCommand() *cobra.Command {
	var (
		control        string
		target         string
		token          string
		tokenFile      string
		maxConnections int
		udp            bool
	)
	cmd := &cobra.Command{
		Use:   "incoming [flags]",
		Short: "forward captured traffic to a local process",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sessionToken, err := resolveSessionToken(token, tokenFile)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "mogate incoming: control=%s target=%s\n", control, target)
			config := incoming.ForwardConfig{
				ControlAddr:    control,
				TargetAddr:     target,
				Token:          sessionToken,
				MaxConnections: maxConnections,
				Logger:         stderrLogger(),
			}
			if !udp {
				return incoming.Forward(cmd.Context(), config)
			}
			return session.Run(cmd.Context(),
				session.Task{Name: "incoming tcp", Run: func(taskCtx context.Context) error { return incoming.Forward(taskCtx, config) }},
				session.Task{Name: "incoming udp", Run: func(taskCtx context.Context) error { return incoming.ForwardUDP(taskCtx, config) }},
			)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&control, "control", "127.0.0.1:30000", "capture-agent control address")
	flags.StringVar(&target, "target", "127.0.0.1:8080", "local application address")
	flags.StringVar(&token, "token", os.Getenv("MOGATE_TOKEN"), tokenFlagUsage)
	flags.StringVar(&tokenFile, "token-file", os.Getenv("MOGATE_TOKEN_FILE"), tokenFileFlagUsage)
	flags.IntVar(&maxConnections, "max-connections", 256, "maximum concurrent connections")
	flags.BoolVar(&udp, "udp", false, "also forward incoming UDP")
	return cmd
}

// newKubeAgentCommand installs nftables redirects and captures pod traffic.
func newKubeAgentCommand() *cobra.Command {
	var (
		appPort           uint
		agentPort         uint
		proxyPort         uint
		control           string
		egressControl     string
		mode              string
		token             string
		tokenFile         string
		table             string
		claimTimeout      time.Duration
		mirrorClaimWindow time.Duration
		maxConnections    int
		udp               bool
		agentGID          uint
		root              string
		podIP             string
	)
	cmd := &cobra.Command{
		Use:   "kube-agent [flags]",
		Short: "install nftables redirects and capture pod traffic",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if appPort > 65535 || agentPort > 65535 || proxyPort > 65535 {
				return errors.New("ports must be between 1 and 65535")
			}
			if uint64(agentGID) > uint64(^uint32(0)) {
				return errors.New("agent gid is out of range")
			}
			sessionToken, err := resolveSessionToken(token, tokenFile)
			if err != nil {
				return err
			}
			redirector, err := kube.NewRedirector(kube.RedirectConfig{
				TableName: table,
				AppPort:   uint16(appPort),
				AgentPort: uint16(agentPort),
				ProxyPort: uint16(proxyPort),
				EnableUDP: udp,
				AgentGID:  uint32(agentGID),
				PodIP:     podIP,
			})
			if err != nil {
				return err
			}
			if err := redirector.Install(); err != nil {
				return err
			}
			defer func() {
				if cleanupErr := redirector.Cleanup(); cleanupErr != nil {
					slog.Error("nftables cleanup failed", "error", cleanupErr)
				}
			}()

			capture, err := incoming.NewCapture(incoming.CaptureConfig{
				ListenAddr:        fmt.Sprintf("0.0.0.0:%d", agentPort),
				ControlAddr:       control,
				UpstreamAddr:      fmt.Sprintf("127.0.0.1:%d", proxyPort),
				Token:             sessionToken,
				Mode:              incoming.Mode(mode),
				ClaimTimeout:      claimTimeout,
				MirrorClaimWindow: mirrorClaimWindow,
				MaxConnections:    maxConnections,
				EnableUDP:         udp,
				Logger:            stderrLogger(),
			})
			if err != nil {
				return err
			}
			handler, err := agent.NewHandler(agent.Config{
				Root:           root,
				MaxConnections: maxConnections,
				Logger:         stderrLogger(),
			})
			if err != nil {
				return err
			}
			egressServer, err := egress.NewServer(egress.ServerConfig{
				ListenAddr:     egressControl,
				Token:          sessionToken,
				MaxConnections: maxConnections,
				Logger:         stderrLogger(),
			}, handler)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "mogate kube-agent: app=%d capture=%d proxy=%d control=%s egress=%s mode=%s\n", appPort, agentPort, proxyPort, control, egressControl, mode)
			return session.Run(cmd.Context(),
				session.Task{Name: "incoming capture", Run: capture.Serve},
				session.Task{Name: "remote egress", Run: egressServer.Serve},
			)
		},
	}
	flags := cmd.Flags()
	flags.UintVar(&appPort, "app-port", 8080, "application container port")
	flags.UintVar(&agentPort, "agent-port", 15080, "traffic-agent capture port")
	flags.UintVar(&proxyPort, "proxy-port", 15081, "reserved application passthrough port")
	flags.StringVar(&control, "control", "0.0.0.0:30000", "control listen address")
	flags.StringVar(&egressControl, "egress-control", "0.0.0.0:30001", "remote egress listen address")
	flags.StringVar(&mode, "mode", string(incoming.ModeSteal), "incoming mode: steal or mirror")
	flags.StringVar(&token, "token", os.Getenv("MOGATE_TOKEN"), tokenFlagUsage)
	flags.StringVar(&tokenFile, "token-file", os.Getenv("MOGATE_TOKEN_FILE"), tokenFileFlagUsage)
	flags.StringVar(&table, "table", kube.DefaultTableName, "dedicated nftables table name")
	flags.DurationVar(&claimTimeout, "claim-timeout", 2*time.Second, "maximum wait for a local claim")
	flags.DurationVar(&mirrorClaimWindow, "mirror-claim-window", 200*time.Millisecond, "mirror-mode cap on waiting for a local claim; raise for high-latency transports since it bounds the added delay to the real response")
	flags.IntVar(&maxConnections, "max-connections", 256, "maximum concurrent connections")
	flags.BoolVar(&udp, "udp", true, "capture UDP on the application port")
	flags.UintVar(&agentGID, "agent-gid", 65533, "group id used to bypass the agent's own egress")
	flags.StringVar(&root, "root", "/", "root visible to remote file operations")
	flags.StringVar(&podIP, "pod-ip", os.Getenv("MOGATE_POD_IP"), "target Pod IP for service-mesh delivery")
	return cmd
}

// runCombinedSession starts an in-process agent, waits for its socket, then
// injects and runs command, returning the first non-nil error.
func runCombinedSession(ctx context.Context, socket, root, library string, files bool, command []string) error {
	server, err := agent.New(agent.Config{SocketPath: socket, Root: root})
	if err != nil {
		return err
	}
	agentCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	ready := make(chan error, 1)
	go func() { ready <- server.Serve(agentCtx) }()
	if err := session.WaitForSocket(ctx, socket, ready); err != nil {
		return err
	}
	err = execute(ctx, execOptions{socket: socket, library: library, files: files}, command)
	cancel()
	serveErr := <-ready
	if err != nil {
		return err
	}
	return serveErr
}

// resolveSessionToken determines the shared session token, preferring the
// token file over the flag or environment value. A token file keeps the secret
// out of argv (visible in ps) and out of the process environment (readable via
// /proc/<pid>/environ and inherited by children). The resolved token is
// validated so a weak or malformed secret fails fast at startup.
func resolveSessionToken(flagToken, tokenFile string) (string, error) {
	token := flagToken
	if tokenFile != "" {
		data, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("read token file %q: %w", tokenFile, err)
		}
		token = strings.TrimRight(string(data), " \t\r\n")
	}
	if err := sessiontransport.ValidateToken(token); err != nil {
		return "", fmt.Errorf("session token: %w", err)
	}
	return token, nil
}

// writeTempTokenFile writes token to a fresh 0600 file inside a private 0700
// directory and returns the path plus a cleanup that removes the directory.
func writeTempTokenFile(token string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "mogate-token-")
	if err != nil {
		return "", nil, fmt.Errorf("create token directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("write token file: %w", err)
	}
	return path, cleanup, nil
}

// execOptions configures how the injector is loaded into a command.
type execOptions struct {
	socket  string
	library string
	files   bool
}

// execute runs command with the injector loaded through the platform loader
// variable. It returns a descriptive error for a non-zero command exit.
func execute(ctx context.Context, options execOptions, command []string) error {
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
func injectedEnvironment(base []string, options execOptions, library string) []string {
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

// stderrLogger returns a text logger writing to stderr.
func stderrLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

// commandAfterDash returns the arguments following a literal "--", or all
// positional arguments when no "--" is present.
func commandAfterDash(cmd *cobra.Command, args []string) []string {
	if dash := cmd.ArgsLenAtDash(); dash >= 0 {
		return args[dash:]
	}
	return args
}

// defaultSocket returns the default per-user relay socket path.
func defaultSocket() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("mogate-%d", os.Getuid()), "agent.sock")
}

// defaultLibrary returns the injector library path discovered beside the binary.
func defaultLibrary() string {
	name := "libmogate.so"
	if runtime.GOOS == "darwin" {
		name = "libmogate.dylib"
	}
	executable, err := os.Executable()
	if err != nil {
		return filepath.Join("bin", name)
	}
	return filepath.Join(filepath.Dir(executable), name)
}
