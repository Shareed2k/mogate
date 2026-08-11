package main

import (
	"context"
	"errors"
	"flag"
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

	"github.com/shareed2k/mogate/internal/agent"
	"github.com/shareed2k/mogate/internal/egress"
	"github.com/shareed2k/mogate/internal/incoming"
	"github.com/shareed2k/mogate/internal/kube"
	"github.com/shareed2k/mogate/internal/session"
	"github.com/shareed2k/mogate/internal/sessiontransport"
)

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

const (
	tokenFlagUsage     = "shared session token (or MOGATE_TOKEN); visible in ps, prefer --token-file"
	tokenFileFlagUsage = "read the session token from a file (or MOGATE_TOKEN_FILE); preferred over --token"
)

const usage = `mogate - local process I/O redirection prototype

Usage:
  mogate agent [flags]
  mogate exec [flags] -- command [args...]
  mogate run [flags] -- command [args...]
  mogate dev [flags] -- command [args...]
  mogate incoming-agent [flags]
  mogate incoming [flags]
  mogate kube-agent [flags]

Commands:
  agent  serve proxy requests on a Unix socket
  exec   inject the hook library into a command (agent already running)
  run    start an in-process agent, then inject and run a command
  dev    run an injected command and attach incoming Kubernetes traffic
  incoming-agent  capture remote TCP/UDP traffic for steal/mirror
  incoming        forward captured traffic to a local process
  kube-agent      install nftables redirects and capture pod traffic
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mogate:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("a command is required")
	}
	switch args[0] {
	case "agent":
		return runAgent(ctx, args[1:])
	case "exec":
		return runExec(ctx, args[1:])
	case "run":
		return runCombined(ctx, args[1:])
	case "dev":
		return runDev(ctx, args[1:])
	case "incoming-agent":
		return runIncomingAgent(ctx, args[1:])
	case "incoming":
		return runIncoming(ctx, args[1:])
	case "kube-agent":
		return runKubeAgent(ctx, args[1:])
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runDev(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("dev", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	socket := flags.String("socket", defaultSocket(), "Unix socket path")
	library := flags.String("library", defaultLibrary(), "injector shared library")
	files := flags.Bool("files", true, "redirect absolute file paths")
	control := flags.String("control", "127.0.0.1:30000", "Kubernetes traffic-agent control address")
	egressControl := flags.String("egress-control", "127.0.0.1:30001", "Kubernetes remote-egress address")
	target := flags.String("target", "127.0.0.1:8080", "local application address")
	token := flags.String("token", os.Getenv("MOGATE_TOKEN"), tokenFlagUsage)
	tokenFile := flags.String("token-file", os.Getenv("MOGATE_TOKEN_FILE"), tokenFileFlagUsage)
	maxConnections := flags.Int("max-connections", 256, "maximum concurrent incoming connections")
	incomingEnabled := flags.Bool("incoming", true, "attach incoming TCP traffic")
	udp := flags.Bool("udp", true, "attach incoming UDP traffic")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() == 0 {
		return errors.New("missing command after --")
	}
	sessionToken, err := resolveSessionToken(*token, *tokenFile)
	if err != nil {
		return err
	}

	relay, err := egress.NewRelay(egress.RelayConfig{
		SocketPath:     *socket,
		RemoteAddr:     *egressControl,
		Token:          sessionToken,
		MaxConnections: *maxConnections,
		Logger:         slog.New(slog.NewTextHandler(os.Stderr, nil)),
	})
	if err != nil {
		return err
	}
	devCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	relayResult := make(chan error, 1)
	go func() { relayResult <- relay.Serve(devCtx) }()
	if err := session.WaitForSocket(devCtx, *socket, relayResult); err != nil {
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
	if *incomingEnabled {
		tasks = append(tasks, session.Task{Name: "incoming tunnel", Run: func(taskCtx context.Context) error {
			return incoming.Forward(taskCtx, incoming.ForwardConfig{
				ControlAddr:    *control,
				TargetAddr:     *target,
				Token:          sessionToken,
				MaxConnections: *maxConnections,
				Logger:         slog.New(slog.NewTextHandler(os.Stderr, nil)),
			})
		}})
	}
	if *incomingEnabled && *udp {
		tasks = append(tasks, session.Task{Name: "incoming udp tunnel", Run: func(taskCtx context.Context) error {
			return incoming.ForwardUDP(taskCtx, incoming.ForwardConfig{
				ControlAddr:    *control,
				TargetAddr:     *target,
				Token:          sessionToken,
				MaxConnections: *maxConnections,
				Logger:         slog.New(slog.NewTextHandler(os.Stderr, nil)),
			})
		}})
	}
	tasks = append(tasks, session.Task{Name: "command", Run: func(taskCtx context.Context) error {
		return execute(taskCtx, execOptions{
			socket:  *socket,
			library: *library,
			files:   *files,
		}, flags.Args())
	}})
	return session.Run(devCtx, tasks...)
}

func runKubeAgent(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("kube-agent", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	appPort := flags.Uint("app-port", 8080, "application container port")
	agentPort := flags.Uint("agent-port", 15080, "traffic-agent capture port")
	proxyPort := flags.Uint("proxy-port", 15081, "reserved application passthrough port")
	control := flags.String("control", "0.0.0.0:30000", "control listen address")
	egressControl := flags.String("egress-control", "0.0.0.0:30001", "remote egress listen address")
	mode := flags.String("mode", string(incoming.ModeSteal), "incoming mode: steal or mirror")
	token := flags.String("token", os.Getenv("MOGATE_TOKEN"), tokenFlagUsage)
	tokenFile := flags.String("token-file", os.Getenv("MOGATE_TOKEN_FILE"), tokenFileFlagUsage)
	table := flags.String("table", kube.DefaultTableName, "dedicated nftables table name")
	claimTimeout := flags.Duration("claim-timeout", 2*time.Second, "maximum wait for a local claim")
	maxConnections := flags.Int("max-connections", 256, "maximum concurrent connections")
	udp := flags.Bool("udp", true, "capture UDP on the application port")
	agentGID := flags.Uint("agent-gid", 65533, "group id used to bypass the agent's own egress")
	root := flags.String("root", "/", "root visible to remote file operations")
	podIP := flags.String("pod-ip", os.Getenv("MOGATE_POD_IP"), "target Pod IP for service-mesh delivery")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("kube-agent accepts no positional arguments")
	}
	if *appPort > 65535 || *agentPort > 65535 || *proxyPort > 65535 {
		return errors.New("ports must be between 1 and 65535")
	}
	if uint64(*agentGID) > uint64(^uint32(0)) {
		return errors.New("agent gid is out of range")
	}
	sessionToken, err := resolveSessionToken(*token, *tokenFile)
	if err != nil {
		return err
	}

	redirector, err := kube.NewRedirector(kube.RedirectConfig{
		TableName: *table,
		AppPort:   uint16(*appPort),
		AgentPort: uint16(*agentPort),
		ProxyPort: uint16(*proxyPort),
		EnableUDP: *udp,
		AgentGID:  uint32(*agentGID),
		PodIP:     *podIP,
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
		ListenAddr:     fmt.Sprintf("0.0.0.0:%d", *agentPort),
		ControlAddr:    *control,
		UpstreamAddr:   fmt.Sprintf("127.0.0.1:%d", *proxyPort),
		Token:          sessionToken,
		Mode:           incoming.Mode(*mode),
		ClaimTimeout:   *claimTimeout,
		MaxConnections: *maxConnections,
		EnableUDP:      *udp,
		Logger:         slog.New(slog.NewTextHandler(os.Stderr, nil)),
	})
	if err != nil {
		return err
	}
	handler, err := agent.NewHandler(agent.Config{
		Root:           *root,
		MaxConnections: *maxConnections,
		Logger:         slog.New(slog.NewTextHandler(os.Stderr, nil)),
	})
	if err != nil {
		return err
	}
	egressServer, err := egress.NewServer(egress.ServerConfig{
		ListenAddr:     *egressControl,
		Token:          sessionToken,
		MaxConnections: *maxConnections,
		Logger:         slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}, handler)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "mogate kube-agent: app=%d capture=%d proxy=%d control=%s egress=%s mode=%s\n", *appPort, *agentPort, *proxyPort, *control, *egressControl, *mode)
	return session.Run(ctx,
		session.Task{Name: "incoming capture", Run: capture.Serve},
		session.Task{Name: "remote egress", Run: egressServer.Serve},
	)
}

func runIncomingAgent(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("incoming-agent", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	listen := flags.String("listen", "0.0.0.0:15080", "captured traffic listen address")
	control := flags.String("control", "127.0.0.1:30000", "control listen address")
	upstream := flags.String("upstream", "", "original service address, required for mirror")
	mode := flags.String("mode", string(incoming.ModeSteal), "incoming mode: steal or mirror")
	token := flags.String("token", os.Getenv("MOGATE_TOKEN"), tokenFlagUsage)
	tokenFile := flags.String("token-file", os.Getenv("MOGATE_TOKEN_FILE"), tokenFileFlagUsage)
	claimTimeout := flags.Duration("claim-timeout", 2*time.Second, "maximum wait for a local claim")
	maxConnections := flags.Int("max-connections", 256, "maximum concurrent connections")
	udp := flags.Bool("udp", false, "also capture UDP on the listen address")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("incoming-agent accepts no positional arguments")
	}
	sessionToken, err := resolveSessionToken(*token, *tokenFile)
	if err != nil {
		return err
	}
	capture, err := incoming.NewCapture(incoming.CaptureConfig{
		ListenAddr:     *listen,
		ControlAddr:    *control,
		UpstreamAddr:   *upstream,
		Token:          sessionToken,
		Mode:           incoming.Mode(*mode),
		ClaimTimeout:   *claimTimeout,
		MaxConnections: *maxConnections,
		EnableUDP:      *udp,
		Logger:         slog.New(slog.NewTextHandler(os.Stderr, nil)),
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "mogate incoming-agent: capture=%s control=%s mode=%s\n", *listen, *control, *mode)
	return capture.Serve(ctx)
}

func runIncoming(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("incoming", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	control := flags.String("control", "127.0.0.1:30000", "capture-agent control address")
	target := flags.String("target", "127.0.0.1:8080", "local application address")
	token := flags.String("token", os.Getenv("MOGATE_TOKEN"), tokenFlagUsage)
	tokenFile := flags.String("token-file", os.Getenv("MOGATE_TOKEN_FILE"), tokenFileFlagUsage)
	maxConnections := flags.Int("max-connections", 256, "maximum concurrent connections")
	udp := flags.Bool("udp", false, "also forward incoming UDP")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("incoming accepts no positional arguments")
	}
	sessionToken, err := resolveSessionToken(*token, *tokenFile)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "mogate incoming: control=%s target=%s\n", *control, *target)
	config := incoming.ForwardConfig{
		ControlAddr:    *control,
		TargetAddr:     *target,
		Token:          sessionToken,
		MaxConnections: *maxConnections,
		Logger:         slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}
	if !*udp {
		return incoming.Forward(ctx, config)
	}
	return session.Run(ctx,
		session.Task{Name: "incoming tcp", Run: func(taskCtx context.Context) error { return incoming.Forward(taskCtx, config) }},
		session.Task{Name: "incoming udp", Run: func(taskCtx context.Context) error { return incoming.ForwardUDP(taskCtx, config) }},
	)
}

func runAgent(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("agent", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	socket := flags.String("socket", defaultSocket(), "Unix socket path")
	root := flags.String("root", "/", "root visible to remote file operations")
	maxConnections := flags.Int("max-connections", 256, "maximum concurrent clients")
	dialTimeout := flags.Duration("dial-timeout", 10*time.Second, "outbound connect and DNS timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("agent accepts no positional arguments")
	}
	server, err := agent.New(agent.Config{
		SocketPath:     *socket,
		Root:           *root,
		MaxConnections: *maxConnections,
		DialTimeout:    *dialTimeout,
		Logger:         slog.New(slog.NewTextHandler(os.Stderr, nil)),
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "mogate agent listening on", *socket)
	return server.Serve(ctx)
}

func runExec(ctx context.Context, args []string) error {
	options, command, err := parseExecFlags("exec", args)
	if err != nil {
		return err
	}
	return execute(ctx, options, command)
}

func runCombined(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	socket := flags.String("socket", defaultSocket(), "Unix socket path")
	root := flags.String("root", "/", "root visible to remote file operations")
	library := flags.String("library", defaultLibrary(), "injector shared library")
	files := flags.Bool("files", true, "redirect absolute file paths")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() == 0 {
		return errors.New("missing command after --")
	}
	server, err := agent.New(agent.Config{SocketPath: *socket, Root: *root})
	if err != nil {
		return err
	}
	agentCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	ready := make(chan error, 1)
	go func() { ready <- server.Serve(agentCtx) }()
	if err := session.WaitForSocket(ctx, *socket, ready); err != nil {
		return err
	}
	err = execute(ctx, execOptions{socket: *socket, library: *library, files: *files}, flags.Args())
	cancel()
	serveErr := <-ready
	if err != nil {
		return err
	}
	return serveErr
}

type execOptions struct {
	socket  string
	library string
	files   bool
}

func parseExecFlags(name string, args []string) (execOptions, []string, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	options := execOptions{}
	flags.StringVar(&options.socket, "socket", defaultSocket(), "agent Unix socket path")
	flags.StringVar(&options.library, "library", defaultLibrary(), "injector shared library")
	flags.BoolVar(&options.files, "files", true, "redirect absolute file paths")
	if err := flags.Parse(args); err != nil {
		return execOptions{}, nil, err
	}
	if flags.NArg() == 0 {
		return execOptions{}, nil, errors.New("missing command after --")
	}
	return options, flags.Args(), nil
}

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

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			return strings.TrimPrefix(item, prefix)
		}
	}
	return ""
}

func defaultSocket() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("mogate-%d", os.Getuid()), "agent.sock")
}

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
