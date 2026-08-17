//go:build integration

package main_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	k3sImage     = "rancher/k3s:v1.34.2-k3s1"
	mogateImage  = "mogate:e2e"
	fixtureImage = "mogate-fixture:e2e"
	toolboxImage = "mogate-toolbox:e2e"
	testToken    = "0123456789abcdef-mogate-e2e-token"
)

func TestK3sE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Docker+k3s integration test in short mode")
	}
	ensureDockerHost(t)
	// Colima exposes its Docker socket through a macOS path that cannot be
	// bind-mounted into its Linux VM by Ryuk. Every resource created below has
	// explicit t.Cleanup handling, so the reaper is unnecessary for this test.
	t.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	root := projectRoot(t)
	workDir := t.TempDir()

	provider, err := testcontainers.NewDockerProvider()
	if err != nil {
		t.Fatalf("create Docker provider: %v", err)
	}
	defer provider.Close()
	buildImage(t, ctx, provider, root, "Dockerfile", "mogate", "e2e")
	buildImage(t, ctx, provider, root, "test/e2e/Dockerfile.fixture", "mogate-fixture", "e2e")
	buildImage(t, ctx, provider, root, "test/e2e/Dockerfile.toolbox", "mogate-toolbox", "e2e")
	t.Cleanup(func() {
		_, _ = provider.Client().ImageRemove(context.Background(), mogateImage, image.RemoveOptions{Force: true, PruneChildren: true})
		_, _ = provider.Client().ImageRemove(context.Background(), fixtureImage, image.RemoveOptions{Force: true, PruneChildren: true})
		_, _ = provider.Client().ImageRemove(context.Background(), toolboxImage, image.RemoveOptions{Force: true, PruneChildren: true})
	})

	k3s, err := testcontainers.Run(ctx, k3sImage,
		testcontainers.WithExposedPorts("6443/tcp"),
		testcontainers.WithCmd("server", "--disable=traefik", "--disable=servicelb", "--write-kubeconfig-mode=644", "--tls-san=127.0.0.1"),
		testcontainers.WithHostConfigModifier(func(config *container.HostConfig) { config.Privileged = true }),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("6443/tcp").WithStartupTimeout(2*time.Minute)),
	)
	if err != nil {
		t.Fatalf("start k3s: %v", err)
	}
	testcontainers.CleanupContainer(t, k3s)
	importImages(t, ctx, provider, k3s, workDir)
	kubeconfig := copyKubeconfig(t, ctx, k3s, workDir)
	waitForNodes(t, ctx, kubeconfig)
	kubectl(t, ctx, kubeconfig, "wait", "--for=condition=Ready", "node", "--all", "--timeout=120s")
	kubectl(t, ctx, kubeconfig, "apply", "-f", filepath.Join(root, "test/e2e/kubernetes.yaml"))
	kubectl(t, ctx, kubeconfig, "rollout", "status", "deployment/mogate-target", "--timeout=120s")
	kubectl(t, ctx, kubeconfig, "rollout", "status", "deployment/cluster-api", "--timeout=120s")

	t.Run("passthrough without local session", func(t *testing.T) {
		assertClusterRequestEventually(t, ctx, kubeconfig, "tcp", "mogate-target:8080", "remote-target")
		assertClusterRequestEventually(t, ctx, kubeconfig, "udp", "mogate-target:8080", "remote-target")
	})

	pod := strings.TrimSpace(kubectl(t, ctx, kubeconfig, "get", "pod", "-l", "app=mogate-target", "-o", "jsonpath={.items[0].metadata.name}"))
	incomingPort, egressPort := freeTCPPort(t), freeTCPPort(t)
	portForwardCtx, stopPortForward := context.WithCancel(ctx)
	portForwardLog := filepath.Join(workDir, "port-forward.log")
	portForward := startCommand(t, portForwardCtx, root, portForwardLog, nil,
		"kubectl", "--kubeconfig", kubeconfig, "port-forward", "pod/"+pod,
		fmt.Sprintf("%d:30000", incomingPort), fmt.Sprintf("%d:30001", egressPort))
	t.Cleanup(func() {
		stopPortForward()
		_ = portForward.Wait()
	})
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		t.Logf("pod state:\n%s", kubectlNoFail(context.Background(), kubeconfig,
			"get", "pods", "-o", "wide"))
		t.Logf("target app logs:\n%s", kubectlNoFail(context.Background(), kubeconfig,
			"logs", pod, "-c", "application", "--tail=200"))
		t.Logf("target agent logs:\n%s", kubectlNoFail(context.Background(), kubeconfig,
			"logs", pod, "-c", "mogate", "--tail=200"))
		t.Logf("target agent previous logs:\n%s", kubectlNoFail(context.Background(), kubeconfig,
			"logs", pod, "-c", "mogate", "--previous", "--tail=200"))
		t.Logf("events:\n%s", kubectlNoFail(context.Background(), kubeconfig,
			"get", "events", "--sort-by=.lastTimestamp"))
		if data, err := os.ReadFile(portForwardLog); err == nil {
			t.Logf("port-forward logs:\n%s", data)
		}
	})
	waitForTCP(t, fmt.Sprintf("127.0.0.1:%d", incomingPort), 30*time.Second)
	waitForTCP(t, fmt.Sprintf("127.0.0.1:%d", egressPort), 30*time.Second)

	hostFixture := filepath.Join(workDir, "mogate-fixture")
	nativeClient := filepath.Join(workDir, "native-client")
	run(t, ctx, root, nil, "go", "build", "-o", hostFixture, "./test/e2e/fixture.go")
	run(t, ctx, root, nil, "cc", "-O2", "-o", nativeClient, "./test/e2e/native/client.c")
	run(t, ctx, root, nil, "make", "build")

	t.Run("incoming tcp and udp steal", func(t *testing.T) {
		localPort := freeTCPAndUDPPort(t)
		localCtx, stopLocal := context.WithCancel(ctx)
		localLog := filepath.Join(workDir, "local-target.log")
		localServer := startCommand(t, localCtx, root, localLog, nil, hostFixture,
			"server", "--address", fmt.Sprintf("127.0.0.1:%d", localPort), "--response", "local-target")
		waitForTCP(t, fmt.Sprintf("127.0.0.1:%d", localPort), 10*time.Second)

		devCtx, stopDev := context.WithCancel(ctx)
		devLog := filepath.Join(workDir, "dev-steal.log")
		dev := startCommand(t, devCtx, root, devLog, []string{"MOGATE_TOKEN=" + testToken},
			filepath.Join(root, "bin/mogate"), "dev", "--files=false",
			"--control", fmt.Sprintf("127.0.0.1:%d", incomingPort),
			"--egress-control", fmt.Sprintf("127.0.0.1:%d", egressPort),
			"--target", fmt.Sprintf("127.0.0.1:%d", localPort), "--", nativeClient, "hold")
		assertClusterRequestEventually(t, ctx, kubeconfig, "tcp", "mogate-target:8080", "local-target")
		assertClusterRequestEventually(t, ctx, kubeconfig, "udp", "mogate-target:8080", "local-target")
		stopDev()
		waitStopped(t, dev, devLog)
		stopLocal()
		waitStopped(t, localServer, localLog)
	})

	t.Run("incoming tcp and udp steal into docker", func(t *testing.T) {
		control := fmt.Sprintf("host.testcontainers.internal:%d", incomingPort)
		script := strings.Join([]string{
			"set -eu",
			"mogate-fixture server --address 127.0.0.1:18080 --response docker-local &",
			"fixture_pid=$!",
			"trap 'kill $fixture_pid 2>/dev/null || true' EXIT INT TERM",
			"until mogate-fixture request --network tcp --address 127.0.0.1:18080 --timeout 100ms >/dev/null 2>&1; do sleep 0.05; done",
			"for attempt in $(seq 1 50); do",
			"  mogate incoming --udp --control \"$CONTROL_ADDR\" --target 127.0.0.1:18080 && exit 0",
			"  sleep 0.1",
			"done",
			"exit 1",
		}, "\n")
		localContainer, err := testcontainers.Run(ctx, toolboxImage,
			testcontainers.WithEntrypoint("/bin/sh", "-c"),
			testcontainers.WithCmd(script),
			testcontainers.WithEnv(map[string]string{
				"CONTROL_ADDR": control,
				"MOGATE_TOKEN": testToken,
			}),
			testcontainers.WithHostConfigModifier(func(config *container.HostConfig) {
				config.ExtraHosts = append(config.ExtraHosts, "host.testcontainers.internal:host-gateway")
			}),
		)
		if err != nil {
			t.Fatalf("start Docker incoming target: %v", err)
		}
		testcontainers.CleanupContainer(t, localContainer)
		t.Cleanup(func() {
			if !t.Failed() {
				return
			}
			logs, logErr := localContainer.Logs(context.Background())
			if logErr != nil {
				t.Logf("Docker incoming logs unavailable: %v", logErr)
				return
			}
			defer logs.Close()
			body, _ := io.ReadAll(logs)
			t.Logf("Docker incoming logs:\n%s", body)
		})

		assertClusterRequestEventually(t, ctx, kubeconfig, "tcp", "mogate-target:8080", "docker-local")
		assertClusterRequestEventually(t, ctx, kubeconfig, "udp", "mogate-target:8080", "docker-local")
	})

	t.Run("injected cluster dns and tcp egress", func(t *testing.T) {
		output := runDevClient(t, ctx, root, nativeClient, incomingPort, egressPort, "--udp=false", "tcp")
		if !strings.Contains(output, "remote-cluster-api") {
			t.Fatalf("unexpected TCP egress output %q", output)
		}
	})
	for _, mode := range []string{"tcp-nonblocking", "tcp-select", "tcp-dup"} {
		mode := mode
		t.Run("injected "+mode+" egress", func(t *testing.T) {
			output := runDevClient(t, ctx, root, nativeClient, incomingPort, egressPort, "--udp=false", mode)
			if !strings.Contains(output, "remote-cluster-api") {
				t.Fatalf("unexpected %s egress output %q", mode, output)
			}
		})
	}
	readinessMode := "tcp-epoll"
	if runtime.GOOS == "darwin" {
		readinessMode = "tcp-kqueue"
	}
	t.Run("injected "+readinessMode+" egress", func(t *testing.T) {
		output := runDevClient(t, ctx, root, nativeClient, incomingPort, egressPort, "--udp=false", readinessMode)
		if !strings.Contains(output, "remote-cluster-api") {
			t.Fatalf("unexpected %s egress output %q", readinessMode, output)
		}
	})
	t.Run("injected cluster dns and udp egress", func(t *testing.T) {
		output := runDevClient(t, ctx, root, nativeClient, incomingPort, egressPort, "--udp=true", "udp")
		if !strings.Contains(output, "remote-cluster-api") {
			t.Fatalf("unexpected UDP egress output %q", output)
		}
	})
	t.Run("injected unconnected udp egress", func(t *testing.T) {
		output := runDevClient(t, ctx, root, nativeClient, incomingPort, egressPort, "--udp=true", "udp-unconnected")
		if !strings.Contains(output, "remote-cluster-api") {
			t.Fatalf("unexpected unconnected UDP egress output %q", output)
		}
	})
	t.Run("injected udp ancillary metadata", func(t *testing.T) {
		output := runDevClient(t, ctx, root, nativeClient, incomingPort, egressPort, "--udp=true", "udp-ancillary")
		if !strings.Contains(output, "remote-cluster-api") {
			t.Fatalf("unexpected UDP ancillary egress output %q", output)
		}
	})

	toolControl := fmt.Sprintf("host.testcontainers.internal:%d", incomingPort)
	toolEgress := fmt.Sprintf("host.testcontainers.internal:%d", egressPort)
	t.Run("real tool compatibility", func(t *testing.T) {
		tests := []struct {
			name    string
			command []string
			want    string
		}{
			{
				name: "bash dev tcp",
				command: []string{"bash", "-c",
					"exec 3<>/dev/tcp/cluster-api.default.svc.cluster.local/8080; printf probe >&3; IFS= read -r -N 18 reply <&3; printf %s \"$reply\""},
				want: "remote-cluster-api",
			},
			{name: "curl http", command: []string{"curl", "--fail", "--silent", "http://cluster-api.default.svc.cluster.local:8080/"}, want: "remote-cluster-api"},
			{name: "wget http", command: []string{"wget", "-qO-", "http://cluster-api.default.svc.cluster.local:8080/"}, want: "remote-cluster-api"},
			{name: "telnet tcp", command: []string{"bash", "-c", "{ printf probe; sleep 1; } | telnet cluster-api.default.svc.cluster.local 8080"}, want: "remote-cluster-api"},
			{name: "dig udp", command: []string{"bash", "-c", "answer=$(dig +short cluster-api.default.svc.cluster.local); test -n \"$answer\"; printf %s \"$answer\""}, want: "."},
			{name: "dig tcp", command: []string{"bash", "-c", "answer=$(dig +tcp +short cluster-api.default.svc.cluster.local); test -n \"$answer\"; printf %s \"$answer\""}, want: "."},
		}
		for _, test := range tests {
			test := test
			t.Run(test.name, func(t *testing.T) {
				output := runToolbox(t, ctx, toolControl, toolEgress, test.command)
				if !strings.Contains(output, test.want) {
					t.Fatalf("tool output %q does not contain %q", output, test.want)
				}
			})
		}
	})
}

func runToolbox(t *testing.T, ctx context.Context, control, egress string, command []string) string {
	t.Helper()
	args := []string{
		"dev", "--files=false", "--incoming=false", "--udp=false",
		"--control", control,
		"--egress-control", egress,
		"--target", "127.0.0.1:1", "--",
	}
	args = append(args, command...)
	container, err := testcontainers.Run(ctx, toolboxImage,
		testcontainers.WithCmd(args...),
		testcontainers.WithEnv(map[string]string{"MOGATE_TOKEN": testToken}),
		testcontainers.WithHostConfigModifier(func(config *container.HostConfig) {
			config.ExtraHosts = append(config.ExtraHosts, "host.testcontainers.internal:host-gateway")
		}),
		testcontainers.WithWaitStrategy(wait.ForExit().WithExitTimeout(30*time.Second)),
	)
	if err != nil {
		t.Fatalf("run toolbox %s: %v", strings.Join(command, " "), err)
	}
	testcontainers.CleanupContainer(t, container)
	logs, err := container.Logs(ctx)
	if err != nil {
		t.Fatalf("toolbox logs: %v", err)
	}
	defer logs.Close()
	output, err := io.ReadAll(logs)
	if err != nil {
		t.Fatalf("read toolbox logs: %v", err)
	}
	state, err := container.State(ctx)
	if err != nil {
		t.Fatalf("toolbox state: %v", err)
	}
	if state.ExitCode != 0 {
		t.Fatalf("toolbox %s exited %d\n%s", strings.Join(command, " "), state.ExitCode, output)
	}
	return string(output)
}

func runDevClient(t *testing.T, ctx context.Context, root, client string, incomingPort, egressPort int, udpFlag, network string) string {
	t.Helper()
	args := []string{
		"dev", "--files=false", "--incoming=false", udpFlag,
		"--control", fmt.Sprintf("127.0.0.1:%d", incomingPort),
		"--egress-control", fmt.Sprintf("127.0.0.1:%d", egressPort),
		"--target", "127.0.0.1:1", "--", client, network,
		"cluster-api.default.svc.cluster.local", "8080", "remote-cluster-api",
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		attemptCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		command := exec.CommandContext(attemptCtx, filepath.Join(root, "bin/mogate"), args...)
		command.Dir = root
		command.Env = append(os.Environ(), "MOGATE_TOKEN="+testToken)
		if network == "udp-ancillary" {
			command.Env = append(command.Env, "MOGATE_EXPECT_PKTINFO=1")
		}
		output, err := command.CombinedOutput()
		attemptErr := attemptCtx.Err()
		cancel()
		if err == nil {
			return string(output)
		}
		if errors.Is(attemptErr, context.DeadlineExceeded) {
			t.Fatalf("%s %s: timed out\n%s", command.Path, strings.Join(args, " "), output)
		}
		if strings.Contains(string(output), "watcher-active") && time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		t.Fatalf("%s %s: %v\n%s", command.Path, strings.Join(args, " "), err, output)
	}
}

func buildImage(t *testing.T, ctx context.Context, provider *testcontainers.DockerProvider, root, dockerfile, repo, tag string) {
	t.Helper()
	_, err := provider.BuildImage(ctx, &testcontainers.ContainerRequest{FromDockerfile: testcontainers.FromDockerfile{
		Context: root, Dockerfile: dockerfile, Repo: repo, Tag: tag, KeepImage: true,
	}})
	if err != nil {
		t.Fatalf("build %s:%s: %v", repo, tag, err)
	}
}

func importImages(t *testing.T, ctx context.Context, provider *testcontainers.DockerProvider, k3s testcontainers.Container, workDir string) {
	t.Helper()
	waitForContainerd(t, ctx, k3s)
	reader, err := provider.Client().ImageSave(ctx, []string{mogateImage, fixtureImage})
	if err != nil {
		t.Fatalf("save E2E images: %v", err)
	}
	defer reader.Close()
	archivePath := filepath.Join(workDir, "images.tar")
	archive, err := os.OpenFile(archivePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("create image archive: %v", err)
	}
	if _, err := io.Copy(archive, reader); err != nil {
		_ = archive.Close()
		t.Fatalf("save image archive: %v", err)
	}
	if err := archive.Close(); err != nil {
		t.Fatalf("close image archive: %v", err)
	}
	if err := k3s.CopyFileToContainer(ctx, archivePath, "/tmp/mogate-images.tar", 0o600); err != nil {
		t.Fatalf("copy images into k3s: %v", err)
	}
	code, output, err := k3s.Exec(ctx, []string{
		"/bin/ctr",
		"--address", "/run/k3s/containerd/containerd.sock",
		"--namespace", "k8s.io",
		"images", "import", "/tmp/mogate-images.tar",
	})
	if err != nil || code != 0 {
		body, _ := io.ReadAll(output)
		t.Fatalf("import images into k3s: code=%d err=%v output=%s", code, err, body)
	}
}

func waitForContainerd(t *testing.T, ctx context.Context, k3s testcontainers.Container) {
	t.Helper()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		code, _, err := k3s.Exec(ctx, []string{
			"/bin/sh", "-c", "test -S /run/k3s/containerd/containerd.sock",
		})
		if err == nil && code == 0 {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for k3s containerd: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func copyKubeconfig(t *testing.T, ctx context.Context, k3s testcontainers.Container, workDir string) string {
	t.Helper()
	host, err := k3s.Host(ctx)
	if err != nil {
		t.Fatalf("k3s host: %v", err)
	}
	port, err := k3s.MappedPort(ctx, "6443/tcp")
	if err != nil {
		t.Fatalf("k3s mapped port: %v", err)
	}
	var reader io.ReadCloser
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		reader, err = k3s.CopyFileFromContainer(ctx, "/etc/rancher/k3s/k3s.yaml")
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("copy k3s kubeconfig: %v", err)
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, 1<<20))
	if err != nil {
		t.Fatalf("read k3s kubeconfig: %v", err)
	}
	data = bytes.Replace(data, []byte("https://127.0.0.1:6443"), []byte("https://"+net.JoinHostPort(host, port.Port())), 1)
	path := filepath.Join(workDir, "kubeconfig.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

func waitForNodes(t *testing.T, ctx context.Context, kubeconfig string) {
	t.Helper()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if strings.TrimSpace(kubectlNoFail(ctx, kubeconfig, "get", "nodes", "-o", "name")) != "" {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for k3s node registration: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func assertClusterRequest(t *testing.T, ctx context.Context, kubeconfig, network, address, expected string) {
	t.Helper()
	if got := clusterRequest(t, ctx, kubeconfig, network, address); got != expected {
		t.Fatalf("%s response=%q, want %q", network, got, expected)
	}
}

func assertClusterRequestEventually(t *testing.T, ctx context.Context, kubeconfig, network, address, expected string) {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		probeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		last = clusterRequestNoFail(probeCtx, kubeconfig, network, address)
		cancel()
		if last == expected {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("%s response=%q, want %q", network, last, expected)
}

func clusterRequest(t *testing.T, ctx context.Context, kubeconfig, network, address string) string {
	t.Helper()
	result := clusterRequestNoFail(ctx, kubeconfig, network, address)
	if result == "" {
		t.Fatalf("%s cluster request failed", network)
	}
	return result
}

func clusterRequestNoFail(ctx context.Context, kubeconfig, network, address string) string {
	name := "probe-" + network + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	defer func() {
		_ = kubectlNoFail(context.Background(), kubeconfig, "delete", "pod", name, "--ignore-not-found", "--wait=false")
	}()
	if output := kubectlNoFail(ctx, kubeconfig, "run", name, "--restart=Never", "--image="+fixtureImage, "--image-pull-policy=Never", "--",
		"request", "--network", network, "--address", address, "--timeout", "8s"); strings.Contains(output, "error:") {
		return ""
	}
	for ctx.Err() == nil {
		phase := strings.TrimSpace(kubectlNoFail(ctx, kubeconfig, "get", "pod", name, "-o", "jsonpath={.status.phase}"))
		if phase == "Succeeded" {
			return strings.TrimSpace(kubectlNoFail(ctx, kubeconfig, "logs", name))
		}
		if phase == "Failed" {
			return ""
		}
		time.Sleep(200 * time.Millisecond)
	}
	return ""
}

func kubectl(t *testing.T, ctx context.Context, kubeconfig string, args ...string) string {
	t.Helper()
	output, err := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", kubeconfig}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

func kubectlNoFail(ctx context.Context, kubeconfig string, args ...string) string {
	output, _ := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", kubeconfig}, args...)...).CombinedOutput()
	return string(output)
}

func run(t *testing.T, ctx context.Context, dir string, extraEnv []string, name string, args ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	command.Env = append(os.Environ(), extraEnv...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output)
	}
	return string(output)
}

func startCommand(t *testing.T, ctx context.Context, dir, logPath string, extraEnv []string, name string, args ...string) *exec.Cmd {
	t.Helper()
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open command log: %v", err)
	}
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	command.Env = append(os.Environ(), extraEnv...)
	command.Stdout, command.Stderr = logFile, logFile
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		t.Fatalf("start %s: %v", name, err)
	}
	go func() {
		<-ctx.Done()
		_ = logFile.Close()
	}()
	return command
}

func waitStopped(t *testing.T, command *exec.Cmd, logPath string) {
	t.Helper()
	if err := command.Wait(); err != nil && !isKilled(err) {
		data, _ := os.ReadFile(logPath)
		t.Fatalf("command stopped: %v\n%s", err, data)
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func freeTCPAndUDPPort(t *testing.T) int {
	t.Helper()
	for range 20 {
		port := freeTCPPort(t)
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
		if err == nil {
			_ = udp.Close()
			return port
		}
	}
	t.Fatal("could not reserve a TCP/UDP port")
	return 0
}

func waitForTCP(t *testing.T, address string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("TCP endpoint %s did not become ready", address)
}

func ensureDockerHost(t *testing.T) {
	t.Helper()
	if os.Getenv("DOCKER_HOST") != "" {
		return
	}
	output, err := exec.Command("docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}").Output()
	if err != nil {
		t.Fatalf("discover Docker host: %v", err)
	}
	if err := os.Setenv("DOCKER_HOST", strings.TrimSpace(string(output))); err != nil {
		t.Fatalf("set Docker host: %v", err)
	}
}

func projectRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve project root: %v", err)
	}
	return root
}

func isKilled(err error) bool {
	return errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "signal: killed")
}
