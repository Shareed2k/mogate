# mogate

`mogate` is a prototype of a local interception layer. It injects a native shim into a process and sends selected libc
operations to a Go relay over a protected Unix socket.

This repository is an engineering foundation, not a feature-complete interception layer.

## What works

| Capability | Linux | macOS |
| --- | --- | --- |
| Blocking TCP `connect` proxy | Implemented and tested | Implemented and tested |
| Nonblocking TCP + `poll`/`select`/`SO_ERROR` | Implemented and tested | Implemented and tested |
| Linux `epoll` / macOS `kqueue` connect readiness | Implemented and tested | Implemented and tested |
| Connected UDP `send`/`recv` | Implemented and tested | Implemented and tested |
| Connected and unconnected UDP `sendto`/`recvfrom` | Implemented and tested | Implemented and tested |
| UDP `sendmsg`/`recvmsg`, `PEEK`/`TRUNC`/`DONTWAIT` | Implemented | Implemented |
| Portable UDP ancillary metadata | Implemented and k3s-tested | Implemented and k3s-tested |
| Descriptor aliases via `dup*` and `fcntl(F_DUPFD*)` | Implemented and tested | Implemented and tested |
| Incoming TCP steal/mirror tunnel | Implemented and tested | Implemented and tested |
| Incoming UDP steal/mirror tunnel | Implemented and tested | Implemented and tested |
| DNS A/AAAA lookup | Implemented and tested | Implemented and tested |
| Raw UDP/TCP DNS on port 53, including c-ares | Implemented and k3s-tested | Implemented |
| Virtual `getsockname`/`getpeername` identity | Implemented and k3s-tested | Implemented and tested |
| Absolute-path `open`/`openat` | Implemented | Implemented and tested |
| Remote `read`/`write`/`close` | Implemented | Implemented and tested |
| Remote `lseek`/`fstat` | Implemented | Implemented |
| Root-confined file access | Implemented with `os.Root` | Implemented with `os.Root` |

The macOS build was exercised end to end with a custom native process, including SIP-restricted system binaries (see below).

### macOS SIP-restricted binaries

macOS System Integrity Protection and the hardened runtime make protected
system binaries such as `/usr/bin/curl` and `/bin/bash` ignore
`DYLD_INSERT_LIBRARIES`, so the injector cannot load into them directly. `mogate`
works around this by running an ad-hoc-re-signed **copy** of the target instead
of the original:

- The restricted binary is copied, thinned to its `x86_64` slice, and ad-hoc
  re-signed. Re-signing strips the entitlements that enforce library
  validation, so the copy honors `DYLD_INSERT_LIBRARIES` and the injector loads.
- Originals are never modified; only the copy is patched.
- The `x86_64` copy runs under Rosetta 2. Restricted children reached through
  `execve`/`execvp`/`posix_spawn(p)` and `#!` scripts are patched the same way,
  so an injected `bash` keeps interception across the processes it launches.

Requirements: Rosetta 2 must be installed for the `x86_64` path, and an
`x86_64` build of the injector library must be present. Limitation:
`arm64e`-only binaries with no `x86_64` slice cannot be re-signed without
library validation and are unsupported — such targets fail loudly rather than
running uninjected.

## Deliberate current limits

- Nonblocking TCP returns `EINPROGRESS`; `poll`, `select`, Linux `epoll`, macOS
  `kqueue`, and `SO_ERROR` expose completion after the remote dial finishes.
- Connected and unconnected IPv4/IPv6 UDP supports `sendto`, `recvfrom`,
  `sendmsg`, and `recvmsg`. The Wire Contract carries destination/source
  packet information, interface index, hop limit, traffic class, and receive
  timestamp independently of the host ABI. The injector translates these to
  and from `IP_PKTINFO`/`IPV6_PKTINFO`, TTL/hop-limit, TOS/traffic-class, and
  `SCM_TIMESTAMP`/`SCM_TIMESTAMPNS` control messages.
- Process-local or Linux-offload ancillary messages such as `SCM_RIGHTS`,
  credentials, error-queue records, `UDP_SEGMENT`, and `UDP_GRO` are rejected
  with `ENOTSUP`; they cannot be transferred safely or faithfully across this
  process/pod boundary without a feature-specific protocol.
- Nonblocking UDP receive uses readiness probing around the framed stream. It
  preserves datagram boundaries and `MSG_PEEK`/`MSG_TRUNC`, but is not a
  byte-for-byte replacement for every platform-specific socket option.
- Incoming TCP and UDP are supported. HTTP header/path filtering, TLS termination and multiple simultaneous watchers are not implemented.
- Relative `openat`, directory operations, metadata mutation and memory mapping are not intercepted.
- Kubernetes remote file operations currently see the sidecar filesystem and
  explicitly shared volumes, not another container's private root filesystem.
- DNS interception currently supports numeric services such as `80`; named services fall back to libc.
- Incoming control is token-authenticated and intended to run through `kubectl port-forward`. It is not encrypted by itself and must not be exposed publicly.

These limits matter: claiming transparent compatibility without them would produce subtle data corruption and networking failures.

## Architecture

```text
target process
  └─ injected C ABI shim
       └─ versioned framed protocol over Unix sockets
            └─ local Go relay
                 └─ authenticated, versioned binary port-forward tunnel
                      └─ Go agent in the Pod network namespace
                           ├─ cluster TCP dial + byte tunnel
                           ├─ connected UDP datagram session
                           ├─ cluster DNS resolver
                           └─ root-confined sidecar file sessions

remote pod sidecar
  ├─ atomic nftables table programmed through Netlink
  ├─ TCP/UDP capture port and loop-safe application proxy port
  └─ claim tunnels over kubectl port-forward
       └─ local application
```

The supported application and agent are Go. The injected library is compiled as C-only code extracted from the cgo preamble in `injector/main.go`. This avoids loading a Go runtime into every target process and prevents the runtime from recursively triggering its own file hooks.

## Build

Requirements: Go 1.24 or newer and a C compiler (`clang` on macOS, `gcc` or `clang` on Linux).

```sh
make build
make test
```

Artifacts:

- `bin/mogate`
- `bin/libmogate.dylib` on macOS
- `bin/libmogate.so` on Linux

## Docker + k3s end-to-end tests

The integration suite uses `github.com/testcontainers/testcontainers-go` to
build the mogate and fixture images and start a privileged single-node k3s
container. It verifies:

- TCP and UDP passthrough when no local session is attached;
- incoming TCP and UDP stealing by a local process;
- incoming TCP and UDP stealing into an application running inside Docker;
- cluster DNS resolution from an injected native process;
- injected blocking and nonblocking TCP egress through the pod network namespace;
- `poll`/`select` plus the host platform's `epoll` or `kqueue` readiness path;
- descriptor aliasing and connected/unconnected UDP egress;
- portable UDP ancillary metadata across a macOS client and Linux k3s agent.
- real injected programs: Bash `/dev/tcp`, `curl`, `wget`, `telnet`, and
  `dig` over both UDP and TCP.

Requirements are Docker, `kubectl`, a C compiler, and Go 1.24 or newer. Run:

```sh
make e2e
```

The suite discovers the active Docker context, imports locally built images
into k3s containerd, and removes its containers and images during cleanup.

## Run

Start an agent and process together:

```sh
bin/mogate run --library bin/libmogate.dylib --root / -- your-command args...
```

On Linux, use `bin/libmogate.so` instead. The binary normally discovers the library beside itself, so an installed pair can be invoked more simply:

```sh
bin/mogate run --root / -- your-command args...
```

Run the components separately:

```sh
bin/mogate agent --socket /tmp/mogate-agent.sock --root /remote/root
bin/mogate exec --socket /tmp/mogate-agent.sock --library bin/libmogate.dylib -- your-command
```

Use `--files=false` to proxy only TCP, UDP and DNS.

For an injected interactive shell, every child process inherits the loader
environment:

```sh
bin/mogate run -- bash
```

Alternatively, source `shell/mogate.sh` and use `mogate-inject command ...` or
`mogate-shell`. This is the local injection path; no machine-wide TUN/VIF or
root daemon is installed.

To combine local injection, remote cluster egress, and the incoming Kubernetes
attachment in one process, first establish both port-forwards described below
and run:

```sh
MOGATE_TOKEN='the-same-random-token' \
  bin/mogate dev \
    --control 127.0.0.1:30000 \
    --egress-control 127.0.0.1:30001 \
    --target 127.0.0.1:8080 \
    -- bash
```

Commands launched from that shell inherit the injection. If the command itself
starts the application, replace `bash` with that command. After sourcing the
shell helper, the short form is `mogate-dev bash`.

For egress-only use, pass `--incoming=false`. This avoids claiming the single
incoming watcher while preserving injected cluster DNS plus TCP and UDP
egress:

```sh
MOGATE_TOKEN='the-same-random-token' \
  bin/mogate dev --incoming=false --egress-control 127.0.0.1:30001 -- bash
```

Raw DNS clients that send directly to the local resolver on port 53 are
forwarded to the agent's cluster resolver. When the destination is rewritten,
the response still reports the originally requested DNS peer, preserving the
source validation used by asynchronous resolvers such as c-ares.

## Embedding

The local control plane is also a small Go API, so a tool can drive an Injection
Session directly instead of shelling out to `mogate dev`. Import
`github.com/shareed2k/mogate/pkg/local` and call `local.Run`:

```go
import "github.com/shareed2k/mogate/pkg/local"

err := local.Run(ctx, local.Config{
    ControlAddr:    "127.0.0.1:30000",     // local addr port-forwarded to agent control
    EgressAddr:     "127.0.0.1:30001",     // local addr port-forwarded to agent egress
    Target:         "127.0.0.1:8080",      // local app (incoming steal/mirror target)
    TokenFile:      "/run/mogate/token",   // 0600 file; token never on argv or env
    Socket:         "/run/mogate/agent.sock",
    InjectorLib:    "bin/libmogate.dylib", // libmogate.so on Linux
    Root:           "/",                   // "" disables file redirection
    UDP:            true,                  // include UDP tunnels alongside TCP
    MaxConnections: 256,                   // 0 selects the internal default
    Modes:          local.Modes{Egress: true, Incoming: true, Files: true},
}, []string{"your-app", "--flag"})
```

`Run` establishes the egress relay, attaches the incoming TCP (and UDP, when
`UDP` is set) tunnels when `Modes.Incoming` is enabled, and runs the command with
the injector loaded, returning when the command exits or `ctx` is cancelled. The
session token is read from `TokenFile` only, keeping it out of argv and the
environment; `Run` requires a non-empty `Target` whenever `Modes.Incoming` is
set. The in-Pod agent ships as the container image built from the `Dockerfile`,
and the injector library is produced by `make build`. The public surface is
intentionally just `local.{Config, Modes, Run}`, so it stays a stable pin for
embedders.

## Incoming traffic

Build and publish the capture-agent image:

```sh
docker build -t YOUR_REGISTRY/mogate:latest .
docker push YOUR_REGISTRY/mogate:latest
```

Replace the image and token placeholders under `deploy/kubernetes`, then patch
the target workload. The example assumes the original application listens on
`8080`, the capture sidecar listens on `15080`, reserved passthrough uses
`15081`, and control uses `30000`.

`mogate kube-agent` creates a dedicated `inet mogate` table directly over
Netlink. Its `prerouting` chain captures inbound application connections. Its
`output` chain captures service-mesh delivery over loopback or the target Pod
IP, while the reserved
proxy port lets the agent reach the original application without redirecting
itself. Reapplying replaces only this table in one nftables batch; graceful
shutdown deletes only this table.

TCP and UDP use the same application, capture, and proxy port numbers. Because
`kubectl port-forward` transports TCP only, UDP datagrams are multiplexed by
session ID inside a dedicated authenticated TCP control connection. Each
remote UDP source gets an independent connected local UDP socket. Session
counts are bounded and idle sessions are closed automatically.

For UDP traffic arriving through a Kubernetes Service, that Service must also
declare a `protocol: UDP` port. A TCP-only Service never sends UDP packets to
the Pod, so there is nothing for the agent to capture.

Forward the incoming-control and remote-egress ports from the patched pod:

```sh
kubectl port-forward pod/YOUR_POD 30000:30000 30001:30001
```

Forward captured connections to the local application:

```sh
MOGATE_TOKEN='the-same-random-token' \
  bin/mogate incoming --udp --control 127.0.0.1:30000 --target 127.0.0.1:8080
```

In `steal`, traffic goes to the local process while a watcher is connected. If
the watcher is absent or misses the claim timeout, the agent passes the
connection through to the original application. In `mirror`, the original
workload produces the client response while the local application receives a
bounded best-effort copy; local responses are discarded.

## Security model

- The Unix socket is created with mode `0600`.
- The default socket lives in a per-user directory.
- File paths are resolved through `os.Root`, preventing `..` and symlink escapes from the configured root.
- Protocol payloads and concurrent connections are bounded.
- The Kubernetes remote-egress listener is token-authenticated, bounded, and
  intended to remain cluster-local behind `kubectl port-forward`.
- Incoming control requires a session token of at least 16 characters and compares it in constant time.
- The Kubernetes control port should remain cluster-local and be reached through `kubectl port-forward`.
- The Kubernetes agent owns only its named nftables table and requires
  `CAP_NET_ADMIN`; it never invokes a shell or the `nft`/`iptables` executables.

Do not expose the Unix relay socket or remote-egress TCP port to untrusted
users: the agent intentionally has network and filesystem authority within its
configured boundary.

## Path toward broader coverage

1. Complete the filesystem surface: directories, `readlink`, mutations and an explicit `mmap` policy.
2. Add feature-specific policies for error queues and UDP GSO/GRO where applications require them.
3. Replace per-connection incoming claims with an encrypted multiplexed transport.
4. Add HTTP filters, TLS delivery and concurrent incoming sessions.
5. Add process/environment metadata and per-feature include/exclude policies.
