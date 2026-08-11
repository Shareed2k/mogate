# ADR 0003: Canonicalize UDP ancillary metadata

Status: accepted

## Context

`cmsghdr` layouts, numeric constants, alignment, and available message types
differ between Linux and macOS. Copying the `msg_control` byte region through
the tunnel would therefore be incorrect when the Injected Process and Remote
Agent run on different operating systems.

mirrord currently hooks `sendmsg` and `recvmsg` but explicitly ignores their
control-message headers. Telepresence normally avoids this syscall-level
problem because application sockets remain local kernel sockets behind its
virtual network interface.

## Decision

The Wire Contract represents the portable semantics rather than either OS ABI:

- packet source/destination address;
- interface index;
- hop limit or TTL;
- traffic class or TOS;
- receive timestamp in nanoseconds.

The Remote Agent converts native Linux packet metadata to this representation.
The injector converts it to the local platform's `cmsghdr` layout and observes
the application's relevant `setsockopt` selections. Outgoing supported control
messages are converted in the opposite direction.

New additive operations distinguish metadata-capable UDP sessions from legacy
UDP sessions. An older Remote Agent therefore returns an explicit unsupported
operation instead of silently discarding metadata.

## Consequences

Applications can use the common packet-information and timestamp APIs across a
macOS/Linux boundary. Truncation follows `MSG_CTRUNC` semantics.

`SCM_RIGHTS`, credentials, error queues, and UDP GSO/GRO remain explicitly
unsupported. These carry process-local authority or Linux-specific transport
semantics and require dedicated protocol and policy rather than opaque bytes.
