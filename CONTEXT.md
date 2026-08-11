# Mogate

Mogate gives a local process selected network and filesystem behaviour from a
remote workload while allowing that process to receive the workload's traffic.

## Language

**Injection Session**:
The bounded lifetime during which an Injected Process uses a Remote Workload's
environment and may receive its traffic.
_Avoid_: dev session, local session

**Injected Process**:
A local process whose selected operating-system operations participate in an
Injection Session.
_Avoid_: target process, hooked process

**Remote Workload**:
The workload whose network environment, filesystem view, and incoming traffic
an Injection Session adopts.
_Avoid_: target pod, remote service

**Remote Agent**:
The participant beside a Remote Workload that performs remote operations and
coordinates incoming traffic for an Injection Session.
_Avoid_: sidecar, traffic agent

**Wire Contract**:
The versioned shared language understood by an Injected Process and a Remote
Agent during an Injection Session.
_Avoid_: protocol implementation, message format

**Virtual Descriptor**:
A descriptor visible to an Injected Process whose resource is owned elsewhere
in the Injection Session.
_Avoid_: fake fd, remote fd

**Traffic Claim**:
The exclusive assignment of one incoming connection or datagram flow to an
Injected Process.
_Avoid_: interception request, connection takeover

**Passthrough**:
Delivery of unclaimed incoming traffic to the Remote Workload.
_Avoid_: fallback, bypass

**Steal**:
An incoming mode in which a successful Traffic Claim makes the Injected Process
responsible for the response.
_Avoid_: redirect mode

**Mirror**:
An incoming mode in which the Remote Workload remains responsible for the
response while an Injected Process receives a best-effort copy.
_Avoid_: copy mode
