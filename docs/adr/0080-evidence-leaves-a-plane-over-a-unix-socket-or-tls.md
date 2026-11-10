# ADR-0080: Evidence leaves a plane over a unix socket or TLS

Status: accepted
Date: 2026-11-10

Amends [ADR-0014](0014-evidence-spool-and-sinks.md) on where the exporter
may send and [ADR-0072](0072-the-collector-keeps-bounded-segments-of-one-project-behind-a-credential.md)
on where `collect` listens. Builds on
[ADR-0020](0020-a-trail-and-counters-without-a-collector.md).

## Context

The exporter sends every event and the collector's bearer credential on each
request. Until 0.17 it took an `http` endpoint on a loopback IP literal under
`export.allow_plaintext`, and `collect --listen` took a loopback address. On
plaintext TCP the plane cannot tell who answers: while `collect` is down,
any local account that binds its port first receives the credential, can
write evidence with it, and can answer with the acceptance that releases the
records from the spool. 0.16 added `unix:///path` with
`export.collector_uid`, where the plane reads the socket peer's account from
the kernel before it sends anything, kept TCP one more release with a
`doctor` warning, and announced that TCP export would be removed in 0.17.

## Decision

- `export.endpoint` is `unix:///path` with `export.collector_uid`, or an
  `https` URL. An `http` endpoint is refused at load, naming 0.17 and both
  ways that remain; so is `export.allow_plaintext: true`. The key stays for
  one release so that a configuration still setting it is told why rather
  than that the key is unknown.
- A unix endpoint's socket path is at most 103 bytes, what a macOS socket
  address holds, checked at load as `listener.socket` is.
- The exporter refuses `http` even when built directly, and has no setting
  that allows it.
- `collect --listen` takes `unix:///path` only; a TCP address is refused,
  naming 0.17. `doctor` drops its plaintext warning, since a plaintext
  endpoint no longer loads.
- `dev` runs its collector on a unix socket in a directory of its own under
  the system's temporary directory, apart from the state, whose path grows
  with `--state` and a scenario's name.

## Security / compatibility impact

**Breaking:** a configuration with an `http` endpoint or
`export.allow_plaintext: true`, and a `collect --listen host:port`, stop
working. The upgrade is `collect --listen unix:///path` and
`export.endpoint: unix:///path` with `export.collector_uid` set to the
account `collect` prints, or a collector behind TLS. Over `https` the plane
trusts the system's certificate roots: whoever holds a certificate they
accept for the collector's name receives the credential. A unix endpoint
needs a platform that names a socket's peer, Linux and macOS today.

## Alternatives considered

- Remove TCP export entirely, `https` included: a plane in a container could
  no longer export off its host.
- Keep plaintext behind the setting with a warning: the credential still
  goes to whoever holds the port while the collector is down.

## Consequences

Every configuration, example and test rig that ran a collector on a loopback
port moves to a unix socket. A collector on another host is reached over
TLS, which `collect` does not serve; a proxy that terminates TLS in front of
it does.

## Validation

`internal/gatewayconfig` refuses an `http` endpoint, the old key set true
beside any endpoint, and a 104-byte socket path, and loads a 103-byte one
and an `https` URL (`TestPlaintextExportIsRefusedNamingTheRelease`,
`TestAUnixEndpointsPathFitsASocketAddress`). `adapters/otel` refuses `http`
when built directly (`TestAPlaintextCollectorIsRefused`). `collect` refuses
every TCP address before it opens the trail
(`TestCollectListensOnAUnixSocketOnly`), and `dev`'s live tests export over
its socket.
