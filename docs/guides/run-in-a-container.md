---
title: Run the gateway in a container
summary: Run the release image of the gateway with Docker, with its evidence on a volume and its port reachable from the host alone.
type: how-to
covers: [.goreleaser.yaml, .github/workflows/release.yml]
---

# Run the gateway in a container

Use this when the gateway should run as a container rather than as a binary
on the host. The image holds only `guardana-gateway`, on a distroless base,
and runs as user 65532. It is `experimental` ([status.md](../status.md)) and
is published with each release, whose notes name its digest.

## Prerequisites

- A configuration that runs outside a container, with its bundle, its
  freshness statement and its floor directory
  ([run-the-gateway.md](run-the-gateway.md)).
- The image's digest from the release notes, checked with the commands in
  [RELEASING.md](../../RELEASING.md#checking-the-image).
- A directory for the evidence spool, owned by user 65532 and writable by no
  one else. Under Kubernetes the plane refuses an `emptyDir`, which is mode
  0777, and a volume that `fsGroup` makes group-writable; give the directory
  owner 65532 and mode 0700 before the gateway starts, from an init container
  for example.

## Steps

1. Change the configuration for the container:
   - `listener.address: 0.0.0.0:8080`. Inside the container, `127.0.0.1` is
     the container itself. Remove loopback entries from `listener.origins`:
     one is admitted only while the listener is on the loopback.
   - `evidence.dir: /var/lib/guardana/spool`, where the step below mounts the
     spool. A relative path resolves against the configuration's directory,
     which is mounted read-only.
   - Upstream addresses the container can reach. A `command` upstream has
     nothing to run in this image.
   - The collector at an `https` endpoint. A plaintext export is admitted only
     to a loopback IP literal, which here is the container itself.
   - `policy.state_dir: /var/lib/guardana/floors`, a volume that outlives the
     container, beside the spool and the approvals directory. Make it on the
     host with `guardana-control policy state init --kind plane --bundle-id <bundle id>
     floors`, then `chown -R 65532 floors`: the plane refuses a floor directory another user
     owns. A volume that does not outlive the container protects nothing: a
     floor made anew at each start takes any older bundle.
   - The configuration directory owned by 65532, its files with one name each,
     and neither writable by others: `chown -R 65532 conf`. The plane refuses a
     configuration owned by any account but its own or root, here the host
     user who made it.
   - The bundle and the statement can stay in the read-only configuration
     directory. Run `renew` where the freshness key lives, not in the
     container, and copy the statement into that directory; the plane
     reads it again every `policy.poll_interval`.
   - The pause file and the approvals and hold journal directories, if you
     use them, on volumes owned by 65532. The plane refuses them when the
     group or others may write them, and the pause file when another account
     owns it.
2. Run it by digest, with the port published on the host's loopback only:

   ```
   docker run --rm -p 127.0.0.1:8080:8080 \
     -v "$PWD/conf:/etc/gateway:ro" -v "$PWD/spool:/var/lib/guardana/spool" \
     -v "$PWD/floors:/var/lib/guardana/floors" \
     ghcr.io/guardana/control-gateway@sha256:<digest> run --config /etc/gateway/gateway.yaml
   ```

   The listener takes no credential but a run token under `runs.dir`, so
   anyone who reaches the port calls tools as the configured principal. If you publish it beyond the host's loopback,
   put something that authenticates callers in front of it.

## Verify

Set `health.address: 0.0.0.0:8081`, add `-p 127.0.0.1:8081:8081`, and run
`curl -s http://127.0.0.1:8081/healthz`. The answer names the mode and the
bundle, as it does outside a container, and `"freshness":"confirmed"`.

## Roll back

Stop the container. What the collector has not acknowledged stays in the
spool directory.
