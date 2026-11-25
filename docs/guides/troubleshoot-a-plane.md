---
title: Troubleshoot a plane
summary: Why a call was refused in OBSERVE, why an approval did not let a call run, why health says degraded with HTTP 200, and why a signed plane will not start.
type: how-to
covers: [cmd/guardana-gateway/health.go, cmd/guardana-gateway/health_stops.go, cmd/guardana-gateway/authority.go, cmd/guardana-gateway/doctor_authority.go, internal/gateway/admit.go, internal/gateway/mode.go, internal/gateway/resume.go, internal/gateway/approve.go, adapters/mcp/answer.go]
---

# Troubleshoot a plane

Each entry starts from what you see, names the cause, and gives the command
that shows it. [Failure modes](../reference/failure-modes.md) says, part by
part, what the plane does when a part it depends on fails. The gateway is
`experimental` ([mcp-gateway](../status.md#mcp-gateway)).

## Prerequisites

- A plane you run as [run the gateway](run-the-gateway.md) shows, its
  configuration file, and the health address it serves.

## A call was refused in OBSERVE

**Symptom.** The answer is marked `blocked`, `isError: true`, its text the
reason codes, though `OBSERVE` enforces nothing the policy decides.

**Cause.** What the plane refuses on its own account it refuses in every
mode: an operator's pause (`PAUSED`), a stopped run (`RUN_STOPPED`) or,
under `signed`, a stopped agent or principal (`AGENT_OR_PRINCIPAL_STOPPED`), a pause
file or stop list it cannot read (`PAUSE_STATE_UNAVAILABLE`,
`STOP_STATE_UNAVAILABLE`), a halt after unauthorized bytes ran
(`EXECUTED_ARGS_MISMATCH`), evidence it cannot keep (`EVIDENCE_UNAVAILABLE`),
and a call the adapter could not translate. The full table is on
[enforcement modes](../concepts/enforcement-modes.md#what-the-enforcement-point-blocks-in-every-mode).

**Show it.**

```
curl -s http://127.0.0.1:8081/healthz | jq '{mode, halted, pause: .pause.state, stops: .stops.state}'
guardana-control pause list /srv/pause/pause.json
curl -s http://127.0.0.1:8081/metrics | grep pipeline_blocks_total
```

The block counter is labelled with the first reason code. `OBSERVE` holds no
call: an answer marked `pending` comes from a plane in another mode, which
`mode` shows.

## An approval did not let the call run

**Symptom.** You approved a held request, and the agent's call still did not run.

**Cause.** An approval is spent only by the agent's retry of the same call,
under the same policy bundle, before it expires
([approvals](../concepts/approvals-and-the-held-call.md#the-states-of-a-held-request)):

- No retry came: nothing runs until the agent sends the call again.
- The retry's arguments differ: it is a new request, decided anew; a hold
  gives it a new `approval_id`.
- The approval expired first (`approvals.ttl`, `15m` by default): the held
  trail closes `APPROVAL_EXPIRED`.
- The bundle went stale or was replaced: the retry is blocked
  `POLICY_STALE`, and one under the newer bundle is decided anew.
- The plane restarted: a lost hold never runs; with a hold journal the next
  start closes an approved one `APPROVAL_NOT_RESUMED`.
- The approved call already ran once: a later identical call is refused
  `APPROVAL_ALREADY_USED` until the approval expires.
- Under `signed`, the answer counts only from a roster operator granted the
  call's tenant and project ([set up signed operators](set-up-signed-operators.md)).

**Show it.** `guardana-control approvals list /var/lib/guardana/approvals`
prints each record's state and digests; the retry's answer carries its
codes; `guardana-gateway trail <dir>` prints the kind of each request's last
event.

## Health says degraded with HTTP 200

**Symptom.** `/healthz` answers `200` with `"status":"degraded"`.

**Cause.** The plane serves, but either its policy is not confirmed
(`policy.freshness` is `unconfirmed` or `expired`), so material calls are
blocked `POLICY_STALE` outside `OBSERVE`, or its stop list has passed nine
tenths of a bound (`stops.degraded`), past which no more stops can be
written. A halt, a spool that cannot answer, or a pause or stop state that
is unknown answers `503` instead.

**Show it.**

```
curl -s http://127.0.0.1:8081/healthz | jq '{status, freshness: .policy.freshness, stops_degraded: .stops.degraded}'
curl -s http://127.0.0.1:8081/metrics | grep policy_refresh_refused_total
```

The counter names why each poll refused the bundle or statement. If the
policy is not confirmed, rerun `policy renew` and copy the statement
([a policy that is not confirmed](../reference/failure-modes.md#a-policy-that-is-not-confirmed));
if the stop list is degraded, start a new one with `stops init --carry` and
restart ([reaction](../reference/reaction.md)).

## A signed plane will not start

**Symptom.** Under `approvals.authority: signed`, `run` exits naming a key and
`under the signed authority the plane's own account may not be able to change
it`, or naming the environment, `approvals.inbox_dir` or `records/`.

**Cause.** A signed plane refuses to start when its own account owns or may
write the configuration, the roster, the root key, the pause file, the
route, the stop list or the runs directory's `records/`, or a directory on
their path; when any of those entries is missing or carries an access control
list (on Linux and macOS); when it runs as root; when the environment sets any of its keys;
when its own account does not own `approvals.inbox_dir`; and while `records/`
holds more than 65,536 records. After an upgrade,
[upgrade a plane from 0.18](upgrade-a-plane-from-0-18.md) lists what 0.19
refuses that 0.18 took, a route naming a deadline or retry rule among them. A
key a signed plane requires and does not find, such as `plane_id`,
`approvals.inbox_dir`, a `trust` key or an `operators` kind, is refused with
the configuration, which names the key. A roster it cannot take does not stop the start, but
no operator's signature counts until one is taken.

**Show it.**

```
guardana-gateway doctor --config gateway.yaml
```

`doctor` stops at the first check it fails: `configuration` names a missing
or refused key, and `trust` names the path and why, or, once it passes, the
roster's id and serial. [Which account owns what](set-up-signed-operators.md#which-account-owns-what)
lists the layout that passes.
