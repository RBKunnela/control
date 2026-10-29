"""The client against a real plane, set up and read back through the built commands alone."""

from __future__ import annotations

import base64
import json
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from guardana_control.enforce import CallBlocked, Client, Result, Status

BUNDLE = "enforce-e2e"
TENANT, PRINCIPAL, AGENT = "acme", "agent-runner", "refund-worker"

POLICY = """{"apiVersion":"agent-policy/v1alpha1",
  "bundle":{"id":"enforce-e2e","version":"1","serial":1,"maxStaleSeconds":600},
  "rules":[
    {"id":"allow-reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}},
    {"id":"deny-refunds","effect":"DENY","when":{"action":{"effect":["TRANSACT"]}}}
  ]}
"""

PLANE = """mode: ENFORCE
project_id: orders
tenant_id: acme
environment: dev
listener:
  kind: enforce_api
  socket: {socket}
  execution_lifetime: 2m
  principal:
    id: agent-runner
  agent:
    id: refund-worker
health:
  address: 127.0.0.1:0
policy:
  bundle_id: enforce-e2e
  bundle_file: policy.bundle
  key_id: {key_id}
  public_key: {public_key}
  statement_file: policy.statement
  state_dir: floors
  freshness_key_id: {freshness_key_id}
  freshness_public_key: {freshness_public_key}
  poll_interval: 30s
runs:
  dir: runs
evidence:
  dir: spool
export:
  endpoint: {collector}
  allow_plaintext: true
  linger: 5ms
tools:
  - name: read_order
    effect: READ
    provider: orders
    resource_type: order
    resource_from: /id
  - name: refund
    effect: TRANSACT
    provider: payments
    resource_type: order
    resource_from: /id
"""


def values(output: str) -> dict[str, str]:
    """The `name: value` lines a command printed."""
    pairs = (line.partition(": ") for line in output.splitlines())
    return {name: value for name, colon, value in pairs if colon}


def built_commands(directory: Path) -> tuple[Path, Path]:
    """The plane and the command: the two executables directory holds.

    The plane is the one named *-gateway and the command is the other, so
    that neither is found by the product's name. Any other holding is a
    ValueError that names the executables.
    """
    found = sorted(
        entry for entry in directory.iterdir() if entry.is_file() and os.access(entry, os.X_OK)
    )
    planes = [entry for entry in found if entry.name.endswith("-gateway")]
    others = [entry for entry in found if entry not in planes]
    if len(planes) != 1 or len(others) != 1:
        names = ", ".join(entry.name for entry in found) or "none"
        raise ValueError(
            f"{directory} holds the executables {names}; want two, one of them named *-gateway"
        )
    return planes[0], others[0]


class Plane(unittest.TestCase):
    def setUp(self) -> None:
        named = os.environ.get("ENFORCE_E2E_BIN", "")
        if not named or not Path(named).is_dir():
            self.fail("ENFORCE_E2E_BIN names no directory holding the built commands")
        try:
            self.gateway, self.control = built_commands(Path(named))
        except ValueError as exc:
            self.fail(f"ENFORCE_E2E_BIN: {exc}")
        # The plane's own variables would override the configuration written here.
        prefix = self.control.name.upper().replace("-", "_") + "_"
        self.env = {
            name: value for name, value in os.environ.items() if not name.startswith(prefix)
        }
        # A socket path is bounded at about 104 bytes, and its directory must be private.
        self.dir = Path(tempfile.mkdtemp(prefix="enfe", dir="/tmp"))
        self.addCleanup(shutil.rmtree, self.dir)
        self.processes: list[tuple[subprocess.Popen[bytes], Path]] = []

    def run_to_end(self, command: Path, *arguments: str) -> str:
        """What a command printed; anything but a clean exit fails the test."""
        # Every command run here is one of the two the gate built and named.
        done = subprocess.run(  # noqa: S603
            [str(command), *arguments],
            cwd=self.dir,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if done.returncode != 0:
            self.fail(f"{command.name} {arguments[0]} exited {done.returncode}:\n{done.stderr}")
        return done.stdout

    def start(self, name: str, command: Path, *arguments: str) -> Path:
        """Starts a command that serves until the test ends, and returns the file it prints to."""
        printed = self.dir / f"{name}.out"
        with printed.open("wb") as out:
            process = subprocess.Popen(  # noqa: S603
                [str(command), *arguments],
                cwd=self.dir,
                env=self.env,
                stdout=out,
                stderr=subprocess.STDOUT,
            )
        self.processes.append((process, printed))
        self.addCleanup(self.stop, process)
        return printed

    def stop(self, process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    def printed_after(self, printed: Path, prefix: str) -> str:
        """The rest of the line a served command printed after prefix, awaited for a minute."""
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            for line in printed.read_text(encoding="utf-8").splitlines():
                if line.startswith(prefix):
                    return line.removeprefix(prefix)
            exited = [
                p.returncode for p, out in self.processes if out == printed and p.poll() is not None
            ]
            if exited:
                break
            time.sleep(0.05)
        self.fail(f"no line {prefix!r} from {printed.name}:\n{printed.read_text(encoding='utf-8')}")

    def lay_out(self) -> tuple[str, str]:
        """Signs the policy, opens a run and starts a collector and the plane.

        Returns the plane's socket and the run's token. The run is opened
        first: a plane refuses a runs directory no run was opened in.
        """
        (self.dir / "policy.json").write_text(POLICY, encoding="utf-8")
        keys = values(self.run_to_end(self.control, "policy", "keygen", "--out", "keys"))
        fresh = values(self.run_to_end(self.control, "policy", "keygen", "--out", "freshness"))
        self.run_to_end(
            self.control,
            "policy",
            "sign",
            "--key",
            "keys/signing.key",
            "--out",
            "policy.bundle",
            "policy.json",
        )
        self.run_to_end(
            self.control,
            "policy",
            "state",
            "init",
            "--kind",
            "signer",
            "--bundle-id",
            BUNDLE,
            "signer-floors",
        )
        self.run_to_end(
            self.control,
            "policy",
            "renew",
            *("--key", "freshness/signing.key", "--bundle", "policy.bundle"),
            *("--bundle-public-key", "keys/signing.pub", "--floor", "signer-floors"),
            *("--out", "policy.statement"),
        )
        self.run_to_end(
            self.control,
            "policy",
            "state",
            "init",
            "--kind",
            "plane",
            "--bundle-id",
            BUNDLE,
            "floors",
        )
        for name in ("spool", "runs", "sock"):
            (self.dir / name).mkdir(mode=0o700)
        token = self.open_run()
        collecting = self.start(
            "collect", self.gateway, "collect", "--listen", "127.0.0.1:0", "--out", "trail.jsonl"
        )
        socket_path = str(self.dir / "sock" / "s")
        plane = self.dir / "plane.yaml"
        plane.write_text(
            PLANE.format(
                socket=socket_path,
                key_id=keys["key_id"],
                public_key=keys["public_key"],
                freshness_key_id=fresh["key_id"],
                freshness_public_key=fresh["public_key"],
                collector=self.printed_after(collecting, "collect: listening on "),
            ),
            encoding="utf-8",
        )
        plane.chmod(0o600)
        serving = self.start("plane", self.gateway, "run", "--config", "plane.yaml")
        self.assertEqual(self.printed_after(serving, "listening for tools on "), socket_path)
        return socket_path, token

    def open_run(self) -> str:
        opened = values(
            self.run_to_end(
                self.control,
                "runs",
                "open",
                *("--project", "orders", "--tenant", TENANT),
                *("--principal-type", "service", "--principal", PRINCIPAL),
                *("--agent", AGENT, "--ttl", "1h", "runs"),
            )
        )
        if not opened.get("token", "").startswith(opened.get("run_id", "no run") + "."):
            self.fail("runs open printed no run and token")
        return opened["token"]

    def kinds(self, request: object) -> list[str]:
        """The kinds of the events the trail holds of one request, in order."""
        exported = self.run_to_end(
            self.gateway, "trail", "export", "--request", str(request), "trail.jsonl"
        )
        records = [json.loads(line) for line in exported.splitlines()]
        return [record["event"]["kind"] for record in records if record["type"] == "event"]

    def await_trails(self, count: int) -> str:
        """The trail command's summary once the collector holds count whole trails."""
        want = f"trails {count}: ok {count}, open 0, failed 0, indeterminate 0;"
        summary = ""
        for _ in range(40):
            done = subprocess.run(  # noqa: S603
                [str(self.gateway), "trail", "trail.jsonl"],
                cwd=self.dir,
                env=self.env,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            summary = done.stdout + done.stderr
            if done.returncode == 0 and want in summary:
                return summary
            time.sleep(0.25)
        self.fail(f"the trail did not reach {want!r}:\n{summary}")

    def post_raw(self, socket_path: str, token: str, operation: str, body: dict[str, str]) -> bytes:
        """The plane's whole answer to one request, as the bytes it put on the socket."""
        sent = json.dumps(body).encode("utf-8")
        head = (
            f"POST /enforce/v1alpha1/{operation} HTTP/1.1\r\nHost: plane\r\nRun-Token: {token}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(sent)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as raw:
            raw.settimeout(30)
            raw.connect(socket_path)
            raw.sendall(head + sent)
            answer = b""
            while more := raw.recv(65536):
                answer += more
        return answer

    def assert_a_large_answer_is_chunked(
        self, socket_path: str, token: str, arguments: bytes
    ) -> None:
        """Admits arguments by hand, reads how the answer is framed, and gives the handle up."""
        proposed = base64.b64encode(arguments).decode("ascii")
        answer = self.post_raw(
            socket_path, token, "admit", {"tool": "read_order", "arguments": proposed}
        )
        head, _, rest = answer.partition(b"\r\n\r\n")
        self.assertTrue(head.startswith(b"HTTP/1.1 200 "), head)
        self.assertIn(b"\r\ntransfer-encoding: chunked", head.lower())
        body = b""
        while rest:
            size, _, rest = rest.partition(b"\r\n")
            count = int(size.partition(b";")[0], 16)
            body, rest = body + rest[:count], rest[count + 2 :]
        self.assertGreater(len(body), 2048)
        handle = json.loads(body)["execution"]["handle"]
        gave_up = self.post_raw(
            socket_path, token, "abort", {"handle": handle, "cause": "ABORT_CAUSE_NOT_SENT"}
        )
        self.assertTrue(gave_up.endswith(b'{"ending":"ENDING_RECORDED"}'), gave_up)

    def test_an_allowed_call_runs_and_a_denied_one_never_reaches_the_tool(self) -> None:
        socket_path, token = self.lay_out()
        client = Client(socket_path, token, 30.0)
        ran: list[bytes] = []

        def tool(authorized: bytes) -> Result:
            ran.append(authorized)
            return Result(Status.SUCCESS)

        large = b'{"id":"ord-1","note":"' + b"n" * 3000 + b'"}'
        self.assert_a_large_answer_is_chunked(socket_path, token, large)
        allowed = client.call("read_order", large, tool)
        self.assertEqual((allowed.outcome, allowed.ran), ("OUTCOME_EXECUTE", True))
        self.assertEqual(allowed.ending, "ENDING_RECORDED")
        self.assertEqual(ran, [large])
        decided = dict(allowed.decision or {})
        self.assertEqual(
            (decided.get("verdict"), decided.get("policyRuleIds"), decided.get("reasonCodes")),
            ("VERDICT_ALLOW", ("allow-reads",), ("RULE_ALLOW",)),
        )

        with self.assertRaises(CallBlocked) as blocked:
            client.call("refund", b'{"id":"ord-2"}', tool)
        denied = dict(blocked.exception.answer.decision or {})
        self.assertEqual(blocked.exception.answer.ran, False)
        self.assertEqual(
            (denied.get("verdict"), denied.get("policyRuleIds"), denied.get("reasonCodes")),
            ("VERDICT_DENY", ("deny-refunds",), ("RULE_DENY",)),
        )
        self.assertEqual(ran, [large], "the denied call reached the tool")

        # The third trail is the admit made by hand and given up.
        summary = self.await_trails(3)
        closed, stopped = decided["requestId"], denied["requestId"]
        self.assertIn(
            f"request={closed} project=orders tenant=acme last=EVENT_KIND_ACTION_COMPLETED ok",
            summary,
        )
        self.assertIn(
            f"request={stopped} project=orders tenant=acme last=EVENT_KIND_ACTION_BLOCKED ok",
            summary,
        )
        self.assertEqual(
            self.kinds(closed),
            [
                "EVENT_KIND_ACTION_PROPOSED",
                "EVENT_KIND_POLICY_DECIDED",
                "EVENT_KIND_ACTION_STARTED",
                "EVENT_KIND_ACTION_COMPLETED",
            ],
        )
        self.assertEqual(
            self.kinds(stopped),
            [
                "EVENT_KIND_ACTION_PROPOSED",
                "EVENT_KIND_POLICY_DECIDED",
                "EVENT_KIND_ACTION_BLOCKED",
            ],
        )


class Commands(unittest.TestCase):
    """Which of the built files is the plane and which the command, whatever the product's name."""

    def holding(
        self, *commands: str, files: tuple[str, ...] = (), directories: tuple[str, ...] = ()
    ) -> Path:
        """A directory of executables named commands, plain files and directories."""
        directory = Path(tempfile.mkdtemp(prefix="enfb"))
        self.addCleanup(shutil.rmtree, directory)
        for name in (*commands, *files):
            (directory / name).write_bytes(b"")
            (directory / name).chmod(0o755 if name in commands else 0o644)
        for name in directories:
            (directory / name).mkdir()
        return directory

    def test_the_plane_is_named_gateway_and_the_command_is_the_other(self) -> None:
        for commands, plane, command in (
            (("acme-gateway", "acme-control"), "acme-gateway", "acme-control"),
            (("acme-gateway", "acme-plane"), "acme-gateway", "acme-plane"),
            (("z-gateway", "a"), "z-gateway", "a"),
            (("a-gateway", "z"), "a-gateway", "z"),
        ):
            with self.subTest(commands=commands):
                directory = self.holding(*commands)
                self.assertEqual(
                    built_commands(directory), (directory / plane, directory / command)
                )

    def test_what_cannot_be_run_is_no_command(self) -> None:
        directory = self.holding(
            "acme-gateway", "acme", files=("notes-gateway", "notes"), directories=("old-gateway",)
        )
        self.assertEqual(
            built_commands(directory), (directory / "acme-gateway", directory / "acme")
        )

    def test_any_other_holding_is_refused_and_named(self) -> None:
        for commands, files, said in (
            ((), (), "the executables none"),
            (("acme-gateway",), (), "the executables acme-gateway"),
            (("acme",), (), "the executables acme"),
            (("acme-gateway",), ("acme",), "the executables acme-gateway"),
            (
                ("acme-gateway", "acme", "acme-more"),
                (),
                "the executables acme, acme-gateway, acme-more",
            ),
            (("acme", "acme-control"), (), "the executables acme, acme-control"),
            (("a-gateway", "b-gateway"), (), "the executables a-gateway, b-gateway"),
            (
                ("a-gateway", "b-gateway", "c"),
                (),
                "the executables a-gateway, b-gateway, c",
            ),
        ):
            with self.subTest(commands=commands, files=files):
                directory = self.holding(*commands, files=files)
                with self.assertRaises(ValueError) as raised:
                    built_commands(directory)
                self.assertEqual(
                    str(raised.exception),
                    f"{directory} holds {said}; want two, one of them named *-gateway",
                )
