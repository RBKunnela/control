"""Writes what a qualification run leaves on disk, in the layout Inv reads:
<root>/cases/<group>/<invocation>/ for the runtime's stream and exits, the
snapshot, the trail, the health counts and the approvals; <root>/events/
<group>/<invocation>/ for the hook events; <root>/p/<group>/ for the project."""

import json
import os
import shutil
import tempfile
from typing import Any

from harness_judge import judged
from harness_observed import Inv
from harness_verdicts import Cases

SEEDS = {
    "target.txt": "port = 3000\n",
    "second.txt": "mode = draft\n",
    "secret": "a line only the file holds",
    "replacement": "replaced by another hook",
}


class Run:
    """One run's observations under a new directory, removed by close."""

    def __init__(self) -> None:
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="qualification-"))
        self.cases = os.path.join(self.root, "cases")
        self.events = os.path.join(self.root, "events")
        os.makedirs(self.cases)
        os.makedirs(self.events)
        self.write(os.path.join(self.cases, "seeds.json"), json.dumps(SEEDS))
        self.calls = 0
        self.invocations: dict[tuple[str, str], Invocation] = {}

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    @staticmethod
    def write(path: str, text: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def inv(self, group: str, name: str = "run") -> "Invocation":
        """The invocation group/name, made complete and empty the first time."""
        key = (group, name)
        if key not in self.invocations:
            self.invocations[key] = Invocation(self, group, name)
        return self.invocations[key]

    def accessor(self) -> Cases:
        """The case accessor the judges take, reading this run afresh."""
        return lambda group, name: Inv(self.cases, self.events, group, name)

    def verdicts(self) -> dict[str, str]:
        return {r["id"]: r["verdict"] for r in judged(self.cases, self.events)}

    def result(self, case_id: str) -> dict[str, Any]:
        return next(r for r in judged(self.cases, self.events) if r["id"] == case_id)


class Invocation:
    """One invocation that ran to the end with status 0, its snapshot empty,
    its trail empty and no run halted, until the methods say otherwise."""

    def __init__(self, run: Run, group: str, name: str) -> None:
        self.run, self.group = run, group
        self.dir = os.path.join(run.cases, group, name)
        self.events = os.path.join(run.events, group, name)
        self.project = os.path.join(run.root, "p", group)
        os.makedirs(self.dir, exist_ok=True)
        os.makedirs(self.events, exist_ok=True)
        os.makedirs(self.project, exist_ok=True)
        self.stream: list[dict[str, Any]] = []
        self.trail: list[dict[str, Any]] = []
        self.hooks = 0
        self.put("runtime-1.exit", "0\n")
        self.put("runtime-1.err", "")
        self.snapshot({})
        self.health(0, 0)
        self.flush()

    def put(self, name: str, text: str) -> None:
        Run.write(os.path.join(self.dir, name), text)

    def drop(self, name: str) -> None:
        os.remove(os.path.join(self.dir, name))

    def path(self, base: str) -> str:
        return os.path.join(self.project, base)

    def flush(self) -> None:
        self.put("stream-1.jsonl", "".join(json.dumps(line) + "\n" for line in self.stream))
        trail = [{"type": "event", "event": e} for e in self.trail]
        self.put("trail.jsonl", "".join(json.dumps(line) + "\n" for line in trail))

    def call(
        self,
        tool: str,
        tool_input: dict[str, Any],
        answer: str = "done",
        error: bool = False,
        parent: str | None = None,
    ) -> str:
        """A tool call in the stream and the runtime's answer to it; its id."""
        self.run.calls += 1
        call_id = f"toolu_{self.run.calls:04d}"
        use = {"type": "tool_use", "id": call_id, "name": tool, "input": tool_input}
        line: dict[str, Any] = {"type": "assistant", "message": {"content": [use]}}
        if parent:
            line["parent_tool_use_id"] = parent
        self.stream.append(line)
        result: dict[str, Any] = {"type": "tool_result", "tool_use_id": call_id}
        result.update(content=answer, is_error=error)
        self.stream.append({"type": "user", "message": {"content": [result]}})
        self.flush()
        return call_id

    def unanswered(self, tool: str, tool_input: dict[str, Any]) -> str:
        call_id = self.call(tool, tool_input)
        self.stream.pop()
        self.flush()
        return call_id

    def hook(
        self, kind: str, tool: str, tool_input: dict[str, Any], call: str, **meta: Any
    ) -> None:
        """A recorded hook event; meta defaults to the bridge's silent admit."""
        self.hooks += 1
        stem = os.path.join(self.events, f"{self.hooks:03d}")
        event = {"hook_event_name": kind, "tool_name": tool, "tool_input": tool_input}
        event["tool_use_id"] = call
        if "agent" in meta:
            event["agent_id"] = meta.pop("agent")
        Run.write(stem + ".json", json.dumps(event))
        Run.write(stem + ".meta.json", json.dumps({"act": "pass", "exit": 0, "stdout": ""} | meta))

    def request(self, rid: str, name: str, base: str, kinds: list[str], **parts: Any) -> None:
        """One request's trail events, one per kind: the first proposes name on
        base and carries the decision and approval parts given, the last the
        result part (status, protocol status)."""
        events: list[dict[str, Any]] = [
            {"requestId": rid, "kind": "EVENT_KIND_" + kind} for kind in kinds
        ]
        events[0]["proposed"] = {"action": {"name": name}, "resource": {"id": self.path(base)}}
        decision = {k: parts[k] for k in ("actionDigest", "verdict", "reasonCodes") if k in parts}
        if decision:
            events[0]["decision"] = decision
        if "approvalId" in parts:
            approval = {"approvalId": parts["approvalId"], "actionDigest": parts["actionDigest"]}
            events[0]["approval"] = approval
        if "result" in parts:
            status, protocol = parts["result"]
            events[-1]["result"] = {"status": status, "toolProtocolStatus": protocol}
        self.trail += events
        self.flush()

    def snapshot(self, files: dict[str, str]) -> None:
        self.put("files.json", json.dumps(files))

    def health(self, before: int, after: int) -> None:
        self.put("healthz.before.json", json.dumps({"pipeline": {"runs_halted": before}}))
        self.put("healthz.json", json.dumps({"pipeline": {"runs_halted": after}}))
