"""What one qualification invocation left on disk: the runtime's stream and exits,
the hook events, the project's snapshot, the trail and the plane's health."""

import json
import os
import re
from typing import Any

Record = dict[str, Any]


def load_json(path: str, default: Any = None) -> Any:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def jsonl(path: str) -> tuple[list[Record], str | None]:
    """The object on each line of path, and why a line or the file could not be
    read, or None. A line that does not parse is never skipped, since what it
    held is not known."""
    out: list[Record] = []
    name = os.path.basename(path)
    try:
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                try:
                    value = json.loads(line)
                except ValueError:
                    return out, f"line {n} of {name} does not parse"
                if not isinstance(value, dict):
                    return out, f"line {n} of {name} is not an object"
                out.append(value)
    except (OSError, UnicodeDecodeError) as e:
        return out, f"{name} could not be read: {type(e).__name__}"
    return out, None


def events(path: str) -> tuple[list[Record], str | None]:
    """The hook events recorded in path, and why one could not be read, or
    None. Every invocation's settings create path, so one that cannot be
    listed, absent included, is not known; a missing meta file is a hook that
    wrote none, as one killed while the bridge ran; an unreadable one is not
    known."""
    out: list[Record] = []
    try:
        names = sorted(n for n in os.listdir(path) if re.fullmatch(r"\d{3}\.json", n))
    except OSError as e:
        base = os.path.basename(path)
        return out, f"the hook events of {base} could not be listed: {type(e).__name__}"
    for name in names:
        stem = os.path.join(path, name[:-5])
        ev = load_json(stem + ".json")
        if not isinstance(ev, dict):
            return out, f"hook event {name} could not be read"
        meta = load_json(stem + ".meta.json") if os.path.exists(stem + ".meta.json") else {}
        if not isinstance(meta, dict):
            return out, f"the meta file of hook event {name} could not be read"
        if isinstance(meta.get("stderr"), str):
            meta["stderr"] = scrub(PROGRAM.sub("", meta["stderr"]))
        tool_input = ev.get("tool_input")
        out.append(
            {
                "kind": ev.get("hook_event_name", ""),
                "tool": ev.get("tool_name", ""),
                "call": ev.get("tool_use_id", ""),
                "agent": ev.get("agent_id", ""),
                "input": tool_input if isinstance(tool_input, dict) else {},
                "meta": meta,
            }
        )
    return out, None


# The program's name the bridge puts before each line it writes; the results
# keep the reason alone.
PROGRAM = re.compile(r"^[^\s:]+: hook: ", re.M)

# An absolute path, which would name the machine the qualification ran on.
PATH = re.compile(r"(?<![\w.])/[^\s\"';:,()\[\]]+")


def scrub(text: str) -> str:
    home = os.path.expanduser("~")
    if len(home) > 1:
        text = text.replace(home, "<path>")
    return re.sub(r"(<path>)+", "<path>", PATH.sub("<path>", text))


def content_of(line: Record, role: str) -> list[Any]:
    """The content items of a stream line from role, or none."""
    message = line.get("message") if line.get("type") == role else None
    content = message.get("content") if isinstance(message, dict) else None
    return content if isinstance(content, list) else []


def items(stream: list[Record], role: str, kind: str) -> list[Record]:
    return [
        item
        for line in stream
        for item in content_of(line, role)
        if isinstance(item, dict) and item.get("type") == kind
    ]


class Inv:
    """What one runtime invocation left behind. The project is work's p/<group>,
    work being the directory that holds cases unless given."""

    def __init__(
        self, cases: str, events_root: str, group: str, name: str, work: str | None = None
    ) -> None:
        self.name = group + "/" + name
        root = work or os.path.dirname(os.path.abspath(cases))
        self.project = os.path.join(root, "p", group)
        d = self.dir = os.path.join(cases, group, name)
        self.skipped = os.path.exists(os.path.join(d, "skipped"))
        self.unselected = os.path.exists(os.path.join(d, "unselected"))
        names = sorted(os.listdir(d)) if os.path.isdir(d) else []
        runs = (re.fullmatch(r"runtime-(\w+)\.exit", n) for n in names)
        keys = [m.group(1) for m in runs if m]
        self.ran = len(keys)
        problems: list[str | None] = []
        self.stream: list[Record] = []
        for key in keys:
            if f"stream-{key}.jsonl" not in names:
                problems.append(f"runtime-{key} left no stream")
                continue
            values, problem = jsonl(os.path.join(d, f"stream-{key}.jsonl"))
            self.stream += values
            problems.append(problem)
        self.events, problem = events(os.path.join(events_root, group, name))
        problems.append(problem)
        files = load_json(os.path.join(d, "files.json"))
        self.observed_files = isinstance(files, dict)
        self.files: dict[str, Any] = files if isinstance(files, dict) else {}
        self.observed_trail = os.path.isfile(os.path.join(d, "trail.jsonl"))
        trail: list[Record] = []
        if self.observed_trail:
            trail, problem = jsonl(os.path.join(d, "trail.jsonl"))
            problems.append(problem)
        self.trail = [r["event"] for r in trail if r.get("type") == "event"]
        self.problem = next((p + " in " + self.name for p in problems if p), None)
        self.halts = runs_halted(load_json(os.path.join(d, "healthz.json")))
        self.halts_before = runs_halted(load_json(os.path.join(d, "healthz.before.json")))
        self.observed_health = self.halts is not None and self.halts_before is not None
        approved = load_json(os.path.join(d, "approved.json"), {})
        self.approved: Record = approved if isinstance(approved, dict) else {}
        self.exits = [read_text(os.path.join(d, f"runtime-{k}.exit")).strip() for k in keys]
        self.stopped = any(
            "stopped after" in read_text(os.path.join(d, n))
            for n in names
            if re.fullmatch(r"runtime-\w+\.err", n)
        )

    def returned(self) -> bool:
        """Whether every runtime invocation ended on its own, with status 0."""
        return bool(self.exits) and all(x == "0" for x in self.exits) and not self.stopped

    def calls(self) -> list[Record]:
        """Every tool call in the stream: its name, id, the call it ran under, and its input."""
        out = []
        for line in self.stream:
            for item in content_of(line, "assistant"):
                if isinstance(item, dict) and item.get("type") == "tool_use":
                    out.append(
                        {
                            "name": item.get("name"),
                            "id": item.get("id"),
                            "parent": line.get("parent_tool_use_id"),
                            "input": item.get("input") or {},
                        }
                    )
        return out

    def result(self, call_id: object) -> Record | None:
        """The runtime's answer to the tool call call_id, or None."""
        for item in items(self.stream, "user", "tool_result"):
            if item.get("tool_use_id") == call_id:
                return item
        return None

    def refused(self, call_id: object) -> bool:
        """Whether the runtime answered the tool call call_id with an error."""
        answer = self.result(call_id)
        return answer is not None and answer.get("is_error") is True

    def said(self, call_id: object) -> str:
        """The text of the runtime's answer to the tool call call_id."""
        content = (self.result(call_id) or {}).get("content")
        return content if isinstance(content, str) else json.dumps(content)

    def in_project(self, path: object) -> bool:
        d = os.path.dirname(str(path))
        return d in (self.project, self.project.removeprefix("/private"), "/private" + self.project)

    def tool_uses(self, prefix: str) -> list[Record]:
        return [
            item
            for item in items(self.stream, "assistant", "tool_use")
            if str(item.get("name", "")).startswith(prefix)
        ]

    def tool_results(self) -> list[str]:
        return [
            json.dumps(item.get("content")) for item in items(self.stream, "user", "tool_result")
        ]

    def hook(self, kind: str, tool: str, base: str | None = None) -> list[Record]:
        """The recorded events of kind for tool, on a file named base when given."""
        return [
            e
            for e in self.events
            if e["kind"] == kind
            and e["tool"] == tool
            and (base is None or os.path.basename(str(e["input"].get("file_path", ""))) == base)
        ]

    def requests(self) -> dict[Any, Record]:
        out: dict[Any, Record] = {}
        for e in self.trail:
            empty: Record = {"kinds": [], "codes": [], "statuses": [], "protocol": []}
            r = out.setdefault(e.get("requestId"), empty)
            r["kinds"].append(e.get("kind", "").replace("EVENT_KIND_", ""))
            if "proposed" in e:
                r["name"] = e["proposed"]["action"].get("name")
                r["resource"] = e["proposed"].get("resource", {}).get("id", "")
            if "decision" in e:
                r["digest"] = e["decision"].get("actionDigest")
                r["verdict"] = e["decision"].get("verdict")
                r["codes"] += e["decision"].get("reasonCodes", [])
            if "approval" in e:
                approvals = r.setdefault("approvals", {})
                approvals[e["approval"].get("approvalId")] = e["approval"].get("actionDigest")
            if "result" in e:
                r["statuses"].append(e["result"].get("status"))
                r["protocol"].append(e["result"].get("toolProtocolStatus", ""))
        return out

    def on(self, tool: str, base: str) -> list[Record]:
        return [
            r
            for r in self.requests().values()
            if r.get("name") == tool and os.path.basename(r.get("resource", "")) == base
        ]

    def digest_of(self, approval: str) -> Any:
        for r in self.requests().values():
            if approval in r.get("approvals", {}):
                return r["approvals"][approval]
        return None

    def started(self, digest: object) -> int:
        return self.count("ACTION_STARTED", digest)

    def completed(self, digest: object) -> int:
        return self.count("ACTION_COMPLETED", digest)

    def count(self, kind: str, digest: object) -> int:
        if digest is None:
            return 0
        reqs = self.requests().values()
        return sum(r["kinds"].count(kind) for r in reqs if r.get("digest") == digest)

    def halted(self) -> bool:
        """Whether the plane halted a run during the invocation; read only when
        observed_health says both counts were read."""
        if self.halts is None or self.halts_before is None:
            return False
        return self.halts > self.halts_before


def runs_halted(health: Any) -> int | None:
    """The plane's count of halted runs in a /healthz answer, or None."""
    pipeline = health.get("pipeline") if isinstance(health, dict) else None
    n = pipeline.get("runs_halted") if isinstance(pipeline, dict) else None
    return n if isinstance(n, int) and not isinstance(n, bool) else None
