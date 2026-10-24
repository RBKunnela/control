"""What one qualification invocation left on disk: the runtime's stream and exits,
the hook events, the project's snapshot, the trail and the plane's health."""

import json
import os
import re


def load_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def lines(path):
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return out


def events(path):
    out = []
    try:
        names = sorted(n for n in os.listdir(path) if re.fullmatch(r"\d{3}\.json", n))
    except OSError:
        return out
    for name in names:
        stem = os.path.join(path, name[:-5])
        ev = load_json(stem + ".json")
        ev = ev if isinstance(ev, dict) else {}
        meta = load_json(stem + ".meta.json", {})
        if isinstance(meta.get("stderr"), str):
            meta["stderr"] = scrub(PROGRAM.sub("", meta["stderr"]))
        out.append({
            "kind": ev.get("hook_event_name", ""),
            "tool": ev.get("tool_name", ""),
            "call": ev.get("tool_use_id", ""),
            "agent": ev.get("agent_id", ""),
            "input": ev.get("tool_input") if isinstance(ev.get("tool_input"), dict) else {},
            "meta": meta,
        })
    return out


# The program's name the bridge puts before each line it writes; the results
# keep the reason alone.
PROGRAM = re.compile(r"^[^\s:]+: hook: ", re.M)

# An absolute path, which would name the machine the qualification ran on.
PATH = re.compile(r"(?<![\w.])/[^\s\"';:,()\[\]]+")


def scrub(text):
    home = os.path.expanduser("~")
    if len(home) > 1:
        text = text.replace(home, "<path>")
    return re.sub(r"(<path>)+", "<path>", PATH.sub("<path>", text))


class Inv:
    """What one runtime invocation left behind."""

    def __init__(self, cases, events_root, group, name):
        self.name = group + "/" + name
        self.project = os.path.join(os.path.dirname(os.path.abspath(cases)), "p", group)
        d = self.dir = os.path.join(cases, group, name)
        self.skipped = os.path.exists(os.path.join(d, "skipped"))
        self.unselected = os.path.exists(os.path.join(d, "unselected"))
        names = sorted(os.listdir(d)) if os.path.isdir(d) else []
        self.ran = sum(1 for n in names if re.fullmatch(r"runtime-\w+\.exit", n))
        self.stream = [x for n in names if re.fullmatch(r"stream-\w+\.jsonl", n) for x in lines(os.path.join(d, n))]
        self.events = events(os.path.join(events_root, group, name))
        files = load_json(os.path.join(d, "files.json"))
        self.observed_files = isinstance(files, dict)
        self.files = files if self.observed_files else {}
        self.observed_trail = os.path.isfile(os.path.join(d, "trail.jsonl"))
        self.trail = [r["event"] for r in lines(os.path.join(d, "trail.jsonl")) if r.get("type") == "event"]
        self.health = load_json(os.path.join(d, "healthz.json"), {})
        self.health_before = load_json(os.path.join(d, "healthz.before.json"), {})
        self.approved = load_json(os.path.join(d, "approved.json"), {})
        self.exits = [read_text(os.path.join(d, n)).strip() for n in names if re.fullmatch(r"runtime-\w+\.exit", n)]
        self.stopped = any("stopped after" in read_text(os.path.join(d, n))
                           for n in names if re.fullmatch(r"runtime-\w+\.err", n))

    def returned(self):
        """Whether every runtime invocation ended on its own, with status 0."""
        return bool(self.exits) and all(x == "0" for x in self.exits) and not self.stopped

    def calls(self):
        """Every tool call in the stream: its name, id, the call it ran under, and its input."""
        out = []
        for line in self.stream:
            content = (line.get("message") or {}).get("content") if line.get("type") == "assistant" else None
            for item in content if isinstance(content, list) else []:
                if isinstance(item, dict) and item.get("type") == "tool_use":
                    out.append({"name": item.get("name"), "id": item.get("id"),
                                "parent": line.get("parent_tool_use_id"), "input": item.get("input") or {}})
        return out

    def result(self, call_id):
        """The runtime's answer to the tool call call_id, or None."""
        for line in self.stream:
            content = (line.get("message") or {}).get("content") if line.get("type") == "user" else None
            for item in content if isinstance(content, list) else []:
                if isinstance(item, dict) and item.get("type") == "tool_result" and item.get("tool_use_id") == call_id:
                    return item
        return None

    def refused(self, call_id):
        """Whether the runtime answered the tool call call_id with an error."""
        answer = self.result(call_id)
        return answer is not None and answer.get("is_error") is True

    def said(self, call_id):
        """The text of the runtime's answer to the tool call call_id."""
        content = (self.result(call_id) or {}).get("content")
        return content if isinstance(content, str) else json.dumps(content)

    def in_project(self, path):
        d = os.path.dirname(str(path))
        return d in (self.project, self.project.removeprefix("/private"), "/private" + self.project)

    def tool_uses(self, prefix):
        out = []
        for line in self.stream:
            content = (line.get("message") or {}).get("content") if line.get("type") == "assistant" else None
            for item in content if isinstance(content, list) else []:
                if isinstance(item, dict) and item.get("type") == "tool_use" and str(item.get("name", "")).startswith(prefix):
                    out.append(item)
        return out

    def tool_results(self):
        out = []
        for line in self.stream:
            content = (line.get("message") or {}).get("content") if line.get("type") == "user" else None
            for item in content if isinstance(content, list) else []:
                if isinstance(item, dict) and item.get("type") == "tool_result":
                    out.append(json.dumps(item.get("content")))
        return out

    def hook(self, kind, tool, base=None):
        """The recorded events of kind for tool, on a file named base when given."""
        return [
            e for e in self.events
            if e["kind"] == kind and e["tool"] == tool
            and (base is None or os.path.basename(str(e["input"].get("file_path", ""))) == base)
        ]

    def requests(self):
        out = {}
        for e in self.trail:
            r = out.setdefault(e.get("requestId"), {"kinds": [], "codes": [], "statuses": [], "protocol": []})
            r["kinds"].append(e.get("kind", "").replace("EVENT_KIND_", ""))
            if "proposed" in e:
                r["name"] = e["proposed"]["action"].get("name")
                r["resource"] = e["proposed"].get("resource", {}).get("id", "")
            if "decision" in e:
                r["digest"] = e["decision"].get("actionDigest")
                r["verdict"] = e["decision"].get("verdict")
                r["codes"] += e["decision"].get("reasonCodes", [])
            if "approval" in e:
                r.setdefault("approvals", {})[e["approval"].get("approvalId")] = e["approval"].get("actionDigest")
            if "result" in e:
                r["statuses"].append(e["result"].get("status"))
                r["protocol"].append(e["result"].get("toolProtocolStatus", ""))
        return out

    def on(self, tool, base):
        return [r for r in self.requests().values()
                if r.get("name") == tool and os.path.basename(r.get("resource", "")) == base]

    def digest_of(self, approval):
        for r in self.requests().values():
            if approval in r.get("approvals", {}):
                return r["approvals"][approval]
        return None

    def started(self, digest):
        return sum(r["kinds"].count("ACTION_STARTED") for r in self.requests().values() if r.get("digest") == digest)

    def completed(self, digest):
        return sum(r["kinds"].count("ACTION_COMPLETED") for r in self.requests().values() if r.get("digest") == digest)

    def halted(self):
        before = (self.health_before.get("pipeline") or {}).get("runs_halted", 0)
        return (self.health.get("pipeline") or {}).get("runs_halted", 0) > before
