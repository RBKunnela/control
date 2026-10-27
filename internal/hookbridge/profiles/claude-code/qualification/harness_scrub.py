"""A copy of a run's observations that may be kept beside its results file.

The copy holds only the files the judge reads. The work directory becomes
SCRUBBED and the events directory SCRUBBED/events, so the judge finds each
project where the paths say it is; any other absolute path and the home
directory become <path>; every identifier becomes id-<n>, the same one for
the same identifier throughout the copy, so what the judge compares still
compares. Of the runtime's stream only the tool calls, their results, a
sub-agent's answer among them, and the run's status are kept, never the
model's text or reasoning; of its standard error, only whether it stopped.
A copy is worth keeping only when harness.py rejudge judges it as the run was
judged, and only after a person has read it.
"""

import json
import os
import re
import shutil

from harness_observed import Record

SCRUBBED = "/scrubbed"

# What the judge reads of an invocation's directory, and of an events directory.
CASE_FILES = re.compile(
    r"skipped|unselected|runtime-\w+\.(exit|err)|stream-\w+\.jsonl|files\.json|trail\.jsonl"
    r"|healthz(\.before)?\.json|approved\.json|approvals\.txt"
)
EVENT_FILES = re.compile(r"\d{3}(\.meta)?\.json")

# The stream lines the judge reads, and of each the blocks it reads: the
# model's text and reasoning are never kept.
STREAM_TYPES = ("assistant", "user", "result")
KEPT_BLOCKS = {"assistant": "tool_use", "user": "tool_result"}
UNREADABLE = "<a stream line that did not parse>\n"

# Of a runtime's standard error the judge reads whether it stopped the run.
STOPPED = "stopped after"


def judged_part(line: Record) -> Record:
    """The members of a stream line the judge reads."""
    kind = line.get("type")
    if kind == "result":
        return {k: line[k] for k in ("type", "subtype", "is_error") if k in line}
    message = line.get("message")
    message = message if isinstance(message, dict) else {}
    content = message.get("content")
    keep = KEPT_BLOCKS.get(str(kind))
    blocks = []
    if isinstance(content, list):
        blocks = [b for b in content if isinstance(b, dict) and b.get("type") == keep]
    out: Record = {"type": kind, "message": {"role": message.get("role"), "content": blocks}}
    if "parent_tool_use_id" in line:
        out["parent_tool_use_id"] = line["parent_tool_use_id"]
    return out


# A UUID, a tool call's id, an approval's id, a hex digest or id (as the one
# after run-) and a base64url digest; each of the last three holds a letter,
# so no number is taken.
IDENTIFIER = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|toolu_\w+"
    r"|(?<!\w)(?=[\w-]*[A-Za-z])(?:[0-9A-Z]{26}|[0-9a-f]{16,}|[A-Za-z0-9_-]{43}=?)(?![\w-])"
)
OTHER_PATH = re.compile(r"(?<![\w.])/(?!scrubbed\b)[^\s\"';:,()\[\]]+")


class Scrubber:
    def __init__(self, work: str, events_root: str) -> None:
        self.roots: list[tuple[str, str]] = []
        for placeholder, given in ((SCRUBBED + "/events", events_root), (SCRUBBED, work)):
            real = os.path.realpath(given)
            spellings = {real, real.removeprefix("/private"), "/private" + real}
            self.roots += [(s, placeholder) for s in spellings]
        self.roots.sort(key=lambda r: -len(r[0]))
        self.home = os.path.expanduser("~")
        self.ids: dict[str, str] = {}

    def text(self, text: str) -> str:
        for real, placeholder in self.roots:
            text = re.sub(re.escape(real) + r"(?![\w.-])", placeholder, text)
        if len(self.home) > 1:
            text = text.replace(self.home, "<path>")
        text = re.sub(r"(<path>)+", "<path>", OTHER_PATH.sub("<path>", text))
        return IDENTIFIER.sub(self.identifier, text)

    def identifier(self, m: re.Match[str]) -> str:
        return self.ids.setdefault(m.group(0), f"id-{len(self.ids) + 1}")

    def stream(self, text: str) -> str:
        """The stream without what the judge does not read. A line that does
        not parse is replaced by one that does not parse either, so the copy
        is as unreadable as the run without keeping what the line held."""
        kept = []
        for line in text.splitlines(keepends=True):
            try:
                value = json.loads(line)
            except ValueError:
                kept.append(UNREADABLE)
                continue
            if not isinstance(value, dict):
                kept.append(UNREADABLE)
            elif value.get("type") in STREAM_TYPES:
                kept.append(json.dumps(judged_part(value)) + "\n")
        return self.text("".join(kept))


def copy_scrubbed(cases: str, events_root: str, work: str, out: str) -> None:
    """Writes the scrubbed copy of cases and events_root to out, which must not exist."""
    if os.path.lexists(out):
        raise FileExistsError(out)
    s = Scrubber(work, events_root)
    partial = out + ".partial"
    shutil.rmtree(partial, ignore_errors=True)
    try:
        copy_file(
            s, os.path.join(cases, "seeds.json"), os.path.join(partial, "cases", "seeds.json")
        )
        for side, root, wanted in (
            ("cases", cases, CASE_FILES),
            ("events", events_root, EVENT_FILES),
        ):
            for group in sorted(n for n in os.listdir(root) if n != "seeds.json"):
                for inv in sorted(os.listdir(os.path.join(root, group))):
                    src = os.path.join(root, group, inv)
                    os.makedirs(os.path.join(partial, side, group, inv))
                    for name in sorted(os.listdir(src)):
                        if wanted.fullmatch(name):
                            dst = os.path.join(partial, side, group, inv, name)
                            copy_file(s, os.path.join(src, name), dst)
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    os.replace(partial, out)


def copy_file(s: Scrubber, src: str, dst: str) -> None:
    with open(src, encoding="utf-8", errors="surrogateescape") as f:
        text = f.read()
    name = os.path.basename(src)
    if name.startswith("stream-"):
        text = s.stream(text)
    elif name.startswith("runtime-") and name.endswith(".err"):
        text = s.text("".join(line for line in text.splitlines(keepends=True) if STOPPED in line))
    else:
        text = s.text(text)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write(text)
