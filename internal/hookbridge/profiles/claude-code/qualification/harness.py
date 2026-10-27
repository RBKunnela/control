"""The judging half of qualify.sh: settings, snapshots, verdicts and results.

qualify.sh runs the plane and the runtime and leaves, per invocation, what it
saw in <cases>/<group>/<invocation>/ and the hook events in
<events>/<group>/<invocation>/. Every verdict here is read from those files.
A case whose tool call was not made, or whose observation is missing or
cannot be read, is unknown, never passed.

    harness.py settings --template <file> --out <file> --hook <command> [options]
    harness.py page-check --template <file> --page <file>
    harness.py snapshot <project> <out>
    harness.py held <events dir>
    harness.py field <json file> <dotted path>
    harness.py free-port
    harness.py judge <cases> <events> [--work <dir>]
    harness.py scrub --cases <dir> --events <dir> --work <dir> --out <dir>
    harness.py rejudge <scrubbed copy> <results>
    harness.py report --results <jsonl> --meta <json> --out <file>

What an invocation left behind is read in harness_observed.py, each case is
judged in harness_judge.py by the judges of harness_verdicts.py,
harness_hold.py and harness_rewrite.py, and harness_scrub.py makes the copy
of the observations that may be kept; all sit beside this file.
"""

import argparse
import json
import os
import re
import socket
import sys
from typing import Any

# Run isolated, Python leaves this file's directory off the path. It goes last,
# so nothing beside this file can stand in for a module of the standard library.
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from harness_judge import judged
from harness_observed import events, jsonl, load_json
from harness_scrub import SCRUBBED, copy_scrubbed
from harness_verdicts import FAIL, PASS, UNKNOWN

KEEP = 2048


# settings


def settings(args: argparse.Namespace) -> None:
    with open(args.template, encoding="utf-8") as f:
        doc = json.load(f)
    for event, groups in doc["hooks"].items():
        for group in groups:
            for hook in group["hooks"]:
                hook["command"] = args.hook
                if event != "PreToolUse":
                    continue
                if args.pre:
                    hook["command"] = args.pre
                if args.pre_timeout:
                    hook["timeout"] = args.pre_timeout
                if args.no_fail_closed:
                    hook.pop("onFailure", None)
            if event == "PreToolUse" and args.extra_pre:
                extra = {"type": "command", "command": args.extra_pre, "timeout": 30}
                group["hooks"].append(extra)
    if args.disable:
        doc["disableAllHooks"] = True
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


def page_check(args: argparse.Namespace) -> None:
    """Fails unless the page's settings block is the template, commands aside."""
    with open(args.page, encoding="utf-8") as f:
        page = f.read()
    blocks = re.findall(r"```json\n(.*?)```", page, re.S)
    found = [json.loads(b) for b in blocks if '"hooks"' in b]
    if len(found) != 1:
        sys.exit(f"harness: the page holds {len(found)} settings blocks, want 1")
    with open(args.template, encoding="utf-8") as f:
        template = json.load(f)

    def blank(doc: Any) -> Any:
        for groups in doc["hooks"].values():
            for group in groups:
                for hook in group["hooks"]:
                    hook["command"] = "@HOOK@"
        return doc

    if blank(found[0]) != template:
        sys.exit("harness: the page's settings differ from " + args.template)


# observations


def snapshot(args: argparse.Namespace) -> None:
    """Writes every file of the project, a symbolic link as its target. A
    project that is not there, or a walk that fails anywhere, writes nothing:
    an empty snapshot would read as a call that had no effect."""
    if not os.path.isdir(args.project):
        sys.exit(f"harness: the project {args.project} is not a directory")

    def fail(e: OSError) -> None:
        raise e

    files = {}
    for base, dirs, names in os.walk(args.project, onerror=fail):
        links = [d for d in dirs if os.path.islink(os.path.join(base, d))]
        dirs[:] = [d for d in dirs if d != ".claude" and d not in links]
        for name in links:
            path = os.path.join(base, name)
            files[os.path.relpath(path, args.project)] = "symbolic link to " + os.readlink(path)
        for name in names:
            path = os.path.join(base, name)
            with open(path, "rb") as raw:
                text = raw.read(KEEP).decode("utf-8", "replace")
            files[os.path.relpath(path, args.project)] = text
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(files, f, indent=1, sort_keys=True)


def held(args: argparse.Namespace) -> None:
    for ev in reversed(events(args.dir)[0]):
        m = re.search(r"held for approval (\S+);", ev["meta"].get("stderr", ""))
        if m and ev["kind"] == "PreToolUse":
            print(m.group(1))
            return


def field(args: argparse.Namespace) -> None:
    value = load_json(args.file, {})
    for key in args.path.split("."):
        value = value.get(key) if isinstance(value, dict) else None
    print("" if value is None else value)


def free_port(_: argparse.Namespace) -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        print(s.getsockname()[1])


# verdicts


def judge(args: argparse.Namespace) -> None:
    try:
        results = judged(args.cases, args.events, args.work)
    except ValueError as e:
        sys.exit(f"harness: {e}")
    for r in results:
        print(json.dumps(r))


def scrub(args: argparse.Namespace) -> None:
    copy_scrubbed(args.cases, args.events, args.work, args.out)


def recorded_verdicts(path: str) -> tuple[dict[str, str], str | None]:
    """The verdict of each case in a results file or the judge's lines, and
    why they could not be read, or None."""
    name = os.path.basename(path)
    cases: Any
    if path.endswith(".jsonl"):
        cases, problem = jsonl(path)
    else:
        doc = load_json(path)
        cases = doc.get("cases") if isinstance(doc, dict) else None
        problem = None
    if problem:
        return {}, problem
    if not isinstance(cases, list) or not cases:
        return {}, name + " holds no cases"
    if not all(isinstance(r, dict) and isinstance(r.get("id"), str) for r in cases):
        return {}, name + " holds a case with no id"
    return {r["id"]: str(r.get("verdict")) for r in cases}, None


def rejudge(args: argparse.Namespace) -> int:
    """Judges a scrubbed copy again; 0 when every case has its recorded
    verdict, 1 when one differs, 2 when either side cannot be read."""
    want, problem = recorded_verdicts(args.results)
    try:
        got = {r["id"]: r["verdict"] for r in judged(*copy_dirs(args.copy), SCRUBBED)}
    except ValueError as e:
        problem = problem or str(e)
    if problem:
        print("harness: " + problem, file=sys.stderr)
        return 2
    differ = sorted(k for k in set(want) | set(got) if want.get(k) != got.get(k))
    for k in differ:
        print(f"harness: {k} was {want.get(k)}, the scrubbed copy is judged {got.get(k)}")
    if differ:
        return 1
    print(f"harness: the scrubbed copy is judged as recorded, {len(got)} cases")
    return 0


def copy_dirs(copy: str) -> tuple[str, str]:
    return os.path.join(copy, "cases"), os.path.join(copy, "events")


# results


def report(args: argparse.Namespace) -> int:
    results, problem = jsonl(args.results)
    if problem:
        print("harness: " + problem, file=sys.stderr)
        return 2
    meta = load_json(args.meta, {})
    doc = dict(meta, cases=results)
    if args.judged_at:
        doc["judged_at"] = args.judged_at
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print("%-24s %-5s %-8s %s" % ("case", "runs", "verdict", "note"))  # noqa: UP031
    for r in results:
        note = r["observed"].get("unknown", "")
        print("%-24s %-5d %-8s %s" % (r["id"], r["invocations"], r["verdict"], note))  # noqa: UP031
    verdicts = [r["verdict"] for r in results]
    counts = {v: verdicts.count(v) for v in (PASS, FAIL, UNKNOWN)}
    print(f"{counts[PASS]} passed, {counts[FAIL]} failed, {counts[UNKNOWN]} unknown")
    if not results or any(v not in (PASS, FAIL, UNKNOWN) for v in verdicts):
        return 2
    if counts[FAIL]:
        return 1
    return 3 if counts[UNKNOWN] else 0


def parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="harness.py")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("settings")
    p.add_argument("--template", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--hook", required=True)
    p.add_argument("--pre")
    p.add_argument("--pre-timeout", type=int)
    p.add_argument("--no-fail-closed", action="store_true")
    p.add_argument("--extra-pre")
    p.add_argument("--disable", action="store_true")
    p.set_defaults(fn=settings)
    p = sub.add_parser("page-check")
    p.add_argument("--template", required=True)
    p.add_argument("--page", required=True)
    p.set_defaults(fn=page_check)
    p = sub.add_parser("snapshot")
    p.add_argument("project")
    p.add_argument("out")
    p.set_defaults(fn=snapshot)
    p = sub.add_parser("held")
    p.add_argument("dir")
    p.set_defaults(fn=held)
    p = sub.add_parser("field")
    p.add_argument("file")
    p.add_argument("path")
    p.set_defaults(fn=field)
    p = sub.add_parser("free-port")
    p.set_defaults(fn=free_port)
    p = sub.add_parser("judge")
    p.add_argument("cases")
    p.add_argument("events")
    p.add_argument("--work", help="the directory the project paths were under, when moved")
    p.set_defaults(fn=judge)
    p = sub.add_parser("scrub")
    p.add_argument("--cases", required=True)
    p.add_argument("--events", required=True)
    p.add_argument("--work", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=scrub)
    p = sub.add_parser("rejudge")
    p.add_argument("copy")
    p.add_argument("results")
    p.set_defaults(fn=rejudge)
    p = sub.add_parser("report")
    p.add_argument("--results", required=True)
    p.add_argument("--meta", required=True)
    p.add_argument("--out", required=True)
    p.add_argument(
        "--judged-at", help="the commit whose judge read the observations, when not the run's"
    )
    p.set_defaults(fn=report)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return int(args.fn(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
