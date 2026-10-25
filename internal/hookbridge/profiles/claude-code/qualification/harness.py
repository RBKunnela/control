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
    harness.py judge <cases> <events>
    harness.py report --results <jsonl> --meta <json> --out <file>

What an invocation left behind is read in harness_observed.py, and each case
is judged in harness_verdicts.py; both sit beside this file.
"""

import argparse
import json
import os
import re
import socket
import sys

# Run isolated, Python leaves this file's directory off the path. It goes last,
# so nothing beside this file can stand in for a module of the standard library.
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from harness_observed import events, jsonl, load_json  # noqa: E402
from harness_verdicts import FAIL, PASS, UNKNOWN, judge  # noqa: E402

KEEP = 2048


# settings


def settings(args):
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
                group["hooks"].append({"type": "command", "command": args.extra_pre, "timeout": 30})
    if args.disable:
        doc["disableAllHooks"] = True
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


def page_check(args):
    """Fails unless the page's settings block is the template, commands aside."""
    with open(args.page, encoding="utf-8") as f:
        page = f.read()
    blocks = re.findall(r"```json\n(.*?)```", page, re.S)
    found = [json.loads(b) for b in blocks if '"hooks"' in b]
    if len(found) != 1:
        sys.exit("harness: the page holds %d settings blocks, want 1" % len(found))
    with open(args.template, encoding="utf-8") as f:
        template = json.load(f)

    def blank(doc):
        for groups in doc["hooks"].values():
            for group in groups:
                for hook in group["hooks"]:
                    hook["command"] = "@HOOK@"
        return doc

    if blank(found[0]) != template:
        sys.exit("harness: the page's settings differ from " + args.template)


# observations


def snapshot(args):
    files = {}
    for base, dirs, names in os.walk(args.project):
        dirs[:] = [d for d in dirs if d != ".claude"]
        for name in names:
            path = os.path.join(base, name)
            with open(path, "rb") as f:
                files[os.path.relpath(path, args.project)] = f.read(KEEP).decode("utf-8", "replace")
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(files, f, indent=1, sort_keys=True)


def held(args):
    for ev in reversed(events(args.dir)[0]):
        m = re.search(r"held for approval (\S+);", ev["meta"].get("stderr", ""))
        if m and ev["kind"] == "PreToolUse":
            print(m.group(1))
            return


def field(args):
    value = load_json(args.file, {})
    for key in args.path.split("."):
        value = value.get(key) if isinstance(value, dict) else None
    print("" if value is None else value)


def free_port(_):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        print(s.getsockname()[1])


# results


def report(args):
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
    print("%-24s %-5s %-8s %s" % ("case", "runs", "verdict", "note"))
    for r in results:
        note = r["observed"].get("unknown", "")
        print("%-24s %-5d %-8s %s" % (r["id"], r["invocations"], r["verdict"], note))
    verdicts = [r["verdict"] for r in results]
    counts = {v: verdicts.count(v) for v in (PASS, FAIL, UNKNOWN)}
    print("%d passed, %d failed, %d unknown" % (counts[PASS], counts[FAIL], counts[UNKNOWN]))
    if not results or any(v not in (PASS, FAIL, UNKNOWN) for v in verdicts):
        return 2
    if counts[FAIL]:
        return 1
    return 3 if counts[UNKNOWN] else 0


def main():
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
    p.set_defaults(fn=judge)
    p = sub.add_parser("report")
    p.add_argument("--results", required=True)
    p.add_argument("--meta", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--judged-at", help="the commit whose judge read the observations, when not the run's")
    p.set_defaults(fn=report)
    args = parser.parse_args()
    sys.exit(args.fn(args) or 0)


if __name__ == "__main__":
    main()
