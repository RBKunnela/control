"""One MCP client operation against a plane, printed as one JSON object.

The check that runs the guide end to end calls this once per step, so the
steps a person takes between two calls (an approval, a file removed) happen
outside it. It speaks Streamable HTTP through the MCP project's Python SDK.
"""

import argparse
import asyncio
import json
import sys
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


def answer_of(result: Any, ns: str) -> dict[str, Any]:
    """The parts of a tool result the check reads.

    A block or a pending state is the plane's only when its meta carries the
    namespace's answer key; an upstream cannot set that key, since the plane
    strips the namespace from what an upstream sends.
    """
    meta = result.meta or {}
    text = "".join(c.text for c in result.content if getattr(c, "type", "") == "text")
    return {
        "is_error": bool(result.isError),
        "answer": meta.get(ns + "answer", ""),
        "reason_code": meta.get(ns + "reason_code", ""),
        "reason_codes": list(meta.get(ns + "reason_codes", [])),
        "approval_id": meta.get(ns + "approval_id", ""),
        "text": text,
    }


async def run(args: argparse.Namespace) -> dict[str, Any]:
    async with streamable_http_client(args.url) as (read, write, _), ClientSession(read, write) as session:
        init = await session.initialize()
        if args.op == "tools":
            listed = await session.list_tools()
            return {
                "protocol": init.protocolVersion,
                "tools": sorted(t.name for t in listed.tools),
            }
        arguments = json.loads(args.arguments)
        if not isinstance(arguments, dict):
            raise SystemExit("the arguments are not a JSON object")
        result = await session.call_tool(args.tool, arguments)
        return answer_of(result, args.ns)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="the plane's MCP endpoint")
    parser.add_argument("--ns", required=True, help="the plane's meta namespace, with its trailing slash")
    sub = parser.add_subparsers(dest="op", required=True)
    sub.add_parser("tools", help="initialize and list the tools")
    call = sub.add_parser("call", help="call one tool")
    call.add_argument("tool")
    call.add_argument("arguments", help="the arguments as one JSON object")
    args = parser.parse_args()
    # A plane that never answers ends the step instead of the job's budget.
    json.dump(asyncio.run(asyncio.wait_for(run(args), timeout=60)), sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
