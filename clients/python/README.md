# guardana-control

A Python client of the Guardana Control enforcement API. A tool of yours asks
a plane before it acts and reports how the call ended, so the policy, the
approvals and the evidence trail that cover an MCP call cover it too.

`experimental`: the contract is `v1alpha1` and may change with any release.
Use the client of the plane's own release. Python 3.11 or later, no
dependencies.

No release carries it yet. From a checkout of the repository:

```
pip install ./clients/python
```

That builds the package on your machine with `flit_core`.

```python
from guardana_control.enforce import (
    CallBlocked,
    CallPending,
    Client,
    Result,
    Status,
)

client = Client(socket="/run/guardana/enforce.sock", token=run_token, timeout=5.0)


def refund(authorized: bytes) -> Result:
    receipt = payments.refund(authorized)  # send exactly these bytes
    return Result(Status.SUCCESS, value=receipt)


try:
    answer = client.call("refund", b'{"order_id":"ord-1"}', refund)
except CallBlocked as blocked:
    ...  # the tool did not run; blocked.answer.decision says why
except CallPending as held:
    ...  # an approver decides; ask again after held.answer.held.retry_after
```

What `call` does for you:

- runs the tool only on an `EXECUTE` answer it reads in full, with the bytes
  the plane authorized, which differ from yours when a rule rewrote them;
- sends one `complete` or one `abort`, never both, never twice;
- reports `UNKNOWN` when the tool raised, since it cannot tell whether the
  effect happened; raise `NotSent` only when the bytes never left;
- returns only when the tool ran and the closing record landed. Anything else
  raises. Only an `EnforceError` tells you, in `answer.ran`, whether the tool
  ran: entered, and not ended by `NotSent`. Any other exception is the tool's own, raised again after its
  run was reported `UNKNOWN`, or a `TypeError` or `ValueError` for a call
  misused before anything was sent;
- raises `ToolRaised`, an `EnforceError` with the outer call's answer, when
  your tool lets out the exception of a call of its own, alone or in a group
  of exceptions.

It cooperates and is not a security boundary. It runs inside the process it
constrains, so a plane reports its calls as `decided, not enforced`.

The guide is
[Decide a tool of your own](https://control.guardana.dev/docs/guides/decide-a-tool-of-your-own/);
the rules a client keeps are the cases in
[testdata/enforce](https://github.com/guardana/control/tree/main/testdata/enforce).
