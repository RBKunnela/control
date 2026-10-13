# guardana-control

A Python client of the Guardana Control enforcement API. A tool of yours asks
a plane before it acts and reports how the call ended, so the policy, the
approvals and the evidence trail that cover an MCP call cover it too.

`experimental`: the contract is `v1alpha1` and may change with any release.
Use the client of the plane's own release. Python 3.11 or later, no
dependencies.

```
pip install "guardana-control @ git+https://github.com/guardana/control@<tag>#subdirectory=clients/python"
```

`<tag>` is the tag of your plane's release.

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
  raises: an `EnforceError` carries an `answer` whose `ran` says whether the
  tool was entered, and a plain `TypeError` or `ValueError` says the call was
  misused before the tool could run.

It cooperates and is not a security boundary. It runs inside the process it
constrains, so a plane reports its calls as `decided, not enforced`.

The guide is
[Decide a tool of your own](https://control.guardana.dev/docs/guides/decide-a-tool-of-your-own/);
the rules a client keeps are the cases in
[testdata/enforce](https://github.com/guardana/control/tree/main/testdata/enforce).
