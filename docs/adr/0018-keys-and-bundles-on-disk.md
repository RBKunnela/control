# ADR-0018: A policy key and a signed bundle each have one format on disk

Status: accepted
Date: 2026-09-24

Builds on [ADR-0007](0007-repository-layout-and-dependency-rule.md),
[ADR-0011](0011-contract-corrections-before-publication.md) and
[ADR-0016](0016-approval-providers-and-the-lost-hold.md).

Amended by [ADR-0038](0038-a-signed-freshness-statement-and-a-serial-floor.md),
which decides that a serial floor on disk stops a rollback across a restart and
that a freshness key signs the statements that keep a bundle current;
[status.md](../status.md) says how much of it a plane does today.

Amended by [ADR-0066](0066-each-decision-about-authority-is-a-port.md),
which decides that a signer port may hold a key that never reaches the
process and that a signed roster names each key's algorithm;
[status.md](../status.md) says how much of it a plane does today.

## Context

ADR-0011 fixed how a bundle is signed: Ed25519 over DSSE's pre-authentication
encoding of the canonical bytes, `signature_alg` a fixed string, and `key_id`
an unauthenticated hint that selects a key the operator pinned. It did not fix
how the key is held, how it is named, or how either reaches the plane, and no
command made them: `policy.Sign` was reached by `policy test` alone, with a
fixed key, while the run guide required a signed bundle without saying how to
get one.

The gateway already reads three things: a binary `PolicyBundle` file,
`policy.key_id`, and `policy.public_key` as standard base64 of 32 bytes. Other
programs will script the making of all three, a lab's setup and a pipeline
among them, so the formats outlive the change that introduces them.

## Decision

**Two commands, in the approver's binary.** `guardana-control policy keygen
--out <dir>` makes a key pair and `guardana-control policy sign --key <file>
--out <file> <document>` makes a bundle. That binary still links neither the
pipeline nor evidence (ADR-0016).

**A key pair is a directory keygen creates.** `--out` names a path that must
not exist. keygen creates it `0700` and writes `signing.key` and `signing.pub`
into it, each through a temporary file, a sync, a link that never replaces and
a sync of the directory, and removes what it created when any step fails.
Creating the directory is the one step that decides that no key is ever
overwritten: an existing path is refused and nothing is written. After creating
it, keygen opens the path without following a link or waiting on it and
refuses anything but an empty directory the user owns, then works through that
handle, so a link, a pipe or a directory that is not empty or not the user's,
swapped in, receives nothing. An empty directory the user owns, swapped in,
cannot be told from the one made and is taken.

**The private key is one PKCS#8 block in PEM.** The file holds exactly one
block of type `PRIVATE KEY`, with no headers, nothing before it and only white
space after it, whose payload is an Ed25519 key in PKCS#8 version 1: the
encoding of RFC 8410's first example, and the one Go's standard library
writes. The payload must re-encode to itself byte for byte, because the
library's parser ignores bytes after the key, so a version 2 key that carries
its public half is refused too. An OpenSSH key, an encrypted key, an EC or RSA
key and a public key are each refused by name. The file is judged from the
opened descriptor: a regular file, owned by the user running the command,
within a size bound, with no permission bit for the group or for others, so
`0400`, `0600` and `0700` are read and anything wider is refused.

**The key reaches a process as a path and nothing else.** Never a flag value,
an environment variable or standard input. Every command of both binaries
refuses an argument that holds a PEM marker, opening or closing, the start of
the body line every key file of this format begins with, a line break or
another control character, before anything parses or reads it, with a sentence
that repeats none of it, because such an argument is key text in the place of a
path. The gateway's configuration refuses the same text, at load and naming the
key, in every setting that names a path: the bundle file, the approvals, hold
journal and evidence directories, the pause file and an upstream's command.
Whatever either binary prints from a setting, a file or the environment passes
through one function that withholds a PEM block or marker and a base64 run
holding the body line's start, and quotes a control, separator or format
character, so no refusal, `doctor` line or listing repeats key text. No refusal
quotes the key file or prints the `--key` value: a refusal about the key names
the flag and the check that failed.

**The public key is one line**, standard base64 of the 32 raw bytes, which is
what `policy.public_key` takes. The line as `signing.pub` holds it, with its one
trailing newline, is taken too, and no other spelling. One package writes it
and parses it for both binaries.

**The key id is derived, never chosen.** It is `ed25519-` followed by the first
16 lowercase hex digits of SHA-256 over the 32 raw public key bytes. `sign`
computes it from the key it signs with and takes no flag for it. The gateway
still accepts any id it is configured with, so a configuration written before
this record stays valid. Sixty-four bits is ample for a hint: a collision turns
an unknown key into a signature that does not verify, never into a bundle that
is accepted.

**Sign never writes a bundle the loader refuses.** It reads the document first
and refuses one that does not parse before it opens the key. It then signs and
loads the result under the key's own public half, and writes nothing when that
load refuses. A plane may still refuse the bundle, because a plane also pins a
bundle id, a key and a staleness budget. The bundle is written `0644`, because
a bundle is public, through a temporary file and a rename; for one build, the
same document and key give the same bytes. An `--out` that is the same file as
the key or the document is refused, and an `--out` that exists is replaced only
when it already holds a policy bundle, so no other file, another key included,
is ever replaced.

**Output a script can read.** keygen prints exactly two lines, `key_id: <id>`
and `public_key: <line>`, the two members the configuration's `policy` group
needs. sign prints one `name: value` line each for `bundle_id`, `version`,
`serial`, `digest`, `key_id` and `out`.

**The gateway binary never reads a private key.** Dev mode signs with a key it
draws in memory and pins that key's public half, so nothing the gateway writes
holds a private key.

**A plane that pins another key says which.** When the bundle's `key_id` is
not the configured one, the refusal names both. Both are public, and this is
the refusal a key rotation produces.

**A platform without permission bits refuses.** Where the mode of a key file
cannot be read, both commands refuse with a line of their own rather than use a
key whose exposure they cannot check.

## Security / compatibility impact

Whoever can read `signing.key` can sign a bundle every plane that pins its
public half accepts: the file is the policy authority. The permission rule
refuses a key file that another account owns or holds any permission on; it
cannot protect a key from the account that owns it, and it does not try.

No wire contract, digest, reason code or public Go package changes. `key_id`
stays a hint that selects a key and is never trusted on its own. A bundle can
still be rolled back across a restart, because the serial the holder checks
lives for one process; `sign` does not compare an existing `--out` with the
bundle it writes.

## Alternatives considered

- **A raw base64 seed as the private key file.** It has the shape of the public
  line, 44 characters of base64, so it can be pasted into `policy.public_key`,
  which lives in a configuration file, a variable and `doctor`'s output.
- **An operator-chosen key id.** A second spelling to keep in step between
  keygen, sign and the configuration, and an id that can be reused for another
  key.
- **keygen into an existing directory with two exclusive creates.** A run that
  dies between them, or a directory already holding only the public file,
  leaves a private key whose public half nobody printed.
- **An encrypted private key.** The standard library reads no encrypted PKCS#8,
  and a passphrase needs a way in that is not a flag or a variable; the
  permission rule is what this build offers.
- **The gateway signing at start from a private key file.** It would put the
  policy authority's key on the host that runs the plane.

## Consequences

An operator makes one key pair per policy authority and signs each document
with it. A key mounted into a container needs mode `0400`, since the usual
`0444` is refused. A rotation signs with the new key and changes
`policy.key_id` and `policy.public_key` together, because a plane pins one key.
The file handling these commands need lives in `internal/files`, which the
approvals store, the hold journal and the spool can move onto later.

## Declared limits

- The permission check reads the mode bits and the owner. On macOS an access
  control list can grant what the mode bits do not show, and the check does not
  read it; on Linux a named entry raises the group bits, which the check
  refuses.
- A crash between keygen's two links leaves the private key alone, or a
  temporary file, inside the owner-only directory. The next keygen refuses the
  path, and the operator removes it.
- A failure to sync the directory after the rename is reported although the
  new bundle may already be in place.
- Only the `--key` value is never printed. Key text in another encoding, a raw
  seed or hex, or a key file's body line split or spaced so that no argument
  holds its whole start, given as the document or as `--out`, is named in a
  refusal or in `sign`'s output line.
- When keygen fails, its cleanup removes the directory at `--out` if that is an
  empty directory, which can be one swapped in after keygen made its own.

## Validation

Tests in `internal/policykey` and in the two commands: the DER prefix RFC 8410
fixes for an Ed25519 PKCS#8 key and the key id, both as literal goldens; the
permission table read through the descriptor; every PEM refusal; a fuzz target
on the key reader whose refusals echo no eight-byte window of their input; no
output of any path, success and every refusal including one reached after the
key was parsed, holding the seed or the private key in any encoding, with the
key's text given as `--key`, as the document and as any other argument among
them; `--out` as the key or the document by a relative spelling and by a hard
link, and an existing `--out` that is not a bundle, another key among them,
left as it was; an `--out` reaching the key through a link and `..` refused;
a refused document leaving `--out` unchanged; a link, a pipe or another
directory swapped in after keygen created its own receiving no key; and a key
pair and
bundle made through the package starting a plane through the gateway's own
reader, with `signing.pub` taken as it is, and failing under another key with
both ids named.
