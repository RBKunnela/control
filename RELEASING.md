# Releasing

`.github/workflows/release.yml` builds, signs and publishes every release;
no asset is uploaded from a laptop. Until 1.0 a release follows every one to
three changes, from 1.0 every Monday, an urgent fix out of turn, each after an
audit of the whole tree
([ADR-0052](docs/adr/0052-a-change-is-gated-on-its-pull-request.md)).

## Cutting a release

1. Reconcile `docs/status.md` with the candidate's exercised commands and
   tests. Move built work out of `planned`; promote `experimental` only when
   documented readiness, compatibility and security checks pass. Record the
   proof and remaining limits.
2. Update `README.md`, `site/index.html` and affected pages to that
   inventory. Remove delivered roadmap/backlog tasks; keep incomplete ones
   `planned`. Regenerate with `make docs-gen`.
3. Add the dated `## [X.Y.Z] - YYYY-MM-DD` section to `CHANGELOG.md`.
   `scripts/release-notes.sh vX.Y.Z` prints it; the workflow refuses
   missing, undated or empty notes. Set its Python spelling (`1.2.3rc1`) in
   `clients/python/pyproject.toml` and run `uv lock` there.
4. Gate the release commit cold with `scripts/gate-commit.sh`; the admin
   pushes it to `main`. Wait for green CI and Security.
5. Tag the commit and push:

   ```sh
   version=X.Y.Z
   git tag -a "v${version}" -m "Guardana Control ${version}"
   git push origin "v${version}"
   ```

6. Approve the Release run (`release`), then its upload job (`pypi`), in
   Review deployments. Only a maintainer or admin may push a `v*` tag or
   approve.
7. After publication, set `"released"` in `docs/docs.json`, regenerate and
   open a pull request; verify the live version, labels and links. Until
   then the website must not name it.

A version is `X.Y.Z`; a suffix such as `-rc.1` marks a preview.

## What the workflow does

1. Builds `guardana-gateway` and `guardana-control` for Linux and macOS on
   amd64 and arm64 from the tag: per platform an archive of both and a demo
   archive with the server, each with a CycloneDX bill of materials, listed
   in `checksums.txt`.
2. Cosign signs checksums keylessly; the certificate names this workflow and tag.
3. Pushes `ghcr.io/guardana/control-gateway`: the gateway alone, nonroot,
   linux/amd64 and linux/arm64, under `sha-<commit>`; drafts the release.
4. Scans every archive and image binary on every platform with
   `govulncheck -mode=binary` (`scripts/scan-binaries.sh`).
5. Runs the demo without Go on `PATH`, attests every file, signs and attests
   the image.
6. Verifies downloads and image, adds the image's version tag, publishes the
   draft with its digest.
7. Builds and attests the Python client's files before the draft; after
   publication a separate job, re-runnable alone, uploads them to PyPI and
   reads them back.

A known-vulnerable symbol, called or not, or an unavailable scan stops release.
Only `main`'s head may release, with CI, Security and the newest CodeQL
analysis covering it; advancing `main` before approval fails it. Before
Publish, failure leaves at most a draft and staging/version image tags:
delete them, fix the cause, release the next version. Publish requires
exactly the verified files and rereads their digests; failure then leaves a public
release and reports recovery steps.

## A dry run

Run the workflow from `main` with the intended tag. It checks the gate and notes,
builds and scans unsigned `0.0.0-snapshot.<commit>` archives and image, runs
the image and demo on the runner's platform, and publishes only the Python
client, to TestPyPI as `X.Y.Z.dev<run>`.
`make release-snapshot`, `make check-demo-archive` and `make scan-binaries`
build, scan and run locally with Docker; they check neither gate nor notes.

## A tag never moves

Never delete, move or reuse a published tag or replace release files.
Name a broken release in the next version's changelog.

## Checking a download

Download the archive, `checksums.txt` and `checksums.txt.sigstore.json`, then,
for `v0.1.0-alpha`:

```sh
sha256sum --ignore-missing -c checksums.txt

cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/guardana/control/.github/workflows/release.yml@refs/tags/v0.1.0-alpha" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify guardana-control_0.1.0-alpha_linux_amd64.tar.gz \
  --repo guardana/control \
  --cert-identity "https://github.com/guardana/control/.github/workflows/release.yml@refs/tags/v0.1.0-alpha" \
  --source-ref refs/tags/v0.1.0-alpha --deny-self-hosted-runners
```

On macOS use `shasum -a 256 --ignore-missing -c checksums.txt`. The signature
and the attestation bind the checksummed archive to the workflow and tag.

## Checking the image

A writer can overwrite a registry tag or the notes. Check the notes' digest
with cosign v3 or later; it signs the index, not each platform's image. For
`vX.Y.Z`:

```sh
tag=vX.Y.Z
image=ghcr.io/guardana/control-gateway@sha256:<the digest in the release notes>

cosign verify "$image" \
  --certificate-identity "https://github.com/guardana/control/.github/workflows/release.yml@refs/tags/${tag}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify "oci://$image" \
  --repo guardana/control \
  --cert-identity "https://github.com/guardana/control/.github/workflows/release.yml@refs/tags/${tag}" \
  --source-ref "refs/tags/${tag}" --deny-self-hosted-runners
```
