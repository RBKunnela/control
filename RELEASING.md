# Releasing

How a version is cut, and how anyone checks what was published.
`.github/workflows/release.yml` builds, signs and publishes every release;
nothing is uploaded from a laptop.

## Cutting a release

1. Give the version its section in `CHANGELOG.md`, with the date:
   `## [X.Y.Z] - YYYY-MM-DD`. The workflow publishes that section as the
   release notes and fails if it is missing, undated or empty.
   `scripts/release-notes.sh vX.Y.Z` prints it.
2. Commit that on `main`, and let CI and Security finish green on it.
3. Tag the commit and push the tag:

   ```sh
   version=X.Y.Z
   git tag -a "v${version}" -m "Guardana Control ${version}"
   git push origin "v${version}"
   ```

4. Approve the waiting run: the tag's Release run, Review deployments. Only a
   maintainer or the admin may push a `v*` tag or approve its run.
5. Once the release is published, set `"released"` in `docs/docs.json` to the
   version, run `make docs-gen` and commit. Only then does the website name
   it.

A version is a plain `X.Y.Z`; a suffix such as `-rc.1` marks a preview of it.

## What the workflow does

1. Builds the binaries for Linux and macOS on amd64 and arm64 from the tagged
   commit, packs per platform an archive of the two binaries and a demo
   archive that adds the demo's server, each with a CycloneDX bill of
   materials, and writes `checksums.txt`.
2. Signs `checksums.txt` with cosign, keyless: the certificate names this
   workflow and the tag.
3. Pushes the image `ghcr.io/guardana/control-gateway`, `guardana-gateway`
   alone as a nonroot user, for linux/amd64 and linux/arm64 under the staging
   tag `sha-<commit>`, and drafts the release.
4. Scans every binary of every archive, and the image's binary for each
   platform, with `govulncheck -mode=binary` (`scripts/scan-binaries.sh`).
5. Runs the demo archive with no Go on `PATH`, attests every file, and signs
   and attests the image.
6. Verifies it as a user would, tags the image with the version, and
   publishes the draft with the image's digest in its notes.

A known-vulnerable symbol in a binary, called or not, or a scan that could not
run, stops the release. The workflow releases only `main`'s head, once CI and
Security passed on it and `main`'s newest CodeQL analysis covers it: a push to
`main` before approval fails it. Until Publish, a failure leaves at most a
draft and the image's staging and version tags: delete them, fix the cause,
release the next version. Publish makes the draft public only if it holds
exactly the verified files, then reads it again; a failure there leaves a
public release and says what to do.

## A dry run

Run the workflow by hand with the tag the release will carry. It makes the
same gate check, prints the notes, builds and scans the archives and the image
as `0.0.0-snapshot.<commit>`, unsigned, runs the image and the demo for the
runner's platform, and publishes nothing. `make release-snapshot`,
`make check-demo-archive` and `make scan-binaries` build, scan and run the
demo locally, with Docker, and check neither the gate nor the notes.

## A tag never moves

A published tag is never deleted, moved or reused, and a published release
never gets other files. A broken release is named in the next version's
changelog.

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

On macOS use `shasum -a 256 --ignore-missing -c checksums.txt`. In turn: the
archive is the one the checksum file names, this repository's release workflow
signed that file for that tag, and that workflow built the archive from that
tag.

## Checking the image

Anyone with write access to the repository or package can overwrite a
registry tag or release notes. Take the digest from the notes and check it
with cosign v3 or later. The signature covers the index, not each platform's
image. For `vX.Y.Z`:

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
