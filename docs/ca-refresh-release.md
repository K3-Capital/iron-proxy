# Release procedure: CA-hardened iron-proxy v0.54.0 image (KCA-807 / KCA-810)

This document is the operator procedure for cutting the K3 CA-hardened release
image from the `release/0.54` maintenance branch and proving, before rollout,
that the image no longer trusts the compromised eMudhra hierarchy.

It is written for the release owner (Devops / KCA-811). Nothing here is
automated: no release tag, no registry push and no image acceptance happens in
the implementation PR that adds this file.

## 1. What this release is and is not

The release image is the agent egress trust boundary. Agents send their HTTP(S)
through iron-proxy, and the proxy is the component that verifies the upstream
certificate. Go binaries use the system root pool, so the runtime CA bundle
inside this image decides whether forged eMudhra chains are accepted.

The 0.41.0 image that K3 runs today accepts 7 of the 14 published forged chains,
and an in-container `wget https://dv-g3b-emudhra.we-have-a-problem.com/`
succeeds. This release replaces it with a build of the official v0.54.0 source
whose runtime bundle rejects all 14.

This release does **not** change the proxy's application behaviour, K3's private
MITM CA, the production `proxy.yaml`, the allowlist policy, the audit format, or
any upstream selection in another repository. Those are owned elsewhere;
`Dockerfile.release` and the release tooling are the only source changes.

## 2. Source identity

| Item | Value |
| --- | --- |
| Repository | `https://github.com/K3-Capital/iron-proxy` |
| Branch | `release/0.54` (maintenance; never merged into `main`) |
| Upstream baseline | official `paradigmxyz/iron-proxy` tag `v0.54.0` |
| Baseline commit | `60ed3566e5b39b1ef74d4854c62eb2d9fc4b8f42` |
| Go module path | `github.com/ironsh/iron-proxy` (unchanged) |
| Go toolchain | **1.27.3** (`go.mod` `go 1.27.3`) |

`v0.54.0` is the release that states the eMudhra requirement and raises the
toolchain to Go 1.27.3. Do not build this branch with an older compiler, and do
not fall back to fork `main` (0.53-era source). Keep `GOTOOLCHAIN=local` so an
unexpected toolchain download cannot silently substitute a different compiler.

Re-verify the baseline before building:

```sh
git fetch origin release/0.54
git rev-parse origin/release/0.54
git log -1 --format='%H %ci %s' origin/release/0.54
go version          # must print go1.27.3
```

## 3. What changed in the image

`Dockerfile.release` previously started from `alpine:latest` and ran an
unpinned `apk add ca-certificates`, so the shipped bundle floated with whatever
the parent layer carried. That is how an image can keep trusting a revoked
hierarchy while everything else looks healthy.

```
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
ARG TARGETARCH
RUN apk add --no-cache ca-certificates=20261020-r0 ca-certificates-bundle=20261020-r0 openssl
COPY linux/${TARGETARCH}/iron-proxy /usr/local/bin/iron-proxy
ENTRYPOINT ["iron-proxy"]
```

- The base is a verified multi-platform index digest for Linux amd64 and arm64.
- Both the root-source package (`ca-certificates`) and the generated bundle
  (`ca-certificates-bundle`) are pinned to `20261020-r0`, the post-compromise
  release. Normal apk signature validation and the `v3.24` repository branch are
  preserved; there is no `apk upgrade` and no floating package.
- Architecture selection, binary destination, executable behaviour and the
  entrypoint are unchanged.

If a pinned package is unavailable at build time, stop and report a blocker.
Do not float the pin and do not substitute a different base.

## 4. Preconditions

1. Every PR in this stack carries an independent Principal Engineer /
   Principal Software Architect approval **at its current head SHA**. A rebase,
   restack, force-push or base movement invalidates that approval; get a fresh
   review rather than merging on an older approval.
2. The release runs from a clean checkout of the approved source. Any local
   modification changes the built bytes and the `vcs.modified` flag.
3. The operator has existing, authorised GHCR write access to
   `ghcr.io/k3-capital/iron-proxy`. Do not change account, package ACL or
   organisation policy to work around a refusal, and never print credentials.
4. Buildx/BuildKit and both architecture workers (native or verified QEMU)
   are available. `Dockerfile.release` has an `apk` RUN step, so the retired
   COPY-only build's "no emulation needed" assumption does not apply.
5. The intended Git tag and registry version are unused. Absence may only be
   concluded from an authenticated not-found response; an authentication,
   rate-limit or transport error is a blocker, not proof of absence.

## 5. Names for this release

| Kind | Value |
| --- | --- |
| Git tag | `k3-ca-v0.54.0-20261025.1` |
| Image version tag | `0.54.0-k3.ca.20261025.1` |
| Registry package | `ghcr.io/k3-capital/iron-proxy` |

The Git tag deliberately does **not** start with `v`. The inherited upstream
workflow (`.github/workflows/release.yml`) triggers on `v*` tags and publishes
through upstream Docker Hub / GoReleaser-Pro credentials that K3 does not own
and must not use. A `k3-ca-*` tag does not trigger it.

GHCR has no atomic create-only tag guarantee. If a version tag already exists,
or a partial push left one behind, stop: choose a newly reviewed increment
(`...20261025.2`) and never overwrite or republish the version.

## 6. Build and publish

Run from a scratch directory outside the source tree and keep the evidence.

```sh
SRC="$(git rev-parse --show-toplevel)"
SOURCE_SHA="$APPROVED_SOURCE_SHA"          # exact approved head / merge commit
VERSION=0.54.0-k3.ca.20261025.1
GIT_TAG=k3-ca-v0.54.0-20261025.1
IMAGE=ghcr.io/k3-capital/iron-proxy
: "${TMPDIR:?approved build scratch directory required}"

test "$(git rev-parse HEAD)" = "$SOURCE_SHA"
test -z "$(git status --porcelain)"
export GOTOOLCHAIN=local
test "$(go version)" = "go version go1.27.3 linux/amd64"   # adapt to build host

go mod download
go mod verify
go test -race -count=1 ./...
go vet ./...
go build -mod=readonly ./cmd/iron-proxy

BUILD_ROOT="$(mktemp -d "$TMPDIR/kca807-release.XXXXXX")"
CTX="$BUILD_ROOT/context"
for arch in amd64 arm64; do
  mkdir -p "$CTX/linux/$arch"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
    -mod=readonly -trimpath -buildvcs=true \
    -ldflags="-s -w -X github.com/ironsh/iron-proxy/internal/version.Version=$VERSION" \
    -o "$CTX/linux/$arch/iron-proxy" ./cmd/iron-proxy
  go version -m "$CTX/linux/$arch/iron-proxy" | tee "$BUILD_ROOT/version-$arch.txt"
  sha256sum "$CTX/linux/$arch/iron-proxy" | tee "$BUILD_ROOT/binary-$arch.sha256"
done
```

Require `vcs.revision` to equal `$SOURCE_SHA` and `vcs.modified=false` in both
binaries before continuing.

Tag the approved source, then build and push the multi-platform image:

```sh
git tag -a "$GIT_TAG" "$SOURCE_SHA" -m "KCA-807 CA-hardened release $VERSION"
git push origin "refs/tags/$GIT_TAG"
git ls-remote --tags origin "refs/tags/$GIT_TAG*"     # dereference and compare

docker buildx build --pull --no-cache \
  --file "$SRC/Dockerfile.release" \
  --platform linux/amd64,linux/arm64 \
  --provenance mode=max \
  --label org.opencontainers.image.source=https://github.com/K3-Capital/iron-proxy \
  --label "org.opencontainers.image.revision=$SOURCE_SHA" \
  --label "org.opencontainers.image.version=$VERSION" \
  --metadata-file "$BUILD_ROOT/build-metadata.json" \
  --tag "$IMAGE:$VERSION" --push "$CTX"

docker buildx imagetools inspect "$IMAGE:$VERSION" --format '{{json .Manifest}}' \
  | tee "$BUILD_ROOT/index.json"
```

Read the top-level index digest from `index.json`, then keep it in a variable:

```sh
IRON_PROXY_IMAGE="$IMAGE:$VERSION@$INDEX_DIGEST"   # literal digest from the readback
```

Pull and test **that digest**, not the locally built tag: a fresh build can pick
up different OpenSSL or apk packages even when the CA pin is unchanged.

## 7. Required release record

Record and retain, attached to the release issue:

- source repository, branch, `SOURCE_SHA` and the `v0.54.0` upstream anchor;
- Git tag name plus its dereferenced target SHA, and the image version tag;
- operator identity and the approval record for each reviewed head;
- `go version`, Buildx and BuildKit versions;
- `Dockerfile.release` base digest, resolved apk package versions and the
  repository branch (`v3.24`);
- per-architecture binary SHA-256, module version and `vcs.*` fields;
- per-architecture CA bundle SHA-256 and root count;
- the multi-platform index digest, both platform digests, and the OCI
  labels/provenance as read back from the registry;
- the command exits of every acceptance check in section 8;
- the final literal `IRON_PROXY_IMAGE` value.

A pushed tag is not publication evidence, and an unsigned BuildKit provenance
statement is not an independent attestation.

## 8. Acceptance gates for the published digest

All of these run against the published digest before any consumer changes:
several of them cannot run inside the implementation stage, so they are the
release owner's gate, not the code reviewer's.

### 8.1 Bundle distrust, both architectures

```sh
./scripts/test-release-ca.py \
  --image "$IRON_PROXY_IMAGE" \
  --platform linux/amd64 --platform linux/arm64 \
  --output-json "$BUILD_ROOT/ca-acceptance.json"
```

Required result per platform, at both the frozen and live reference time:
**14 tested, 0 accepted, 14 issuer-trust failures, 0 errors**, plus the
known-good control verifying. The runner fails closed: a missing bundle, an
absent `openssl`, a container that never started, an expired or not-yet-valid
fixture, or an unattributable OpenSSL error is an error, never a pass.

For the RED control, the same runner against the known-vulnerable image must
report accepted chains (it reports 7 of 14 for
`ironsh/iron-proxy:0.41.0@sha256:51ccc350be14371321278e0a6597d069da559ff5a7a218f0ef3f4d20dc30c7ea`):

```sh
./scripts/test-release-ca.py --image ironsh/iron-proxy:0.41.0 --expect vulnerable
```

### 8.2 Direct certificate rejection inside the image

On an isolated test egress network, with no proxy environment overrides:

```sh
docker run --rm --platform linux/amd64 --network "$TEST_EGRESS_NETWORK" \
  --entrypoint /bin/sh "$IRON_PROXY_IMAGE" -c \
  'wget -T 20 -O /dev/null https://dv-g3b-emudhra.we-have-a-problem.com/; echo "exit=$?"'
```

Require a non-zero exit with a certificate-verification failure, paired with a
known-good HTTPS control that succeeds in the same container and network. A DNS
failure, timeout, connection refusal or missing `wget` is not a pass. Never
install a different `wget` or CA bundle into the image to make the check work.

The `openssl verify` result and the `wget` result are both required: a Go-only
fix can reject the forged chains while the image's OpenSSL root store still
trusts them.

### 8.3 Actual proxy behaviour

Start the image in an isolated project with the exact production
`compose/iron-proxy/proxy.yaml` bytes, a synthetic MITM CA and synthetic
provider credentials, on a network whose `dns.proxy_ip` matches its own address,
with no production ports published. Require:

- clean startup and `GET http://127.0.0.1:9101/healthz` → `OK`;
- one JSON audit entry per proxied HTTP request, with `action` and
  `request_transforms` present, CONNECT counted separately from the inner
  request;
- a forged-host request through the proxy failing with an upstream TLS error
  (typically 502 with `x509: certificate signed by unknown authority`), not a
  policy denial or a network error;
- `upstream_deny_cidrs` still denying loopback/IMDS targets;
- a strict-mode fixture (`warn: false`, test-only) rejecting a non-allowlisted
  host with `rejected_by: allowlist`, while production stays in warn mode;
- warn-mode research access to a non-allowlisted public host still working;
- no synthetic secret value appearing in the audit stream or container stdout.

Live provider coverage, the full upstream inventory, the deployed health check
and a real Hermes session belong to KCA-811 after deployment.

## 9. Consumer reference

Once the readback is complete, the immutable reference for every consumer is:

```
ghcr.io/k3-capital/iron-proxy:0.54.0-k3.ca.20261025.1@sha256:<registry-verified-index-hex>
```

The digest does not exist until the registry returns it. Never commit this
template with a placeholder, and never publish a `latest` or branch alias.
Consumers pin the version tag **and** the index digest.

## 10. Rollback

Rollback is not "restore the old tag and call it safe". The 0.41.0 digest is
known to trust forged chains, so reverting to it is a security regression, not a
neutral rollback.

- Prefer roll-forward, or a previously verified secure immutable image if one
  exists.
- If the new image causes an outage, stop new agent sessions and contain egress
  while the cause is diagnosed.
- Reverting to the vulnerable digest requires explicit human incident/risk
  acceptance, a time-bounded containment plan and a new remediation window; the
  remediation issue stays open.

Never remove CA verification, attach agents to raw egress, copy provider secrets
into agents, delete the audit volume, or regenerate K3's private MITM CA.

## 11. Fixture provenance and updates

`testdata/emudhra/` holds public certificates only: 14 leaf-first chains from
the published archive, the original archive README, and one known-good public
anchor (`control/isrg-root-x1.pem`). No private keys, no credentials, no network
access is needed to use them.

The inventory in `testdata/emudhra/manifest.json` records the source URL
(`https://emudhra.we-have-a-problem.com/chains.zip`), its SHA-256
(`7b949956955fc501a30f4d98d2f513d34c0bbbe92e29a968194c96e097ce2345`), the
per-file digests, certificate counts and leaf validity windows. The runner
validates all of it on every run and rejects missing, extra, duplicate,
malformed and out-of-window fixtures.

A changed archive, or any change to a fixture file, requires a reviewed
inventory update. Do not extend the fixture set or re-download it silently:
`--expect secure` requires exactly 14 fixtures.
