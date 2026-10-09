# K3 fork builds and releases

The fork uses `.github/workflows/k3-release.yml`, ordinary Go and Docker Buildx.
It does not use GoReleaser Pro, a license key, upstream Docker Hub credentials,
provider credentials or GitHub release assets. The Go module/import path remains
`github.com/ironsh/iron-proxy`. The upstream workflows and their broad egress
rules remain upstream-only; K3 does not run the credentialed integration suite.

## Trust and event matrix

| Event | Synthetic tests, vet, source build | Two-platform OCI candidate | Login / package write / push |
| --- | --- | --- | --- |
| PR into the K3 fork, including stacked and external fork PRs | Yes | Yes, only after tests | Never |
| K3 `main` push | Yes | Yes, only after tests | Never |
| Official upstream `v0.53.0` tag in K3 | No K3 workflow | No | Never |
| Newly created K3 tag such as `v0.53.0-k3.1` | Yes | Yes, only after tests | Only after all gates |
| Forced/deleted/updated K3 tag | Validation may start; build refuses | No successful candidate | Never |
| Malformed K3 tag (e.g. `v0.53.0-k3.latest`) | Validation may start; build refuses | No successful candidate | Never |
| Another repository, manual event, or `pull_request_target` | No K3 execution | No | Never |

The release grammar is `v<major>.<minor>.<patch>-k3.<positive integer>`, without
leading zeroes. This is a downstream version, not an official release. The
publish job explicitly checks the exact repository, push/tag event and new,
non-forced, non-deleted tag. The binary builder validates the complete grammar
and tag/source/workflow identity **before** the publication job can start.

Workflow/job tokens default to `contents: read`; only `publish` adds
`packages: write`. The sole registry credential is the current run's
`${{ secrets.GITHUB_TOKEN }}`, confined to that job. Checkouts explicitly disable
credential persistence. There is no PR-code `pull_request_target` execution,
PAT, provider secret, organization policy change or visibility/ACL change.
Actions use full commit pins. The runner uses the **exact** Go version in
go.mod, `go.sum` verification, `-mod=readonly`, and no reused build artifacts.

## Build inputs and byte identity

* `Dockerfile.k3` replaces the legacy `Dockerfile.release` for this fork only.
  The legacy file and `.goreleaser.yml` are not K3 inputs.
* Runtime: `alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11`.
  The multi-platform index includes Linux amd64 and arm64. Alpine provides the
  CA certificate bundle; no mutable `apk` operation or OpenSSL CLI is needed by
  the CGO-disabled executable. There are no `RUN` instructions and no QEMU.
* Builder: `moby/buildkit:v0.24.0@sha256:6eceb8971ce4fceb3daca562832642706238b7eea72941fcf9896c93c3c4a53e`;
  Buildx is fixed at `v0.27.0`. There is no Docker Go builder image: the pinned
  Actions toolchain builds the executables directly.
* Both base-index references were resolved from Docker Hub manifests, checking
  their raw SHA-256 and platform descriptors. Updating them requires a new
  reviewed source/workflow head, not silently moving a tag.
* Build exactly once per architecture with `CGO_ENABLED=0`, `GOOS=linux`,
  `GOARCH=amd64/arm64`, `-trimpath`, explicit VCS metadata, and an explicit
  version linker value. The native version-only smoke is CI-only and starts no
  proxy/listener/provider integration.
* The build context is `dist/k3`; `Dockerfile.k3.dockerignore` admits only the two
  executables. Each image copies its **already archived binary bytes** to
  `/usr/local/bin/iron-proxy` with executable mode. The publish job downloads
  the same run's candidate artifact; it does not compile another binary.
* Candidate OCI inspection and post-push registry readback verify index,
  platform/config/layer digests, OCI source/revision/version/workflow labels,
  exact image/host binary SHA-256 equality, and each BuildKit SLSA provenance
  statement's subject. The published digest, not the tag, is the consumption
  boundary. BuildKit provenance and run artifacts are not signed OIDC release
  attestations; consumers must verify the reviewed head and exact CI run too.

## Artifacts and provenance

Candidate artifact: `k3-candidate-<full source SHA>` (30 days). Successful
publication artifact: `k3-release-<K3 version>-<full source SHA>` (90 days).
Download through `gh run download <run-id> --repo K3-Capital/iron-proxy --name
<artifact-name> --dir <destination>` and verify `sha256sum -c SHA256SUMS` inside
that destination. Archive artifacts externally before retention expires.

Paths inside the bundle:

* `linux/amd64/iron-proxy`, `linux/arm64/iron-proxy` — raw host executables.
* `iron-proxy_<version>_linux_<arch>.tar.gz` — archives of those exact bytes.
* `SHA256SUMS` — complete binary/archive SHA-256 checksums.
* `release.json` — exact Go version, source/workflow/ref/run identity, official
  upstream base `5bb325ace6c391cd5b2466d024ac3a2162162931`, version, immutable
  build inputs, and binary/archive paths, checksums and Go build metadata.
* `candidate-image.json` — verified but **unpublished** OCI index/platform
  digests. A candidate digest is not proof of GHCR publication.
* `published-image.json` — only after real registry readback: complete
  `ghcr.io/k3-capital/iron-proxy@sha256:...` reference and both platform digests,
  matching binary checksums, labels, workflow/source/run identity.
* `provenance/amd64.json`, `provenance/arm64.json` — actual BuildKit provenance
  statements, bound to the relevant image manifests. Publication replaces the
  candidate statements with statements read back from the published index.

## Deliberate publication after review

First obtain independent approval of the exact **combined** feature/workflow
commit. Do not merge merely to execute this tag-contained workflow. In a
separately authorized publication stage, check both remote tag and registry tag
absence, verify the approved source, then run (substitute the reviewed SHA):

```sh
git ls-remote origin refs/tags/v0.53.0-k3.1
# Stop if the Git tag exists. Never overwrite it.
git tag -a v0.53.0-k3.1 <architect-approved-full-SHA> -m 'K3 Iron Proxy v0.53.0-k3.1'
git push origin refs/tags/v0.53.0-k3.1
```

Read the remote tag back and verify its dereferenced commit. Collect the real
CI result and inspect the published registry and binary artifacts at that
commit. This workflow never emits `latest`, `main`, or a moving `sha-*` tag.
Per-ref concurrency serializes this workflow's attempts. The preflight accepts
**only** an authenticated registry 404 as tag absence, never a 401/403, transport
error, rate limit or generic failed inspect. Existing tags refuse publication,
including reruns after a successful push. GHCR has no atomic create-only tag
operation: unrelated package writers remain a trust boundary, and consumers
must use the independently verified digest. A failed post-push step may leave
an image; inspect it rather than overwriting/retrying blindly.

Permission/authentication failures are blockers; do not switch credentials,
change organization policy, package visibility or branch protection. Restore
an older **accepted immutable artifact** only through separately reviewed
consumer configuration; never overwrite a release or weaken security checks.

## Scoped CI egress and local checks

`egress-rules.k3.yaml` permits Go module/checksum/toolchain storage, GitHub
Actions/downloads, GHCR storage and Docker Hub **base pulls**, not a Docker Hub
publication/login. The pinned inherited egress action also allows its own
GitHub/Actions/Azure infrastructure. Its Docker-enabled mode is not a claim
that privileged Docker networking is unbypassable by malicious PR code; PRs
have no publication credentials and execute only in disposable hosted runners.

The inherited AWS Secrets Manager/SSM, Anthropic/OpenAI, 1Password, wildcard
Google API, GoReleaser and license API allowances are unused on K3. Keep them
upstream-only; never enable those integrations to validate the fork.

With existing local tooling/caches, run the synthetic suite, vet and build:

```sh
go test -race -count=1 ./...
go vet ./...
go build -mod=readonly ./cmd/iron-proxy
python3 -m unittest discover -s scripts/release -p 'test_*.py' -v
git diff --check
```

The Python tests decode the actual workflow YAML through the existing Go YAML
dependency and exercise the event/permission matrix, secret isolation, pins,
registry error handling, and synthetic OCI tamper/refusal cases. CI additionally
runs full-SHA-pinned actionlint and real two-platform OCI verification. Local
cache/toolchain limitations are reported; do not repair/install the host.

Publishing and binary/image verification are distribution evidence only. They
do not authorize target installation, production process/topology changes,
live provider tests, runtime admission or deployment.
