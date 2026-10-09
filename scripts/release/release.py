#!/usr/bin/env python3
"""License-free, tag-gated release tooling; Python standard library only."""

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = "K3-Capital/iron-proxy"
SOURCE = "https://github.com/" + REPOSITORY
IMAGE = "ghcr.io/k3-capital/iron-proxy"
UPSTREAM = "5bb325ace6c391cd5b2466d024ac3a2162162931"
RUNTIME = "alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"
BUILDER = "moby/buildkit:v0.24.0@sha256:6eceb8971ce4fceb3daca562832642706238b7eea72941fcf9896c93c3c4a53e"
VERSION_RE = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-k3\.[1-9][0-9]*\Z")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
ROOT = Path("dist/k3")
ARCHES = ("amd64", "arm64")
ACCEPT = ", ".join(("application/vnd.oci.image.index.v1+json",
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.docker.distribution.manifest.v2+json"))


class ReleaseError(Exception):
    """A failed invariant or unavailable registry permission is a hard blocker."""


def require(condition, message):
    if not condition:
        raise ReleaseError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def tar_bytes(archive, member):
    stream = archive.extractfile(member)
    if stream is None:
        raise ReleaseError("expected a regular archive file")
    with stream:
        return stream.read()


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def command(*args, env=None):
    return subprocess.check_output(args, text=True, env=env).strip()


def trusted_tag(context):
    event = context.get("event", {})
    return (context.get("repository") == REPOSITORY and context.get("event_name") == "push"
            and context.get("ref_type") == "tag" and event.get("created") is True
            and event.get("deleted") is False and event.get("forced") is False
            and context.get("ref", "").startswith("refs/tags/")
            and VERSION_RE.fullmatch(context["ref"][10:]) is not None)


def event_context():
    return {"repository": os.environ["GITHUB_REPOSITORY"],
            "event_name": os.environ["GITHUB_EVENT_NAME"],
            "ref_type": os.environ["GITHUB_REF_TYPE"], "ref": os.environ["GITHUB_REF"],
            "event": json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))}


def build():
    context = event_context()
    require(context["repository"] == REPOSITORY, "wrong build repository")
    source_sha = os.environ["SOURCE_SHA"]
    workflow_sha = os.environ["WORKFLOW_SHA"]
    require(SHA_RE.fullmatch(source_sha) and SHA_RE.fullmatch(workflow_sha), "invalid source/workflow SHA")
    require(command("git", "rev-parse", "HEAD") == source_sha, "checkout is not the requested source")
    subprocess.run(["git", "diff-index", "--quiet", "HEAD", "--"], check=True)
    subprocess.run(["git", "merge-base", "--is-ancestor", UPSTREAM, source_sha], check=True)
    if context["ref_type"] == "tag":
        require(trusted_tag(context), "not a new, immutable K3 release-tag event")
        version = context["ref"][10:]
        require(source_sha == workflow_sha, "release workflow/source commits differ")
        require(command("git", "rev-parse", context["ref"] + "^{commit}") == source_sha,
                "tag does not resolve to the source commit")
    else:
        require(context["event_name"] == "pull_request" or context["ref"] == "refs/heads/main",
                "not a PR or main validation event")
        version = "v0.53.0-k3.0-dev." + source_sha
    directive = re.search(r"(?m)^go (\S+)$", Path("go.mod").read_text(encoding="utf-8"))
    if directive is None:
        raise ReleaseError("go.mod has no exact Go version directive")
    declared = directive.group(1)
    go_version = command("go", "env", "GOVERSION")
    require(go_version == "go" + declared, "installed Go does not match go.mod exactly")
    subprocess.run(["go", "mod", "download"], check=True)
    subprocess.run(["go", "mod", "verify"], check=True)
    require(not ROOT.exists(), "output directory already exists; do not reuse build bytes")
    ROOT.mkdir(parents=True)
    record = {"schema_version": 1, "repository": REPOSITORY, "source_sha": source_sha,
              "workflow_sha": workflow_sha, "workflow_ref": os.environ["WORKFLOW_REF"],
              "upstream_sha": UPSTREAM, "version": version, "go_version": go_version,
              "cgo_enabled": False, "runtime_base": RUNTIME, "builder_base": BUILDER,
              "buildx_version": "v0.27.0", "binaries": {},
              "run_url": f"{SOURCE}/actions/runs/{os.environ['GITHUB_RUN_ID']}/attempts/{os.environ['GITHUB_RUN_ATTEMPT']}"}
    checksums = []
    for arch in ARCHES:
        relative = f"linux/{arch}/iron-proxy"
        output = ROOT / relative
        output.parent.mkdir(parents=True)
        env = dict(os.environ, CGO_ENABLED="0", GOOS="linux", GOARCH=arch, GOTOOLCHAIN="local")
        subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-buildvcs=true",
                        "-ldflags", f"-s -w -X github.com/ironsh/iron-proxy/internal/version.Version={version}",
                        "-o", str(output), "./cmd/iron-proxy"], env=env, check=True)
        info = command("go", "version", "-m", str(output))
        for setting in ("CGO_ENABLED=0", "vcs.revision=" + source_sha, "vcs.modified=false"):
            require(setting in info, "binary build identity mismatch")
        data = output.read_bytes()
        archive_path = f"iron-proxy_{version}_linux_{arch}.tar.gz"
        with (ROOT / archive_path).open("wb") as destination:
            with gzip.GzipFile(filename="", mode="wb", fileobj=destination, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as archive:
                    entry = tarfile.TarInfo("iron-proxy")
                    entry.size = len(data)
                    entry.mode = 0o755
                    archive.addfile(entry, io.BytesIO(data))
        binary_hash = sha256(data)
        archive_hash = sha256((ROOT / archive_path).read_bytes())
        record["binaries"][arch] = {"path": relative, "sha256": binary_hash, "build_info": info,
                                   "archive_path": archive_path, "archive_sha256": archive_hash}
        checksums.extend((f"{binary_hash}  {relative}", f"{archive_hash}  {archive_path}"))
    # Execute only a value-free native version smoke, on this disposable CI runner.
    require(command(str(ROOT / "linux/amd64/iron-proxy"), "--version") == version,
            "binary version smoke failed")
    (ROOT / "SHA256SUMS").write_text("\n".join(sorted(checksums)) + "\n", encoding="utf-8")
    write_json(ROOT / "release.json", record)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write("version=" + version + "\n")
    print(json.dumps(record, sort_keys=True))


def candidate(root=ROOT):
    record = json.loads((root / "release.json").read_text(encoding="utf-8"))
    require(SHA_RE.fullmatch(record["source_sha"]) and SHA_RE.fullmatch(record["workflow_sha"]),
            "invalid candidate source/workflow SHA")
    require(record["repository"] == REPOSITORY and record["upstream_sha"] == UPSTREAM,
            "candidate repository/upstream identity differs")
    require(record["runtime_base"] == RUNTIME and record["builder_base"] == BUILDER,
            "candidate base images differ")
    require(record["cgo_enabled"] is False and set(record["binaries"]) == set(ARCHES),
            "candidate must contain both CGO-disabled Linux binaries")
    expected_checksums = []
    for arch in ARCHES:
        binary = record["binaries"][arch]
        require(binary["path"] == f"linux/{arch}/iron-proxy", "unexpected binary path")
        require(binary["archive_path"] == f"iron-proxy_{record['version']}_linux_{arch}.tar.gz",
                "unexpected archive path")
        for path_key, hash_key in (("path", "sha256"), ("archive_path", "archive_sha256")):
            path = root / binary[path_key]
            require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root.resolve()),
                    "candidate file escapes its artifact root")
            require(sha256(path.read_bytes()) == binary[hash_key], "candidate checksum mismatch")
            expected_checksums.append(f"{binary[hash_key]}  {binary[path_key]}")
        with tarfile.open(root / binary["archive_path"], "r:gz") as archive:
            require([entry.name for entry in archive] == ["iron-proxy"], "unexpected host archive content")
            require(sha256(tar_bytes(archive, "iron-proxy")) == binary["sha256"],
                    "host archive is not the matching binary")
    require((root / "SHA256SUMS").read_text(encoding="utf-8") == "\n".join(sorted(expected_checksums)) + "\n",
            "checksum manifest does not describe exactly the binary/archive set")
    return record


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require(urllib.parse.urlsplit(newurl).scheme == "https", "non-HTTPS registry redirect")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is None:
            return None
        if urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            redirected.remove_header("Authorization")
        return redirected


class Registry:
    def __init__(self):
        token = os.environ.get("GHCR_TOKEN")
        if not token:
            raise ReleaseError("GHCR_TOKEN is unavailable; do not substitute another credential")
        basic = base64.b64encode((os.environ["GITHUB_ACTOR"] + ":" + token).encode()).decode()
        self.opener = urllib.request.build_opener(SafeRedirect())
        self.bearer = json.loads(self.request("https://ghcr.io/token?service=ghcr.io&scope=repository:k3-capital/iron-proxy:pull,push",
                                             {"Authorization": "Basic " + basic}))["token"]

    def request(self, url, headers):
        try:
            with self.opener.open(urllib.request.Request(url, headers=headers), timeout=60) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            # No response bodies, URLs, credentials or signed blob URLs in errors.
            raise ReleaseError(f"registry HTTP {status}") from None
        except urllib.error.URLError:
            raise ReleaseError("registry transport failure") from None

    def get(self, kind, reference):
        require(kind in ("manifests", "blobs"), "unexpected registry resource")
        require(DIGEST_RE.fullmatch(reference) or VERSION_RE.fullmatch(reference), "invalid registry reference")
        return self.request(f"https://ghcr.io/v2/k3-capital/iron-proxy/{kind}/{reference}",
                            {"Authorization": "Bearer " + self.bearer, "Accept": ACCEPT})

    def ensure_absent(self, version):
        try:
            self.get("manifests", version)
        except ReleaseError as error:
            if str(error) == "registry HTTP 404":
                return
            raise
        raise ReleaseError("registry tag already exists; never overwrite or silently rerun publication")


def preflight():
    require(trusted_tag(event_context()), "publication is not a trusted K3 tag push")
    record = candidate()
    require(VERSION_RE.fullmatch(os.environ["VERSION"]), "invalid publication version")
    for key in ("source_sha", "workflow_sha", "version"):
        require(record[key] == os.environ[key.upper()], "candidate does not match this release run")
    require(record["source_sha"] == record["workflow_sha"] == command("git", "rev-parse", "HEAD"),
            "publication checkout/workflow/source mismatch")
    Registry().ensure_absent(record["version"])
    print("Candidate checksums and release identity verified; registry tag is absent.")


def verified_blob(read, digest):
    require(DIGEST_RE.fullmatch(digest), "invalid OCI digest")
    data = read(digest)
    require("sha256:" + sha256(data) == digest, "OCI blob digest mismatch")
    return data


def inspect_index(index, read, record, root=ROOT):
    require("manifests" in index, "image must be a multi-platform index")
    platforms = {}
    attestations = {}
    for descriptor in index["manifests"]:
        platform = descriptor.get("platform", {})
        digest = descriptor["digest"]
        manifest = json.loads(verified_blob(read, digest))
        annotations = descriptor.get("annotations", {})
        if annotations.get("vnd.docker.reference.type") == "attestation-manifest":
            subject = annotations["vnd.docker.reference.digest"]
            require(subject not in attestations, "duplicate image attestation manifest")
            predicates = []
            for layer in manifest["layers"]:
                statement = json.loads(verified_blob(read, layer["digest"]))
                if statement.get("predicateType", "").startswith("https://slsa.dev/provenance/"):
                    require(any("sha256:" + item.get("digest", {}).get("sha256", "") == subject
                                for item in statement.get("subject", [])), "provenance subject mismatch")
                    predicates.append(statement)
            require(bool(predicates), "missing CI build provenance")
            attestations[subject] = {"manifest_digest": digest, "statements": predicates}
            continue
        arch = platform.get("architecture")
        require(platform.get("os") == "linux" and arch in ARCHES and arch not in platforms,
                "unexpected or duplicate image platform")
        config = json.loads(verified_blob(read, manifest["config"]["digest"]))
        require(config["os"] == "linux" and config["architecture"] == arch, "image config platform mismatch")
        require(config["config"]["Entrypoint"] == ["/usr/local/bin/iron-proxy"], "wrong runtime entrypoint")
        expected_labels = {"org.opencontainers.image.source": SOURCE,
                           "org.opencontainers.image.revision": record["source_sha"],
                           "org.opencontainers.image.version": record["version"],
                           "io.github.k3-capital.workflow.sha": record["workflow_sha"]}
        labels = config["config"].get("Labels", {})
        require(all(labels.get(key) == value for key, value in expected_labels.items()), "OCI identity label mismatch")
        # Check the pinned runtime really supplies a usable public CA bundle;
        # never add mutable packages or copy the CI egress action's private CA.
        public_ca_bundle = False
        for base_layer in manifest["layers"][:-1]:
            data = verified_blob(read, base_layer["digest"])
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as layer:
                for item in layer:
                    if item.name.removeprefix("./") == "etc/ssl/certs/ca-certificates.crt" and item.isfile():
                        public_ca_bundle = b"-----BEGIN CERTIFICATE-----" in tar_bytes(layer, item)
        require(public_ca_bundle, "pinned runtime is missing its public CA certificate bundle")
        # The Dockerfile has no RUN: its final layer is precisely the binary COPY.
        layer_data = verified_blob(read, manifest["layers"][-1]["digest"])
        with tarfile.open(fileobj=io.BytesIO(layer_data), mode="r:*") as layer:
            entries = [item for item in layer if item.name.removeprefix("./") == "usr/local/bin/iron-proxy"]
            require(len(entries) == 1 and entries[0].isfile() and entries[0].mode & 0o111,
                    "final image layer is missing the executable")
            binary = tar_bytes(layer, entries[0])
        require(sha256(binary) == record["binaries"][arch]["sha256"], "image/host binary bytes differ")
        platforms[arch] = {"digest": digest, "binary_path": record["binaries"][arch]["path"],
                           "binary_sha256": sha256(binary), "labels": labels}
    require(set(platforms) == set(ARCHES), "missing Linux amd64/arm64 image")
    require(set(attestations) == {item["digest"] for item in platforms.values()}, "missing/unexpected provenance platforms")
    for arch, platform in platforms.items():
        attestation = attestations[platform["digest"]]
        path = f"provenance/{arch}.json"
        write_json(root / path, attestation["statements"])
        platform["provenance_path"] = path
        platform["attestation_manifest_digest"] = attestation["manifest_digest"]
    return platforms


def verify_image(archive_path=None):
    record = candidate(ROOT)
    digest = os.environ["IMAGE_DIGEST"]
    require(DIGEST_RE.fullmatch(digest), "Buildx did not return a complete image digest")
    if archive_path is not None:
        with tarfile.open(archive_path, "r:*") as archive:
            def read_archive(reference):
                return tar_bytes(archive, "blobs/sha256/" + reference[7:])
            raw_root = tar_bytes(archive, "index.json")
            outer = json.loads(raw_root)
            if "sha256:" + sha256(raw_root) == digest:
                index = outer
            else:
                require(any(item["digest"] == digest for item in outer["manifests"]), "OCI export/index identity mismatch")
                index = json.loads(verified_blob(read_archive, digest))
            platforms = inspect_index(index, read_archive, record, ROOT)
        kind, output = "unpublished-oci-archive", "candidate-image.json"
    else:
        registry = Registry()
        raw_index = registry.get("manifests", digest)
        require("sha256:" + sha256(raw_index) == digest, "published index digest mismatch")
        raw_tag = registry.get("manifests", record["version"])
        require("sha256:" + sha256(raw_tag) == digest, "published tag/index mismatch")
        def read_registry(reference):
            # Image/attestation manifests and content blobs share verified digests.
            try:
                return registry.get("blobs", reference)
            except ReleaseError as error:
                if str(error) != "registry HTTP 404":
                    raise
                return registry.get("manifests", reference)
        platforms = inspect_index(json.loads(raw_index), read_registry, record, ROOT)
        kind, output = "readback-verified-registry", "published-image.json"
    image_record = {"kind": kind, "index_digest": digest, "platforms": platforms,
                    "source_sha": record["source_sha"], "workflow_sha": record["workflow_sha"],
                    "version": record["version"], "run_url": record["run_url"]}
    if archive_path is None:
        image_record["reference"] = IMAGE + "@" + digest
    write_json(ROOT / output, image_record)
    print(json.dumps(image_record, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "preflight", "verify-oci", "verify-registry"))
    parser.add_argument("archive", nargs="?")
    args = parser.parse_args()
    try:
        if args.command == "build":
            build()
        elif args.command == "preflight":
            preflight()
        elif args.command == "verify-oci":
            require(bool(args.archive), "OCI archive path is required")
            verify_image(args.archive)
        else:
            verify_image()
    except (ReleaseError, KeyError, ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError) as error:
        # Registry exceptions are deliberately sanitized before reaching this boundary.
        parser.exit(1, f"release validation failed: {error}\n")


if __name__ == "__main__":
    main()
