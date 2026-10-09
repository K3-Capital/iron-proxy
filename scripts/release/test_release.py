"""Synthetic policy/OCI tests. Fixtures are NOT evidence of a published image."""

import ast
import copy
from contextlib import redirect_stdout
import fnmatch
from http.client import HTTPMessage
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
from typing import Any
import unittest
from unittest import mock
import urllib.error
import urllib.request

import release

K3_WORKFLOW = ".github/workflows/k3-release.yml"
WORKFLOWS = (K3_WORKFLOW, ".github/workflows/ci.yml", ".github/workflows/release.yml")


def expression(value, context):
    """Evaluate only the Boolean expression subset used by these real workflows."""
    text = value.replace("&&", " and ").replace("||", " or ")
    text = re.sub(r"\btrue\b", "True", text)
    text = re.sub(r"\bfalse\b", "False", text)
    tree = ast.parse(text, mode="eval")
    allowed = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare, ast.Eq,
               ast.Constant, ast.Call, ast.Name, ast.Load, ast.Attribute)
    for node in ast.walk(tree):
        if not isinstance(node, allowed):
            raise AssertionError("unexpected workflow expression node")
        if isinstance(node, ast.Call) and (not isinstance(node.func, ast.Name)
                                          or node.func.id not in ("startsWith", "contains")):
            raise AssertionError("unexpected workflow expression function")
        if isinstance(node, ast.Name) and node.id not in ("github", "startsWith", "contains"):
            raise AssertionError("unexpected workflow expression variable")
    def namespace(data):
        return SimpleNamespace(**{key: namespace(value) if isinstance(value, dict) else value
                                  for key, value in data.items()})
    return bool(eval(compile(tree, "<workflow-policy>", "eval"), {"__builtins__": {}},
                     {"github": namespace(context), "startsWith": str.startswith,
                      "contains": lambda value, part: part in value}))


def triggered(workflow, context):
    event = context["event_name"]
    if event not in workflow["on"]:
        return False
    config = workflow["on"][event] or {}
    if event == "push":
        key, prefix = ("tags", "refs/tags/") if context["ref_type"] == "tag" else ("branches", "refs/heads/")
        return any(fnmatch.fnmatchcase(context["ref"].removeprefix(prefix), pattern)
                   for pattern in config.get(key, []))
    if event == "pull_request":
        return any(fnmatch.fnmatchcase(context["event"]["pull_request"]["base"]["ref"], pattern)
                   for pattern in config.get("branches", ["*"]))
    return True


def event(name="push", ref="refs/tags/v0.53.0-k3.1", repository=release.REPOSITORY,
          created=True, deleted=False, forced=False, untrusted=False):
    return {"repository": repository, "event_name": name, "ref": ref,
            "ref_type": "tag" if ref.startswith("refs/tags/") else "branch",
            "event": {"created": created, "deleted": deleted, "forced": forced,
                      "pull_request": {"base": {"ref": "main"},
                                       "head": {"repo": {"full_name": "untrusted/fork" if untrusted else repository}}}}}


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.configs = json.loads(subprocess.check_output(
            ["go", "run", "./scripts/release/workflows.go", *WORKFLOWS, "egress-rules.k3.yaml"], text=True))
        cls.workflow = cls.configs[K3_WORKFLOW]

    def test_event_repository_and_permission_matrix(self):
        cases = [
            ("PR", event("pull_request", "refs/pull/1/merge"), True, False),
            ("stacked PR", event("pull_request", "refs/pull/2/merge"), True, False),
            ("untrusted fork PR", event("pull_request", "refs/pull/3/merge", untrusted=True), True, False),
            ("main push", event(ref="refs/heads/main"), True, False),
            ("other branch", event(ref="refs/heads/topic"), False, False),
            ("official tag", event(ref="refs/tags/v0.53.0"), False, False),
            ("K3 tag", event(), True, True),
            ("other repository", event(repository="untrusted/iron-proxy"), False, False),
            ("upstream repository", event(repository="paradigmxyz/iron-proxy"), False, False),
            ("forced tag", event(forced=True), True, False),
            ("deleted tag", event(deleted=True), True, False),
            ("existing tag update", event(created=False), True, False),
            ("invalid K3 grammar", event(ref="refs/tags/v0.53.0-k3.latest"), True, False),
            ("zero K3 version", event(ref="refs/tags/v0.53.0-k3.0"), True, False),
            ("pull_request_target", event("pull_request_target", "refs/pull/3/merge"), False, False),
            ("manual event", event("workflow_dispatch"), False, False),
        ]
        for name, context, expected_checks, expected_publish in cases:
            with self.subTest(name=name):
                jobs = self.workflow["jobs"]
                checks = triggered(self.workflow, context) and expression(jobs["verify"]["if"], context)
                # The strict build-time tag grammar gates the publication dependency.
                publish = (triggered(self.workflow, context) and expression(jobs["publish"]["if"], context)
                           and release.trusted_tag(context))
                self.assertEqual(checks, expected_checks)
                self.assertEqual(publish, expected_publish)
                if checks:
                    for job in ("verify", "package"):
                        self.assertEqual(jobs[job]["permissions"], {"contents": "read"})
                if context["repository"] == release.REPOSITORY:
                    for path in WORKFLOWS[1:]:
                        for job in self.configs[path]["jobs"].values():
                            self.assertFalse(expression(job["if"], context))
        # A stacked base is allowed, not just PRs targeting main.
        stacked = event("pull_request", "refs/pull/2/merge")
        stacked["event"]["pull_request"]["base"]["ref"] = "feat/named-query-params"
        self.assertTrue(triggered(self.workflow, stacked))
        print("Event/permission matrix: 16 contexts plus stacked-base trigger verified.")

    def test_credentials_and_publication_are_job_scoped(self):
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertEqual(self.workflow["jobs"]["publish"]["permissions"], {"contents": "read", "packages": "write"})
        for name in ("verify", "package"):
            job_text = json.dumps(self.workflow["jobs"][name])
            self.assertNotIn("secrets.", job_text)
            self.assertNotIn("docker/login-action", job_text)
            self.assertNotIn("pull_request_target", self.workflow["on"])
        image = next(step for step in self.workflow["jobs"]["package"]["steps"]
                     if step.get("uses", "").startswith("docker/build-push-action@"))
        self.assertIs(image["with"]["push"], False)
        self.assertNotIn("push=true", image["with"]["outputs"])
        publish = self.workflow["jobs"]["publish"]
        self.assertEqual(publish["needs"], ["verify", "package"])
        login = next(step for step in publish["steps"] if step.get("uses", "").startswith("docker/login-action@"))
        self.assertEqual(login["with"]["registry"], "ghcr.io")
        self.assertEqual(login["with"]["password"], "${{ secrets.GITHUB_TOKEN }}")
        image = next(step for step in publish["steps"] if step.get("uses", "").startswith("docker/build-push-action@"))
        self.assertEqual(image["with"]["tags"], release.IMAGE + ":${{ needs.package.outputs.version }}")
        self.assertNotIn("latest", json.dumps(self.workflow))
        self.assertNotIn("GORELEASER", json.dumps(self.workflow))
        self.assertNotIn("DOCKER_HUB", json.dumps(self.workflow))
        preflight = next(i for i, step in enumerate(publish["steps"]) if step.get("run", "").endswith(" preflight"))
        login_index = publish["steps"].index(login)
        self.assertLess(preflight, login_index)

    def test_actions_toolchains_and_base_inputs_are_pinned(self):
        for path in WORKFLOWS:
            for job in self.configs[path]["jobs"].values():
                for step in job["steps"]:
                    action = step.get("uses", "")
                    if action:
                        self.assertRegex(action, r"^[\w./-]+@[0-9a-f]{40}$")
                    if action.startswith("actions/checkout@"):
                        self.assertIs(step["with"]["persist-credentials"], False)
                    if action.startswith("actions/setup-go@"):
                        self.assertEqual(step["with"]["go-version-file"], "go.mod")
        for job in self.workflow["jobs"].values():
            for step in job["steps"]:
                if step.get("uses", "").startswith("docker/setup-buildx-action@"):
                    self.assertEqual(step["with"]["driver-opts"], "image=" + release.BUILDER)
                    self.assertEqual(step["with"]["version"], "v0.27.0")
                if step.get("uses", "").startswith("actions/upload-artifact@"):
                    self.assertIs(step["with"]["overwrite"], False)
                if step.get("uses", "").startswith("docker/build-push-action@"):
                    self.assertEqual(step["with"]["platforms"], "linux/amd64,linux/arm64")
                    self.assertEqual(step["with"]["provenance"], "mode=max")
                    self.assertEqual(step["with"]["context"], "dist/k3")
                    self.assertEqual(step["with"]["file"], "Dockerfile.k3")
        dockerfile = Path("Dockerfile.k3").read_text(encoding="utf-8")
        instructions = [line for line in dockerfile.splitlines() if line and not line.startswith("#")]
        self.assertEqual(instructions[0], "FROM " + release.RUNTIME)
        self.assertFalse(any(line.startswith("RUN ") for line in instructions))
        self.assertIn("COPY --chmod=0755 linux/${TARGETARCH}/iron-proxy /usr/local/bin/iron-proxy", instructions)
        domains = self.configs["egress-rules.k3.yaml"]["domains"]
        self.assertIn("ghcr.io", domains)
        for prohibited in ("amazonaws", "api.anthropic", "api.openai", "1password", "*.googleapis", "goreleaser", "gumroad"):
            self.assertFalse(any(prohibited in domain for domain in domains))


class ReleaseTests(unittest.TestCase):
    def test_wrong_local_toolchain_refuses_before_module_download_or_build(self):
        source_sha = "1" * 40
        values = {"SOURCE_SHA": source_sha, "WORKFLOW_SHA": source_sha}
        with mock.patch.dict(os.environ, values), mock.patch.object(release, "event_context", return_value=event()), \
                mock.patch.object(release, "command", side_effect=[source_sha, source_sha, "go1.27.1"]), \
                mock.patch.object(release.subprocess, "run") as run:
            with self.assertRaisesRegex(release.ReleaseError, "match go.mod exactly"):
                release.build()
            self.assertEqual([call.args[0][0] for call in run.call_args_list], ["git", "git"])

    def test_strict_version_grammar(self):
        for tag in ("v0.53.0-k3.1", "v1.2.3-k3.15"):
            self.assertTrue(release.trusted_tag(event(ref="refs/tags/" + tag)))
        for tag in ("v0.53.0", "v0.53.0-k3.0", "v00.53.0-k3.1", "v0.53.0-k3.01",
                    "v0.53.0-k3.1-extra", "v0.53.0-k3.latest", "v0.53.0-k3.1\n", "latest"):
            with self.subTest(tag=tag):
                self.assertFalse(release.trusted_tag(event(ref="refs/tags/" + tag)))

    def test_registry_absence_is_only_404_and_never_auth_failure(self):
        registry = object.__new__(release.Registry)
        for status in (404, 400, 401, 403, 429, 500, 503):
            with self.subTest(status=status), mock.patch.object(registry, "get", side_effect=release.ReleaseError(f"registry HTTP {status}")):
                if status == 404:
                    registry.ensure_absent("v0.53.0-k3.1")
                else:
                    with self.assertRaises(release.ReleaseError):
                        registry.ensure_absent("v0.53.0-k3.1")
        with mock.patch.object(registry, "get", return_value=b"synthetic existing manifest"):
            with self.assertRaisesRegex(release.ReleaseError, "already exists"):
                registry.ensure_absent("v0.53.0-k3.1")

    def test_registry_errors_and_redirects_do_not_leak_credentials(self):
        registry = object.__new__(release.Registry)
        registry.opener = mock.Mock()
        registry.opener.open.side_effect = urllib.error.HTTPError("https://ghcr.io/token", 403, "denied", HTTPMessage(),
                                                                io.BytesIO(b"synthetic confidential response"))
        with self.assertRaisesRegex(release.ReleaseError, "^registry HTTP 403$"):
            registry.request("https://ghcr.io/token", {"Authorization": "Basic synthetic"})
        request = urllib.request.Request("https://ghcr.io/blob", headers={"Authorization": "Bearer synthetic"})
        redirect = release.SafeRedirect().redirect_request(request, io.BytesIO(), 302, "redirect", HTTPMessage(), "https://storage.example.test/blob")
        assert redirect is not None
        self.assertFalse(redirect.has_header("Authorization"))
        with self.assertRaises(release.ReleaseError):
            release.SafeRedirect().redirect_request(request, io.BytesIO(), 302, "redirect", HTTPMessage(), "http://storage.example.test/blob")

    def fixture(self):
        # Deliberately synthetic bytes, never presented as build/publication evidence.
        blobs = {}
        record = {"source_sha": "1" * 40, "workflow_sha": "2" * 40,
                  "version": "v0.53.0-k3.1", "binaries": {}}
        index = {"manifests": []}
        def blob(data) -> dict[str, Any]:
            if not isinstance(data, bytes):
                data = json.dumps(data, sort_keys=True).encode()
            digest = "sha256:" + release.sha256(data)
            blobs[digest] = data
            return {"digest": digest}
        for arch in release.ARCHES:
            binary = ("synthetic test binary " + arch).encode()
            record["binaries"][arch] = {"path": f"linux/{arch}/iron-proxy", "sha256": release.sha256(binary)}
            layer = io.BytesIO()
            with tarfile.open(fileobj=layer, mode="w:gz") as archive:
                entry = tarfile.TarInfo("usr/local/bin/iron-proxy")
                entry.mode, entry.size = 0o755, len(binary)
                archive.addfile(entry, io.BytesIO(binary))
            base = io.BytesIO()
            with tarfile.open(fileobj=base, mode="w:gz") as archive:
                data = b"-----BEGIN CERTIFICATE----- synthetic test CA bundle"
                entry = tarfile.TarInfo("etc/ssl/certs/ca-certificates.crt")
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
            config = {"os": "linux", "architecture": arch, "config": {
                "Entrypoint": ["/usr/local/bin/iron-proxy"], "Labels": {
                    "org.opencontainers.image.source": release.SOURCE,
                    "org.opencontainers.image.revision": record["source_sha"],
                    "org.opencontainers.image.version": record["version"],
                    "io.github.k3-capital.workflow.sha": record["workflow_sha"]}}}
            manifest = {"config": blob(config), "layers": [blob(base.getvalue()), blob(layer.getvalue())]}
            descriptor = blob(manifest)
            descriptor["platform"] = {"os": "linux", "architecture": arch}
            index["manifests"].append(descriptor)
            subject = descriptor["digest"]
            statement = {"predicateType": "https://slsa.dev/provenance/v0.2", "predicate": {},
                         "subject": [{"digest": {"sha256": subject[7:]}}]}
            attestation = blob({"layers": [blob(statement)]})
            attestation["platform"] = {"os": "unknown", "architecture": "unknown"}
            attestation["annotations"] = {"vnd.docker.reference.type": "attestation-manifest",
                                           "vnd.docker.reference.digest": subject}
            index["manifests"].append(attestation)
        return index, blobs, record

    def candidate_fixture(self, root, record):
        record.update({"repository": release.REPOSITORY, "upstream_sha": release.UPSTREAM,
                       "runtime_base": release.RUNTIME, "builder_base": release.BUILDER,
                       "cgo_enabled": False, "go_version": "go1.26.1", "run_url": "https://example.test/synthetic-run"})
        sums = []
        for arch in release.ARCHES:
            binary = record["binaries"][arch]
            data = ("synthetic test binary " + arch).encode()
            path = root / binary["path"]
            path.parent.mkdir(parents=True)
            path.write_bytes(data)
            binary["archive_path"] = f"iron-proxy_{record['version']}_linux_{arch}.tar.gz"
            with tarfile.open(root / binary["archive_path"], "w:gz") as archive:
                entry = tarfile.TarInfo("iron-proxy")
                entry.size, entry.mode = len(data), 0o755
                archive.addfile(entry, io.BytesIO(data))
            binary["archive_sha256"] = release.sha256((root / binary["archive_path"]).read_bytes())
            sums.extend((f"{binary['sha256']}  {binary['path']}", f"{binary['archive_sha256']}  {binary['archive_path']}"))
        (root / "SHA256SUMS").write_text("\n".join(sorted(sums)) + "\n", encoding="utf-8")
        release.write_json(root / "release.json", record)

    def test_candidate_checksums_archives_and_tamper_refusal(self):
        for scenario in ("valid", "binary", "archive", "checksum manifest", "source identity", "cgo", "base"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, _, record = self.fixture()
                self.candidate_fixture(root, record)
                if scenario == "valid":
                    self.assertEqual(release.candidate(root), record)
                    continue
                if scenario == "binary":
                    (root / record["binaries"]["amd64"]["path"]).write_bytes(b"synthetic corruption")
                elif scenario == "archive":
                    (root / record["binaries"]["arm64"]["archive_path"]).write_bytes(b"synthetic corruption")
                elif scenario == "checksum manifest":
                    (root / "SHA256SUMS").write_text("", encoding="utf-8")
                else:
                    record[{"source identity": "source_sha", "cgo": "cgo_enabled", "base": "runtime_base"}[scenario]] = "wrong"
                    release.write_json(root / "release.json", record)
                with self.assertRaises(release.ReleaseError):
                    release.candidate(root)

    def test_whole_oci_archive_verifier_without_registry_access(self):
        index, blobs, record = self.fixture()
        index_data = json.dumps(index).encode()
        index_digest = "sha256:" + release.sha256(index_data)
        blobs[index_digest] = index_data
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.candidate_fixture(root, record)
            oci = root / "synthetic-oci.tar"
            with tarfile.open(oci, "w") as archive:
                for path, data in [("index.json", json.dumps({"manifests": [{"digest": index_digest}]}).encode()),
                                   *[("blobs/sha256/" + digest[7:], data) for digest, data in blobs.items()]]:
                    entry = tarfile.TarInfo(path)
                    entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data))
            with mock.patch.object(release, "ROOT", root), mock.patch.dict(os.environ, {"IMAGE_DIGEST": index_digest}), \
                    mock.patch.object(release, "Registry", side_effect=AssertionError("OCI validation must be offline")), \
                    redirect_stdout(io.StringIO()):
                release.verify_image(str(oci))
            result = json.loads((root / "candidate-image.json").read_text(encoding="utf-8"))
            self.assertEqual(result["kind"], "unpublished-oci-archive")
            self.assertEqual(result["index_digest"], index_digest)
            self.assertNotIn("reference", result)

    def test_both_platform_layers_match_host_bytes_and_provenance_subjects(self):
        index, blobs, record = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            platforms = release.inspect_index(index, blobs.__getitem__, record, Path(temporary))
            self.assertEqual(set(platforms), set(release.ARCHES))
            for arch in release.ARCHES:
                self.assertEqual(platforms[arch]["binary_sha256"], record["binaries"][arch]["sha256"])
                self.assertTrue((Path(temporary) / platforms[arch]["provenance_path"]).is_file())

    def test_tampered_or_missing_image_data_refuses(self):
        for scenario in ("binary", "source label", "workflow label", "version label", "missing platform", "missing provenance",
                         "duplicate platform", "blob digest", "attestation subject"):
            with self.subTest(scenario=scenario):
                index, blobs, record = self.fixture()
                if scenario == "binary":
                    record["binaries"]["arm64"]["sha256"] = "0" * 64
                elif scenario.endswith("label"):
                    record[{"source label": "source_sha", "workflow label": "workflow_sha", "version label": "version"}[scenario]] = "wrong"
                elif scenario == "missing platform":
                    index["manifests"].pop(2)
                elif scenario == "missing provenance":
                    index["manifests"].pop(3)
                elif scenario == "duplicate platform":
                    index["manifests"].append(copy.deepcopy(index["manifests"][0]))
                elif scenario == "blob digest":
                    blobs[index["manifests"][0]["digest"]] += b"tampering"
                else:
                    index["manifests"][1]["annotations"]["vnd.docker.reference.digest"] = "sha256:" + "0" * 64
                with tempfile.TemporaryDirectory() as temporary, self.assertRaises(release.ReleaseError):
                    release.inspect_index(index, blobs.__getitem__, record, Path(temporary))


if __name__ == "__main__":
    unittest.main()
