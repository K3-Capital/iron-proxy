#!/usr/bin/env python3
"""Opt-in distrust test for released iron-proxy images (eMudhra chain compromise).

The 19 October 2026 compromise left several public eMudhra intermediates able to
mint certificates for arbitrary hosts. A release image is only acceptable if the
public CA bundle it ships refuses every one of the forged chains. This runner
proves exactly that against the candidate image itself:

* it uses the image's own OpenSSL and its own /etc/ssl/certs/ca-certificates.crt,
  disabling every other store (`-no-CApath -no-CAstore`), so nothing on the host
  or in the caller's environment can affect the verdict;
* it never installs, copies or mutates anything inside the candidate - the
  fixtures are mounted read-only and the container runs with `--network none`;
* it fails closed: a missing fixture, a duplicate, an unparseable PEM, a
  certificate that is expired or not yet valid at the reference time, a missing
  tool, a container that never started, or an unrecognised OpenSSL exit is an
  error, never a pass. Only explicit issuer-trust failures count as distrust.

Fixtures are public certificates only (no private keys). Their inventory,
per-file digests and source archive hash live in testdata/emudhra/manifest.json
and are validated on every run; a changed archive needs a reviewed inventory
update rather than silent acceptance.

Examples
--------
    # Candidate image, both release architectures, frozen + live reference time
    ./scripts/test-release-ca.py --image ghcr.io/k3-capital/iron-proxy:0.54.0-k3.ca.20261025.1 \
        --platform linux/amd64 --platform linux/arm64 --output-json /tmp/ca-test.json

    # RED control: the known-vulnerable image is expected to accept chains
    ./scripts/test-release-ca.py --image ironsh/iron-proxy:0.41.0 --expect vulnerable

    # Harness self-checks (no Docker image required)
    ./scripts/test-release-ca.py --self-test

Exit status: 0 when every platform/time mode meets the expectation, 1 when the
image fails the expectation, 2 for a harness, inventory or Docker error.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

MANIFEST_NAME = "manifest.json"
BUNDLE_PATH = "/etc/ssl/certs/ca-certificates.crt"
FIXTURE_MOUNT = "/fixtures"
CUSTOM_ANCHOR_DIR = "/usr/local/share/ca-certificates"
# 2026-10-24T00:00:00Z. The parent incident was measured on this date and every
# published fixture is valid around it; pinning the reference time stops a later
# expiry from making an unpatched image look clean.
DEFAULT_REFERENCE_TIME = 1792800000

# The only exit status `openssl verify` uses to report that verification of a
# certificate failed. Any other non-zero status is a tool, usage, I/O or signal
# failure and says nothing about the trust store, so it is a harness error.
VERIFY_FAILURE_EXIT = 2

# OpenSSL verify error codes that mean "this store does not trust the chain".
# These are issuer/anchor findings only. Code 7 (certificate signature failure)
# is deliberately absent: a corrupted signature proves the fixture is broken,
# not that the bundle stopped trusting an issuer, and accepting it would let an
# invalid measurement pass as security evidence.
# 2  unable to get issuer certificate        18 self-signed certificate
# 19 self-signed certificate in chain         20 unable to get local issuer certificate
# 21 unable to verify the first certificate   27 certificate not trusted
TRUST_ERROR_CODES = {2, 18, 19, 20, 21, 27}

# Explicitly recognised non-trust errors. They surface as failures so a fixture
# that is broken, expired or mismatched can never be read as successful distrust.
# 7 is here, not in TRUST_ERROR_CODES: a certificate whose signature does not
# verify is a corrupted fixture, not evidence that the store dropped an issuer.
NON_TRUST_ERROR_CODES = {
    7: "certificate signature failure (corrupt fixture)",
    9: "certificate is not yet valid",
    10: "certificate has expired",
    23: "certificate revoked",
    26: "unsupported certificate purpose",
    62: "hostname mismatch",
}

PEM_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)


class HarnessError(Exception):
    """The harness, the inventory or the container failed - not a verdict."""


class InventoryError(HarnessError):
    """The fixture inventory on disk does not match its manifest."""


class FixtureError(InventoryError):
    """A fixture cannot be used as distrust evidence."""


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_pem_certificates(text, source):
    """Return the DER bodies of every PEM CERTIFICATE block in *text*.

    Structural validation only: the blocks must be well formed and must decode,
    so a truncated or hand-edited fixture cannot pass as a certificate.
    """
    blocks = PEM_BLOCK_RE.findall(text)
    if not blocks:
        raise FixtureError("%s: no PEM CERTIFICATE block found" % source)
    bodies = []
    for index, block in enumerate(blocks):
        body = block.split("-----BEGIN CERTIFICATE-----", 1)[1]
        body = body.split("-----END CERTIFICATE-----", 1)[0]
        body = "".join(body.split())
        try:
            decoded = base64.b64decode(body, validate=True)
        except Exception as err:  # noqa: BLE001 - any decode failure is the verdict
            raise FixtureError(
                "%s: certificate block %d is not valid base64: %s" % (source, index, err)
            )
        if len(decoded) < 64 or decoded[0] != 0x30:
            raise FixtureError(
                "%s: certificate block %d does not look like DER" % (source, index)
            )
        bodies.append(decoded)
    return bodies


def load_inventory(root):
    """Load and structurally validate the fixture inventory under *root*.

    Duplicate-aware and exact: the manifest's fixture set must equal the *.pem
    files on disk, filenames/hosts/digests must be unique, and every digest must
    match. Nothing is inferred from wildcard counts.
    """
    manifest_path = os.path.join(root, MANIFEST_NAME)
    if not os.path.isfile(manifest_path):
        raise InventoryError("%s: missing fixture manifest" % manifest_path)
    with open(manifest_path, "r", encoding="utf-8") as handle:
        try:
            manifest = json.load(handle)
        except ValueError as err:
            raise InventoryError("%s: invalid JSON: %s" % (manifest_path, err))

    fixtures = manifest.get("fixtures")
    controls = manifest.get("controls")
    if not isinstance(fixtures, list) or not fixtures:
        raise InventoryError("manifest: 'fixtures' must be a non-empty list")
    if not isinstance(controls, list) or not controls:
        raise InventoryError("manifest: 'controls' must be a non-empty list")

    seen_names, seen_hashes, seen_hosts = set(), {}, {}
    for entry in fixtures:
        name = entry.get("file")
        host = entry.get("host")
        expected = entry.get("sha256")
        if not name or not host or not expected:
            raise InventoryError("manifest: fixture entry needs file, host and sha256")
        if name in seen_names:
            raise InventoryError("manifest: duplicate fixture file %s" % name)
        seen_names.add(name)
        if expected in seen_hashes:
            raise InventoryError(
                "manifest: %s and %s declare the same digest"
                % (seen_hashes[expected], name)
            )
        seen_hashes[expected] = name
        if host in seen_hosts:
            raise InventoryError("manifest: duplicate fixture host %s" % host)
        seen_hosts[host] = name

        path = os.path.join(root, name)
        if not os.path.isfile(path):
            raise InventoryError("manifest: fixture %s is missing from disk" % name)
        actual = sha256_file(path)
        if actual != expected:
            raise InventoryError(
                "fixture %s: sha256 %s does not match manifest %s"
                % (name, actual, expected)
            )
        with open(path, "r", encoding="utf-8", errors="strict") as handle:
            bodies = parse_pem_certificates(handle.read(), name)
        declared = entry.get("certificates")
        if declared is not None and declared != len(bodies):
            raise InventoryError(
                "fixture %s: manifest declares %s certificates, PEM holds %d"
                % (name, declared, len(bodies))
            )
        if len(bodies) < 2:
            raise InventoryError(
                "fixture %s: expected a leaf plus at least one intermediate" % name
            )
        entry["_bodies"] = bodies

    on_disk = sorted(
        name for name in os.listdir(root) if name.endswith(".pem") and os.path.isfile(os.path.join(root, name))
    )
    extra = [name for name in on_disk if name not in seen_names]
    if extra:
        raise InventoryError(
            "fixture directory holds PEM files absent from the manifest: %s"
            % ", ".join(extra)
        )

    # A duplicate is also a copy of a fixture under a second name: catch it by
    # comparing decoded certificate bodies, not only by filename.
    by_leaf = {}
    for entry in fixtures:
        leaf = hashlib.sha256(entry["_bodies"][0]).hexdigest()
        if leaf in by_leaf:
            raise InventoryError(
                "fixtures %s and %s carry the same leaf certificate"
                % (by_leaf[leaf], entry["file"])
            )
        by_leaf[leaf] = entry["file"]

    for control in controls:
        name = control.get("file")
        expected = control.get("sha256")
        if not name or not expected:
            raise InventoryError("manifest: control entry needs file and sha256")
        path = os.path.join(root, name)
        if not os.path.isfile(path):
            raise InventoryError("manifest: control %s is missing from disk" % name)
        actual = sha256_file(path)
        if actual != expected:
            raise InventoryError(
                "control %s: sha256 %s does not match manifest %s"
                % (name, actual, expected)
            )
        with open(path, "r", encoding="utf-8", errors="strict") as handle:
            parse_pem_certificates(handle.read(), name)

    return {
        "root": os.path.abspath(root),
        "manifest": manifest,
        "manifest_sha256": sha256_file(manifest_path),
        "fixtures": fixtures,
        "controls": controls,
    }


def parse_openssl_date(value):
    normalized = re.sub(r"\s+", " ", value.strip())
    try:
        parsed = datetime.datetime.strptime(normalized, "%b %d %H:%M:%S %Y GMT")
    except ValueError:
        raise HarnessError("unparseable OpenSSL date %r" % value)
    return int(parsed.replace(tzinfo=datetime.timezone.utc).timestamp())


def parse_leaf_metadata(output, host):
    """Parse `openssl x509 -noout -startdate -enddate -subject` output."""
    start = end = subject = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("notBefore="):
            start = parse_openssl_date(line.split("=", 1)[1])
        elif line.startswith("notAfter="):
            end = parse_openssl_date(line.split("=", 1)[1])
        elif line.startswith("subject="):
            subject = line.split("=", 1)[1].strip()
    if start is None or end is None or subject is None:
        raise HarnessError("OpenSSL did not describe the leaf certificate: %r" % output)
    common_name = None
    match = re.search(r"(?:^|,)\s*CN\s*=\s*(.+?)(?:,|$)", subject)
    if match:
        common_name = match.group(1).strip()
    if common_name != host:
        # The first certificate in the file must be the leaf for the fixture to
        # be a chain in the documented leaf-first order.
        raise FixtureError(
            "first certificate has CN %r, expected leaf for %s" % (common_name, host)
        )
    return {"not_before": start, "not_after": end, "subject": subject, "cn": common_name}


def check_reference_time(metadata, reference_time, name):
    if not (metadata["not_before"] <= reference_time <= metadata["not_after"]):
        raise FixtureError(
            "fixture %s is not valid at reference time %d (%s .. %s); an expired "
            "or not-yet-valid certificate cannot be counted as distrust"
            % (
                name,
                reference_time,
                datetime.datetime.fromtimestamp(metadata["not_before"], datetime.timezone.utc),
                datetime.datetime.fromtimestamp(metadata["not_after"], datetime.timezone.utc),
            )
        )


VERIFY_DIAGNOSTIC_RE = re.compile(r"error (\d+) at (\d+) depth lookup:\s*([^\n]*)")


def classify_verify(exit_code, output):
    """Map one `openssl verify` result to accepted / distrust / error.

    Fail-closed rules, in order:

    * a zero exit is only "accepted" when OpenSSL printed the OK line and no
      diagnostic at all;
    * distrust requires the documented verification-failure status
      (:data:`VERIFY_FAILURE_EXIT`), at least one diagnostic, and *every*
      diagnostic to be an issuer/trust finding - a later expiry, hostname,
      revocation or signature diagnostic downgrades the whole result to error;
    * every other status (usage errors, signals, a wrapper's own exit code) is a
      harness error, however trust-like the text looks.

    Returns (state, code, detail). ``code`` is the first offending OpenSSL code
    when one was parsed.
    """
    text = output or ""
    stripped = text.strip()
    diagnostics = VERIFY_DIAGNOSTIC_RE.findall(text)

    if exit_code == 0:
        if diagnostics:
            codes = sorted({int(code) for code, _, _ in diagnostics})
            return (
                "error",
                codes[0],
                "exit 0 with error diagnostics %s: %s"
                % (codes, " | ".join(d[2].strip() for d in diagnostics)),
            )
        if stripped.endswith(": OK"):
            return "accepted", None, stripped
        return "error", None, "exit 0 without an OpenSSL OK line: %r" % stripped

    if exit_code != VERIFY_FAILURE_EXIT:
        return (
            "error",
            None,
            "unexpected openssl exit %s (verification failure must be %d): %s"
            % (exit_code, VERIFY_FAILURE_EXIT, stripped),
        )

    if not diagnostics:
        return (
            "error",
            None,
            "verification failure exit %s without a diagnostic: %r"
            % (exit_code, stripped),
        )

    codes = [int(code) for code, _, _ in diagnostics]
    offending = [code for code in codes if code not in TRUST_ERROR_CODES]
    rendered = " | ".join(
        "%s (depth %s): %s" % (code, depth, message.strip())
        for code, depth, message in diagnostics
    )
    if offending:
        unknown = [code for code in offending if code not in NON_TRUST_ERROR_CODES]
        reason = (
            "non-trust diagnostic"
            if not unknown
            else "diagnostic not attributable to issuer trust"
        )
        return "error", offending[0], "%s: %s" % (reason, rendered)
    return "distrust", codes[0], rendered


def run_command(command, timeout):
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        raise HarnessError("docker is not installed or not on PATH")
    except subprocess.TimeoutExpired:
        raise HarnessError("command timed out after %ss: %s" % (timeout, " ".join(command)))
    output = completed.stdout.decode("utf-8", "replace")
    if completed.returncode != 0:
        message = output.strip()
        # `docker run` uses 125 for daemon/CLI errors and 126/127 for a missing
        # entrypoint; none of those are a verdict about the image's trust store.
        if completed.returncode in (125, 126, 127) or "Unable to find image" in message:
            raise HarnessError(
                "container could not run the command (exit %s): %s"
                % (completed.returncode, message)
            )
    return completed.returncode, output


# Test seam. The harness self-tests replace this with a stub so that container
# outcomes (corrupted signatures, unexpected exits, multiple diagnostics) can be
# exercised end to end through the real aggregation without Docker.
RUNNER = run_command


def docker_prefix(image, platform, fixtures_root):
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--platform",
        platform,
        "--mount",
        "type=bind,src=%s,dst=%s,readonly" % (fixtures_root, FIXTURE_MOUNT),
        "--entrypoint",
        "/bin/sh",
        image,
        "-c",
    ]


IDENTITY_SCRIPT = """
echo "openssl=$(openssl version 2>&1)"
echo "wget=$(wget 2>&1 | head -1)"
echo "bundle_sha256=$(sha256sum %s 2>/dev/null | cut -d' ' -f1)"
echo "bundle_certs=$(grep -c -- 'BEGIN CERTIFICATE' %s 2>/dev/null)"
echo "certs_dir_entries=$(ls -A /etc/ssl/certs 2>/dev/null | wc -l)"
echo "custom_anchors=$(ls -A %s 2>/dev/null | tr '\\n' ' ')"
echo "ssl_cert_file=${SSL_CERT_FILE:-unset}"
echo "ssl_cert_dir=${SSL_CERT_DIR:-unset}"
apk info -e -v ca-certificates ca-certificates-bundle openssl 2>&1 | sed 's/^/package=/'
""" % (
    BUNDLE_PATH,
    BUNDLE_PATH,
    CUSTOM_ANCHOR_DIR,
)


def probe_identity(image, platform, fixtures_root, timeout):
    command = docker_prefix(image, platform, fixtures_root) + [IDENTITY_SCRIPT]
    _, output = RUNNER(command, timeout)
    identity: dict = {"raw": output.strip().splitlines()}
    packages = []
    for line in output.splitlines():
        if line.startswith("package="):
            packages.append(line[len("package=") :].strip())
        elif "=" in line:
            key, value = line.split("=", 1)
            identity[key] = value.strip()
    identity["packages"] = [p for p in packages if p]
    problems = []
    if not identity.get("openssl"):
        problems.append("openssl is not installed in the image")
    if not identity.get("bundle_sha256"):
        problems.append("%s is missing or unreadable" % BUNDLE_PATH)
    try:
        if int(identity.get("bundle_certs", "0")) <= 0:
            problems.append("%s holds no certificates" % BUNDLE_PATH)
    except ValueError:
        problems.append("could not count certificates in %s" % BUNDLE_PATH)
    if identity.get("custom_anchors", "").strip():
        problems.append(
            "image carries extra trust anchors in %s: %s"
            % (CUSTOM_ANCHOR_DIR, identity["custom_anchors"].strip())
        )
    if identity.get("ssl_cert_file") not in (None, "unset") or identity.get(
        "ssl_cert_dir"
    ) not in (None, "unset"):
        problems.append(
            "image sets SSL_CERT_FILE/SSL_CERT_DIR, which would substitute another store"
        )
    identity["problems"] = problems
    return identity


def read_leaf_metadata(image, platform, fixtures_root, name, timeout):
    script = "openssl x509 -in %s/%s -noout -startdate -enddate -subject" % (
        FIXTURE_MOUNT,
        name,
    )
    command = docker_prefix(image, platform, fixtures_root) + [script]
    exit_code, output = RUNNER(command, timeout)
    if exit_code != 0:
        raise HarnessError(
            "openssl could not read fixture %s inside the image (exit %s): %s"
            % (name, exit_code, output.strip())
        )
    return output


def build_verify_command(image, platform, fixtures_root, name, reference_time):
    """The exact offline verify invocation for one fixture.

    Only the image's own bundle is consulted: -no-CApath and -no-CAstore drop
    every other default store, and nothing is mounted except the fixtures.
    """
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--platform",
        platform,
        "--mount",
        "type=bind,src=%s,dst=%s,readonly" % (fixtures_root, FIXTURE_MOUNT),
        "--entrypoint",
        "openssl",
        image,
        "verify",
        "-no-CApath",
        "-no-CAstore",
        "-CAfile",
        BUNDLE_PATH,
        "-purpose",
        "sslserver",
        "-verify_hostname",
        os.path.splitext(name)[0],
        "-attime",
        str(reference_time),
        "-untrusted",
        "%s/%s" % (FIXTURE_MOUNT, name),
        "%s/%s" % (FIXTURE_MOUNT, name),
    ]


def verify_fixture(image, platform, fixtures_root, name, reference_time, timeout):
    return RUNNER(
        build_verify_command(image, platform, fixtures_root, name, reference_time),
        timeout,
    )


def verify_control_command(image, platform, fixtures_root, name, reference_time):
    """Known-good control: a trusted anchor, so no hostname or usage check.

    This is the harness's positive control. If it fails to verify, the harness
    cannot distinguish trust from a broken run, and every "distrust" result in
    the same run is meaningless.
    """
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--platform",
        platform,
        "--mount",
        "type=bind,src=%s,dst=%s,readonly" % (fixtures_root, FIXTURE_MOUNT),
        "--entrypoint",
        "openssl",
        image,
        "verify",
        "-no-CApath",
        "-no-CAstore",
        "-CAfile",
        BUNDLE_PATH,
        "-attime",
        str(reference_time),
        "%s/%s" % (FIXTURE_MOUNT, name),
    ]


def verify_control(image, platform, fixtures_root, name, reference_time, timeout):
    return RUNNER(
        verify_control_command(image, platform, fixtures_root, name, reference_time),
        timeout,
    )


def check_time_mode(
    inventory, image, platform, reference_time, mode, expectation, timeout
):
    """Run every fixture plus the control at one reference time."""
    rows = []
    errors = []
    for entry in inventory["fixtures"]:
        name = entry["file"]
        host = entry["host"]
        try:
            metadata = parse_leaf_metadata(
                read_leaf_metadata(
                    image, platform, inventory["root"], name, timeout
                ),
                host,
            )
            check_reference_time(metadata, reference_time, name)
            exit_code, output = verify_fixture(
                image, platform, inventory["root"], name, reference_time, timeout
            )
        except HarnessError as err:
            rows.append(
                {
                    "fixture": name,
                    "host": host,
                    "state": "error",
                    "detail": str(err),
                }
            )
            errors.append("%s: %s" % (name, err))
            continue
        state, code, detail = classify_verify(exit_code, output)
        rows.append(
            {
                "fixture": name,
                "host": host,
                "state": state,
                "openssl_error": code,
                "openssl_exit": exit_code,
                "detail": detail.strip().splitlines()[-1] if detail else "",
                "leaf_not_before": metadata["not_before"],
                "leaf_not_after": metadata["not_after"],
            }
        )

    control_rows = []
    control_failed = 0
    for control in inventory["controls"]:
        name = control["file"]
        try:
            exit_code, output = verify_control(
                image, platform, inventory["root"], name, reference_time, timeout
            )
            state, code, detail = classify_verify(exit_code, output)
            if exit_code != 0 or state != "accepted":
                control_failed += 1
                errors.append(
                    "control %s did not verify: %s" % (name, detail.strip() or "unknown")
                )
            control_rows.append(
                {
                    "control": name,
                    "state": state,
                    "openssl_error": code,
                    "openssl_exit": exit_code,
                    "expected": control.get("expected", "verified"),
                }
            )
        except HarnessError as err:
            control_failed += 1
            control_rows.append({"control": name, "state": "error", "detail": str(err)})
            errors.append("control %s: %s" % (name, err))

    tested = len(rows)
    accepted = sum(1 for row in rows if row["state"] == "accepted")
    distrust = sum(1 for row in rows if row["state"] == "distrust")
    row_errors = sum(1 for row in rows if row["state"] == "error")
    expected_count = len(inventory["fixtures"])

    if expectation == "secure":
        if tested != expected_count:
            errors.append("tested %d fixtures, inventory holds %d" % (tested, expected_count))
        if row_errors:
            errors.append("%d fixture(s) produced harness errors" % row_errors)
        if accepted:
            errors.append("%d forged chain(s) still accepted" % accepted)
        if distrust != expected_count:
            errors.append(
                "%d of %d fixtures failed for issuer-trust reasons"
                % (distrust, expected_count)
            )
    else:  # vulnerable RED control
        if row_errors:
            errors.append("%d fixture(s) produced harness errors" % row_errors)
        if tested != expected_count:
            errors.append("tested %d fixtures, inventory holds %d" % (tested, expected_count))
        if accepted == 0:
            errors.append(
                "expected the vulnerable image to accept at least one forged chain, "
                "none were accepted"
            )

    return {
        "mode": mode,
        "reference_time": reference_time,
        "reference_time_utc": datetime.datetime.fromtimestamp(
            reference_time, datetime.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tested": tested,
        "accepted": accepted,
        "distrust": distrust,
        "errors": row_errors,
        "controls_failed": control_failed,
        "results": rows,
        "controls": control_rows,
        "failures": errors,
        "pass": not errors,
    }


def run(args, inventory, live_time):
    evidence = {
        "schema_version": 1,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "image": args.image,
        "expectation": args.expect,
        "bundle_path": BUNDLE_PATH,
        "fixtures": {
            "directory": inventory["root"],
            "manifest_sha256": inventory["manifest_sha256"],
            "count": len(inventory["fixtures"]),
            "source_url": inventory["manifest"].get("source", {}).get("url"),
            "archive_sha256": inventory["manifest"].get("source", {}).get(
                "archive_sha256"
            ),
        },
        "platforms": [],
        "failures": [],
    }
    exit_code = 0
    for platform in args.platform:
        platform_evidence = {"platform": platform, "checks": [], "failures": []}
        try:
            identity = probe_identity(
                args.image, platform, inventory["root"], args.timeout
            )
        except HarnessError as err:
            platform_evidence["failures"].append("image probe failed: %s" % err)
            platform_evidence["pass"] = False
            evidence["platforms"].append(platform_evidence)
            evidence["failures"].append("%s: %s" % (platform, err))
            exit_code = 2
            continue
        platform_evidence["identity"] = identity
        if identity["problems"]:
            platform_evidence["failures"].extend(identity["problems"])
            evidence["failures"].extend(
                "%s: %s" % (platform, problem) for problem in identity["problems"]
            )
            exit_code = exit_code or 1

        modes = [("frozen", args.verify_time)]
        if live_time:
            modes.append(("live", int(datetime.datetime.now(datetime.timezone.utc).timestamp())))

        for mode, reference_time in modes:
            try:
                result = check_time_mode(
                    inventory,
                    args.image,
                    platform,
                    reference_time,
                    mode,
                    args.expect,
                    args.timeout,
                )
            except HarnessError as err:
                result = {
                    "mode": mode,
                    "reference_time": reference_time,
                    "failures": [str(err)],
                    "pass": False,
                }
                exit_code = 2
            platform_evidence["checks"].append(result)
            if not result["pass"]:
                for failure in result["failures"]:
                    message = "%s/%s: %s" % (platform, mode, failure)
                    platform_evidence["failures"].append(message)
                    evidence["failures"].append(message)
                invalid = result.get("errors") or result.get("controls_failed")
                exit_code = max(exit_code, 2 if invalid else 1)
        platform_evidence["pass"] = not platform_evidence["failures"]
        evidence["platforms"].append(platform_evidence)

    evidence["pass"] = not evidence["failures"]
    if not evidence["pass"] and exit_code == 0:
        exit_code = 1
    return exit_code, evidence


def describe(evidence):
    lines = []
    for platform in evidence["platforms"]:
        identity = platform.get("identity", {})
        lines.append(
            "== %s == image %s"
            % (platform["platform"], evidence["image"])
        )
        if identity:
            lines.append(
                "   openssl=%s bundle=%s (%s certs)"
                % (
                    identity.get("openssl", "missing"),
                    identity.get("bundle_sha256", "missing"),
                    identity.get("bundle_certs", "?"),
                )
            )
            for package in identity.get("packages", []):
                lines.append("   package %s" % package)
        for check in platform.get("checks", []):
            if "tested" not in check:
                lines.append("   %s: ERROR %s" % (check["mode"], "; ".join(check["failures"])))
                continue
            lines.append(
                "   %-6s tested=%d accepted=%d distrust=%d errors=%d controls_failed=%s -> %s"
                % (
                    check["mode"],
                    check["tested"],
                    check["accepted"],
                    check["distrust"],
                    check["errors"],
                    check.get("controls_failed", "?"),
                    "PASS" if check["pass"] else "FAIL",
                )
            )
            for failure in check["failures"]:
                lines.append("     ! %s" % failure)
    lines.append(
        "RESULT: %s (%d platform failure(s))"
        % ("PASS" if evidence["pass"] else "FAIL", len(evidence["failures"]))
    )
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Harness self-checks. These need no Docker image: they pin the behaviour that
# keeps a broken fixture or a broken command from being reported as distrust.
# --------------------------------------------------------------------------


class ClassificationTests(unittest.TestCase):
    def test_ok_is_accepted(self):
        state, _, _ = classify_verify(0, "/fixtures/x.pem: OK")
        self.assertEqual(state, "accepted")

    def test_issuer_errors_are_distrust(self):
        output = (
            "C = IN, O = eMudhra Technologies Limited, CN = emSign Root TLS CA - G3\n"
            "error 20 at 2 depth lookup: unable to get local issuer certificate\n"
            "error /fixtures/x.pem: verification failed"
        )
        for code in (2, 18, 19, 20, 21, 27):
            state, parsed, _ = classify_verify(2, "error %d at 1 depth lookup: nope" % code)
            self.assertEqual(state, "distrust")
            self.assertEqual(parsed, code)
        state, code, _ = classify_verify(2, output)
        self.assertEqual((state, code), ("distrust", 20))

    def test_signature_failure_is_not_distrust(self):
        # A corrupted signature shows the fixture is broken, not that the store
        # stopped trusting an issuer. Counting it as security evidence would let
        # an invalid measurement pass.
        state, code, detail = classify_verify(
            2, "error 7 at 0 depth lookup: certificate signature failure"
        )
        self.assertEqual(state, "error")
        self.assertEqual(code, 7)
        self.assertIn("signature", detail)

    def test_unexpected_exit_statuses_are_errors(self):
        trust = "error 20 at 1 depth lookup: unable to get local issuer certificate"
        for status in (42, -11, 1, 125, -6):
            state, _, detail = classify_verify(status, trust)
            self.assertEqual(state, "error", "exit %s must not be a verdict" % status)
            self.assertIn(str(status), detail)

    def test_zero_exit_with_diagnostics_is_an_error(self):
        state, _, _ = classify_verify(
            0, "error 20 at 1 depth lookup: unable to get local issuer certificate"
        )
        self.assertEqual(state, "error")

    def test_every_diagnostic_is_inspected(self):
        trust = "error 20 at 1 depth lookup: unable to get local issuer certificate"
        for extra in (
            "error 10 at 0 depth lookup: certificate has expired",
            "error 62 at 0 depth lookup: hostname mismatch",
            "error 7 at 0 depth lookup: certificate signature failure",
            "error 99 at 0 depth lookup: novel failure",
        ):
            state, code, detail = classify_verify(2, trust + "\n" + extra)
            self.assertEqual(state, "error", "later diagnostic must not be ignored: %s" % extra)
            self.assertEqual(code, int(extra.split()[1]))
            self.assertIn("unable to get local issuer certificate", detail)
        # Two issuer findings are still one verdict: distrust.
        state, code, _ = classify_verify(
            2,
            trust + "\nerror 18 at 2 depth lookup: self-signed certificate in chain",
        )
        self.assertEqual((state, code), ("distrust", 20))

    def test_non_trust_errors_are_errors(self):
        for code in (9, 10, 23, 26, 62):
            state, _, detail = classify_verify(
                2, "error %d at 0 depth lookup: something" % code
            )
            self.assertEqual(state, "error", "code %d must not count as distrust" % code)
            self.assertIn(str(code), detail)

    def test_unrecognised_result_is_error(self):
        self.assertEqual(classify_verify(1, "")[0], "error")
        self.assertEqual(classify_verify(0, "garbage")[0], "error")
        self.assertEqual(classify_verify(2, "error 99 at 0 depth lookup: novel")[0], "error")

    def test_expired_leaf_metadata_is_error_not_distrust(self):
        metadata = {
            "not_before": 1700000000,
            "not_after": 1710000000,
            "subject": "CN = host.example",
            "cn": "host.example",
        }
        with self.assertRaises(FixtureError):
            check_reference_time(metadata, DEFAULT_REFERENCE_TIME, "host.example")

    def test_not_yet_valid_leaf_metadata_is_error(self):
        metadata = {
            "not_before": 1900000000,
            "not_after": 2000000000,
            "subject": "CN = host.example",
            "cn": "host.example",
        }
        with self.assertRaises(FixtureError):
            check_reference_time(metadata, DEFAULT_REFERENCE_TIME, "host.example")

    def test_leaf_metadata_requires_leaf_first(self):
        output = "notBefore=Oct 20 00:59:36 2026 GMT\nnotAfter=May  3 01:04:36 2027 GMT\nsubject=CN = other.example"
        with self.assertRaises(FixtureError):
            parse_leaf_metadata(output, "dv-g3b-emudhra.we-have-a-problem.com")

    def test_leaf_metadata_parses(self):
        output = "notBefore=Oct 20 00:59:36 2026 GMT\nnotAfter=May  3 01:04:36 2027 GMT\nsubject=CN = dv-g3b-emudhra.we-have-a-problem.com"
        metadata = parse_leaf_metadata(output, "dv-g3b-emudhra.we-have-a-problem.com")
        self.assertEqual(metadata["not_before"], 1792457976)
        check_reference_time(metadata, DEFAULT_REFERENCE_TIME, "fixture")


class InventoryTests(unittest.TestCase):
    HOST = "dv-g3b-emudhra.we-have-a-problem.com"

    def _make_root(self):
        root = tempfile.mkdtemp(prefix="kca810-fixtures-")
        self.addCleanup(shutil.rmtree, root, True)
        return root

    def _valid_chain(self, host=None):
        # Two concatenated, DER-shaped, base64-valid blocks. The harness checks
        # structure only; trust decisions happen inside the image.
        body = base64.b64encode(bytes([0x30, 0x82, 0x00, 0x40]) + bytes(range(60))).decode()
        block = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % body
        return block + block

    def _write_manifest(self, root, entries, controls, extra_manifest=None):
        manifest = {
            "source": {"url": "https://example.invalid/chains.zip", "archive_sha256": "0" * 64},
            "fixtures": entries,
            "controls": controls,
        }
        if extra_manifest:
            manifest.update(extra_manifest)
        with open(os.path.join(root, MANIFEST_NAME), "w", encoding="utf-8") as handle:
            json.dump(manifest, handle)

    def _entry(self, root, host, name=None):
        name = name or "%s.pem" % host
        path = os.path.join(root, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self._valid_chain(host))
        return {
            "file": name,
            "host": host,
            "sha256": sha256_file(path),
            "certificates": 2,
        }

    def _control(self, root):
        name = "control/root.pem"
        os.makedirs(os.path.join(root, "control"), exist_ok=True)
        path = os.path.join(root, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self._valid_chain("root.invalid"))
        return {"file": name, "sha256": sha256_file(path), "expected": "verified"}

    def test_valid_inventory_loads(self):
        root = self._make_root()
        entry = self._entry(root, self.HOST)
        control = self._control(root)
        self._write_manifest(root, [entry], [control])
        inventory = load_inventory(root)
        self.assertEqual(len(inventory["fixtures"]), 1)

    def test_missing_fixture_is_rejected(self):
        root = self._make_root()
        entry = self._entry(root, self.HOST)
        os.unlink(os.path.join(root, entry["file"]))
        self._write_manifest(root, [entry], [self._control(root)])
        with self.assertRaises(InventoryError):
            load_inventory(root)

    def test_extra_fixture_is_rejected(self):
        root = self._make_root()
        entry = self._entry(root, self.HOST)
        control = self._control(root)
        self._entry(root, "sneaky.example")
        self._write_manifest(root, [entry], [control])
        with self.assertRaises(InventoryError):
            load_inventory(root)

    def test_duplicate_content_is_rejected(self):
        root = self._make_root()
        first = self._entry(root, self.HOST)
        second_path = os.path.join(root, "copy.pem")
        with open(os.path.join(root, first["file"]), "rb") as src, open(
            second_path, "wb"
        ) as dst:
            dst.write(src.read())
        second = {
            "file": "copy.pem",
            "host": "copy.example",
            "sha256": sha256_file(second_path),
            "certificates": 2,
        }
        self._write_manifest(root, [first, second], [self._control(root)])
        with self.assertRaises(InventoryError):
            load_inventory(root)

    def test_malformed_pem_is_rejected(self):
        root = self._make_root()
        entry = self._entry(root, self.HOST)
        with open(os.path.join(root, entry["file"]), "w", encoding="utf-8") as handle:
            handle.write("-----BEGIN CERTIFICATE-----\nnot base64!!\n-----END CERTIFICATE-----\n")
        entry["sha256"] = sha256_file(os.path.join(root, entry["file"]))
        self._write_manifest(root, [entry], [self._control(root)])
        with self.assertRaises(InventoryError):
            load_inventory(root)

    def test_tampered_digest_is_rejected(self):
        root = self._make_root()
        entry = self._entry(root, self.HOST)
        entry["sha256"] = "f" * 64
        self._write_manifest(root, [entry], [self._control(root)])
        with self.assertRaises(InventoryError):
            load_inventory(root)

    def test_single_certificate_fixture_is_rejected(self):
        root = self._make_root()
        name = "%s.pem" % self.HOST
        path = os.path.join(root, name)
        body = base64.b64encode(bytes([0x30, 0x82, 0x00, 0x40]) + bytes(range(60))).decode()
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % body)
        entry = {"file": name, "host": self.HOST, "sha256": sha256_file(path), "certificates": 1}
        self._write_manifest(root, [entry], [self._control(root)])
        with self.assertRaises(InventoryError):
            load_inventory(root)


def test_pem_chain(seed=""):
    """Two concatenated, DER-shaped, base64-valid blocks.

    Structural only: the harness never parses X.509 itself. ``seed`` keeps
    distinct fixtures distinct so the inventory's duplicate detection is not
    tripped by identical test bytes.
    """
    payload = hashlib.sha256(seed.encode("utf-8")).digest() + bytes(range(28))
    body = base64.b64encode(bytes([0x30, 0x82, 0x00, 0x40]) + payload).decode()
    block = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % body
    return block + block


def write_test_corpus(root, hosts, control="control/root.pem"):
    """Write a structurally valid fixture inventory for runner-level tests."""
    os.makedirs(os.path.join(root, "control"), exist_ok=True)
    fixtures = []
    for host in hosts:
        name = "%s.pem" % host
        path = os.path.join(root, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(test_pem_chain(host))
        fixtures.append(
            {"file": name, "host": host, "sha256": sha256_file(path), "certificates": 2}
        )
    control_path = os.path.join(root, control)
    with open(control_path, "w", encoding="utf-8") as handle:
        handle.write(test_pem_chain("control"))
    manifest = {
        "source": {"url": "https://example.invalid/chains.zip", "archive_sha256": "0" * 64},
        "fixtures": fixtures,
        "controls": [
            {"file": control, "sha256": sha256_file(control_path), "expected": "verified"}
        ],
    }
    with open(os.path.join(root, MANIFEST_NAME), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle)
    return fixtures


IDENTITY_OUTPUT = "\n".join(
    [
        "openssl=OpenSSL 3.5.9 29 Sep 2026",
        "wget=BusyBox v1.37.0 multi-call binary.",
        "bundle_sha256=" + "a" * 64,
        "bundle_certs=118",
        "certs_dir_entries=240",
        "custom_anchors=",
        "ssl_cert_file=unset",
        "ssl_cert_dir=unset",
        "package=ca-certificates-20261020-r0",
        "package=ca-certificates-bundle-20261020-r0",
        "package=openssl-3.5.9-r0",
    ]
) + "\n"

TRUST_DIAGNOSTIC = "error 20 at 2 depth lookup: unable to get local issuer certificate"


class StubRunner:
    """Deterministic stand-in for the container runner.

    Drives the real aggregation and exit-status logic without Docker, so the
    tests cover the paths that matter: what a bad measurement is allowed to
    become in the final result.
    """

    def __init__(self, verify_by_fixture, control=(0, "control/root.pem: OK")):
        self.verify_by_fixture = verify_by_fixture
        self.control = control
        self.calls = []

    def __call__(self, command, timeout):
        self.calls.append(command)
        joined = " ".join(command)
        if "bundle_certs=" in joined:
            return 0, IDENTITY_OUTPUT
        if "-noout" in joined:
            match = re.search(r"-in\s+(\S+)", joined)
            name = match.group(1).rsplit("/", 1)[-1]
            host = os.path.splitext(name)[0]
            return 0, (
                "notBefore=Oct 20 00:59:36 2026 GMT\n"
                "notAfter=May  3 01:04:36 2027 GMT\n"
                "subject=CN = %s" % host
            )
        if "control/" in joined:
            return self.control
        name = command[-2].rsplit("/", 1)[-1]
        return self.verify_by_fixture[name]


class RunnerRegressionTests(unittest.TestCase):
    """End-to-end runner regressions with authentic-shaped inputs."""

    HOSTS = ["alpha.example", "beta.example"]

    def _run(self, verify_by_fixture, control=(0, "control/root.pem: OK"), expect="secure"):
        root = tempfile.mkdtemp(prefix="kca810-runner-")
        self.addCleanup(shutil.rmtree, root, True)
        write_test_corpus(root, self.HOSTS)
        inventory = load_inventory(root)
        args = build_parser().parse_args(
            [
                "--image", "test:image",
                "--platform", "linux/amd64",
                "--verify-time", str(DEFAULT_REFERENCE_TIME),
                "--fixtures", root,
                "--expect", expect,
                "--skip-live-time",
            ]
        )
        # main() normalises these; call run() with the normalised values.
        args.verify_time = DEFAULT_REFERENCE_TIME
        stub = StubRunner(verify_by_fixture, control)
        global RUNNER
        previous = RUNNER
        RUNNER = stub
        self.addCleanup(lambda: globals().__setitem__("RUNNER", previous))
        exit_code, evidence = run(args, inventory, False)
        return exit_code, evidence, stub

    def test_all_issuer_failures_pass(self):
        exit_code, evidence, _ = self._run(
            {name: (2, TRUST_DIAGNOSTIC) for name in ("alpha.example.pem", "beta.example.pem")}
        )
        self.assertEqual(exit_code, 0)
        self.assertTrue(evidence["pass"])
        self.assertEqual(evidence["platforms"][0]["checks"][0]["distrust"], 2)

    def test_corrupted_signatures_cannot_pass_as_distrust(self):
        exit_code, evidence, _ = self._run(
            {
                name: (2, "error 7 at 0 depth lookup: certificate signature failure")
                for name in ("alpha.example.pem", "beta.example.pem")
            }
        )
        self.assertEqual(exit_code, 2)
        self.assertFalse(evidence["pass"])
        check = evidence["platforms"][0]["checks"][0]
        self.assertEqual(check["distrust"], 0)
        self.assertEqual(check["errors"], 2)
        self.assertTrue(
            all(
                row["state"] == "error" and row["openssl_error"] == 7
                for row in check["results"]
            )
        )
        self.assertTrue(
            all("signature failure" in row["detail"] for row in check["results"])
        )

    def test_unexpected_exit_cannot_pass(self):
        exit_code, evidence, _ = self._run(
            {name: (42, TRUST_DIAGNOSTIC) for name in ("alpha.example.pem", "beta.example.pem")}
        )
        self.assertEqual(exit_code, 2)
        self.assertFalse(evidence["pass"])
        self.assertEqual(evidence["platforms"][0]["checks"][0]["distrust"], 0)

    def test_signal_status_cannot_pass(self):
        exit_code, evidence, _ = self._run(
            {name: (-11, TRUST_DIAGNOSTIC) for name in ("alpha.example.pem", "beta.example.pem")}
        )
        self.assertEqual(exit_code, 2)
        self.assertFalse(evidence["pass"])

    def test_mixed_diagnostic_cannot_pass(self):
        exit_code, evidence, _ = self._run(
            {
                name: (
                    2,
                    TRUST_DIAGNOSTIC
                    + "\nerror 10 at 0 depth lookup: certificate has expired",
                )
                for name in ("alpha.example.pem", "beta.example.pem")
            }
        )
        self.assertEqual(exit_code, 2)
        self.assertFalse(evidence["pass"])

    def test_failing_positive_control_blocks_pass(self):
        exit_code, evidence, _ = self._run(
            {name: (2, TRUST_DIAGNOSTIC) for name in ("alpha.example.pem", "beta.example.pem")},
            control=(2, "control/root.pem: unable to get local issuer certificate"),
        )
        self.assertEqual(exit_code, 2)
        self.assertFalse(evidence["pass"])
        self.assertEqual(evidence["platforms"][0]["checks"][0]["controls_failed"], 1)

    def test_vulnerable_expectation_still_independent_of_errors(self):
        exit_code, evidence, _ = self._run(
            {
                "alpha.example.pem": (2, "error 7 at 0 depth lookup: certificate signature failure"),
                "beta.example.pem": (0, "beta.example.pem: OK"),
            },
            expect="vulnerable",
        )
        self.assertEqual(exit_code, 2)
        self.assertFalse(evidence["pass"])


class DockerCommandTests(unittest.TestCase):
    NAME = "dv-g3b-emudhra.we-have-a-problem.com.pem"

    def test_verify_command_is_offline_readonly_and_store_scoped(self):
        command = build_verify_command(
            "image:tag", "linux/arm64", "/tmp/fixtures", self.NAME, DEFAULT_REFERENCE_TIME
        )
        joined = " ".join(command)
        self.assertIn("--network none", joined)
        self.assertIn("dst=%s,readonly" % FIXTURE_MOUNT, joined)
        self.assertIn("-no-CApath -no-CAstore", joined)
        self.assertIn("-CAfile %s" % BUNDLE_PATH, joined)
        self.assertIn("-attime %d" % DEFAULT_REFERENCE_TIME, joined)
        self.assertIn("-purpose sslserver", joined)
        self.assertIn("-verify_hostname dv-g3b-emudhra.we-have-a-problem.com", joined)
        self.assertIn("--platform linux/arm64", joined)
        # The fixture is both the untrusted chain and the target: leaf-first.
        self.assertEqual(joined.count("%s/%s" % (FIXTURE_MOUNT, self.NAME)), 2)
        # No write, no install, no host trust store.
        for forbidden in ("--volume", "apk", "/etc/ssl/certs:/", "type=none"):
            self.assertNotIn(forbidden, joined)

    def test_control_command_omits_hostname_check(self):
        command = verify_control_command(
            "image:tag", "linux/amd64", "/tmp/fixtures", "control/isrg-root-x1.pem", 1
        )
        joined = " ".join(command)
        self.assertNotIn("-verify_hostname", joined)
        self.assertNotIn("-purpose", joined)

    def test_missing_docker_is_a_harness_error(self):
        with self.assertRaises(HarnessError):
            run_command(["docker-command-that-does-not-exist-kca810"], 5)


def self_test():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for case in (
        ClassificationTests,
        InventoryTests,
        RunnerRegressionTests,
        DockerCommandTests,
    ):
        suite.addTests(loader.loadTestsFromTestCase(case))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def build_parser():
    parser = argparse.ArgumentParser(
        description="Prove a release image distrusts the published eMudhra forged chains."
    )
    parser.add_argument("--image", help="candidate image reference (tag or tag@digest)")
    parser.add_argument(
        "--platform",
        action="append",
        default=None,
        help="image platform to test, repeatable (default: linux/amd64)",
    )
    parser.add_argument(
        "--verify-time",
        default=str(DEFAULT_REFERENCE_TIME),
        help="frozen OpenSSL reference time (unix seconds or RFC3339); default %d"
        % DEFAULT_REFERENCE_TIME,
    )
    parser.add_argument(
        "--fixtures",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "testdata", "emudhra"),
        help="fixture inventory directory (default: testdata/emudhra)",
    )
    parser.add_argument(
        "--expect",
        choices=("secure", "vulnerable"),
        default="secure",
        help="'secure' requires 14/14 distrust; 'vulnerable' is the RED control for a known-bad image",
    )
    parser.add_argument("--output-json", help="write the full evidence document here ('-' for stdout)")
    parser.add_argument("--timeout", type=int, default=120, help="per-command timeout in seconds")
    parser.add_argument(
        "--skip-live-time",
        action="store_true",
        help="only run the frozen reference time (default also runs live time)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the harness self-checks; no image is required",
    )
    return parser


def parse_reference_time(value):
    value = str(value).strip()
    if value.isdigit():
        return int(value)
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise SystemExit("--verify-time must be unix seconds or RFC3339, got %r" % value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return int(parsed.timestamp())


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.image:
        parser.error("--image is required unless --self-test is used")
    args.platform = args.platform or ["linux/amd64"]
    args.verify_time = parse_reference_time(args.verify_time)

    try:
        inventory = load_inventory(args.fixtures)
    except HarnessError as err:
        sys.stderr.write("FIXTURE INVENTORY ERROR: %s\n" % err)
        return 2

    if args.expect == "secure" and len(inventory["fixtures"]) != 14:
        sys.stderr.write(
            "FIXTURE INVENTORY ERROR: expected exactly 14 fixtures, manifest holds %d\n"
            % len(inventory["fixtures"])
        )
        return 2

    try:
        exit_code, evidence = run(args, inventory, not args.skip_live_time)
    except HarnessError as err:
        sys.stderr.write("HARNESS ERROR: %s\n" % err)
        return 2

    print(describe(evidence))
    if args.output_json:
        document = json.dumps(evidence, indent=2) + "\n"
        if args.output_json == "-":
            sys.stdout.write(document)
        else:
            with open(args.output_json, "w", encoding="utf-8") as handle:
                handle.write(document)
            print("evidence: %s" % os.path.abspath(args.output_json))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
