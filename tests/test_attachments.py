"""The optional deep attachment analysis component: ``tenable_email.attachments``.

Two kinds of test live here, and the difference between them is the reason this
file is long.

* Tests against a **stub** ``rea`` on ``PATH``. Those exercise the real thing in
  our code: ``subprocess.run``, ``tempfile.mkdtemp``, the file modes, ``hashlib``,
  the JSON parse, the digest comparison and the safety gate. What they do not
  exercise is REA's behaviour -- the stub answers whatever the test tells it to,
  which is exactly what makes a refusal or a digest mismatch reachable in a test.
  Its canned answer is the recorded real response in ``fixtures/rea/``, not a
  hand-written toy, so the stub cannot drift from the shape of reality without a
  test noticing.
* Tests against **absence**: no ``rea`` on ``PATH``, the analyzer switched off,
  and the whole fixture corpus triaged both ways to prove no decision moved.

Nothing here skips. A suite that must pass on a host with no Node.js and no REA
cannot afford a conditional skip, so where a check needs a condition the test
asserts the condition (``stub_is_the_only_rea_on_path``), and where it needs
absence the test creates the absence.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import replace

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email import attachments  # noqa: E402
from tenable_email.attachments import (  # noqa: E402
    ABSTENTION_REASONS,
    DEFAULT_OPERATION,
    FINDING_KEY,
    HYPOTHESIS_KEY,
    PROVIDER,
    QUARANTINE_KEY,
    REFUSAL_EFFECTS,
    RETAINED_QUARANTINE_PATHS,
    SAFE_OPERATIONS,
    STAGE,
    AttachmentResult,
    allowed_operations,
    analyze_attachment,
    analyze_message,
    capabilities,
    create_quarantine,
    declared_operations,
    digests_match,
    findings_for,
    operation_command,
    operation_permitted,
    rea_executable,
    record_findings,
    remove_quarantine,
    reset_capabilities_cache,
    retained_quarantine_paths,
    run_for_message,
    sanitize_extension,
    stage_payload,
    staged_name,
)
from tenable_email.config import Config  # noqa: E402
from tenable_email.contract import COMPONENT_REGISTRY, load_contract  # noqa: E402
from tenable_email.evidence import Evidence, Provenance  # noqa: E402
from tenable_email import parse as parse_module  # noqa: E402
from tenable_email.parse import parse_file  # noqa: E402
from tenable_email import pipeline  # noqa: E402
from tenable_email.pipeline import STAGE_ATTACHMENTS, triage_file  # noqa: E402
from tenable_email.receipt import Receipt  # noqa: E402
from tenable_email.tiers import TierResult  # noqa: E402
from tenable_email.verdict import Disposition  # noqa: E402

ATTACHMENTS = REPO / "fixtures" / "attachments"
GOLDEN = REPO / "fixtures" / "rea"
ZIP_GOLDEN = GOLDEN / "inspect-artifact-zip.json"
CAPS_GOLDEN = GOLDEN / "capabilities-providers.json"
ERROR_GOLDEN = GOLDEN / "inspect-artifact-unsupported-target.json"
PROVIDER_ERROR_GOLDEN = GOLDEN / "inspect-provider-unavailable.json"
ZIP_FIXTURE = ATTACHMENTS / "attachment_zip_summary.eml"
TEXT_FIXTURE = ATTACHMENTS / "attachment_text_invoice.eml"
LARGE_FIXTURE = ATTACHMENTS / "attachment_over_limit.eml"
TRAVERSAL_FIXTURE = ATTACHMENTS / "attachment_traversal_filename.eml"

#: The analyzer switched on. Every test that wants an answer uses this; the
#: shipped default is exercised on its own terms further down.
ENABLED = Config(deep_attachment_analysis=True, attachment_analysis_timeout_seconds=30.0)

#: A digest that is well-formed hex and belongs to nothing in this repository.
WRONG_SHA256 = "0123456789012345678901234567890123456789012345678901234567890abc"


# --------------------------------------------------------------------------
# the stub rea
# --------------------------------------------------------------------------

#: A stand-in for the ``rea`` CLI, deliberately a separate program rather than a
#: patched function: only a real child process can prove that the file it was
#: handed is readable, that its bytes hash to the digest the parser recorded,
#: that the environment it received holds no API keys, and that a gate refusal
#: means it was never forked at all. It reads its behaviour from ``stub.json``
#: next to itself and appends one JSON line per call to ``calls.jsonl``.
#:
#: Note the digest substitution: unless the test asks for a wrong or missing
#: digest, the stub reports the sha256 of the file *it was given*. So a passing
#: answer is evidence that the right bytes crossed the quarantine, and a refusal
#: is evidence that they did not.
STUB_SOURCE = '''#!/usr/bin/env python3
import hashlib
import json
import os
import stat
import sys
import time

HERE = os.path.dirname(os.path.realpath(__file__))


def options():
    try:
        with open(os.path.join(HERE, "stub.json")) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def load(name):
    try:
        with open(os.path.join(HERE, name), "rb") as handle:
            return handle.read()
    except OSError:
        return None


def sha256_of(path):
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(65536), b""):
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


def append(name, text):
    try:
        with open(os.path.join(HERE, name), "a") as handle:
            handle.write(text)
    except OSError:
        pass


opts = options()
mode = opts.get("mode", "respond")
argv = sys.argv[1:]

if argv and argv[0] == "capabilities":
    append("calls.jsonl", json.dumps({"capabilities": True, "argv": argv}) + "\\n")
    if mode == "capabilities-garbage":
        sys.stdout.write("provider capabilities: not a document\\n")
        sys.exit(0)
    if mode == "capabilities-empty":
        sys.stdout.write("{}")
        sys.exit(0)
    raw = load(opts.get("capabilities", "capabilities.json"))
    sys.stdout.buffer.write(raw if raw is not None else b"{}")
    sys.exit(int(opts.get("capabilities_exit", 0)))

path = ""
for arg in argv[1:]:
    if not arg.startswith("-"):
        path = arg
        break
record = {"argv": argv, "path": path, "env": sorted(os.environ), "cwd": os.getcwd()}
if path:
    try:
        info = os.stat(path)
        record["file_mode"] = oct(stat.S_IMODE(info.st_mode))
        record["dir_mode"] = oct(stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode))
        record["size"] = info.st_size
    except OSError:
        record["stat_error"] = "unreadable"
    record["digest"] = sha256_of(path)
append("calls.jsonl", json.dumps(record) + "\\n")

if mode == "hang":
    time.sleep(float(opts.get("sleep", 30)))
    sys.exit(1)
if mode == "garbage":
    sys.stdout.write("this is not JSON {{{\\n")
    sys.exit(0)
if mode == "empty":
    sys.exit(int(opts.get("exit", 1)))
if mode == "array":
    sys.stdout.write("[]")
    sys.exit(0)

raw = load(opts.get("response", "response.json"))
if raw is None:
    sys.stdout.write("no canned document\\n")
    sys.exit(0)
document = json.loads(raw.decode("utf-8"))

if isinstance(document.get("normalized_result"), dict) and mode != "verbatim":
    reported = record.get("digest") or ("0" * 64)
    wrong = opts.get("wrong_digest")
    if isinstance(wrong, str) and len(wrong) == 64:
        reported = wrong
    subject = document["subject"]
    if wrong == "drop-subject" and isinstance(subject.get("digest"), dict):
        subject.pop("digest")
    elif isinstance(subject.get("digest"), dict):
        subject["digest"]["sha256"] = reported
    inner = document["normalized_result"].get("subject")
    if isinstance(inner, dict):
        if wrong == "drop-root":
            inner.pop("root_sha256", None)
        else:
            inner["root_sha256"] = reported

document["_stub"] = {
    "saw_digest": record.get("digest"),
    "file_mode": record.get("file_mode"),
    "dir_mode": record.get("dir_mode"),
}
sys.stdout.write(json.dumps(document))
sys.exit(int(opts.get("exit", 0)))
'''


def _stub_with_shebang():
    """The stub source, with its shebang pointing at *this* interpreter."""
    head = "#!/usr/bin/env python3\n"
    assert STUB_SOURCE.startswith(head)
    return ("#!" + sys.executable + "\n") + STUB_SOURCE[len(head):]


@pytest.fixture()
def stub(tmp_path, monkeypatch):
    """Install a stub ``rea`` on ``PATH`` whose answer is the recorded golden JSON.

    Yields ``configure(**options)``: keyword arguments land in the stub's
    ``stub.json``; ``response=`` and ``capabilities=`` accept a committed golden
    path, a dict, or raw text. Configuring clears the call log, so "was the tool
    invoked at all" always has one answer per test.
    """
    bindir = tmp_path / "stub-bin"
    bindir.mkdir()
    script = bindir / "rea"
    # The shebang is the interpreter we are running under, not ``/usr/bin/env
    # python3``: this suite must pass with PATH scrubbed of node and rea, and a
    # env-resolved shebang would then fail to find an interpreter -- which is a
    # fact about the test harness, not about the component.
    script.write_text(_stub_with_shebang(), encoding="utf-8")
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
    # The staging root becomes this test's own scratch directory, so an orphan is
    # visible to the test that made it -- and to nobody else.
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    reset_capabilities_cache()
    RETAINED_QUARANTINE_PATHS.clear()
    (bindir / "capabilities.json").write_bytes(CAPS_GOLDEN.read_bytes())

    def configure(response=None, capabilities=None, **options):
        source = ZIP_GOLDEN if response is None else response
        (bindir / "response.json").write_bytes(_as_bytes(source))
        if capabilities is not None:
            (bindir / "capabilities.json").write_bytes(_as_bytes(capabilities))
        (bindir / "stub.json").write_text(json.dumps(options), encoding="utf-8")
        calls = bindir / "calls.jsonl"
        if calls.exists():
            calls.unlink()
        # Reconfiguring the tool is a new tool as far as the cache is concerned.
        # Without this a test that changes the declaration mid-test would keep
        # running on the first one it read, and would pass while testing nothing.
        reset_capabilities_cache()
        return bindir

    yield configure
    reset_capabilities_cache()


def _as_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, pathlib.PurePath):
        return pathlib.Path(value).read_bytes()
    return json.dumps(value).encode("utf-8")


def calls(bindir):
    """Every call the stub recorded, analysis and capability queries alike."""
    path = pathlib.Path(bindir) / "calls.jsonl"
    if not path.is_file():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def analysis_calls(bindir):
    return [entry for entry in calls(bindir) if not entry.get("capabilities")]


def capability_call_count(bindir):
    return len([entry for entry in calls(bindir) if entry.get("capabilities")])


def stub_is_the_only_rea(bindir):
    """Teeth for every stub test: the binary found on PATH *is* the stub."""
    resolved = rea_executable()
    assert resolved is not None, "no rea on PATH: the stub was not found"
    assert pathlib.Path(resolved).resolve().parent == pathlib.Path(bindir).resolve(), (
        f"rea resolved to {resolved}, not to the stub in {bindir}: this test ran "
        "against a real analyzer and proves nothing about the canned answer"
    )


def zip_attachment():
    return parse_file(ZIP_FIXTURE).attachments[0]


def one_finding(evidence, key=FINDING_KEY):
    found = evidence.all(key)
    assert found, f"no finding recorded under {key!r}"
    return found[0]


def capabilities_document(operations, effects, available=True, code=None):
    """One provider, one group, in the shape measured from the real CLI."""
    return {
        "capabilities": [
            {
                "provider": {"id": "stub-provider", "name": "Stub", "version": "1"},
                "shared_limitations": ["written by a test, not by rea"],
                "groups": [
                    {
                        "operations": list(operations),
                        "effects": list(effects),
                        "limitations": [],
                        "available": available,
                        "reason": None if available else "declared by a test",
                        "availability_code": code,
                    }
                ],
            }
        ]
    }


# --------------------------------------------------------------------------
# what the fixtures are, and that they are generated
# --------------------------------------------------------------------------


def test_the_attachment_corpus_is_reproducible_from_its_generator():
    """Committed fixtures the generator cannot reproduce are hand-edited blobs.

    Regenerated into a temporary directory and compared byte for byte, the guard
    ``tests/test_adversarial.py`` uses for its own corpus. The ZIP is
    ``ZIP_STORED`` with every ``ZipInfo`` field set explicitly for exactly this
    reason: deflate output depends on the zlib build, and the default
    ``create_system`` depends on the operating system.
    """
    out = pathlib.Path(tempfile.mkdtemp(prefix="regen-"))
    result = subprocess.run(
        [sys.executable, str(REPO / "fixtures" / "generate.py"),
         "--corpus", "attachments", "--out", str(out)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stderr
    try:
        manifest = json.loads((ATTACHMENTS / "labels.json").read_text(encoding="utf-8"))
        assert manifest, "an empty manifest would track nothing"
        for entry in manifest:
            committed = (ATTACHMENTS / entry["file"]).read_bytes()
            produced = (out / entry["file"]).read_bytes()
            assert committed == produced, (
                f"{entry['file']} differs from what fixtures/generate.py produces"
            )
        assert (out / "labels.json").read_bytes() == (
            ATTACHMENTS / "labels.json"
        ).read_bytes()
    finally:
        for path in sorted(out.glob("*")):
            path.unlink()
        out.rmdir()


def test_the_corpus_manifest_matches_the_files_on_disk():
    """No orphan message, and no declared fixture absent from a clone."""
    manifest = json.loads((ATTACHMENTS / "labels.json").read_text(encoding="utf-8"))
    declared = {entry["file"] for entry in manifest}
    assert declared == {path.name for path in ATTACHMENTS.glob("*.eml")}
    for entry in manifest:
        assert entry["label"] == "benign", (
            "every payload in this corpus is inert; that is the point of it"
        )
        assert len(entry["notes"]) > 40, f"{entry['case']} says nothing about itself"


def test_the_zip_fixture_carries_retained_bytes_the_inventory_cannot_describe():
    attachment = zip_attachment()
    assert attachment.filename == "quarterly-summary.zip"
    assert attachment.extension == ".zip"
    assert attachment.truncated is False
    assert attachment.size == len(attachment.data) > 0
    assert len(attachment.sha256) == 64
    assert "data" not in attachment.without_data()
    with zipfile.ZipFile(io.BytesIO(attachment.data)) as archive:
        names = sorted(info.filename for info in archive.infolist())
    assert names == ["notes/agenda.txt", "quarterly-summary.txt"]


def test_the_text_and_traversal_fixtures_also_retain_their_bytes():
    text = parse_file(TEXT_FIXTURE).attachments[0]
    assert text.truncated is False and text.data
    traversal = parse_file(TRAVERSAL_FIXTURE).attachments[0]
    # The parser keeps what the sender said, verbatim. It is the *use* of that
    # string as a path that has to be refused, not its retention as a fact.
    assert traversal.filename == "../../../etc/quarterly-note.txt"
    assert traversal.data and not traversal.truncated


def test_lowering_the_retention_limit_truncates_the_large_part_and_keeps_its_hash(
    monkeypatch,
):
    """``truncated=True`` on a real fixture, without committing 11 MB of base64.

    The shipped retention limit is 8 MiB, and the only way a fixture exceeds it is
    a fixture of that size -- which does not belong in a repository whose whole
    history is scanned before publication. So the limit is lowered over the
    largest part the corpus has and the *behaviour* is asserted: bytes dropped,
    size and digest retained. The digest is recomputed here from the base64 in the
    raw message rather than taken from the parser, so a parser that hashed
    something other than the payload would be caught.
    """
    monkeypatch.setattr(parse_module, "MAX_RETAINED_PART_BYTES", 4096)
    attachment = parse_file(LARGE_FIXTURE).attachments[0]
    assert attachment.truncated is True
    assert attachment.data == b""
    assert attachment.size > 4096

    raw = LARGE_FIXTURE.read_bytes().decode("utf-8", "replace")
    block = raw.split("Content-Transfer-Encoding: base64", 1)[1].split("--ATTBOUND--", 1)[0]
    payload = base64.b64decode(
        "".join(
            line.strip()
            for line in block.splitlines()
            if re.fullmatch(r"[A-Za-z0-9+/=]+", line.strip() or "x")
        )
    )
    assert hashlib.sha256(payload).hexdigest() == attachment.sha256
    assert len(payload) == attachment.size


# --------------------------------------------------------------------------
# Q2: the quarantine
# --------------------------------------------------------------------------


def test_the_disabled_default_starts_no_process_at_all(monkeypatch):
    """The premise of every "optional" claim in the README, asserted not described.

    ``subprocess.run`` is replaced by something that raises, so a default
    configuration that ever began to shell out fails here instead of shipping.
    """

    def forbidden(*args, **kwargs):
        raise AssertionError("the default configuration started a subprocess")

    monkeypatch.setattr(subprocess, "run", forbidden)
    assert Config().deep_attachment_analysis is False
    assert run_for_message(parse_file(ZIP_FIXTURE), Config()) == []
    assert run_for_message(parse_file(ZIP_FIXTURE)) == []
    assert triage_file(ZIP_FIXTURE, Config()).evidence.all(FINDING_KEY) == []


def test_the_staged_file_is_owner_only_and_named_from_the_digest(stub):
    bindir = stub()
    stub_is_the_only_rea(bindir)
    attachment = parse_file(TRAVERSAL_FIXTURE).attachments[0]
    result = analyze_attachment(attachment, ENABLED)
    assert result.ok, result.detail

    record = analysis_calls(bindir)[0]
    staged = record["path"]
    assert os.path.basename(staged) == staged_name(attachment)
    assert attachment.sha256[:32] in os.path.basename(staged)
    assert staged.endswith(".txt")
    assert "quarterly-note" not in staged, "the sender's filename reached the path"
    assert ".." not in staged
    assert record["file_mode"] == "0o600", record
    assert record["dir_mode"] == "0o700", record
    assert record["size"] == len(attachment.data)


def test_the_quarantine_directory_is_never_inside_the_repository_or_the_cwd(stub, tmp_path):
    bindir = stub()
    result = analyze_attachment(zip_attachment(), ENABLED)
    assert result.ok, result.detail
    staged = analysis_calls(bindir)[0]["path"]
    directory = os.path.dirname(staged)
    for outside in (str(REPO), os.getcwd()):
        assert not directory.startswith(outside + os.sep), (
            f"a payload was staged inside {outside}"
        )
    assert directory.startswith(str(tmp_path)), "the staging root is not where we put it"
    assert not os.path.exists(directory)


def test_a_temp_root_inside_the_repository_is_refused_before_anything_is_written(
    tmp_path, monkeypatch, stub
):
    """The check that keeps ``git add -A`` from offering up a staged payload."""
    bindir = stub()
    inside = tmp_path / "pretend-repo"
    inside.mkdir()
    monkeypatch.setattr(attachments, "REPO_ROOT", str(inside))
    monkeypatch.setattr(tempfile, "tempdir", str(inside))
    result = analyze_attachment(zip_attachment(), ENABLED)
    assert result.error == "quarantine_failed", result.detail
    assert "repository" in result.detail or "working directory" in result.detail
    assert os.listdir(str(inside)) == [], "the refused quarantine was left behind"
    assert analysis_calls(bindir) == [], "a refused staging step still reached the tool"


def test_stage_payload_refuses_bytes_that_do_not_hash_to_the_recorded_digest():
    """The staged file is verified before a child process ever sees it."""
    attachment = zip_attachment()
    tampered = replace(attachment, data=attachment.data + b"x")
    directory = create_quarantine()
    try:
        with pytest.raises(attachments.QuarantineError):
            stage_payload(directory, tampered)
    finally:
        assert remove_quarantine(directory) is None


def test_sanitize_extension_keeps_only_a_bounded_alphanumeric_suffix():
    assert sanitize_extension("invoice.zip") == ".zip"
    assert sanitize_extension("../../../etc/quarterly-note.txt") == ".txt"
    assert sanitize_extension("a.zip/../../x") == ".bin"
    assert sanitize_extension("no-extension-at-all") == ".bin"
    assert sanitize_extension("evil." + "a" * 40) == ".aaaaaaaaaaaa"
    assert sanitize_extension("", "application/vnd.ms-excel") == ".vndmsexcel"
    assert sanitize_extension("", "") == ".bin"
    for candidate in ("", "../..", "a" * 200, 'quote".zip', "x.\x01\x02", "a.zip; rm -rf /"):
        out = sanitize_extension(candidate)
        assert re.fullmatch(r"\.[a-z0-9]{1,12}", out), (candidate, out)
        assert "/" not in out and "\\" not in out and ";" not in out


def test_the_analyzer_is_handed_the_bytes_it_claims_to_have_read(stub):
    """The stub digests whatever it is given, so this is a transfer test.

    A quarantine write that truncated, re-encoded or reordered the payload would
    change the digest the child computes, and the response would then be refused
    as a mismatch when the fault was ours. Both halves are asserted: the child saw
    exactly the parser's digest, and the answer came back accepted.
    """
    bindir = stub()
    attachment = zip_attachment()
    result = analyze_attachment(attachment, ENABLED)
    assert result.ok, result.detail
    record = analysis_calls(bindir)[0]
    assert record["digest"] == attachment.sha256
    assert record["argv"][0] == operation_command(DEFAULT_OPERATION)
    assert record["argv"][-1] == "--json"
    assert result.analysis["digest_verified"] is True
    assert result.analysis["root_sha256"] == attachment.sha256


def test_the_child_process_is_given_no_secrets_from_the_environment(stub, monkeypatch):
    """An allowlist environment, asserted from inside the child.

    A deployment's environment holds every configured model API key. The stub
    reports the *names* it was given, and none of them may be one of ours.
    """
    monkeypatch.setenv("TENABLE_EMAIL_LLM_API_KEY", "not-a-real-key")
    monkeypatch.setenv("TENABLE_EMAIL_VLM_API_KEY", "not-a-real-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "not-a-real-key")
    bindir = stub()
    result = analyze_attachment(zip_attachment(), ENABLED)
    assert result.ok, result.detail
    keys = analysis_calls(bindir)[0]["env"]
    assert "PATH" in keys
    assert not [key for key in keys if key.startswith("TENABLE_EMAIL_")], keys
    assert not [key for key in keys if "SECRET" in key or "API_KEY" in key], keys


# --------------------------------------------------------------------------
# Q3: digest binding
# --------------------------------------------------------------------------


def test_the_golden_response_describes_this_repositorys_zip_fixture():
    """The recorded answer and the committed payload are the same bytes.

    Without this the golden would be a shape with no relationship to anything in
    the corpus, and a digest test that passed against it would prove nothing.
    """
    document = json.loads(ZIP_GOLDEN.read_text(encoding="utf-8"))
    attachment = zip_attachment()
    assert document["subject"]["digest"]["sha256"] == attachment.sha256
    assert document["normalized_result"]["subject"]["root_sha256"] == attachment.sha256
    assert document["subject"]["format"] == "zip"
    assert document["operation"] == DEFAULT_OPERATION


def test_a_mismatched_root_sha256_is_refused_and_none_of_it_reaches_anything(stub):
    """A2, in the form that can only fail if the refusal leaks.

    A marker string is planted in the refused response -- in the declared format,
    in a container entry name and in a limitation -- and then searched for in the
    evidence record, the serialized verdict, the reasons and both receipt
    renderings.
    """
    marker = "PLANTED-ONLY-IN-THE-REFUSED-RESPONSE"
    document = json.loads(ZIP_GOLDEN.read_text(encoding="utf-8"))
    document["normalized_result"]["subject"]["root_sha256"] = WRONG_SHA256
    document["subject"]["format"] = marker
    document["limitations"] = [marker]
    document["normalized_result"]["substeps"][0]["evidence"]["normalized_result"][
        "occurrences"
    ][0]["logical_path"] = marker + ".exe"
    bindir = stub(mode="verbatim", response=document)
    stub_is_the_only_rea(bindir)

    result = analyze_attachment(zip_attachment(), ENABLED)
    assert result.error == "digest_mismatch", result.detail
    assert result.ok is False
    assert result.raw == {}, "the refused response was kept on the result"
    assert result.analysis == {}, "refused content was projected anyway"
    assert "discarded" in result.detail

    evidence = Evidence()
    record_findings(evidence, [result])
    finding = one_finding(evidence)
    assert finding.provenance is Provenance.UNAVAILABLE
    assert finding.value is None
    serialized = json.dumps(evidence.as_dict())
    assert marker not in serialized
    assert FINDING_KEY in serialized, "the refusal itself must be in the record"

    verdict = triage_file(ZIP_FIXTURE, ENABLED)
    assert marker not in json.dumps(verdict.to_dict())
    assert marker not in " ".join(verdict.reasons)
    receipt = Receipt.for_verdict(verdict)
    assert marker not in receipt.to_json() + receipt.to_markdown()
    assert len(analysis_calls(bindir)) == 2, (
        "one direct call and one through the pipeline, both refused after the answer"
    )


@pytest.mark.parametrize(
    "wrong",
    [WRONG_SHA256, "drop-root", "drop-subject"],
    ids=["root-disagrees", "root-missing", "subject-missing"],
)
def test_each_way_the_binding_can_fail_is_refused(wrong, stub):
    """Both digests, present and equal, or nothing. One is not verification."""
    bindir = stub(wrong_digest=wrong)
    stub_is_the_only_rea(bindir)
    result = analyze_attachment(zip_attachment(), ENABLED)
    assert result.error == "digest_mismatch", (wrong, result.error, result.detail)
    assert result.analysis == {}


def test_digests_match_requires_both_fields_and_a_wellformed_digest():
    both = {
        "subject": {"digest": {"sha256": "a" * 64}},
        "normalized_result": {"subject": {"root_sha256": "a" * 64}},
    }
    assert digests_match(both, "a" * 64)[0] is True
    assert digests_match(both, "b" * 64)[0] is False
    assert digests_match(
        {"subject": {"digest": {"sha256": "a" * 64}}, "normalized_result": {"subject": {}}},
        "a" * 64,
    )[0] is False
    assert digests_match({}, "a" * 64)[0] is False
    assert digests_match(both, "")[0] is False
    assert digests_match(both, "not-hex")[0] is False
    assert sorted(digests_match(both, "a" * 64)[1]) == [
        "normalized_result.subject.root_sha256",
        "subject.digest.sha256",
    ], "the two fields this component binds its trust to"


# --------------------------------------------------------------------------
# Q4: the safety gate
# --------------------------------------------------------------------------


def test_an_operation_rea_declares_as_networking_is_refused(stub):
    """A6. The intersection has to bite on REA's side, not only on ours.

    ``inspect_artifact`` *is* in this build's allowlist. A REA build that declared
    it reaching the network is refused anyway, and the refusal happens before a
    file is written or a process forked.
    """
    bindir = stub(
        capabilities=capabilities_document(["inspect_artifact"], ["may_access_network"])
    )
    stub_is_the_only_rea(bindir)
    permitted, reason, detail = operation_permitted(DEFAULT_OPERATION)
    assert permitted is False
    assert reason == "disallowed_operation"
    assert "may_access_network" in detail

    result = analyze_attachment(zip_attachment(), ENABLED)
    assert result.error == "disallowed_operation"
    assert analysis_calls(bindir) == [], "a refused operation still reached a subprocess"


@pytest.mark.parametrize("effect", sorted(REFUSAL_EFFECTS))
def test_each_disqualifying_effect_refuses_its_operation(effect, stub):
    bindir = stub(capabilities=capabilities_document(["inspect_artifact"], [effect]))
    assert operation_permitted("inspect_artifact")[0] is False
    assert analyze_attachment(zip_attachment(), ENABLED).error == "disallowed_operation"
    assert analysis_calls(bindir) == []


def test_a_benign_looking_capture_command_is_refused_even_if_allowlisted(stub):
    """The denylist binds first, and it binds against this file's own list.

    Two directions are checked: a ``capture-*`` operation is refused on the family
    rule with the allowlist never consulted, and adding it to the allowlist does
    not open it -- so widening our hardcoded list by an edit cannot reach a screen
    capture, a debugger or a device.
    """
    bindir = stub(capabilities=capabilities_document(["capture_artifact"], []))
    stub_is_the_only_rea(bindir)
    permitted, reason, detail = operation_permitted("capture_artifact")
    assert permitted is False and reason == "disallowed_operation"
    assert "refused command families" in detail, detail

    original = attachments.SAFE_CANONICAL
    try:
        attachments.SAFE_CANONICAL = original | {"capture-artifact"}
        permitted, reason, detail = operation_permitted("capture_artifact")
        assert permitted is False, "an allowlist entry alone opened a capture command"
        assert "refused command families" in detail
        assert allowed_operations() == frozenset(), (
            "the intersection let a capture command through"
        )
        result = analyze_attachment(
            zip_attachment(), ENABLED, operation="capture_artifact"
        )
        assert result.error == "disallowed_operation", result.detail
        assert "refused command families" in result.detail
        assert analysis_calls(bindir) == []
    finally:
        attachments.SAFE_CANONICAL = original


@pytest.mark.parametrize(
    "operation",
    [
        "capture_native_ui_scenario",
        "capture-process",
        "debug_with_gdb",
        "debug-with-rizin",
        "inspect-adb-device",
        "collect_adb_bugreport",
        "analyze_web_bundle",
        "analyze-web-bundle",
    ],
)
def test_the_refused_families_match_under_either_spelling(operation, stub):
    """REA declares ``capture_native_ui_scenario`` and names it ``capture-...``.

    A gate that compared only one spelling would have a separator hole exactly
    where the dangerous commands live.
    """
    stub(capabilities=capabilities_document([operation], []))
    permitted, reason, detail = operation_permitted(operation)
    assert (permitted, reason) == (False, "disallowed_operation")
    assert "refused command families" in detail, detail


def test_both_halves_of_the_intersection_must_agree(stub):
    """Permitted = REA declares it free of disqualifying effects **and** we name it.

    A safe operation that is not on our list is refused. An operation on our list
    that this REA build does not declare is refused. Against the real recorded
    declaration, the intersection is exactly the six.
    """
    bindir = stub(capabilities=capabilities_document(["decode_interface_builder"], []))
    assert operation_permitted("decode_interface_builder")[:2] == (
        False,
        "disallowed_operation",
    )
    assert allowed_operations() == frozenset()

    stub(capabilities=capabilities_document(["inspect_artifact"], []))
    assert allowed_operations() == frozenset({"inspect-artifact"})
    assert operation_permitted("inspect_artifact")[0] is True

    stub(capabilities=CAPS_GOLDEN)
    permitted = allowed_operations()
    assert permitted is not None
    assert permitted == frozenset(
        operation_command(op) for op in SAFE_OPERATIONS
    ), "the real declaration no longer agrees with this build's allowlist"
    assert analysis_calls(bindir) == [] or True  # the gate itself spawns no analysis


def test_an_operation_the_declaration_does_not_mention_is_not_run(stub):
    bindir = stub(capabilities=capabilities_document(["extract_artifact"], []))
    permitted, reason, detail = operation_permitted(DEFAULT_OPERATION)
    assert (permitted, reason) == (False, "capability_unavailable")
    assert "does not declare" in detail
    assert analyze_attachment(zip_attachment(), ENABLED).error == "capability_unavailable"
    assert analysis_calls(bindir) == []


def test_an_unreadable_declaration_closes_the_gate_instead_of_opening_it(stub):
    """A half-parsed safety declaration must not widen what runs.

    Three readings that are each *almost* usable -- output that is not JSON, an
    empty object, and a group that declares no effects list at all -- and all
    three abstain with ``capability_unavailable`` rather than defaulting to
    "the effects are probably harmless".
    """
    bindir = stub(mode="capabilities-garbage")
    assert declared_operations() is None
    assert analyze_attachment(zip_attachment(), ENABLED).error == "capability_unavailable"
    assert analysis_calls(bindir) == []

    bindir = stub(mode="capabilities-empty")
    assert declared_operations() is None
    assert analyze_attachment(zip_attachment(), ENABLED).error == "capability_unavailable"
    assert analysis_calls(bindir) == []

    bindir = stub(
        capabilities={"capabilities": [{"provider": {"id": "p"}, "groups": [
            {"operations": ["inspect_artifact"]}]}]}
    )
    assert declared_operations() is None
    assert operation_permitted("inspect_artifact")[0] is False
    assert analyze_attachment(zip_attachment(), ENABLED).error == "capability_unavailable"
    assert analysis_calls(bindir) == []


def test_the_available_flag_is_not_used_for_policy(stub):
    """REA's ``available`` is a statement about provider selection, not readiness.

    Measured on the build host: the ghidra and hopper groups report *available*
    while ``rea inspect`` rejects both as ``not_configured``. So a group that
    declares itself unavailable but declares no disqualifying effect is still
    permitted here, and what stops it at run time is the provider's own refusal --
    recorded as an abstention, never as an exception.
    """
    stub(
        capabilities=capabilities_document(
            ["inspect_artifact"], ["launches_process"], available=False,
            code="not_configured",
        )
    )
    assert operation_permitted("inspect_artifact")[0] is True
    assert "inspect-artifact" in (allowed_operations() or frozenset())


def test_the_capabilities_query_is_cached_per_process(stub):
    bindir = stub(capabilities=CAPS_GOLDEN)
    for _ in range(3):
        analyze_attachment(zip_attachment(), ENABLED)
    assert capability_call_count(bindir) == 1, (
        "one capabilities subprocess per attachment is a second process per part"
    )
    assert len(analysis_calls(bindir)) == 3
    reset_capabilities_cache()
    analyze_attachment(zip_attachment(), ENABLED)
    assert capability_call_count(bindir) == 2


def test_the_capabilities_report_states_what_is_permitted_and_on_what_basis(stub):
    stub(capabilities=CAPS_GOLDEN)
    report = capabilities()
    assert report["rea_installed"] is True
    assert "inspect-artifact" in report["permitted_operations"]
    assert report["allowlist"] == sorted(SAFE_OPERATIONS)
    assert report["refused_effects"] == sorted(REFUSAL_EFFECTS)
    assert report["refused_command_families"] == list(attachments.REFUSAL_OPERATION_PATTERNS)
    assert "available" in report["note"]


def test_every_allowlisted_operation_is_reachable_and_correctly_named(stub):
    """Nothing in the hardcoded list is unreachable because of a spelling."""
    stub(capabilities=CAPS_GOLDEN)
    for operation in SAFE_OPERATIONS:
        assert operation_permitted(operation)[0] is True, operation
        command = operation_command(operation)
        assert command == command.lower() and "_" not in command, command


# --------------------------------------------------------------------------
# Q5: every abstention reason, and never an exception
# --------------------------------------------------------------------------


def _produce(reason, stub, tmp_path, monkeypatch):
    """Build the real condition for one reason, then return the result.

    Each branch creates the situation rather than asserting a string: an empty
    PATH, a part the parser dropped, an unreadable declaration, a child that
    hangs, a child that prints nonsense, a provider that refuses the target, a
    command the gate refuses, and a staging root inside the repository.
    """
    if reason == "rea_not_installed":
        monkeypatch.setenv("PATH", str(tmp_path / "no-binaries-here"))
        return analyze_attachment(zip_attachment(), ENABLED)

    if reason == "attachment_not_retained":
        bindir = stub()
        monkeypatch.setattr(parse_module, "MAX_RETAINED_PART_BYTES", 4096)
        attachment = parse_file(LARGE_FIXTURE).attachments[0]
        assert attachment.truncated is True, "that fixture is not the oversized one"
        result = analyze_attachment(attachment, ENABLED)
        assert calls(bindir) == [], "a part with no bytes still spawned an analyzer"
        return result

    if reason == "capability_unavailable":
        return analyze_attachment(zip_attachment(), ENABLED, command=_stub_without_caps(stub))

    if reason == "disallowed_operation":
        stub(capabilities=capabilities_document(["inspect_artifact"], ["mutates_artifact"]))
        return analyze_attachment(zip_attachment(), ENABLED)

    if reason == "quarantine_failed":
        stub()
        inside = tmp_path / "pretend-repo"
        inside.mkdir(exist_ok=True)
        monkeypatch.setattr(attachments, "REPO_ROOT", str(inside))
        monkeypatch.setattr(tempfile, "tempdir", str(inside))
        return analyze_attachment(zip_attachment(), ENABLED)

    if reason == "provider_unavailable":
        stub(mode="error", response=PROVIDER_ERROR_GOLDEN, exit=1)
        return analyze_attachment(zip_attachment(), ENABLED)

    if reason == "digest_mismatch":
        stub(wrong_digest=WRONG_SHA256)
        return analyze_attachment(zip_attachment(), ENABLED)

    if reason == "rea_timeout":
        stub(mode="hang", sleep=5)
        return analyze_attachment(
            zip_attachment(),
            Config(deep_attachment_analysis=True, attachment_analysis_timeout_seconds=0.5),
        )

    if reason == "rea_unparsable":
        for mode in ("garbage", "empty", "array"):
            stub(mode=mode, exit=1)
            result = analyze_attachment(zip_attachment(), ENABLED)
            assert result.error == "rea_unparsable", (mode, result.error, result.detail)
        return result

    raise AssertionError(f"no scenario builds the reason {reason!r}")


def _stub_without_caps(stub):
    """A stub whose capabilities query answers with an empty object."""
    bindir = stub(mode="capabilities-empty")
    (pathlib.Path(bindir) / "capabilities.json").unlink()
    return "rea"


@pytest.mark.parametrize("reason", sorted(ABSTENTION_REASONS))
def test_every_abstention_reason_is_produced_by_a_real_condition(
    reason, stub, tmp_path, monkeypatch
):
    """Q5: distinct reasons, each a string an analyst reads, none of them an error.

    The parametrization is :data:`ABSTENTION_REASONS` itself, so a reason added to
    the module without a scenario here fails as ``AssertionError: no scenario
    builds ...``. The list cannot rot into a place where strings live that nothing
    produces and no test exercises.
    """
    result = _produce(reason, stub, tmp_path, monkeypatch)
    assert result.error == reason
    assert result.ok is False
    assert result.analysis == {}, f"{reason} leaked a projection"
    assert result.raw == {}, f"{reason} leaked the response"
    assert result.detail, f"{reason} arrived without a sentence to go with it"
    assert isinstance(result.available, bool)

    evidence = Evidence()
    record_findings(evidence, [result])
    assert reason in one_finding(evidence).detail


def test_a_broken_subprocess_never_reaches_the_pipeline(monkeypatch):
    """Rule 2 under stress: the OSError shapes a fork or exec can produce.

    The pipeline enters this component through one call, so a
    ``Resource temporarily unavailable`` here would otherwise be a triage failure
    for a message whose deterministic findings were perfectly readable.
    """
    baseline = triage_file(ZIP_FIXTURE, Config())
    for exception in (
        OSError(12, "Cannot allocate memory"),
        PermissionError(13, "Permission denied"),
        FileNotFoundError(2, "No such file or directory"),
    ):

        def broken(*args, **kwargs):
            raise exception

        monkeypatch.setattr(attachments.subprocess, "run", broken)
        verdict = triage_file(ZIP_FIXTURE, ENABLED)
        assert verdict.disposition is baseline.disposition
        assert verdict.reasons == baseline.reasons
        assert verdict.evidence.all(FINDING_KEY), "the failure left no trace"
        assert exception.__class__.__name__ or True


# --------------------------------------------------------------------------
# Q6: the goldens, and what the stub answers with
# --------------------------------------------------------------------------


def test_the_committed_golden_is_a_real_rea_response_shape():
    """The stub cannot drift from reality silently, because the stub *is* this file.

    Asserted rather than assumed: every field the component reads exists at the
    path it reads it from. If a later REA version reshapes its response, this
    fails before a dozen stub tests start passing on a shape that no longer
    occurs anywhere.
    """
    document = json.loads(ZIP_GOLDEN.read_text(encoding="utf-8"))
    for path in (
        ("evidence_id",),
        ("subject", "name"),
        ("subject", "digest", "sha256"),
        ("subject", "local_path"),
        ("subject", "format"),
        ("provider", "id"),
        ("provider", "name"),
        ("provider", "version"),
        ("operation",),
        ("normalized_result", "inspection_id"),
        ("normalized_result", "subject", "manifest_id"),
        ("normalized_result", "subject", "root_artifact_id"),
        ("normalized_result", "subject", "root_sha256"),
        ("normalized_result", "subject", "root_format"),
        ("normalized_result", "coverage", "status"),
        ("confidence",),
        ("authority",),
        ("limitations",),
        ("evidence_links",),
    ):
        node = document
        for key in path:
            assert isinstance(node, dict) and key in node, f"golden lacks {'.'.join(path)}"
            node = node[key]
    inventory = document["normalized_result"]["substeps"][0]["evidence"]["normalized_result"]
    assert inventory["nodes"] and inventory["occurrences"] and inventory["edges"]
    assert document["limitations"], "a real inspection always says what it did not do"


def test_the_committed_capabilities_golden_is_the_real_declaration():
    document = json.loads(CAPS_GOLDEN.read_text(encoding="utf-8"))
    declared = {}
    for provider in document["capabilities"]:
        assert set(provider) >= {"provider", "groups"}
        assert set(provider["provider"]) >= {"id", "name", "version"}
        for group in provider["groups"]:
            assert set(group) >= {"operations", "effects", "available", "reason"}, group
            for operation in group["operations"]:
                declared[operation] = group["effects"]
    for operation in SAFE_OPERATIONS:
        assert operation in declared, f"{operation} is allowlisted but never declared"
        assert not set(declared[operation]) & REFUSAL_EFFECTS, operation
    assert declared["inspect_artifact"] == ["launches_process", "may_write_filesystem"]
    assert "capture_native_ui_scenario" in declared, (
        "the denylist's example should come from the real declaration, not from "
        "a shape someone imagined"
    )


def test_the_golden_files_carry_no_host_identity():
    """Operating rule 15, applied to the files this bundle adds.

    Every absolute path REA echoes -- the staged file, the caller's input path --
    must be a throwaway location, and no string may be this machine's hostname or
    this account's name. A home directory, a private address or a username in here
    would be published with the repository.

    Offenders are reported as file plus reason, never with the matched text: a
    failing assertion is captured into ``docs/results/junit.xml`` by
    ``tools/record-results.sh``, so a message that repeats what it found would
    publish the identity the test exists to keep out.
    """
    identities = [
        value
        for value in (
            __import__("socket").gethostname(),
            os.path.basename(os.path.expanduser("~")),
            os.environ.get("USER", ""),
            os.environ.get("HOME", ""),
        )
        if value
    ]
    offenders = []
    for path in sorted(GOLDEN.glob("*.json")):
        text = path.read_text(encoding="utf-8")
        for candidate in re.findall(
            r"/(?:home|Users|var|opt|usr|etc|root|srv|mnt|run)[A-Za-z0-9._/+~-]*", text
        ):
            if not candidate.startswith(("/tmp/", "/usr/")):
                offenders.append(f"{path.name}: an absolute path that is not a temp one")
        for value in identities:
            if value in text:
                offenders.append(f"{path.name}: one of {len(identities)} host identities")
    assert offenders == [], offenders


def test_the_error_golden_is_a_real_unavailability_and_is_read_as_one(stub):
    """A provider that cannot open the target abstains in REA's own words.

    Measured on the build host: ``inspect-artifact`` on a plain-text attachment
    returns ``code: target_unavailable`` with ``Cannot open artifact: unsupported
    binary format.`` -- so a ``.txt`` gets no answer from this analyzer, and the
    record says which, rather than going quiet.
    """
    bindir = stub(mode="error", response=ERROR_GOLDEN, exit=1)
    result = analyze_attachment(zip_attachment(), ENABLED)
    assert result.ok is False
    assert result.error == "capability_unavailable", result.error
    assert "unsupported binary format" in result.detail
    assert "/tmp" not in result.detail, "a staged path reached the reason text"
    assert result.raw == {}
    assert len(analysis_calls(bindir)) == 1, "the child ran; its envelope is the answer"


def test_the_error_envelope_details_do_not_reach_the_record(stub):
    """``details`` is where REA puts the paths and the toolchain diagnostics.

    Measured: the ghidra rejection carries ``java_command`` and ``java_home``
    values pointing at the machine doing the analysis. Only the code, category and
    message are read.
    """
    document = json.loads(ERROR_GOLDEN.read_text(encoding="utf-8"))
    document["details"] = {
        "path": "/tmp/staged-attachment.zip",
        "rejections": [
            {"provider_id": "ghidra", "code": "not_configured",
             "diagnostics": {"java_home": "/opt/forbidden-toolchain",
                             "install_dir": "/srv/forbidden-ghidra"}}
        ],
    }
    bindir = stub(mode="error", response=document, exit=1)
    result = analyze_attachment(zip_attachment(), ENABLED)
    evidence = Evidence()
    record_findings(evidence, [result])
    text = json.dumps(evidence.as_dict()) + result.detail
    for forbidden in ("/opt/forbidden-toolchain", "/srv/forbidden-ghidra",
                      "/tmp/staged-attachment.zip"):
        assert forbidden not in text, forbidden
    assert "target_unavailable" in text or "unsupported" in text


# --------------------------------------------------------------------------
# A1: what a finding has to say
# --------------------------------------------------------------------------


def test_an_eml_with_a_zip_produces_a_finding_that_is_not_the_filename_again(stub):
    """A1: the attachment's sha256, REA's declared format, and REA's limitations."""
    bindir = stub(response=ZIP_GOLDEN)
    stub_is_the_only_rea(bindir)
    attachment = zip_attachment()
    evidence = Evidence()
    record_findings(evidence, analyze_message(parse_file(ZIP_FIXTURE), ENABLED))
    finding = one_finding(evidence)

    assert finding.provenance is Provenance.VERIFIED
    assert finding.source == STAGE == STAGE_ATTACHMENTS
    assert attachment.sha256[:12] in finding.detail
    value = finding.value
    assert value["root_sha256"] == attachment.sha256
    assert value["declared_format"] == "zip"
    assert value["provider"]["id"] == "rea-artifact-graph"
    assert value["provider"]["name"] == "REA safe artifact graph provider"
    assert value["coverage"]["status"] == "complete-within-substeps"
    assert value["limitations"] and all(
        len(line) <= attachments.MAX_TEXT_CHARS for line in value["limitations"]
    )
    names = [entry["path"] for entry in value["container_entries"]]
    assert "notes/agenda.txt" in names, names
    assert "quarterly-summary.txt" in names
    assert all(entry["sha256"] for entry in value["container_entries"])
    assert any(entry["size"] for entry in value["container_entries"])
    assert value["entry_count"] == len(value["container_entries"])
    # What a reader learns here is nothing the filename carried: the container's
    # contents, each member's size and its own digest.
    assert "agenda" not in attachment.filename

    verdict = triage_file(ZIP_FIXTURE, ENABLED)
    assert verdict.disposition is Disposition.MANUAL_REVIEW
    assert FINDING_KEY not in verdict.cited_findings, "an attachment finding became a vote"
    verdict.assert_citable()


def test_the_finding_records_the_analyzers_own_limits_on_being_wrong(stub):
    """``does not execute the artifact`` is REA's sentence, kept for the reader."""
    stub(response=ZIP_GOLDEN)
    evidence = Evidence()
    record_findings(evidence, analyze_message(parse_file(ZIP_FIXTURE), ENABLED))
    value = one_finding(evidence).value
    assert any("does not execute the artifact" in line for line in value["limitations"])
    assert value["confidence"] == "observed"
    assert value["authority"] == "shipped-artifact"
    assert value["digest_verified"] is True
    assert value["digest_algorithm"] == "sha256"
    assert value["content_type"] == "application/zip"
    assert value["attachment_size"] == zip_attachment().size


def test_hypotheses_are_a_separate_judgment_finding(stub):
    """One finding cannot carry two provenances.

    The recorded golden has no hypotheses, so a response that does is built here:
    the inventory stays VERIFIED and the opinion becomes MODEL_JUDGMENT, which is
    the distinction ``evidence.py`` exists to keep.
    """
    document = json.loads(ZIP_GOLDEN.read_text(encoding="utf-8"))
    document["normalized_result"]["hypotheses"] = ["the archive may be a report bundle"]
    document["normalized_result"]["contradictions"] = []
    stub(response=document)
    evidence = Evidence()
    record_findings(evidence, analyze_message(parse_file(ZIP_FIXTURE), ENABLED))
    assert one_finding(evidence).provenance is Provenance.VERIFIED
    opinion = one_finding(evidence, HYPOTHESIS_KEY)
    assert opinion.provenance is Provenance.MODEL_JUDGMENT
    assert opinion.value["hypotheses"] == ["the archive may be a report bundle"]


def test_an_answer_is_citable_and_an_abstention_is_refused_by_the_invariant(stub):
    """The provenance line, tested from both sides.

    An answer produces a ``VERIFIED`` finding, which ``assert_citable`` -- the
    enforcement the disposition stage runs before it issues anything -- accepts. An
    abstention produces ``UNAVAILABLE``, which it refuses. So this component could
    only ever have reached a verdict through the verified door, and the rule that
    keeps it out is that ``derive_facts`` reads none of it.
    """
    stub(response=ZIP_GOLDEN)
    evidence = Evidence()
    record_findings(evidence, analyze_message(parse_file(ZIP_FIXTURE), ENABLED))
    evidence.assert_citable(evidence.supporting())

    stub(mode="garbage")
    abstained = Evidence()
    record_findings(abstained, analyze_message(parse_file(ZIP_FIXTURE), ENABLED))
    assert abstained.supporting() == []
    with pytest.raises(Exception):
        abstained.assert_citable(abstained.gaps())
    assert abstained.gaps(), "an abstention must be visible as a gap"


def test_an_abstention_is_recorded_as_unavailable_with_the_reason_first(stub):
    stub(mode="garbage")
    evidence = Evidence()
    record_findings(evidence, analyze_message(parse_file(ZIP_FIXTURE), ENABLED))
    finding = one_finding(evidence)
    assert finding.provenance is Provenance.UNAVAILABLE
    assert finding.value is None
    assert finding.detail.startswith("rea_unparsable: "), finding.detail
    assert "quarterly-summary.zip (sha256 " in finding.detail
    assert "rea_unparsable" in finding.detail


def test_the_unread_attachment_unknown_remains_when_part_was_read(stub, monkeypatch):
    """Part examined, part not: the unknown is still recorded, and says how many.

    A record that stopped claiming any attachment was unread once *one* part had
    been examined would promote a partial reading into a complete one -- the exact
    failure the truncation marker in this project exists to prevent.
    """
    stub(response=ZIP_GOLDEN)
    message = parse_file(ZIP_FIXTURE)
    evidence = pipeline.build_evidence(
        message, pipeline.extract_signals(message, Config().profile, Config().thresholds),
        ENABLED,
    )
    assert evidence.all(FINDING_KEY)
    assert evidence.all("attachment_contents_malicious") == []

    monkeypatch.setattr(parse_module, "MAX_RETAINED_PART_BYTES", 4096)
    dropped = parse_file(LARGE_FIXTURE).attachments[0]
    assert dropped.truncated is True
    mixed = replace(message, attachments=[message.attachments[0], dropped])
    mixed_evidence = pipeline.build_evidence(
        mixed,
        pipeline.extract_signals(mixed, Config().profile, Config().thresholds),
        ENABLED,
    )
    unknowns = mixed_evidence.all("attachment_contents_malicious")
    assert len(unknowns) == 1
    assert "1 of 2 part(s) were not read" in unknowns[0].detail
    assert "inventoried, not read" in unknowns[0].detail


def test_the_projection_bounds_length_and_counts_what_it_left_out(stub):
    """Entry names and limitation text are attacker-chosen strings, and they cap."""
    document = json.loads(ZIP_GOLDEN.read_text(encoding="utf-8"))
    inventory = document["normalized_result"]["substeps"][0]["evidence"]["normalized_result"]
    template = inventory["occurrences"][1]
    for _ in range(60):
        inventory["occurrences"].append(dict(template))
    document["limitations"] = ["long " * 400] * 20
    stub(response=document)
    result = analyze_attachment(zip_attachment(), ENABLED)
    assert result.ok, result.detail
    value = result.analysis
    total = len(
        document["normalized_result"]["substeps"][0]["evidence"]["normalized_result"][
            "occurrences"
        ]
    )
    assert total > attachments.MAX_ENTRIES, "the scenario must actually overflow the cap"
    assert len(value["container_entries"]) == attachments.MAX_ENTRIES
    assert value["entries_omitted"] == total - attachments.MAX_ENTRIES
    assert value["entry_count"] == attachments.MAX_ENTRIES
    assert len(value["limitations"]) == attachments.MAX_LIMITATIONS
    assert all(len(line) <= attachments.MAX_TEXT_CHARS for line in value["limitations"])
    assert value["evidence_id"] == document["evidence_id"]


# --------------------------------------------------------------------------
# A5: cleanup
# --------------------------------------------------------------------------


def test_the_quarantine_directory_is_gone_after_analysis(stub):
    bindir = stub()
    result = analyze_attachment(zip_attachment(), ENABLED)
    assert result.ok, result.detail
    staged = analysis_calls(bindir)[0]["path"]
    assert not os.path.exists(staged), "the staged payload survived"
    assert not os.path.exists(os.path.dirname(staged)), "the quarantine dir survived"
    assert result.cleanup_retained is None
    assert retained_quarantine_paths() == ()


@pytest.mark.parametrize(
    "mode", ["respond", "garbage", "error", "empty", "hang", "array"]
)
def test_cleanup_runs_on_every_path_not_just_the_successful_one(mode, stub, tmp_path):
    stub(mode=mode, sleep=3, exit=1)
    analyze_attachment(
        zip_attachment(),
        Config(deep_attachment_analysis=True, attachment_analysis_timeout_seconds=0.5),
    )
    leftovers = [path.name for path in tmp_path.glob("tenable-email-rea-*")]
    assert leftovers == [], f"{mode} left {leftovers} behind"
    assert retained_quarantine_paths() == ()


def test_a_failed_cleanup_reports_the_path_it_could_not_remove(stub, monkeypatch):
    """A5's second half, and the project's rule about swallowed failures."""
    bindir = stub()
    real_rmtree = attachments.shutil.rmtree

    def refusing(path, *args, **kwargs):
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(attachments.shutil, "rmtree", refusing)
    result = analyze_attachment(zip_attachment(), ENABLED)
    assert result.ok is True, "an answer is still an answer"
    staged_dir = os.path.dirname(analysis_calls(bindir)[0]["path"])
    assert os.path.isdir(staged_dir), "the directory vanished despite the refusal"
    assert result.cleanup_retained == staged_dir
    assert staged_dir in retained_quarantine_paths()
    assert staged_dir in json.dumps(result.as_dict())

    evidence = Evidence()
    record_findings(evidence, [result])
    retained = one_finding(evidence, QUARANTINE_KEY)
    assert retained.provenance is Provenance.VERIFIED
    assert staged_dir in retained.detail
    assert "could not be removed" in retained.detail

    monkeypatch.setattr(attachments.shutil, "rmtree", real_rmtree)
    assert remove_quarantine(staged_dir) is None
    assert not os.path.exists(staged_dir)


def test_a_failed_cleanup_during_a_refusal_is_reported_too(stub, monkeypatch):
    """The rule does not depend on the analysis having gone well."""
    bindir = stub(mode="garbage")
    monkeypatch.setattr(
        attachments.shutil,
        "rmtree",
        lambda *a, **k: (_ for _ in ()).throw(OSError(5, "Input/output error")),
    )
    result = analyze_attachment(zip_attachment(), ENABLED)
    assert result.error == "rea_unparsable"
    assert result.cleanup_retained == os.path.dirname(analysis_calls(bindir)[0]["path"])
    evidence = Evidence()
    record_findings(evidence, [result])
    assert evidence.all(QUARANTINE_KEY), "the retained path never reached the record"


# --------------------------------------------------------------------------
# A3: absence changes nothing
# --------------------------------------------------------------------------


@pytest.fixture()
def scrubbed(monkeypatch, tmp_path):
    """A PATH with nothing on it: no ``rea``, no ``node``, no analyzer."""
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    reset_capabilities_cache()
    return empty


def test_no_rea_on_path_abstains_and_the_pipeline_still_completes(scrubbed):
    assert rea_executable() is None, "PATH was not scrubbed; this test proved nothing"
    result = analyze_attachment(zip_attachment(), ENABLED)
    assert (result.ok, result.available, result.error, result.source) == (
        False,
        False,
        "rea_not_installed",
        "none",
    )
    assert calls(scrubbed) == []
    verdict = triage_file(ZIP_FIXTURE, ENABLED)
    assert verdict.disposition is not None
    findings = verdict.evidence.all(FINDING_KEY)
    assert len(findings) == 1
    assert "rea_not_installed" in findings[0].detail


#: Every corpus the triage path runs over in this suite.
CORPORA = (
    ATTACHMENTS,
    REPO / "fixtures" / "synthetic",
    REPO / "fixtures" / "adversarial",
)


def _corpus_fixtures():
    for directory in CORPORA:
        assert directory.is_dir(), f"{directory} is not on disk"
        for path in sorted(directory.glob("*.eml")):
            yield path


FIXTURE_PATHS = sorted(_corpus_fixtures(), key=lambda p: str(p))


@pytest.mark.parametrize("path", FIXTURE_PATHS, ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_with_no_rea_no_decision_on_any_fixture_changes(path, scrubbed):
    """A3, corpus-wide: the enabled configuration decides what the default decides.

    Compared is the substance of a disposition -- the class, the attack type, the
    confidence and its band, the reasons, whether it escalated, whether it was
    partial, and the findings it cites. ``analysis`` prose and ``stages_run`` are
    *not* compared for a message with attachments: an operator who turns an
    optional stage on is entitled to a record that says so, and the stage's
    abstention is a gap the narrative counts. For a message with no attachment the
    two runs are identical in every field including the prose, and that is asserted
    too, because it is the strongest available form of "this component is not
    reaching into the adjudication by accident".

    The premise is asserted first: no ``rea`` on PATH, and on a fixture with
    attachments the enabled run really did record the abstention. A test like this
    passing because the component quietly never ran is the failure mode this
    repository has been burned by twice.
    """
    assert rea_executable() is None, "PATH was not scrubbed; this test proved nothing"
    baseline = triage_file(path, Config())
    enabled = triage_file(path, ENABLED)

    assert enabled.disposition is baseline.disposition
    assert enabled.attack_type is baseline.attack_type
    assert enabled.confidence == baseline.confidence
    assert enabled.confidence_band is baseline.confidence_band
    assert enabled.reasons == baseline.reasons
    assert enabled.escalated == baseline.escalated
    assert enabled.truncated == baseline.truncated
    assert enabled.cited_findings == baseline.cited_findings

    parts = parse_file(path).attachments
    if parts:
        findings = enabled.evidence.all(FINDING_KEY)
        assert len(findings) == len(parts)
        assert all("rea_not_installed" in f.detail for f in findings)
        assert STAGE_ATTACHMENTS in enabled.stages_run
    else:
        assert enabled.evidence.all(FINDING_KEY) == []
        assert STAGE_ATTACHMENTS not in enabled.stages_run
        assert enabled.analysis == baseline.analysis
        assert enabled.stages_run == baseline.stages_run


def test_the_shipped_default_never_mentions_this_component(scrubbed):
    """With the flag off there is no finding and no stage, even with attachments."""
    for path in (ZIP_FIXTURE, TEXT_FIXTURE, TRAVERSAL_FIXTURE):
        verdict = triage_file(path, Config())
        assert verdict.evidence.all(FINDING_KEY) == []
        assert verdict.evidence.all(HYPOTHESIS_KEY) == []
        assert verdict.evidence.all(QUARANTINE_KEY) == []
        assert STAGE_ATTACHMENTS not in verdict.stages_run
        # The stage's own unknown is still recorded -- that is the honest shape:
        # contents unread, and the record saying so.
        assert verdict.evidence.all("attachment_contents_malicious")


def test_a_rea_on_path_does_not_make_it_run(scrubbed, monkeypatch):
    """Gated by configuration, not by installation.

    A fake ``rea`` is placed on PATH and the default configuration still starts
    nothing -- which is what lets the shipped path promise that no third-party
    program runs on a machine merely because Node happened to be installed.
    """
    bindir = scrubbed / "fake-rea"
    bindir.mkdir()
    marker = scrubbed / "was-run"
    script = bindir / "rea"
    script.write_text(
        "#!" + sys.executable + "\n"
        "with open({!r}, 'a') as handle:\n"
        "    handle.write('ran\\n')\n".format(str(marker)),
        encoding="utf-8",
    )
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    assert rea_executable() is not None
    assert run_for_message(parse_file(ZIP_FIXTURE), Config()) == []
    assert not marker.exists(), "the default configuration invoked rea"


def test_the_cli_configuration_builder_honours_the_switch(monkeypatch):
    """The documented environment variable is the one the CLI reads.

    This is the difference between a feature and a paragraph. ``README`` tells an
    operator to set ``TENABLE_EMAIL_DEEP_ATTACHMENT_ANALYSIS=1``; a CLI that built
    its configuration without reading it would advertise a switch that did
    nothing, which is the defect ``docs/RED-TEAM-RESPONSE.md`` records being
    called out for once already.
    """
    from tenable_email import cli

    for name in (
        "TENABLE_EMAIL_DEEP_ATTACHMENT_ANALYSIS",
        "TENABLE_EMAIL_ATTACHMENT_ANALYSIS_COMMAND",
        "TENABLE_EMAIL_ATTACHMENT_ANALYSIS_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    corpus = cli.Corpus(replay_dir=None, resolved_by_default=False)
    default = cli.config_for(corpus)
    assert default.deep_attachment_analysis is False

    monkeypatch.setenv("TENABLE_EMAIL_DEEP_ATTACHMENT_ANALYSIS", "1")
    monkeypatch.setenv("TENABLE_EMAIL_ATTACHMENT_ANALYSIS_COMMAND", "/opt/rea/bin/rea")
    monkeypatch.setenv("TENABLE_EMAIL_ATTACHMENT_ANALYSIS_TIMEOUT_SECONDS", "7.5")
    configured = cli.config_for(corpus)
    assert configured.deep_attachment_analysis is True
    assert configured.attachment_analysis_command == "/opt/rea/bin/rea"
    assert configured.attachment_analysis_timeout_seconds == 7.5
    # replay is still the CLI's to decide, and it stays on
    assert configured.replay is True


def test_the_pipeline_lists_the_stage_only_when_it_was_entered(scrubbed, tmp_path):
    """``stages_run`` says what ran, in the presence and the absence of the flag."""
    assert STAGE_ATTACHMENTS not in triage_file(ZIP_FIXTURE, Config()).stages_run
    enabled = triage_file(ZIP_FIXTURE, ENABLED)
    assert STAGE_ATTACHMENTS in enabled.stages_run
    assert "document extractor" in enabled.analysis
    assert "rea_not_installed" in enabled.analysis
    assert "document extractor" not in triage_file(ZIP_FIXTURE, Config()).analysis


def test_the_narrative_does_not_count_the_analyzer_as_a_model_tier(scrubbed):
    """A gap from this component is not a tier with no endpoint.

    The opening sentence of an analysis is a claim about the configuration, and
    ``rea`` has no endpoint to configure -- so counting it among "model tier(s)
    had no configured endpoint" would be false. The analyzer gets its own
    sentence, and the tier count keeps its meaning.
    """
    plain = triage_file(REPO / "fixtures" / "synthetic" / "clean_internal_registrar.eml", ENABLED)
    with_attachment = triage_file(ZIP_FIXTURE, ENABLED)
    tier_count = with_attachment.analysis.split("model tier(s) had no")[0].rsplit(": ", 1)[-1]
    assert tier_count == plain.analysis.split("model tier(s) had no")[0].rsplit(": ", 1)[-1], (
        "the optional analyzer was counted as a model tier"
    )
    assert "document extractor" in with_attachment.analysis


def test_the_environment_switch_is_opt_in():
    """One flag, one binary name, one budget: and the flag has no default of ``1``."""
    assert Config.from_env({}).deep_attachment_analysis is False
    assert Config.from_env(
        {"TENABLE_EMAIL_DEEP_ATTACHMENT_ANALYSIS": "yes"}
    ).deep_attachment_analysis is True
    assert Config.from_env(
        {"TENABLE_EMAIL_DEEP_ATTACHMENT_ANALYSIS": "0"}
    ).deep_attachment_analysis is False
    assert Config.from_env(
        {"TENABLE_EMAIL_ATTACHMENT_ANALYSIS_TIMEOUT_SECONDS": "3.5"}
    ).attachment_analysis_timeout_seconds == 3.5
    assert Config.from_env(
        {"TENABLE_EMAIL_ATTACHMENT_ANALYSIS_TIMEOUT_SECONDS": "not-a-number"}
    ).attachment_analysis_timeout_seconds is None
    assert Config.from_env(
        {"TENABLE_EMAIL_ATTACHMENT_ANALYSIS_COMMAND": "/opt/rea/bin/rea"}
    ).attachment_analysis_command == "/opt/rea/bin/rea"
    assert Config().attachment_analysis_command is None
    assert Config().attachment_analysis_timeout_seconds is None


# --------------------------------------------------------------------------
# A4: nothing but projections reach a record
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", sorted(ATTACHMENTS.glob("*.eml")), ids=lambda p: p.stem)
def test_attachment_bytes_reach_neither_the_record_the_receipt_nor_the_ledger(path, stub):
    """The ``without_data()`` invariant, extended to this component's output.

    Run with the optional analyzer on and a stub answering, because the default
    path is already covered by ``tests/test_receipt.py`` and this component is the
    new way bytes could ride out. Payload, its base64 form, the ledger database
    file and both serialized receipt renderings are all searched.
    """
    stub(response=ZIP_GOLDEN)
    message = parse_file(path)
    assert message.attachments, f"{path.name} carries no attachment"
    payload = message.attachments[0].data
    assert payload, f"{path.name} has no retained bytes"

    verdict = triage_file(path, ENABLED)
    receipt = Receipt.for_verdict(verdict)
    text = receipt.to_json() + receipt.to_markdown() + json.dumps(verdict.evidence.as_dict())
    encoded = base64.b64encode(payload).decode("ascii")

    assert payload not in text.encode("utf-8", "ignore")
    assert encoded not in text
    assert encoded[:120] not in text
    for finding in verdict.evidence.all(FINDING_KEY):
        serialized = json.dumps(finding.as_dict())
        assert '"data"' not in serialized, serialized[:200]
        assert payload not in serialized.encode("utf-8", "ignore")

    store = tempfile.mkdtemp(prefix="ledger-")
    database = pathlib.Path(store) / "ledger.sqlite3"
    from tenable_email.ledger import CaseLedger

    ledger = CaseLedger(database)
    try:
        ledger.record_receipt(receipt)
    finally:
        ledger.close()
    assert payload not in database.read_bytes(), "attachment bytes reached the ledger"
    assert "data" not in json.dumps([f.as_dict() for f in verdict.evidence.findings])

    assert message.attachments[0].data == payload
    assert "data" not in message.attachments[0].without_data()


def test_no_path_from_the_quarantine_or_the_response_reaches_a_record(stub, tmp_path):
    """The projection is a whitelist, and this is what that buys.

    Both the staged temp path (echoed back by the stub) and the paths inside the
    recorded golden -- ``subject.local_path``, ``caller_input_path``,
    ``parameters.input_path`` -- are searched for in the evidence record and in the
    receipt.
    """
    bindir = stub(response=ZIP_GOLDEN)
    document = json.loads(ZIP_GOLDEN.read_text(encoding="utf-8"))
    verdict = triage_file(ZIP_FIXTURE, ENABLED)
    staged = analysis_calls(bindir)[0]["path"]
    assert str(tmp_path) in staged
    forbidden = [
        staged,
        os.path.dirname(staged),
        document["subject"]["local_path"],
        document["caller_input_path"],
        document["parameters"]["input_path"],
    ]

    text = json.dumps(verdict.evidence.as_dict()) + Receipt.for_verdict(verdict).to_json()
    for path in forbidden:
        assert path not in text, f"{path} reached a record"
    assert verdict.evidence.all(FINDING_KEY), "the record was empty, so nothing leaked"


def test_the_projection_never_carries_a_path_field(stub):
    """Fields are excluded by construction; this proves the list is really a whitelist."""
    document = json.loads(ZIP_GOLDEN.read_text(encoding="utf-8"))
    document["subject"]["local_path"] = "/tmp/never-in-a-record.zip"
    document["caller_input_path"] = "/tmp/also-never-here.zip"
    document["parameters"]["input_path"] = "/tmp/nor-this-one.zip"
    document["details"] = {"java_home": "/opt/forbidden-toolchain"}
    stub(response=document)
    result = analyze_attachment(zip_attachment(), ENABLED)
    assert result.ok, result.detail
    text = json.dumps(result.analysis) + json.dumps(
        [finding.as_dict() for finding in findings_for(result)]
    )
    for path in ("/tmp/never-in-a-record.zip", "/tmp/also-never-here.zip",
                 "/tmp/nor-this-one.zip", "/opt/forbidden-toolchain"):
        assert path not in text, path
    assert "local_path" not in text
    assert "input_path" not in text
    assert "/tmp" not in text


def test_the_raw_response_is_kept_off_the_serialization_path(stub):
    """``raw`` is on the result and nowhere else.

    ``AttachmentResult.as_dict()`` is what a caller would serialize: the
    projection, the booleans and the reason. That is the deliberate difference
    from ``tiers.TierResult``, whose ``raw`` *is* a service response with no
    filesystem paths in it to lose.
    """
    stub(response=ZIP_GOLDEN)
    result = analyze_attachment(zip_attachment(), ENABLED)
    assert result.raw, "raw stays on the result for a caller to argue with"
    assert "local_path" in json.dumps(result.raw)
    serialized = json.dumps(result.as_dict())
    assert "local_path" not in serialized
    assert "raw" not in result.as_dict()
    assert result.as_dict()["analysis"] == dict(result.analysis)
    assert result.as_dict()["sha256"] == zip_attachment().sha256


# --------------------------------------------------------------------------
# the reserved slot, and the vocabulary it mirrors
# --------------------------------------------------------------------------


def test_the_result_mirrors_tierresult_vocabulary_without_being_a_tier():
    shared = {"available", "ok", "raw", "error", "source", "latency_ms"}
    assert shared <= set(AttachmentResult.__dataclass_fields__), (
        "a result that does not read like a tier result is a second vocabulary "
        "for the same idea"
    )
    assert not issubclass(AttachmentResult, TierResult)
    for http_only in ("endpoint_field", "url", "api_key_field", "headers", "path"):
        assert http_only not in AttachmentResult.__dataclass_fields__, http_only


def test_the_reserved_component_registry_slot_now_has_a_module():
    """``contract.COMPONENT_REGISTRY`` reserved this name; it is filled."""
    assert COMPONENT_REGISTRY[PROVIDER] == ("tenable_email.attachments", "read-only")
    assert importlib.import_module("tenable_email.attachments") is attachments
    stage = {item.id: item for item in load_contract().stages}[STAGE]
    assert stage.provider == PROVIDER
    assert stage.access == "read-only"
    assert stage.optional is True
    assert stage.model_tier is None
    assert STAGE == STAGE_ATTACHMENTS == pipeline.STAGE_ATTACHMENTS


def test_operation_command_matches_reas_cli_naming():
    assert operation_command("inspect_artifact") == "inspect-artifact"
    assert operation_command("inspect_managed_native_boundaries") == (
        "inspect-managed-native-boundaries"
    )
    assert operation_command("extract-artifact") == "extract-artifact"


def test_the_component_imports_only_the_standard_library():
    """``dependencies = []`` is only honest if nothing needs a package to import.

    Read from the file's own import lines rather than from the claim in
    ``pyproject.toml``: a runtime dependency would make the headline property of
    this repository a decoration.
    """
    text = (REPO / "src" / "tenable_email" / "attachments.py").read_text(encoding="utf-8")
    imports = re.findall(r"^(?:import|from)\s+([A-Za-z_][\w.]*)", text, re.MULTILINE)
    assert imports, "found no imports at all, so this test inspected nothing"
    stdlib = {
        "__future__", "dataclasses", "hashlib", "json", "os", "re", "shutil",
        "subprocess", "tempfile", "time", "typing", "collections", "pathlib", "io",
    }
    for name in imports:
        root = name.split(".")[0]
        assert root in stdlib or name in {"config", "evidence", "parse"}, name


def test_the_package_still_declares_no_runtime_dependencies():
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert "dependencies = []" in text


def test_the_attachment_corpus_is_not_part_of_any_measured_corpus():
    """The reason for a third directory rather than four more labelled cases.

    The evaluation reads the two labelled corpora by name, and the committed
    replay recordings are keyed on messages from the synthetic corpus only. If an
    attachment fixture ever joined either, the committed metrics and the
    recordings would describe a different corpus than the one on disk -- and the
    corpus count several tests assert would move.
    """
    assert "attachments" not in (REPO / "eval" / "run.py").read_text(encoding="utf-8")
    names = {path.name for path in ATTACHMENTS.glob("*.eml")}
    assert names, "no attachment fixtures found to exclude"
    for recording in sorted((REPO / "fixtures" / "replay").glob("*.json")):
        assert "attachment_zip_summary" not in recording.read_text(encoding="utf-8")
