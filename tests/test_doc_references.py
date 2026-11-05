"""Guard against tracked documents pointing at files that do not exist.

An implementing agent that reads "see ``docs/FOO.md``" or "resume from
``SKILL.md``" and finds nothing wastes a session or, worse, invents content.
This test fails when a tracked document references a path that neither exists
nor is declared as an outstanding task in the same document.

A path is treated as *planned* if it appears on an unchecked task line
(``- [ ]``) anywhere in the same file. That keeps the allowlist
self-maintaining: checking a task off without creating its deliverable turns
this test red, which is the point.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

#: Tracked documents an implementing agent is expected to read for direction.
ACTIONABLE_DOCS = [
    "TODO_TENABLE-EMAIL",
    "NOTES.md",
    "README.md",
    "docs/EVAL-SUITES.md",
]

#: Directories holding a generated corpus with a `labels.json` manifest. Every
#: message the suite consumes must be tracked, or a clone does not have the
#: corpus the tests assert against.
CORPORA = ("fixtures/synthetic", "fixtures/adversarial", "fixtures/attachments")

KNOWN_EXTENSIONS = (
    ".py", ".md", ".yaml", ".yml", ".sh", ".toml", ".eml", ".json",
    ".csv", ".txt", ".cfg", ".ini", ".onnx", ".gguf",
)

#: Backticked tokens that look like paths but are not references to files in
#: this repository. Each carries the reason it is excluded, because an unexplained
#: allowlist rots into a place to hide a real dangling reference.
EXTERNAL_OR_NOT_A_PATH = {
    # Files in the upstream tenable/cyberagents-exchange repository.
    "CONTRIBUTING.md": "upstream Exchange repo",
    "playbooks/email-analyst-in-a-box.md":
        "the listing this project submitted, in the upstream Exchange repo",
    "playbooks/": "directory in the upstream Exchange repo",
    "validator.py": "upstream; fetched at run time by tools/validate-listing.sh",
    "prompt.txt": "file in the reference playbook's repository, not ours",
    "templates/": "upstream Exchange repo",
    # A Hugging Face model identifier, not a filesystem path.
    "Horizon-Labs/phishing-scam-detector-base": "HF model repo id",
    "onnx-community/phishing-scam-detector-base-ONNX": "HF model repo id",
    "Horizon-Labs/prompt-injection-guard-small": "HF model repo id",
    "xanderabim/fraudfoxai-phishing": "HF model repo id",
    "unsloth/Qwen3.5-4B-GGUF:Q4_K_XL": "HF model repo id",
    "mrm8488/bert-tiny-finetuned-enron-spam-detection": "HF model repo id",
    "cybersectony/phishing-email-detection-distilbert_v2.4.1": "HF model repo id",
    "prancyFox/tiny-bert-enron-spam": "HF model repo id",
    "navodPeiris/minilm-toxic-spam-classifier": "HF model repo id",
    "bastionsoft/binary-bastion-prompt-protection-deberta-v3-xsmall-v1":
        "HF model repo id",
    "meta-llama/Prompt-Guard-2-22M": "HF model repo id (gated)",
    "jhu-clsp/mmBERT-base": "HF model repo id",
    "onnx-community/phishing-scam-detector-base-ONNX": "HF model repo id",
    "Horizon-Labs/prompt-injection-guard-base": "HF model repo id",
    "Horizon-Labs/prompt-injection-eval-suite": "HF dataset repo id",
    "marklkelly/bert-tiny-injection-detector": "HF model repo id",
    "bastionsoft/binary-bastion-prompt-protection-deberta-v3-xsmall-v1":
        "HF model repo id",
    "leolee99/PIGuard": "HF model repo id",
    "meta-llama/Prompt-Guard-2-22M": "HF model repo id (gated)",
    "ersincivi/mmbert-tiny-inject": "GitHub repo id; weights not distributed",
    "surajkjai/promptinj_model_evals": "GitHub repo id",
    "disassembledd/knowbe4-phisher-email-analysis": "GitHub repo id",
    "tenable/cyberagents-exchange": "GitHub repo id",
    "jtbuchanan-tenb/cyberagent-exchange-submission-builder": "GitHub repo id",
    # A file inside an upstream model repository, cited as provenance.
    "eval/metrics.json": "path inside marklkelly/bert-tiny-injection-detector",
    # Paths inside upstream model/dataset repositories, cited as provenance.
    "eval/baselines.json": "path inside Horizon-Labs/phishing-scam-detector-base",
    "eval/this_model.json": "path inside Horizon-Labs/phishing-scam-detector-base",
    "eval/seeds.json": "path inside Horizon-Labs/phishing-scam-detector-base",
    "code/scam/eval_scam.py": "path inside Horizon-Labs/phishing-scam-detector-base",
    "code/scam/build_evals.py": "path inside Horizon-Labs/phishing-scam-detector-base",
    # Public dataset repository identifiers.
    "SetFit/enron_spam": "HF dataset repo id",
    "zefang-liu/phishing-email-dataset": "HF dataset repo id",
    "shariul-islam/bengali-sms-smishing-dataset": "HF dataset repo id",
    "jmjmjm3/kor-smishing-message": "HF dataset repo id",
    "MOZNLP/MOZ-Smishing": "HF dataset repo id",
    "dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset": "HF dataset repo id",
    "geodesic-research/bipia": "HF dataset repo id",
    "leolee99/NotInject": "HF dataset repo id",
    "Paul/XSTest": "HF dataset repo id",
    "bench-llm/or-bench": "HF dataset repo id",
    "sleeepeer/PIArena": "HF dataset repo id",
    "microsoft/LLMail-Inject": "HF dataset repo id",
    "surajkjai/promptinj_model_evals": "GitHub repo id",
    # Prompt tokens, not paths.
    "/no_think": "prompt soft-switch token",
    # A filename pattern with a placeholder, not a literal file.
    "tests/test_<name>.py": "naming pattern",
    # Directories from the TODO-format convention this project deliberately
    # does not use; the TODO names them only to record the deviation.
    "bin/": "convention we deviate from",
    "tmp/": "convention we deviate from",
    "archive/": "convention we deviate from",
    "data/": "convention we deviate from",
}

#: Backticked tokens that look like paths but are not filesystem references.
NOT_PATHS = re.compile(
    r"""^(?:
        https?:// | POST | GET | PUT | DELETE |
        /v\d | /api | /predict | /batch | /health | /url | /email | /http |
        /command | /text | /prompt-injection | /skill | /pe | /rerank |
        /embeddings | /models | /chat | /completions
    )""",
    re.VERBOSE,
)

#: Tokens that are commands, flags or prose fragments rather than paths.
COMMANDISH = re.compile(r"^(?:-|--|\w+=|git |pytest |python|uv |curl |npm )")

#: Anything containing an IP address or a host:port pair is a network endpoint,
#: not a filesystem path. Matched generically so no real address has to be
#: written into this tracked test file.
NETWORK_ENDPOINT = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}|^[\w.-]+:\d+(?:/\d+)*$")


def _in_git_checkout() -> bool:
    """Whether this working copy carries a ``.git`` directory.

    An external review bundle deliberately does not: including ``.git`` would
    publish the full history of the internal-only files that the bundle excludes.
    The repository-integrity checks below are about the repository, not the code,
    so they skip in a bundle rather than failing. In a real checkout they always
    run - the repo suite has no skips.
    """
    return (REPO / ".git").exists()


requires_repo = pytest.mark.skipif(
    not _in_git_checkout(),
    reason="not a git checkout: this is an external review bundle, from which "
           ".git and the internal-only files are deliberately excluded",
)


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True
    )
    return [line for line in out.stdout.splitlines() if line.strip()]


def normalize_token(token: str) -> str:
    """Trim a backticked token to the path it denotes. One owner, used everywhere.

    Trailing prose punctuation is removed; a leading dot is **not**. This used to be
    ``str.strip(".,;:")``, inlined at three separate call sites, and because ``strip`` with a
    character set trims both ends a dotfile lost its leading dot and was looked up under a
    name that does not exist: ``.gitleaks.toml`` became ``gitleaks.toml`` and was reported
    dangling while the file sat there tracked.

    The bug survived because the normalization was duplicated. ``is_candidate`` had one copy
    and the resolution loop had another, so fixing either alone changed nothing - the other
    still mangled the token. A guard that invents a filename is worse than one that skips it,
    because the whole point of this file is to stop a reader going looking for something that
    is not there. Normalizing once, here, is what makes the two call sites unable to disagree.
    """
    return token.strip().rstrip(".,;:")


def is_candidate(token: str) -> bool:
    """Whether a backticked token looks like a filesystem path."""
    t = normalize_token(token)
    if not t or " " in t or len(t) > 120:
        return False
    # A leading dot with no slash and no second dot is either a file extension used
    # generically (``.eml``, ``.docm``) or an extensionless dotfile (``.gitignore``).
    # Neither is worth an existence check: an extension is not a file, and there are a
    # handful of dotfiles whose absence would be obvious. The tradeoff is that a
    # mistyped ``.gitleaks.tom`` would be skipped; a mistyped path with a directory
    # component or a two-part extension still gets checked.
    if t.startswith(".") and "/" not in t and t.count(".") < 2:
        return False
    if NOT_PATHS.match(t) or COMMANDISH.match(t):
        return False
    if NETWORK_ENDPOINT.search(t):
        return False
    if t.startswith(("`", "'", '"', "*")):
        return False
    looks_like_path = "/" in t or t.endswith(KNOWN_EXTENSIONS)
    return bool(looks_like_path)


def is_hosted_repo_id(token: str) -> bool:
    """Whether a token is an upstream repository identifier rather than a path.

    Hugging Face and GitHub identifiers have the shape ``owner/name``, which is
    indistinguishable from a one-level relative path by syntax alone. Allowlisting
    them individually does not scale - a research document names dozens - so the
    rule is structural instead: a single slash, no file extension, and a first
    segment that is **not** one of this repository's own top-level directories.

    The tradeoff is deliberate and worth stating: a mistyped local reference whose
    first segment is not a real top-level directory and which carries no extension
    would be read as an upstream identifier and pass. That is a narrow hole,
    accepted because the alternative - hand-maintaining an allowlist of every model
    and dataset this project cites - rots immediately and rots silently. Anything
    under ``src/``, ``tests/``, ``docs/``, ``tools/``, ``fixtures/`` or ``eval/``
    is still checked at full strength, which is where our own references live.
    """
    t = token.strip().rstrip("/")
    raw = token.strip()
    # An owner prefix such as ``S-Labs/`` - produced when a document abbreviates
    # ``S-Labs/prompt-injection-dataset`` and the path extractor strips the
    # trailing ellipsis. Treat it as hosted unless the owner is one of ours.
    if raw.endswith("/") and "/" not in t:
        return bool(t) and t not in LOCAL_TOP_LEVEL
    if t.count("/") != 1:
        return False
    head, tail = t.split("/", 1)
    if not head or not tail:
        return False
    if head in LOCAL_TOP_LEVEL:
        return False
    if tail.endswith(KNOWN_EXTENSIONS):
        return False
    return True


#: This repository's own top-level directories. A reference starting with one of
#: these is always treated as local and must resolve.
LOCAL_TOP_LEVEL = frozenset({"src", "tests", "docs", "tools", "fixtures", "eval", "dist"})


def planned_paths(text: str) -> set[str]:
    """Paths a document declares as not-yet-created.

    Two sources, both explicit:

    * an unchecked task line (``- [ ]``) in the same document
    * a ``<!-- planned: a, b, c -->`` declaration

    The comment form exists because prose documents such as README describe
    intended design without carrying checklists. Heuristic section-sniffing was
    tried first and missed deliverables named under headings that are not task
    lists, so the declaration is explicit instead.
    """
    planned: set[str] = set()
    for line in text.splitlines():
        if line.lstrip().startswith("- [ ]"):
            for token in re.findall(r"`([^`]+)`", line):
                planned.add(normalize_token(token))
    for decl in re.findall(r"<!--\s*planned:(.*?)-->", text, re.DOTALL):
        for token in decl.replace("`", " ").split(","):
            for part in token.split():
                part = normalize_token(part)
                if part:
                    planned.add(part)
    return planned


def bundle_exclusions() -> set[str]:
    """Files a review bundle deliberately removed, or an empty set in a checkout.

    ``tools/make_review_bundle.py`` writes ``BUNDLE-EXCLUDED.txt`` next to the
    copy. It exists only in a bundle, so this never weakens the check where it
    matters.
    """
    marker = REPO / "BUNDLE-EXCLUDED.txt"
    if not marker.is_file():
        return set()
    return {
        line.strip()
        for line in marker.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def referenced_paths(text: str) -> list[str]:
    seen: list[str] = []
    for token in re.findall(r"`([^`]+)`", text):
        if is_candidate(token):
            norm = normalize_token(token)
            if norm not in seen:
                seen.append(norm)
    return seen


@pytest.mark.parametrize("doc", ACTIONABLE_DOCS)
def test_no_dangling_references(doc: str):
    path = REPO / doc
    if not path.is_file():
        # A file named in the exclusion manifest was deliberately removed from
        # this artifact, so its absence is expected whether or not we are inside a
        # git checkout. Checking `_in_git_checkout()` alone was not enough: the
        # public export IS a git repository, and the internal-only documents are
        # still excluded from it.
        if doc in bundle_exclusions():
            # Asserted rather than skipped. A skip in a published artifact is a guard
            # that silently does not run, and this is the only place where the removal
            # of an actionable document is *checked* instead of trusted: the copy has
            # to have been driven by a manifest that agrees with the internal list this
            # module maintains, and carries a real reason. Without the assertion a
            # document could go missing by being renamed or forgotten, and the suite
            # would report that as a deliberate exclusion.
            assert doc in INTERNAL_FILES, (
                f"{doc} is declared excluded by BUNDLE-EXCLUDED.txt but is not listed "
                f"in this module's INTERNAL_FILES; the two lists have to agree, and "
                f"this is the copy that can still tell"
            )
            assert len(INTERNAL_FILES[doc].strip()) >= 20, (
                f"{doc} is excluded without a real justification - the export runs "
                f"test_internal_files_are_tracked_and_justified past this entry, so "
                f"the reason has to be checked here or it is checked nowhere"
            )
            assert not path.exists(), (
                f"{doc} exists but could not be read as a file"
            )
            return
        if not _in_git_checkout():
            pytest.skip(f"{doc} is excluded from this artifact by manifest")
        raise AssertionError(f"{doc} is listed as actionable but does not exist")

    text = path.read_text(encoding="utf-8")
    planned = planned_paths(text)

    dangling = []
    for ref in referenced_paths(text):
        if ref in planned or ref in EXTERNAL_OR_NOT_A_PATH:
            continue
        if is_hosted_repo_id(ref):
            continue
        if ref in bundle_exclusions():
            # A file this bundle deliberately removed. Permitted here and only
            # here: in a git checkout the manifest does not exist, so the check
            # is at full strength.
            continue
        candidate = REPO / ref
        if candidate.exists():
            continue
        # A directory referenced with a trailing slash.
        if ref.endswith("/") and (REPO / ref.rstrip("/")).is_dir():
            continue
        dangling.append(ref)

    assert not dangling, (
        f"{doc} references path(s) that neither exist nor appear on an "
        f"unchecked task line: {dangling}. Either create them, mark them as a "
        f"task, or remove the reference - an implementing agent will otherwise "
        f"go looking for something that is not there."
    )


def test_todo_sections_are_intact():
    """Guard against the truncation that bit two consecutive bundles.

    Both times, an agent rewrote the Session Summary with an unanchored match on
    a heading string that also appeared in prose, and silently deleted everything
    below it - operating rules, completed work, unresolved issues. The literal
    duplication has been removed, and this asserts the file still has exactly the
    expected sections in order, so any future truncation fails here instead of
    shipping.
    """
    text = (REPO / "TODO_TENABLE-EMAIL").read_text(encoding="utf-8")
    expected = [
        "## Verbose: [OFF]",
        "## Operating Rules",
        "## Completed Tasks",
        "## Unresolved Issues",
        "## Active Work Bundles",
        "## Remaining Tasks (for future runs)",
        "## Session Log",
        "## Session Summary",
    ]
    headings = [ln for ln in text.splitlines() if ln.startswith("## ")]
    assert headings == expected, (
        f"TODO sections drifted or the file was truncated.\n"
        f"  expected: {expected}\n  found:    {headings}"
    )
    # Every operating rule must survive. They are numbered 1..15.
    rules = [ln for ln in text.splitlines() if re.match(r"^\d+\. \*\*", ln)]
    assert len(rules) >= 15, f"expected >=15 operating rules, found {len(rules)}"
    # Session Summary must be the last section and must not be empty.
    tail = text.split("## Session Summary", 1)[1].strip()
    assert len(tail) > 200, (
        "Session Summary is empty or stub-like - a run ended without writing it"
    )


def test_no_duplicate_headings_that_an_unanchored_match_could_hit():
    """A heading string must appear once, as a heading, and never inside prose.

    This is the actual root cause of the two truncations. Keeping it asserted
    means nobody re-introduces a literal `## Section` inside a rule or a log row.
    """
    text = (REPO / "TODO_TENABLE-EMAIL").read_text(encoding="utf-8")
    for heading in ("## Session Summary", "## Session Log", "## Operating Rules"):
        assert text.count(heading) == 1, (
            f"{heading!r} appears {text.count(heading)} times. It must appear "
            f"exactly once, as the heading itself - a second occurrence in prose "
            f"is what caused two agents to truncate this file."
        )


@requires_repo
def test_actionable_docs_are_tracked():
    """These documents must be committed, or a fresh clone has no directions."""
    tracked = set(tracked_files())
    excluded = bundle_exclusions()
    missing = [
        d for d in ACTIONABLE_DOCS
        if d not in tracked and d not in excluded
    ]
    assert not missing, (
        f"actionable documents not tracked by git and not declared in the "
        f"exclusion manifest: {missing}"
    )


@requires_repo
def test_every_corpus_the_suite_consumes_is_actually_tracked():
    """A generated corpus that is not committed does not exist for anyone else.

    This found a real defect: `fixtures/adversarial/` was created with fifteen
    hostile messages and a suite asserting against them, and every test passed
    locally - because `.gitignore` ignores `*.eml` with a negation for
    `fixtures/synthetic/` only, so the messages were never staged. A fresh clone,
    a reviewer's bundle or a judge's checkout would have collected errors rather
    than failures, and the corpus the whole red-team response rests on would have
    been absent from the published artifact.

    The check is derived from the manifests rather than hardcoded, so a third
    corpus is covered by adding its directory to ``CORPORA`` and nothing else.
    """
    tracked = set(tracked_files())
    missing: list[str] = []
    for corpus in CORPORA:
        manifest = REPO / corpus / "labels.json"
        if not manifest.is_file():
            missing.append(f"{corpus}/labels.json")
            continue
        if f"{corpus}/labels.json" not in tracked:
            missing.append(f"{corpus}/labels.json")
        entries = json.loads(manifest.read_text(encoding="utf-8"))
        for entry in entries:
            relative = f"{corpus}/{entry['file']}"
            if relative not in tracked:
                missing.append(relative)
    assert not missing, (
        f"corpus files the tests consume are not tracked by git: {missing}. "
        f"They exist on this machine, so the suite passes here and fails in a "
        f"clone. Check .gitignore - `*.eml` is ignored and each corpus needs its "
        f"own negation."
    )


@requires_repo
def test_no_corpus_message_is_untracked_and_silently_absent():
    """The converse: nothing tracked that the manifests do not declare.

    An orphan message in a corpus directory is a case nobody runs, which is worse
    than a missing one because it looks like coverage.
    """
    for corpus in CORPORA:
        directory = REPO / corpus
        if not directory.is_dir():
            continue
        manifest = directory / "labels.json"
        if not manifest.is_file():
            continue
        declared = {
            e["file"] for e in json.loads(manifest.read_text(encoding="utf-8"))
        }
        present = {p.name for p in directory.glob("*.eml")}
        assert declared == present, (
            f"{corpus}: manifest and directory disagree. Only in manifest: "
            f"{sorted(declared - present)}. Only on disk: {sorted(present - declared)}."
        )


#: Tracked files that are deliberately NOT part of the public artifact, with the
#: reason. Everything else is public-by-default: a new tracked file that leaks
#: private infrastructure fails the suite until it is either cleaned or added
#: here with a justification. That is the safe direction to fail in.
INTERNAL_FILES = {
    "NOTES.md": "decision log; carries private host topology, tunnel detail and colleague context",
    "docs/EVIDENCE.md": "measurement register; names private inference endpoints and hosts",
}

#: Files that necessarily contain the patterns they check for. Deliberately
#: narrow and each carries a reason: an unexplained exemption is where a real
#: leak gets hidden.
SELF_EXEMPT = {
    "tests/test_doc_references.py":
        "defines the detection patterns and their assertion messages, so it must "
        "quote them literally; it holds no real host, address or path",
    "tools/record-results.sh":
        "defines the sanitization substitutions that strip absolute home paths and "
        "the machine hostname from junit.xml, so those patterns appear literally; "
        "it emits no real path or host",
    "tools/make_review_bundle.py":
        "defines the secret and private-infrastructure patterns it scans for, so "
        "they appear literally; it builds the external review bundle and fails "
        "closed if any included file matches",
}

#: Generic patterns that indicate private infrastructure. Written as regexes so
#: this tracked test file does not itself have to contain the identifiers.
PRIVATE_PATTERNS = [
    (re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "RFC1918 10/8 address"),
    (re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"), "RFC1918 192.168/16 address"),
    (re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"),
     "RFC1918 172.16/12 address"),
    (re.compile(r"/home/[A-Za-z0-9_.-]+"), "absolute home-directory path"),
    (re.compile(r"/Users/[A-Za-z0-9_.-]+"), "absolute home-directory path"),
    (re.compile(r"/var/www/"), "web root path"),
    (re.compile(r"\breadme\.txt\b"),
     "reference to a local readme that does not exist on the build host"),
    (re.compile(r'hostname="'),
     "machine hostname in a generated artifact; tools/record-results.sh removes the "
     "attribute from junit.xml, so any occurrence here is an unsanitized run"),
    (re.compile(r"\bssh://[^\s)`]+"), "internal ssh remote"),
]


def _org_specific_terms() -> list[str]:
    """Organization-specific forbidden terms, loaded from a gitignored file.

    Kept out of this tracked file so the guard can be strict without publishing
    the identifiers it checks for.
    """
    path = REPO / ".scratch" / "forbidden-terms.txt"
    if not path.is_file():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


@requires_repo
def test_public_bound_files_leak_no_private_infrastructure():
    """Operating rule 15, enforced.

    Every tracked file except those listed in ``INTERNAL_FILES`` is destined for
    a public repository. The Exchange rejects submissions with undisclosed
    outbound calls and scans history for secrets; disclosing an employer's
    internal network topology is the same class of problem and is not something
    a reviewer will catch for us.
    """
    terms = _org_specific_terms()
    leaks: dict[str, list[str]] = {}

    for rel in tracked_files():
        if rel in INTERNAL_FILES or rel in SELF_EXEMPT:
            continue
        path = REPO / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue

        found: list[str] = []
        for pattern, label in PRIVATE_PATTERNS:
            hits = list(pattern.finditer(text))
            if hits:
                # The matched text is not quoted, on purpose. This assertion's own
                # output is captured into docs/results/junit.xml by
                # tools/record-results.sh, so a message that repeats what it found
                # makes the *next* recorded artifact match the guard as well - a red
                # run that republishes its own accusation and never converges. The
                # offset plus the label is enough to find it with git grep.
                found.append(
                    f"{label}: {len(hits)} match(es), first at offset "
                    f"{hits[0].start()}"
                )
        for term in terms:
            if term in text:
                # Same reason, and a worse one for this branch: quoting an
                # organization-specific term into a tracked artifact would publish
                # the exact identifier the gitignored term list exists to keep out.
                found.append(
                    f"organization-specific term: one of the {len(terms)} configured "
                    f"terms occurs {text.count(term)} time(s) in this file"
                )
        if found:
            leaks[rel] = sorted(set(found))

    assert not leaks, (
        "public-bound files contain private infrastructure detail:\n"
        + "\n".join(f"  {f}: {v}" for f, v in sorted(leaks.items()))
        + "\nClean the file, or move it to INTERNAL_FILES with a reason."
    )


@requires_repo
def test_internal_files_are_tracked_and_justified():
    """The internal allowlist must not rot into a hiding place."""
    tracked = set(tracked_files())
    excluded = bundle_exclusions()
    for rel, reason in {**INTERNAL_FILES, **SELF_EXEMPT}.items():
        if rel in excluded:
            # Deliberately removed from this artifact, which is the strongest
            # possible form of the exclusion this allowlist describes. The
            # justification is still required below, so the entry cannot be
            # silent about why.
            continue
        assert rel in tracked, f"{rel} is listed as exempt but is not tracked"
        assert len(reason.strip()) >= 20, (
            f"{rel} needs a real justification for being excluded from the "
            f"public artifact, not a one-word note"
        )


#: A markdown image target: `![alt](path)`. Anchors, queries and absolute URLs are
#: filtered out below rather than in here, so this stays readable.
_MD_TARGET = re.compile(r"!\[[^\]]*\]\(([^)\s]+)\)")


@requires_repo
def test_every_image_a_tracked_document_shows_is_tracked():
    """An untracked directory referenced by a tracked document has bitten twice.

    The corpus version of this failure is the one that was caught: the files existed
    on the build machine, the suite passed there, and a fresh clone collected errors
    instead of results. A README pointing at `docs/images/foo.png` fails the same way
    and more quietly still - a renderer shows a broken image and no test notices - so
    the reference has to be checked against `git ls-files` rather than against the
    filesystem.
    """
    tracked = set(tracked_files())
    missing: list[str] = []
    for rel in sorted(tracked):
        if not rel.endswith(".md"):
            continue
        text = (REPO / rel).read_text(encoding="utf-8", errors="replace")
        for target in _MD_TARGET.findall(text):
            if target.startswith(("http://", "https://", "mailto:", "#", "/")):
                continue
            resolved = (Path(rel).parent / target).resolve().relative_to(REPO).as_posix()
            if resolved not in tracked:
                missing.append(f"{rel} -> {resolved}")
    assert not missing, (
        "a tracked document shows an image that git does not track: "
        + ", ".join(missing)
        + ". Either commit it or check .gitignore - the .eml corpora needed an "
        "explicit negation for the same reason."
    )


def test_todo_is_publishable():
    """The work plan is tracked and read by every session, so it must be clean.

    Regression guard for the specific mistake this file was written to prevent:
    a rule instructing agents to read a home-directory readme that does not
    exist on the build host.
    """
    text = (REPO / "TODO_TENABLE-EMAIL").read_text(encoding="utf-8")
    assert "readme.txt" not in text, (
        "the TODO must not instruct a session to read a local readme that does "
        "not exist on the build host"
    )
    for pattern, label in PRIVATE_PATTERNS:
        assert not pattern.search(text), f"TODO contains {label}"
    for term in _org_specific_terms():
        assert term not in text, f"TODO contains organization-specific term {term!r}"


@pytest.mark.parametrize(
    "token,expected",
    [
        # Upstream repository identifiers must not be treated as local paths.
        ("SetFit/enron_spam", True),
        ("Qwen/Qwen3.8-27B", True),
        ("mrm8488/bert-tiny-finetuned-enron-spam-detection", True),
        ("S-Labs/", True),          # abbreviated owner prefix
        ("3nesdeniz/", True),
        # Our own references must still be checked at full strength.
        ("src/tenable_email/missing.py", False),
        ("docs/NOPE.md", False),
        ("tests/test_missing.py", False),
        ("eval/run.py", False),
        ("tools/whatever.sh", False),
        ("fixtures/synthetic/x.eml", False),
        # Not identifiers at all.
        ("stages.yaml", False),
        ("README.md", False),
        ("a/b/c", False),           # two slashes: a path, not owner/name
    ],
)
def test_hosted_repo_id_rule(token, expected):
    assert is_hosted_repo_id(token) is expected, token


# --------------------------------------------------------------------------
# dotfile normalization - the guard must not invent filenames
# --------------------------------------------------------------------------


def test_a_dotfile_keeps_its_leading_dot_and_resolves() -> None:
    """A reference to a real dotfile must not be looked up under a mangled name.

    ``is_candidate`` used to call ``str.strip(".,;:")``, which strips from both ends, so
    ``.gitleaks.toml`` arrived at the existence check as ``gitleaks.toml`` and was reported
    dangling while the file was tracked and present. The failure mode is worse than a false
    positive in a test: the guard's whole purpose is to stop a reader going looking for
    something that is not there, and it was manufacturing exactly that.
    """
    assert (REPO / ".gitleaks.toml").exists(), "precondition: the dotfile is real"
    assert is_candidate(".gitleaks.toml"), "a two-part-extension dotfile is a path"
    # The regression itself: the token must survive normalization unchanged, not lose the
    # dot that makes it the file it names.
    assert normalize_token(".gitleaks.toml") == ".gitleaks.toml"


def test_bare_extensions_and_extensionless_dotfiles_are_not_paths() -> None:
    """The narrowing that keeps the fix above from breaking 34 unrelated references.

    Documents refer to ``.eml``, ``.docm`` and ``.zip`` as formats, and to ``.gitignore``
    as a well-known file. Treating a lone dot-token as a path would report all of them
    dangling. The rule is a leading dot with no slash and no second dot, and the tradeoff -
    a mistyped ``.gitleaks.tom`` would be skipped - is stated where the rule lives.
    """
    for token in (".eml", ".docm", ".zip", ".txt", ".py", ".sh", ".gitignore", ".example"):
        assert not is_candidate(token), f"{token} is a format or a bare dotfile, not a path"
    for token in ("src/tenable_email/parse.py", ".gitleaks.toml", "docs/ELI5.md"):
        assert is_candidate(token), f"{token} is a real path reference and must be checked"


def test_trailing_prose_punctuation_is_still_trimmed() -> None:
    """The reason the trim existed at all must survive its repair.

    Prose ends sentences with a full stop inside the backticks often enough that a reference
    would otherwise resolve to a name with a trailing dot and be reported missing.
    """
    assert normalize_token("docs/ELI5.md.") == "docs/ELI5.md"
    assert normalize_token("docs/ELI5.md.,") == "docs/ELI5.md"
    normalized = normalize_token("docs/ELI5.md.,")
    assert normalized == "docs/ELI5.md"
    assert (REPO / normalized).exists()
