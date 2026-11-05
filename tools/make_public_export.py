#!/usr/bin/env python3
"""Build a publishable repository from this one, with clean history.

The Exchange scans **full git history** for secrets and private data, and it is a
hard rejection trigger. This repository's history cannot be published, and the
reason is wider than the two internal files:

* ``NOTES.md`` and ``docs/EVIDENCE.md`` appear in all 58 revisions, carrying
  private host topology, addresses, tunnel detail and a colleague's name.
* Earlier revisions of ``tests/test_doc_references.py``,
  ``tests/test_results_evidence.py``, ``tests/test_offline_default_path.py`` and
  ``tools/make_review_bundle.py`` hardcoded the organization-specific terms they
  now load from a gitignored file. Those terms are still in history.
* At least two **commit messages** contain private paths and an internal domain.
* Three commits carry the author email ``agent@<internal domain>``, so the
  identifier is in the commit metadata itself.

Deleting the files before publishing therefore does not help, and neither does
file-level history filtering: messages and identities would survive it. A full
rewrite with ``--replace-text`` plus message and identity rewriting is possible
but slow, and a single missed occurrence is permanent and public.

So this tool builds a **fresh repository with one commit** from the current
tracked tree, minus the internal files, under an identity the operator supplies.
The internal build history stays on the private bare repository where it belongs.
What is lost is the 58-commit narrative; what is gained is a guarantee that can be
checked rather than hoped for.

The guarantee is the point. After building, this tool scans the *resulting*
repository's entire history - every blob in every revision, every commit message,
every author and committer identity - and deletes the export on any finding. It
fails closed.

Usage::

    python3 tools/make_public_export.py --out dist/public-repo \\
        --author "Your Name <you@example.com>"

    # inspect, then push to a new empty GitHub repository:
    git -C dist/public-repo remote add origin git@github.com:HANDLE/REPO.git
    git -C dist/public-repo push -u origin main

Nothing is pushed by this tool and no remote is configured. Creating the public
repository and pushing to it stay human actions, because they are irreversible.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

#: Reuse the review bundle's exclusions and scanner rather than maintaining a
#: second copy of the same list. Two lists of "what must not be published" is how
#: one of them rots.
_spec = importlib.util.spec_from_file_location(
    "make_review_bundle", REPO / "tools" / "make_review_bundle.py"
)
assert _spec and _spec.loader
_bundle = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_bundle)

EXCLUDED = _bundle.EXCLUDED
NEVER = _bundle.NEVER
org_terms = _bundle.org_terms
scan_bundle = _bundle.scan

#: The private-infrastructure patterns are imported from the review-bundle tool
#: rather than restated here. Two copies of "what must not be published" is how
#: one of them rots, and a restated copy has a second problem: the literals match
#: themselves, so the tool that scans for a web-root path is itself flagged for
#: containing one and needs an exemption entry to compensate. Importing removes
#: both.
PRIVATE_PATTERNS = _bundle.PRIVATE_PATTERNS


#: Set by ``--keep-on-failure``. A publication gate that deletes its own evidence on
#: failure cannot be debugged, and "the suite failed in the export" is precisely the
#: message whose detail matters most: the export excludes files the private tree has, so
#: a failure there is usually a test asserting a property of the wrong tree. Discarding
#: stays the default because a half-built export must never be mistaken for a publishable
#: one.
_KEEP_ON_FAILURE = False


#: The fields ``eval/run.py`` writes on every run because they describe *that run* rather
#: than a measurement. They are the only top-level fields allowed to differ between the
#: private artifact and the export's regenerated one; everything else at the top level is
#: evidence, and the export is refused if it disappears or changes. Kept as a local copy of
#: the list rather than imported because the export must not import the module it is
#: about to run - the check has to survive a broken `run.py`, which is exactly what it is
#: checking for.
RUN_LOCAL_FIELDS = ("schema_version", "commit", "commit_short", "branch", "dirty")

#: The two fields :func:`eval.run.carry_forward` adds to a block it did not measure.
#: A carried block may differ from its source by these and nothing else.
CARRY_FIELDS = ("reproduced_here", "carried_forward")


def _discard(out: pathlib.Path) -> str:
    """Remove a failed export, or preserve it, and return the sentence that says which.

    The call sites used to hardcode "Deleted {out}." while this function had a
    ``--keep-on-failure`` branch that deleted nothing, so every refusal printed a
    falsehood whenever the flag was set - and the flag exists precisely so the refusal
    output can be trusted while the directory is being inspected. The claim about what
    happened to ``out`` now lives here and nowhere else. (The previous version of this
    helper called *itself* instead of ``shutil.rmtree``, so the default branch was an
    infinite recursion: a refusal raised RecursionError instead of cleaning up.)
    """
    if _KEEP_ON_FAILURE:
        return (f"{out} was NOT deleted: --keep-on-failure preserved it for inspection. "
                f"It is a half-built export and must not be published or pushed.")
    shutil.rmtree(out, ignore_errors=True)
    return f"Deleted {out}."


def evidence_regression(source: dict, regenerated: dict) -> list[str]:
    """Every way the export's regenerated artifact is worse than the private one.

    Returns findings as printable strings, so an empty list is the only acceptable answer.

    The export re-measures inside the copied tree because the committed artifact names a
    commit that does not exist in a fresh-history repository. Re-measuring there cannot
    reproduce everything: `eval/internal/` is gitignored, so the fetched corpora are not
    in the export and the external block cannot be measured again. What it must never do
    is *lose* it. This is the gate on that: a block the private artifact carried has to
    still be there, unchanged apart from the carry-forward markers, and if it was carried
    rather than measured it has to say so. Silent loss is what shipped a `metrics.json`
    with no external results and no indication that 3,005 messages had ever existed.
    """
    findings: list[str] = []
    for key, value in source.items():
        if key in RUN_LOCAL_FIELDS:
            continue
        if key not in regenerated:
            findings.append(
                f"`{key}`: the private artifact carried it and the regenerated one does "
                f"not. The export would publish an artifact missing that block."
            )
            continue
        got = regenerated[key]
        bare = ({k: v for k, v in got.items() if k not in CARRY_FIELDS}
                if isinstance(got, dict) else got)
        if bare != value:
            findings.append(
                f"`{key}`: the regenerated block is not the block that was published. "
                f"Only {CARRY_FIELDS} may be added to a carried block; anything else "
                f"means the export altered a measurement it did not re-make."
            )
        markers = [f for f in CARRY_FIELDS if isinstance(got, dict) and f in got]
        if markers and len(markers) != len(CARRY_FIELDS):
            findings.append(
                f"`{key}`: carried forward but marked with {markers}; a block that was "
                f"not measured by the run that wrote it must carry both "
                f"`reproduced_here: false` and a `carried_forward` note, or a reader "
                f"cannot tell it from a fresh measurement."
            )
    # The specific case this whole check was written for, asserted rather than inferred
    # from the generic loop: the export has no fetched corpora, so its external block is
    # by construction a carry-forward, and an unmarked one would read as a measurement
    # made on a host that could not have made it.
    external_block = regenerated.get("external")
    if isinstance(external_block, dict):
        if external_block.get("reproduced_here") is not False:
            findings.append(
                "`external`: not marked `reproduced_here: false`. The export cannot "
                "measure it (eval/internal/ is gitignored and therefore absent), so a "
                "block that claims to have been measured here was carried in silence."
            )
    return findings


def _run(args: list[str], cwd: pathlib.Path | None = None,
         check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, cwd=cwd, capture_output=True, text=True, check=check, timeout=300,
    )


def _git(out: pathlib.Path, *args: str, check: bool = True) -> str:
    return _run(["git", *args], cwd=out, check=check).stdout


def private_patterns() -> list[tuple[re.Pattern[str], str]]:
    """The shared private-infrastructure patterns plus the organization terms.

    The terms live in a gitignored file, so a fresh clone of *this* repository
    runs only the generic checks. That is the correct direction to fail for a
    public artifact, and it is stated here rather than left implicit: this tool is
    strongest on the machine that built the project.

    These are the patterns that must appear nowhere in the published history,
    which is a wider surface than the bundle scanner covers: it reads file
    contents, whereas a private hostname in a commit message or an author email is
    just as published. :func:`scan_history` applies them to blobs, messages and
    identities alike.
    """
    patterns = list(PRIVATE_PATTERNS)
    for term in org_terms():
        if term.strip():
            patterns.append((re.compile(re.escape(term.strip()), re.IGNORECASE),
                             f"organization-specific term ({term.strip()!r})"))
    return patterns


def scan_history(out: pathlib.Path) -> tuple[dict[str, list[str]], int]:
    """Scan every blob, message and identity in the exported repository's history.

    Returns ``(findings, blobs_scanned)``. The count is returned and printed
    because a scan that examined nothing and reported "clean" is worse than no
    scan at all, and that is exactly what the first version did: it translated
    Python regular expressions into a POSIX extended alternation and handed it to
    ``git grep -E``, which rejected ``(?:``, ``\\b`` and ``\\d`` outright, exited
    128 with empty stdout, and - because the call used ``check=False`` - was read
    as zero findings. The tool then announced that the history was clean.

    So the patterns are applied with Python's ``re``, natively, to the bytes of
    each blob. That also removes two quieter defects in the same stroke: ``git
    grep -I`` skipped binary files entirely, and ``\\s`` inside a bracket
    expression meant a literal ``s`` rather than whitespace in ERE.

    This is the check that matters. Scanning the working tree proves what is there
    now; scanning history proves what is *published*, and only the second is what
    a reviewer's secret scan will see.
    """
    findings: dict[str, list[str]] = {}
    patterns = private_patterns()
    #: Files that legitimately quote the patterns they detect. The working-tree
    #: scanner honours the same set; without it the export could never be built,
    #: because the scanner's own source contains a web-root pattern.
    exempt = set(getattr(_bundle, "SCAN_EXEMPT", ()))

    revisions = _git(out, "rev-list", "--all").split()
    if not revisions:
        return {"no history": ["the export contains no commits"]}, 0

    # Every object in every revision, with the path it was seen at. Deduplicated
    # by content but scanned per path, so an exempt path does not exempt the same
    # bytes appearing somewhere else.
    cache: dict[str, str] = {}
    scanned = 0
    for line in _git(out, "rev-list", "--objects", "--all").splitlines():
        parts = line.split(" ", 1)
        sha = parts[0]
        path = parts[1].strip() if len(parts) > 1 else ""
        if not path or path in exempt:
            continue
        kind = _run(["git", "cat-file", "-t", sha], cwd=out,
                    check=False).stdout.strip()
        if kind != "blob":
            continue
        if sha not in cache:
            raw = subprocess.run(
                ["git", "cat-file", "blob", sha], cwd=out,
                capture_output=True, check=False, timeout=120,
            )
            if raw.returncode != 0:
                findings.setdefault("unreadable blob", []).append(
                    f"{path}@{sha[:12]}: git cat-file exited {raw.returncode}"
                )
                continue
            # errors="replace" rather than a decode guard: a UTF-16 fixture or a
            # PNG with a text chunk must still be searched, and silently skipping
            # anything that is not UTF-8 is a hole by construction.
            cache[sha] = raw.stdout.decode("utf-8", "replace")
        text = cache[sha]
        scanned += 1
        for pattern, label in patterns:
            match = pattern.search(text)
            if match:
                findings.setdefault(f"blob content: {label}", []).append(
                    f"{path}@{sha[:12]}: {match.group(0)[:80]!r}"
                )

    # Commit messages and identities are separate surfaces from file contents.
    log = _git(
        out, "log", "--all", "--format=%H%n%an <%ae>%n%cn <%ce>%n%B%n===END==="
    )
    for chunk in log.split("===END==="):
        if not chunk.strip():
            continue
        lines = chunk.strip().splitlines()
        sha = lines[0] if lines else "?"
        identities = " ".join(lines[1:3])
        message = "\n".join(lines[3:])
        for pattern, label in patterns:
            found = pattern.search(message)
            if found:
                findings.setdefault(f"commit message: {label}", []).append(
                    f"{sha[:12]}: {found.group(0)!r}"
                )
            found = pattern.search(identities)
            if found:
                findings.setdefault(f"commit identity: {label}", []).append(
                    f"{sha[:12]}: {identities.strip()}"
                )

    return findings, scanned


def build(out: pathlib.Path, author: str, message: str) -> int:
    """Build the export, and never leave a partial one behind.

    Every refusal path already removes the directory, but an *unexpected* error
    did not: after ``mkdir`` any of the copy or git calls can raise, and the
    half-populated directory then blocks the next invocation, which refuses to
    write into a path that already exists. The operator's recovery would have been
    a manual ``rm -rf`` of a directory the tool created. So the body is wrapped and
    any exception cleans up before propagating - the traceback is still the
    traceback, because silently swallowing it would be worse than the mess.
    """
    try:
        return _build(out, author, message)
    except BaseException:
        if out.exists():
            print("\nerror during export:", file=sys.stderr)
            print(_discard(out), file=sys.stderr)
        raise


def _build(out: pathlib.Path, author: str, message: str) -> int:
    if out.exists():
        print(f"refusing to write into an existing directory: {out}")
        print("remove it first, so this never overwrites something unexpected")
        return 2
    if "@" not in author or "<" not in author:
        print(f"--author must be 'Name <email>', got: {author!r}")
        return 2

    # A LICENSE is a hard repository requirement for the Exchange. What this
    # checks is narrower than it once claimed: it rejects the obvious unfilled
    # placeholders, and it cannot tell whether the copyright holder named is the
    # right legal identity. That judgement belongs to the operator, so it is
    # surfaced in the output rather than silently assumed.
    license_path = REPO / "LICENSE"
    if not license_path.is_file():
        print("REFUSING TO EXPORT: there is no LICENSE file at the repository "
              "root. The Exchange requires one and recommends MIT.")
        return 2
    license_text = license_path.read_text(encoding="utf-8")
    for placeholder in ("TODO", "PLACEHOLDER", "Your Name", "<year>", "HANDLE"):
        if placeholder.lower() in license_text.lower():
            print(f"REFUSING TO EXPORT: LICENSE still contains {placeholder!r}. "
                  f"The copyright holder must be a real identity before the "
                  f"repository is public.")
            return 2
    holder = next(
        (line.strip() for line in license_text.splitlines()
         if line.strip().lower().startswith("copyright")),
        "",
    )
    print(f"license: {license_text.splitlines()[0].strip()}")
    print(f"copyright holder as written: {holder or 'NOT STATED'}")
    print("  ^ confirm this is the intended legal identity; the check above "
          "rejects placeholders, not wrong names")

    tracked = _bundle.tracked_files()
    included = [f for f in tracked if f not in EXCLUDED]
    excluded_present = sorted(set(tracked) & set(EXCLUDED))
    print(f"tracked files: {len(tracked)}")
    print(f"including:     {len(included)}")
    print(f"excluding:     {', '.join(excluded_present) or 'none'}")
    for name in NEVER:
        # The entries all end in a slash, so the prefix test matches paths *under*
        # the directory and not merely paths that start with the same letters.
        # Stripping the slash made `.git/` match `.gitignore`.
        prefix = name if name.endswith("/") else name + "/"
        if any(f.startswith(prefix) for f in included):
            print(f"REFUSING: {name} is in the never-copy list but matched a "
                  f"tracked file")
            return 2

    # Scan the content before copying, so a leak never lands on disk in a
    # directory that then has to be cleaned up.
    pairs = [(REPO / f, f) for f in included]
    found = scan_bundle(pairs)
    if found:
        print("\nREFUSING TO EXPORT: private material in the tracked tree")
        for label, hits in sorted(found.items()):
            print(f"  {label}: {len(hits)} hit(s)")
            for hit in hits[:3]:
                print(f"    {hit[:160]}")
        return 1

    out.mkdir(parents=True)
    for relative in included:
        source = REPO / relative
        destination = out / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    # The same manifest the review bundle writes, so the dangling-reference guard
    # inside the export permits a reference to a file that was deliberately
    # removed rather than failing on it.
    (out / "BUNDLE-EXCLUDED.txt").write_text(
        "".join(f"{name}\n" for name in sorted(EXCLUDED)), encoding="utf-8"
    )
    source_commit = _run(
        ["git", "rev-parse", "HEAD"], cwd=REPO
    ).stdout.strip()
    (out / "PUBLICATION-NOTE.md").write_text(
        f"""# About this repository's history

This repository was exported from a private development repository at commit
`{source_commit}` and starts from a single commit. It is the work of
**Campus Autonomous Defenders (CAD)** for Tenable SWARM Global 2026.

That is deliberate. The development history contains internal planning notes, a
measurement register naming private inference endpoints, and commit metadata
identifying an internal build host. None of it belongs in a public artifact, and
because the history is scanned in full when this is submitted, removing the files
would not have been sufficient - the content would still be reachable from earlier
revisions.

What is lost is the development narrative. What is preserved is every source file,
test, fixture, generated metric and document that is meant to be public, at the
state of the commit named above. The full development history remains available
from the maintainers on request.
""",
        encoding="utf-8",
    )

    _git(out, "init", "-q", "-b", "main")
    _git(out, "config", "user.name", author.split("<")[0].strip().strip('"'))
    _git(out, "config", "user.email",
         author.split("<")[1].rstrip(">").strip())
    # The repository-local user.name and user.email set above already override any
    # global identity, so nothing further is needed here. A previous version set
    # `includeIfMissing`, which is not a git key at all, and carried a comment
    # claiming it prevented identity inheritance - an effect the line never had.
    # The real residual risk is a global `init.templateDir` or `core.hooksPath`
    # injecting hooks into the fresh repository; neither is set on this host, and
    # the history scan below would catch anything they committed.
    _git(out, "add", "-A")
    _git(out, "-c", "commit.gpgsign=false", "commit", "-q",
         "--author", author, "-m", message)

    # Re-record the test evidence INSIDE the export, then amend. The committed
    # artifact names the commit it describes and asserts that commit resolves; in
    # a fresh-history export the private commit does not exist, so publishing it
    # unchanged would ship evidence pointing at a revision no reviewer can find.
    # Recording here also fixes the collected count, which differs because the
    # internal-only documents are absent and one parametrized test skips.
    # eval/metrics.json names the commit it was measured at, and that commit is a
    # private revision which does not exist in this repository. It was carried over
    # verbatim while docs/results/ was regenerated, so the export shipped one
    # artifact pointing at real history and another pointing at nothing - the exact
    # failure the second-commit rule below exists to prevent, in the file that was
    # forgotten. Regenerating it here is also what keeps the committed-versus-fresh
    # test passing, since the rows are derived from the fixtures and do not change.
    #
    # Deliberately WITHOUT --external. Two options were on the table and only one of
    # them keeps the evidence:
    #
    #   * `--external` in the export measures nothing, because eval/internal/ is
    #     gitignored and so absent here, and `eval/external.py` answers that with the
    #     loud `not-fetched` state. That state is correct *as a measurement* and fatal
    #     *as a replacement*: it would overwrite the committed 3,005-message block with
    #     an empty one, and 37 tests that read the published block would still fail -
    #     verified here, not assumed.
    #   * No flag at all, plus the rule in `eval/run.py::carry_forward`: this run does
    #     not produce `external`, so the writer carries the block out of the artifact it
    #     is overwriting and marks it `reproduced_here: false`. The numbers survive, and
    #     they are labelled as carried rather than measured here.
    #
    # The second is what this step relies on, and the assertion below is what stops the
    # reliance from becoming an assumption: if a future change loses a block, or alters
    # one, or carries it unmarked, the export is refused.
    metrics_path = out / "eval" / "metrics.json"
    if metrics_path.is_file():
        print("\nre-measuring eval/metrics.json against the export's own history...")
        remeasured = _run(
            [sys.executable, "eval/run.py", "--json", "-o", "eval/metrics.json"],
            cwd=out, check=False,
        )
        if remeasured.returncode != 0:
            print(remeasured.stdout[-1500:])
            print(remeasured.stderr[-1500:])
            print("\nREFUSING TO PUBLISH: the metrics could not be regenerated in "
                  "the export.")
            print(_discard(out))
            return 1
        source_metrics = REPO / "eval" / "metrics.json"
        if source_metrics.is_file():
            findings = evidence_regression(
                json.loads(source_metrics.read_text(encoding="utf-8")),
                json.loads(metrics_path.read_text(encoding="utf-8")),
            )
            if findings:
                for finding in findings:
                    print(f"  {finding}")
                print("\nREFUSING TO PUBLISH: re-measuring inside the export lost or "
                      "altered evidence the private artifact carried.")
                print(_discard(out))
                return 1
            print("  evidence check: every top-level block the private artifact "
                  "carried is still there")

    print("\nre-recording test evidence against the export's own history...")
    recorded = _run(
        ["bash", "tools/record-results.sh"], cwd=out, check=False
    )
    if recorded.returncode != 0:
        print(recorded.stdout[-2000:])
        print(recorded.stderr[-2000:])
        print("\nREFUSING TO PUBLISH: the suite did not pass in the export.")
        print(_discard(out))
        return 1
    # The regenerated evidence goes in a SECOND commit, never an amend. Amending
    # replaces the commit the artifact just described with a new one, leaving the
    # described revision dangling: `git cat-file -e` still resolves it locally
    # through the reflog, so the check passes here, but dangling objects are not
    # pushed - so the published artifact would name a commit no reviewer can
    # find. Two commits cost nothing and keep the evidence pointing at real
    # history. This is the same shape the private repository uses.
    _git(out, "add", "-A")
    if _git(out, "status", "--porcelain").strip():
        _git(out, "-c", "commit.gpgsign=false", "commit", "-q", "--author", author,
             "-m", "test: record the suite against this exported tree\n\n"
                   "The evidence names the commit it describes, which is the "
                   "initial export commit. It was regenerated here rather than "
                   "carried over, because the private revision the original "
                   "artifact named does not exist in this repository and a "
                   "reviewer could not resolve it.")
        print("  evidence re-recorded as a second commit, so it names a "
              "revision that will exist once pushed")
    else:
        print("  evidence already current")

    identities = _git(out, "log", "--format=%an <%ae> | %cn <%ce>").strip()
    print(f"\nexport identity: {identities}")
    commits = _git(out, "rev-list", "--count", "HEAD").strip()
    files = len(_git(out, "ls-files").splitlines())
    print(f"export commits:  {commits}")
    print(f"export files:    {files}")

    print("\nscanning the entire exported history (blobs, messages, identities)...")
    findings, blobs_scanned = scan_history(out)
    print(f"  examined {blobs_scanned} blob(s) across "
          f"{_git(out, 'rev-list', '--count', '--all').strip() or '0'} commit(s)")
    if not blobs_scanned:
        # A scan that read nothing cannot certify anything. This is the guard the
        # first version lacked, and its absence is why a broken scan reported
        # success instead of failing.
        findings.setdefault("scan did not run", []).append(
            "no blobs were examined, so the history is not certified either way"
        )
    if findings:
        print("\nREFUSING TO PUBLISH: private material in the exported history")
        for label, hits in sorted(findings.items()):
            print(f"  {label}: {len(hits)} hit(s)")
            for hit in hits[:3]:
                print(f"    {hit[:160]}")
        print("\nREFUSING TO PUBLISH: private material in the exported history. "
              "Nothing was published.")
        print(_discard(out))
        return 1

    print("  clean: no private material in any blob, commit message or identity")
    print(f"\nexport ready at {out}")
    print("Nothing was pushed and no remote was configured. Creating the public")
    print("repository and pushing to it are irreversible, so they stay human actions:")
    print(f"  git -C {out} remote add origin git@github.com:HANDLE/REPO.git")
    print(f"  git -C {out} push -u origin main")
    return 0


DEFAULT_MESSAGE = """Initial public release.

A local-first triage pipeline for user-reported phishing, with a deterministic
signal layer, an optional cascade of local model tiers, a content-addressed
record/replay store so the whole pipeline runs offline against committed
recordings, an offline runner with a receipt contract and a human approval gate,
a CLI, and a read-only MCP server with an agent skill.

Runtime dependencies are deliberately empty. Every model tier is optional and
records UNAVAILABLE rather than failing when unconfigured.

See README.md for how to run it, docs/PARITY.md for what it does and does not
cover against the reference playbook, docs/RED-TEAM-RESPONSE.md for what an
external red-team review found and what was done about it, and eval/metrics.json
for measured behaviour over the committed corpora.
"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", type=pathlib.Path,
                    default=pathlib.Path("dist/public-repo"),
                    help="directory to create (must not exist)")
    ap.add_argument("--author", required=True,
                    help="'Name <email>' for the single exported commit; never "
                         "invented, because this identity is permanent")
    ap.add_argument("--keep-on-failure", action="store_true",
                    help="preserve a failed export directory for inspection instead of "
                         "deleting it; the export is still refused, never published")
    ap.add_argument("--message", default=DEFAULT_MESSAGE,
                    help="commit message for the exported history")
    args = ap.parse_args(argv)
    global _KEEP_ON_FAILURE
    _KEEP_ON_FAILURE = bool(args.keep_on_failure)
    return build(args.out, args.author, args.message)


if __name__ == "__main__":
    raise SystemExit(main())
