"""The bounded ``.eml`` directory walk -- the boundary every consumer inherits.

``iter_eml_dir`` is the only filesystem walk in this package, and until now it had
no bound: pointed at ``/`` it walked the host, crossed a network mount, found
6,297 messages that belonged to other people's projects and yielded them as the
caller's corpus. That took 44.7 s on the build machine -- 52% of the whole test
suite -- and the safety half of it is worse than the speed half: a
caller-supplied path became an unbounded search of the machine, and the rows that
came back were presented as a complete reading of the directory the caller named.

So the tests here are about four things, each of which has to be true at this
boundary rather than at whichever consumer noticed the problem first:

*   a legitimate corpus walks exactly as it always did, in the same order;
*   a bound that binds is **refused**, not quietly truncated, and the refusal
    names the bound, the directory and how to narrow the request;
*   a partial scan is an explicit opt-in and is recorded on the result;
*   neither a symlinked directory nor a symlinked file lets the walk leave the
    root, and the system trees are never descended.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import sys
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email.parse import (  # noqa: E402
    BOUND_DEPTH,
    BOUND_FILES,
    BOUND_ROOT,
    DEFAULT_MAX_EML_DEPTH,
    DEFAULT_MAX_EML_FILES,
    DirectoryScanError,
    NON_DATA_TREES,
    iter_eml_dir,
    scan_eml_dir,
)

SYNTHETIC = REPO / "fixtures" / "synthetic"
ADVERSARIAL = REPO / "fixtures" / "adversarial"

#: A fixture message, copied wherever a test needs a corpus without needing this
#: one's contents. ``clean_internal_registrar`` is the smallest and least
#: interesting of the fourteen, so nothing here can accidentally measure it.
SEED = SYNTHETIC / "clean_internal_registrar.eml"


def seed(directory: pathlib.Path, count: int) -> list[str]:
    """Fill ``directory`` with ``count`` copies of one fixture. Returns names."""
    directory.mkdir(parents=True, exist_ok=True)
    names = []
    for index in range(count):
        name = f"mail_{index:03d}.eml"
        shutil.copyfile(SEED, directory / name)
        names.append(name)
    return names


# --------------------------------------------------------------------------
# the default bound, and what it is a bound *of*
# --------------------------------------------------------------------------


def test_the_defaults_are_a_count_and_a_depth_and_are_public():
    """The two numbers that hold the walk are constants, not prose.

    They are exported so ``EmlDirectorySource``, the CLI and the MCP tool can all
    talk about the same ceiling. A bound that only one of them knows is a bound
    that the others silently do not have.
    """
    assert DEFAULT_MAX_EML_FILES > 0
    assert DEFAULT_MAX_EML_DEPTH > 0
    assert isinstance(DEFAULT_MAX_EML_FILES, int)
    assert isinstance(DEFAULT_MAX_EML_DEPTH, int)
    # This repository's whole corpus is far below the ceiling, which is the point:
    # the bound is a guard against a filesystem, not an obstacle to a real run.
    assert len(list(iter_eml_dir(REPO / "fixtures"))) < DEFAULT_MAX_EML_FILES


def test_the_system_trees_are_named_for_refusal_not_measured_away():
    assert "/proc" in NON_DATA_TREES
    assert "/sys" in NON_DATA_TREES
    assert "/dev" in NON_DATA_TREES


# --------------------------------------------------------------------------
# a legitimate corpus still works, in the same order
# --------------------------------------------------------------------------


def test_a_real_corpus_walks_complete_and_in_sorted_order():
    paths = list(iter_eml_dir(SYNTHETIC))
    assert len(paths) == 14, f"the synthetic corpus is 14 messages, got {len(paths)}"
    assert paths == sorted(paths), "a reordered batch stops matching its recordings"
    assert all(p.is_file() for p in paths)

    scan = scan_eml_dir(SYNTHETIC)
    assert scan.complete is True
    assert scan.bound is None
    assert scan.files_found == 14
    assert scan.directories_visited == 1
    assert scan.symlinks_skipped == 0
    assert scan.trees_pruned == ()


def test_nested_directories_inside_the_bound_are_found(tmp_path):
    (tmp_path / "2026" / "01" / "inbox").mkdir(parents=True)
    shutil.copyfile(SEED, tmp_path / "top.eml")
    shutil.copyfile(SEED, tmp_path / "2026" / "01" / "inbox" / "deep.eml")
    names = sorted(p.name for p in iter_eml_dir(tmp_path))
    assert names == ["deep.eml", "top.eml"]
    assert scan_eml_dir(tmp_path).complete is True


def test_hidden_directories_are_still_walked_because_they_can_hold_mail(tmp_path):
    """A ``.spool`` directory inside a corpus is data, not a dotfile to be skipped.

    ``Path.rglob`` matched dot-prefixed names, so a walk that stopped matching them
    would quietly drop messages from a corpus that uses one. The bound is a bound
    on reach, not a filter on names.
    """
    (tmp_path / ".spool").mkdir()
    shutil.copyfile(SEED, tmp_path / ".spool" / "m.eml")
    shutil.copyfile(SEED, tmp_path / ".hidden.eml")
    names = sorted(p.name for p in iter_eml_dir(tmp_path))
    assert names == [".hidden.eml", "m.eml"]
    assert scan_eml_dir(tmp_path).complete is True


def test_an_undersized_or_absent_root_reports_the_same_error_as_it_did():
    """The pre-existing error contract of the walk is unchanged.

    Callers -- ``sources.EmlDirectorySource``, the CLI, the MCP tool's
    ``not-a-directory`` code -- branch on ``NotADirectoryError``. A refactor that
    turned it into a new exception type would fix one defect and open another.
    """
    with pytest.raises(NotADirectoryError):
        list(iter_eml_dir(SYNTHETIC / "clean_internal_registrar.eml"))
    with pytest.raises(NotADirectoryError):
        list(iter_eml_dir(REPO / "no-such-directory-here"))


# --------------------------------------------------------------------------
# refusing, loudly, when a bound binds
# --------------------------------------------------------------------------


def test_more_files_than_the_bound_is_a_refusal_not_a_short_answer(tmp_path):
    """A truncating scan that reports success is the failure mode, so: refuse.

    Three assertions, all of which a "does not raise" test would miss: it raises,
    the message names the bound and the directory, and it says how to narrow.
    """
    directory = tmp_path / "overflow"
    seed(directory, 5)
    with pytest.raises(DirectoryScanError) as caught:
        list(iter_eml_dir(directory, max_files=3))
    error = caught.value
    assert error.reason == BOUND_FILES
    message = str(error)
    assert "bound" in message, f"a refusal has to name the bound it hit: {message}"
    assert "3" in message, f"a refusal has to state the number it hit: {message}"
    assert str(directory) in message, f"a refusal has to name the directory: {message}"
    assert "narrow" in message, f"a refusal has to say how to narrow: {message}"
    assert "partial" in message, f"a refusal has to offer the partial opt-in: {message}"


def test_a_deeper_directory_than_the_bound_is_a_refusal_not_a_shallow_scan(
    tmp_path
):
    directory = tmp_path / "deep"
    nested = directory
    for level in range(DEFAULT_MAX_EML_DEPTH + 2):
        nested = nested / f"level_{level}"
    nested.mkdir(parents=True)
    shutil.copyfile(SEED, nested / "buried.eml")

    with pytest.raises(DirectoryScanError) as caught:
        list(iter_eml_dir(directory))
    assert caught.value.reason == BOUND_DEPTH
    assert str(directory) in str(caught.value)
    assert "bound" in str(caught.value)


def test_the_depth_bound_is_measured_not_assumed(tmp_path):
    """The whole point is that an absurd root stops, so prove it with a clock.

    ``/`` on this host holds a network mount with 6,297 ``.eml`` files behind it.
    The unbounded walk took 44,731 ms; a bounded refusal must take milliseconds,
    and a bound that needs minutes to bind is not a bound. The ceiling asserted
    here is two orders of magnitude above what the refusal actually costs, so it
    cannot flake on a loaded machine and still catches the regression it exists
    to catch.
    """
    started = time.perf_counter()
    with pytest.raises(DirectoryScanError):
        list(iter_eml_dir(os.sep))
    elapsed = time.perf_counter() - started
    assert elapsed < 5.0, f"scanning {os.sep!r} took {elapsed * 1000:.1f} ms"


def test_a_root_that_resolves_into_a_system_tree_is_refused_by_name():
    """``/proc`` is not a mail corpus with a long name; it is a refusal.

    Pointed at directly, a depth bound alone would still walk tens of thousands of
    virtual files, and reading them can block outright. Refusing the root is the
    same house rule ``attachments.py`` applies to a quarantine directory that
    resolves somewhere forbidden.
    """
    present = [tree for tree in NON_DATA_TREES if pathlib.Path(tree).is_dir()]
    if not present:  # a host with no procfs has nothing to refuse
        assert not any(pathlib.Path(tree).exists() for tree in NON_DATA_TREES)
        return
    for tree in present:
        with pytest.raises(DirectoryScanError) as caught:
            list(iter_eml_dir(tree))
        assert caught.value.reason == BOUND_ROOT
        assert tree.lstrip(os.sep) in str(caught.value)
        assert "not a mail corpus" in str(caught.value)


def test_a_symlink_named_like_a_system_tree_is_not_walked_as_one(tmp_path):
    """A corpus directory called ``dev`` is data, and stays data.

    The system trees are matched against resolved absolute paths for exactly this
    reason: a name-based rule would refuse a reviewer's ``~/dev/mail`` corpus.
    """
    (tmp_path / "dev").mkdir()
    (tmp_path / "sys").mkdir()
    shutil.copyfile(SEED, tmp_path / "dev" / "one.eml")
    shutil.copyfile(SEED, tmp_path / "sys" / "two.eml")
    names = sorted(p.name for p in iter_eml_dir(tmp_path))
    assert names == ["one.eml", "two.eml"]
    scan = scan_eml_dir(tmp_path)
    assert scan.trees_pruned == ()
    assert scan.complete is True


# --------------------------------------------------------------------------
# the explicit opt-in, recorded
# --------------------------------------------------------------------------


def test_a_partial_scan_is_an_opt_in_and_is_recorded_on_the_result(tmp_path):
    directory = tmp_path / "corpus"
    seed(directory, 5)
    scan = scan_eml_dir(directory, max_files=3, allow_partial=True)
    assert scan.bound == BOUND_FILES, "the bound has to be recorded, not swallowed"
    assert scan.complete is False
    assert scan.files_found == 3
    assert scan.refusal(), "a partial scan still has to explain its own bound"
    # ...and the refusal text is the same text a caller that refused would emit.
    assert "bound" in scan.refusal()

    # The generator form honours the same opt-in rather than a second rule.
    assert len(list(iter_eml_dir(directory, max_files=3, allow_partial=True))) == 3


def test_a_partial_depth_scan_is_recorded_too(tmp_path):
    nested = tmp_path / "tree"
    target = nested
    for level in range(DEFAULT_MAX_EML_DEPTH + 1):
        target = target / f"l{level}"
    target.mkdir(parents=True)
    shutil.copyfile(SEED, target / "buried.eml")
    shutil.copyfile(SEED, nested / "top.eml")
    scan = scan_eml_dir(nested, allow_partial=True)
    assert scan.bound == BOUND_DEPTH
    assert scan.complete is False
    assert [p.name for p in scan.paths] == ["top.eml"]


def test_the_summary_block_says_what_was_scanned(tmp_path):
    """The auditable unit: root, count, bound, completeness, and the skips.

    A batch answer that does not say whether it saw everything cannot be audited,
    so every field the scanner knows is in the block it hands to a caller.
    """
    directory = tmp_path / "corpus"
    seed(directory, 2)
    scan = scan_eml_dir(directory)
    summary = scan.summary()
    assert summary["root"] == str(directory)
    assert summary["files_found"] == 2
    assert summary["bound"] is None
    assert summary["complete"] is True
    assert summary["max_files"] == DEFAULT_MAX_EML_FILES
    assert summary["max_depth"] == DEFAULT_MAX_EML_DEPTH
    assert summary["directories_visited"] == 1
    assert summary["symlinks_skipped"] == 0
    assert summary["trees_pruned"] == []


# --------------------------------------------------------------------------
# symlinks: the bounded walk that is still unbounded
# --------------------------------------------------------------------------


def test_a_symlinked_directory_leaving_the_root_is_not_walked(tmp_path):
    """A symlink to a mail store is the bounded walk that reads the machine anyway.

    ``rglob`` did not follow symlinked directories on this interpreter, but that is
    a detail of one standard-library implementation: the walk's own contract says
    it does not leave the root, and it is enforced here rather than inherited.
    """
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    seed(outside, 3)
    inside = tmp_path / "corpus"
    inside.mkdir()
    shutil.copyfile(SEED, inside / "mine.eml")
    os.symlink(outside, inside / "link_to_elsewhere")

    names = sorted(p.name for p in iter_eml_dir(inside))
    assert names == ["mine.eml"], (
        f"the walk left its root through a symlinked directory: {names}"
    )
    scan = scan_eml_dir(inside)
    assert scan.symlinks_skipped == 1
    assert all(outside.name not in str(p) for p in scan.paths)


def test_a_symlinked_file_leaving_the_root_is_not_yielded(tmp_path):
    """The file form of the same escape, which ``rglob`` *did* allow.

    A symlink to one message outside the root used to come back as a path inside
    it, so a corpus could hand over mail the caller was never pointed at while
    looking exactly like a filename in its own directory.
    """
    outside = tmp_path / "other-people"
    outside.mkdir()
    shutil.copyfile(SEED, outside / "not_yours.eml")
    inside = tmp_path / "corpus"
    (inside / "sub").mkdir(parents=True)
    shutil.copyfile(SEED, inside / "mine.eml")
    os.symlink(outside / "not_yours.eml", inside / "sub" / "looks_local.eml")

    found = sorted(str(p) for p in iter_eml_dir(inside))
    assert found == [str(inside / "mine.eml")], f"the walk left its root: {found}"
    assert "not_yours" not in " ".join(found)
    assert scan_eml_dir(inside).symlinks_skipped == 1


def test_a_symlink_to_a_message_inside_the_root_is_still_that_message(tmp_path):
    """An alias within the corpus is not an escape, and refusing it would be a lie.

    Mail stores symlink the same message from several folders; the rule is about
    leaving the root, and a resolved target inside it satisfies that.
    """
    inside = tmp_path / "corpus"
    (inside / "inbox").mkdir(parents=True)
    (inside / "archive").mkdir()
    shutil.copyfile(SEED, inside / "inbox" / "one.eml")
    os.symlink(inside / "inbox" / "one.eml", inside / "archive" / "one_copy.eml")
    names = sorted(p.name for p in iter_eml_dir(inside))
    assert names == ["one.eml", "one_copy.eml"]
    assert scan_eml_dir(inside).symlinks_skipped == 0
