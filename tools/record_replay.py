#!/usr/bin/env python3
"""Record real model responses for the synthetic corpus into the replay store.

Run it through ``tools/record-replay.sh``, which loads endpoints from the
environment. This script never contains an address: endpoints arrive through
``ModelEndpoints.from_env`` and every one of them defaults to ``None``, so a tier
with no environment entry is reported as not configured and nothing is recorded
for it.

What it does, per fixture in sorted order: build the same payload the pipeline
would build (the same tier ``prepare`` methods, the same prompt builder, the same
link and image selection), call the tier live, and let
:class:`~tenable_email.tiers.Tier` write the recording into the store. That
identity is the point -- a recording made by a different code path would not be
found by the key the pipeline computes, and the offline demo would miss.

What it never does: fabricate an entry. A tier that is unreachable, that times
out, or that answers in a form this project cannot read contributes no recording
and shows up in the failure count instead. The corpus is then replayed with that
tier UNAVAILABLE, which is the honest outcome; a hand-written recording would be
simulated evidence offered as closure.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email.config import Config  # noqa: E402
from tenable_email.parse import iter_eml_dir, parse_file  # noqa: E402
from tenable_email.pipeline import (  # noqa: E402
    build_evidence,
    derive_facts,
    tier_requests,
)
from tenable_email.replay import ReplayStore  # noqa: E402
from tenable_email.signals import extract_signals  # noqa: E402
from tenable_email.tiers import TIER_REGISTRY, consult, read_judgment  # noqa: E402

DEFAULT_FIXTURES = REPO / "fixtures" / "synthetic"
DEFAULT_STORE = REPO / "fixtures" / "replay"

#: A tier whose first call fails this way is not going to answer for the rest of
#: the corpus either, so it is probed once and then left alone. The reason string
#: is what :meth:`tenable_email.tiers.Tier._call_live` produces for a transport
#: failure, and it is matched on its stable prefix rather than its detail.
_TRANSPORT_PREFIX = "unreachable after"


def record_corpus(
    fixtures: Path, store: ReplayStore, config: Config, *, verbose: bool = True
) -> tuple[Counter, Counter]:
    """Call every reachable tier for every fixture. Returns (recorded, failed)."""
    recorded: Counter = Counter()
    failed: Counter = Counter()
    skipped: set[str] = set()

    paths = list(iter_eml_dir(fixtures))
    for index, path in enumerate(paths, 1):
        msg = parse_file(path, body_char_limit=config.thresholds.body_char_limit)
        signals = extract_signals(msg, config.profile, config.thresholds)
        evidence = build_evidence(msg, signals, config, store=None)
        requests = tier_requests(
            msg, signals, derive_facts(signals, evidence), config,
            record_pass=True,
        )
        asked: Counter = Counter()
        for tier, request in requests:
            if tier.name in skipped:
                continue
            asked[tier.name] += 1
            result = consult(tier, request, config, store)
            if not result.available:
                # Not configured: nothing to record, and the other tiers for this
                # fixture are still worth asking.
                skipped.add(tier.name)
                if verbose:
                    print(
                        f"  [{index}/{len(paths)}] {path.stem}: {tier.name}: "
                        f"{result.error} -> tier not configured, nothing recorded"
                    )
                continue
            if not result.ok:
                failed[tier.name] += 1
                if verbose:
                    print(
                        f"  [{index}/{len(paths)}] {path.stem}: {tier.name}: "
                        f"FAILED {result.error}"
                    )
                if (result.error or "").startswith(_TRANSPORT_PREFIX):
                    skipped.add(tier.name)
                    if verbose:
                        print(
                            f"  {tier.name}: unreachable, not asking it again for "
                            f"the remaining {len(paths) - index} fixture(s)"
                        )
                continue
            recorded[tier.name] += 1
            if verbose:
                note = ""
                try:
                    judgment = read_judgment(result, config)
                    note = f" -> {judgment.stance.value}"
                    if judgment.confidence is not None:
                        note += f" {judgment.confidence:.2f}"
                except Exception as exc:  # a recorded answer we cannot read
                    note = f" -> UNREADABLE {exc}"
                print(
                    f"  [{index}/{len(paths)}] {path.stem}: {tier.name}: "
                    f"recorded ({result.latency_ms:.0f} ms){note}"
                )
        if verbose and not asked:
            print(f"  [{index}/{len(paths)}] {path.stem}: no tier consulted")
    return recorded, failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES,
                        help="directory of .eml files (default: fixtures/synthetic)")
    parser.add_argument("--store", type=Path, default=DEFAULT_STORE,
                        help="replay store directory (default: fixtures/replay)")
    parser.add_argument("--quiet", action="store_true", help="per-tier totals only")
    parser.add_argument("--dry-run", action="store_true",
                        help="list which tiers are configured and stop")
    args = parser.parse_args(argv)

    config = Config.from_env()
    # Record mode, whatever the environment said: this tool exists to write
    # recordings, and replay mode would read them instead.
    config = Config(
        profile=config.profile,
        thresholds=config.thresholds,
        endpoints=config.endpoints,
        replay=False,
        replay_dir=str(args.store),
    )

    configured = [tier.name for tier in TIER_REGISTRY if tier.configured(config)]
    print(f"fixtures:   {args.fixtures}")
    print(f"store:      {args.store}")
    print(f"endpoints:  {', '.join(configured) or '(none configured)'}")
    for tier in TIER_REGISTRY:
        if tier.configured(config):
            print(f"  role {tier.name:20} -> {tier.role(config)}")
    if args.dry_run:
        unconfigured = [
            tier.name for tier in TIER_REGISTRY if not tier.configured(config)
        ]
        print(f"unconfigured tiers (left UNAVAILABLE): {', '.join(unconfigured)}")
        return 0
    if not configured:
        print(
            "\nERROR: no tier has an endpoint in the environment, so there is "
            "nothing to record. Endpoints come from TENABLE_EMAIL_* variables; "
            "see tools/record-replay.sh. Nothing is fabricated here, so nothing "
            "can be recorded without a live service."
        )
        return 1

    store = ReplayStore(
        root=args.store,
        forbidden=tuple(config.endpoints.configured_addresses()),
        secrets=tuple(
            v for v in (config.endpoints.llm_api_key, config.endpoints.vlm_api_key)
            if v
        ),
    )
    if not args.quiet:
        print()
    recorded, failed = record_corpus(
        args.fixtures, store, config, verbose=not args.quiet
    )

    print("\nper-tier recording totals")
    print(f"{'tier':22} {'recorded':>9} {'failed':>7}  store entries")
    counts = store.counts_by_tier()
    for tier in TIER_REGISTRY:
        print(
            f"{tier.name:22} {recorded.get(tier.name, 0):>9} "
            f"{failed.get(tier.name, 0):>7}  {counts.get(tier.name, 0):>4}"
        )
    print(
        f"{'TOTAL':22} {sum(recorded.values()):>9} {sum(failed.values()):>7}  "
        f"{store.total:>4}"
    )
    print(f"\nhits={store.hit_count} misses={store.miss_count}")
    if not recorded:
        print(
            "\nWARNING: nothing was recorded. The tiers above that show 0/failed "
            "were unreachable from this host; the corpus will replay with those "
            "tiers UNAVAILABLE, which is reported, not hidden."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
