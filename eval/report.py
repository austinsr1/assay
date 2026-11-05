"""Render the metrics produced by ``eval/run.py`` as Markdown.

Kept separate from the measurement so the numbers can be emitted as JSON for a
machine and as prose for a reader without either format dictating the other. The
renderer adds no interpretation of its own: every figure it prints comes from the
payload, and the caveats it repeats are the ones the payload carries.

Nothing here may compute a metric. A renderer that recalculates is a second
implementation of the measurement, and the two will disagree in whichever
direction flatters the result.

Neither may this file silently drop a section. ``eval/run.py`` attaches a
``selective`` block to every corpus it measures, so a payload without one came
from a harness older than those metrics or was edited by hand: rendering it as
though it had nothing to say would make an absent measurement and an empty one
look identical. That is why the renderer raises, and why the only way past the
raise is a caller saying so out loud.
"""

from __future__ import annotations

from typing import Any


class MissingSelectiveMetrics(ValueError):
    """A payload with no ``selective`` block was rendered as though it had one.

    Raised by :func:`_selective_section` unless the caller passed
    ``require_selective=False``, which converts the loud failure into a
    deliberate, visible choice at the call site instead of a default.
    """


class MalformedExternalMetrics(ValueError):
    """An ``external`` block is present but does not carry what it must.

    Raised rather than skipped because the block is the only place a reader learns
    that a number came from a fetched corpus wrapped in a synthesized envelope. A
    renderer that printed a rate without its licence, revision and limitation would
    turn a measurement about text into an apparent measurement about mail - which is
    the exact failure this repository has been burned by repeatedly. Silence and
    absence are different facts: a payload with no ``external`` key at all is a
    payload measured without ``--external``, and that is rendered as a stated
    absence, not an error.
    """

#: What every external corpus descriptor must carry for its numbers to be printable.
#: ``limitation`` is here because the constraint is structural, not incidental.
REQUIRED_EXTERNAL_FIELDS = (
    "dataset", "label", "revision", "license_observed", "license_verified_on",
    "sha256", "source_url", "row_count_file", "rows_in_corpus", "rows_used",
    "sample", "label_source", "limitation", "synthetic_envelope", "text_origin",
)

#: What the whole block must carry, whether or not anything was measured.
#: ``model_tier`` is required because its absence is the one way this report could imply
#: that the model A/B ran and produced nothing worth printing; ``per_dataset`` is
#: required because the figures a decision is taken on - 339 benign trigger-word prompts,
#: 263 injection-labelled rows against 399 not-injection-labelled ones - are sums over
#: corpora, and a reader shown only per-file tables would have to do that arithmetic, in
#: whichever direction flatters the result.
REQUIRED_BLOCK_FIELDS = (
    "status", "headline", "limitation", "synthetic_envelope", "results", "corpora",
    "unavailable", "model_tier", "per_dataset",
)

#: The sentence that must appear wherever a corpus produced neither a clearance nor an
#: accusation. "0.0% false positives" over a corpus that cleared nothing is an absence of
#: evidence, and the artifact produced by phase 1 printed 0.0% for three corpora without
#: saying so next to the number.
NON_DISCRIMINATING_STATEMENT = (
    "**NON-DISCRIMINATING ON THIS AXIS.** This corpus produced 0 clearances and 0 "
    "accusations, so the 0.0% false-positive and 0.0% coverage rates printed above are "
    "one absence described twice, not two results: a rate of 0 over a population this "
    "configuration never decided anything about is an absence of evidence. The "
    "synthesized envelope removes the positive evidence the clearance condition asks "
    "for, so nothing here *could* clear, and a pipeline that accused nothing over a "
    "corpus it also cleared nothing has been shown neither to over-fire nor to hold. "
    "Read the input-side injection-indicator rate - same denominator, and it does "
    "discriminate - and read this corpus as a coverage cost (every message went to a "
    "person), never as a false-positive achievement."
)


def non_discriminating(metrics: dict[str, Any]) -> bool:
    """Whether a measured corpus decided nothing and accused nothing, and so shows nothing.

    Owned by the renderer because the renderer is what would otherwise print 0.0% and
    let it be read as a result. Deliberately keyed on the two rates rather than on the
    deferral count: a corpus where every row is deferred is exactly a corpus where
    nothing was decided, and the condition states the property that makes the rates
    vacuous instead of a symptom of it.
    """
    if not metrics.get("messages"):
        return False
    return (not metrics.get("auto_clearance_rate")
            and not metrics.get("accusation_rate"))


def _pct(value: float | None) -> str:
    """A rate as a percentage, or an explicit 'n/a' rather than a blank or a zero.

    A rate over an empty denominator is not zero, and printing 0% would claim a
    measurement that was never made.
    """
    if value is None:
        return "n/a (nothing to measure over)"
    return f"{value * 100:.1f}%"


def _int_or_none(value: Any) -> str:
    return "n/a" if value is None else str(value)


def _corpus_section(
    name: str, metrics: dict[str, Any], *, require_selective: bool = True
) -> list[str]:
    out = [f"### Corpus: `{name}` ({metrics['kind']})", ""]
    out.append(f"{metrics['messages']} message(s).")
    out.append("")

    out.append("| Disposition | Count |")
    out.append("|---|---:|")
    for disposition, count in metrics["by_disposition"].items():
        out.append(f"| `{disposition}` | {count} |")
    out.append("")

    out.append("| Metric | Value |")
    out.append("|---|---|")
    out.append(f"| Auto-clearance rate | {_pct(metrics['auto_clearance_rate'])} |")
    out.append(f"| Escalation rate (a human looks) | {_pct(metrics['escalation_rate'])} |")
    out.append(f"| Accusation rate (threat or spam) | {_pct(metrics['accusation_rate'])} |")
    out.append(
        f"| Dispositioned with no model call | {_pct(metrics['no_model_call_rate'])} "
        f"({metrics['model_assisted']} of {metrics['messages']} used a model) |"
    )

    if non_discriminating(metrics):
        # Not a footnote and not a separate section: the sentence has to sit where the
        # 0.0% rates were just printed, or a reader who stops at the table never meets
        # it. This is the guard against phase 1's framing - three corpora, 603 messages,
        # every one deferred, and the artifact's headline numbers were 0.0% false
        # positives.
        out += ["", NON_DISCRIMINATING_STATEMENT, ""]

    if metrics["kind"] == "hostile":
        out.append("")
        out.append(
            "Every message in this corpus is hostile by construction, so the only "
            "number that matters is how many were cleared."
        )
        out.append("")
        out.append("| Metric | Value |")
        out.append("|---|---|")
        out.append(f"| **Hostile messages cleared** | **{metrics['hostile_cleared_count']}** |")
        out.append(f"| Hostile messages deferred to a human | {metrics['hostile_deferred']} |")
        out.append(f"| Hostile messages accused | {metrics['hostile_accused']} |")
        cleared = metrics["hostile_cleared"]
        out.append(
            "| Cleared (each is a finding, not a statistic) | "
            + (", ".join(f"`{c}`" for c in cleared) if cleared else "none")
            + " |"
        )
        declared_open = metrics["declared_open"]
        out.append(
            "| Declared open in the manifest | "
            + (", ".join(f"`{c}`" for c in declared_open) if declared_open else "none")
            + " |"
        )
        regression = metrics["cleared_while_declared_closed"]
        out.append(
            "| **Cleared despite being declared closed** | "
            + (
                "**REGRESSION: " + ", ".join(f"`{c}`" for c in regression) + "**"
                if regression else "none"
            )
            + " |"
        )
    else:
        agreement = metrics["label_agreement"]
        out.append("")
        out.append(
            "Labels come from `labels.json` beside the messages, never from a file "
            "name, so the measurement cannot flatter itself by renaming a fixture. "
            "A deferral is counted separately from agreement and from disagreement: "
            "it is a coverage cost, not a wrong answer, and lumping it with either "
            "hides something."
        )
        out.append("")
        out.append("| Label agreement | Count |")
        out.append("|---|---:|")
        for key in ("agree", "escalated", "disagree", "unlabelled"):
            out.append(f"| {key} | {agreement[key]} |")
        out.append("")
        out.append("| Error metric | Value |")
        out.append("|---|---|")
        out.append(
            f"| **False negatives** (hostile label, cleared) | "
            f"**{metrics['false_negative_count']}** "
            f"of {metrics['hostile_messages']} hostile |"
        )
        out.append(
            f"| **False-negative rate among auto-closed** | "
            f"**{_pct(metrics['false_negative_rate_among_auto_closed'])}** |"
        )
        out.append(
            f"| False accusations (clean label, called threat or spam) | "
            f"{metrics['false_accusation_count']} of {metrics['benign_messages']} benign |"
        )
        out.append(
            f"| False-accusation rate among benign | "
            f"{_pct(metrics['false_accusation_rate_among_benign'])} |"
        )
        out.append(
            f"| Hostile auto-clear rate | {_pct(metrics['hostile_auto_clear_rate'])} "
            f"({metrics['hostile_auto_cleared']} of {metrics['hostile_messages']}) |"
        )
        if metrics["false_negatives"]:
            out.append("")
            out.append("False negatives, named:")
            out.append("")
            for entry in metrics["false_negatives"]:
                out.append(f"- `{entry['case']}` (label `{entry['label']}`)")
        if metrics["false_accusations"]:
            out.append("")
            out.append("False accusations, named:")
            out.append("")
            for entry in metrics["false_accusations"]:
                out.append(f"- `{entry['case']}` (dispositioned `{entry['got']}`)")

    out += _selective_section(
        name, metrics, require_selective=require_selective
    )
    out.append("")
    return out


def _selective_section(
    name: str, metrics: dict[str, Any], *, require_selective: bool = True
) -> list[str]:
    """The selective-prediction view, rendered without recalculating anything.

    Every number comes from the committed artifact. This function performs no
    arithmetic on the measurements beyond formatting, because a renderer that
    recomputes is a second source of truth that can disagree with the first.

    An absent ``selective`` block raises rather than returning no lines: a
    missing section and a section with nothing to say are different facts, and
    conflating them is how an artifact that predates the metrics quietly stops
    reporting them. ``require_selective=False`` renders such an artifact on
    purpose, and says in the output that the block is absent - there is no
    path through this function that produces silence.
    """
    selective = metrics.get("selective")
    if not selective:
        if not require_selective:
            return [
                "", "#### As a selective prediction system", "",
                "*Not present in this artifact.* It was rendered with "
                "`require_selective=False`, so the coverage and risk numbers "
                "below the heading were never measured here rather than "
                "measured and found wanting.", "",
            ]
        raise MissingSelectiveMetrics(
            f"corpus `{name}` has no `selective` block, so the "
            f"selective-prediction section cannot be rendered. `eval/run.py` "
            f"attaches one to every corpus it measures, so this payload came "
            f"from a harness older than those metrics or was edited by hand. "
            f"Regenerate it with `python3 eval/run.py --json "
            f"-o eval/metrics.json`, or render with "
            f"`require_selective=False` to state that the section is absent "
            f"rather than empty."
        )
    point = selective["operating_point"]
    out = ["", "#### As a selective prediction system", ""]
    out.append(
        "This pipeline is a selective classifier: `manual_review` is a deferral to a "
        "person, not a fourth label. So the operative question is not accuracy but how "
        "much of the queue can be automated and what that automation costs in errors."
    )
    out.append("")
    out.append("| Metric | Value |")
    out.append("|---|---|")
    out.append(f"| Coverage (automated without a human) | {_pct(point['coverage'])} |")
    out.append(
        f"| Selective risk (error rate among automated) | "
        f"{_pct(point['selective_risk'])} |"
    )
    out.append(
        f"| False negatives among automated | "
        f"{_int_or_none(point['hostile_accepted_wrong'])} of "
        f"{_int_or_none(point['hostile_accepted'])} |"
    )
    out.append(
        f"| False accusations among automated | "
        f"{_int_or_none(point['benign_accepted_wrong'])} of "
        f"{_int_or_none(point['benign_accepted'])} |"
    )
    out.append(
        f"| AURC (lower is better) | {_num(selective['aurc'])} |"
    )
    out.append(
        f"| E-AURC (ranking quality, 0 is oracle) | {_num(selective['excess_aurc'])} |"
    )
    out.append(
        f"| Curve points | {_int_or_none(selective['curve_points'])} |"
    )
    out.append("")

    errors = point.get("errors_among_accepted") or []
    if errors:
        out.append("Automated decisions that were wrong, named rather than averaged:")
        out.append("")
        for entry in errors:
            status = entry.get("status")
            tail = " - **declared open**" if status == "open" else ""
            out.append(
                f"- `{entry['case']}` label `{entry['label']}` dispositioned "
                f"`{entry['disposition']}` at {entry['confidence']:.2f}{tail}"
            )
        out.append("")

    budgets = [b for b in selective["coverage_at_risk"] if b["satisfied"]]
    if budgets:
        out.append("Coverage available at each automated-error budget:")
        out.append("")
        out.append("| Risk budget | Coverage | Threshold |")
        out.append("|---|---:|---:|")
        for entry in selective["coverage_at_risk"]:
            out.append(
                f"| <= {_pct(entry['risk_budget'])} | {_pct(entry['coverage'])} "
                f"| {_num(entry.get('threshold'))} |"
            )
        out.append("")
    else:
        out.append(
            "*No automated-error budget in the reported range is achievable on this "
            "corpus.* That is a result, not a gap: it means nothing here can be handed "
            "over without a person."
        )
        out.append("")

    composition = selective["deferral_composition"]
    if composition["deferred"]:
        # ``escalated`` is the ensemble's own flag, and it is set from the
        # disposition as well as from tier disagreement - see
        # src/tenable_email/ensemble.py, where an outcome with no votes still
        # marks itself escalated when it lands on a deferral. In the
        # deterministic-only configuration no tier is reachable at all, so
        # calling these "escalated by a model tier" contradicted the
        # model-assisted count printed three words later.
        out.append(
            f"The deferred slice is {composition['deferred']} message(s): "
            f"{composition['truncated']} truncated, {composition['escalated']} "
            f"flagged escalated by the ensemble, "
            f"{composition['model_assisted']} model-assisted, "
            f"{composition['adversarial']} from the adversarial corpus. If the "
            "selector works as designed this slice is enriched for the hard "
            "cases, which is the point rather than a failure."
        )
        out.append("")

    if not selective.get("calibrated", False):
        out.append(
            "*These scores are not calibrated.* The confidence values in this project "
            "are policy labels - 0.90 for a supported clearance, 0.50 for a deferral - "
            "not probabilities. Selective prediction needs only a ranking, so the curve "
            "is legitimate, but E-AURC and every operating point above inherit that "
            "limit, and no threshold here was chosen with a finite-sample guarantee."
        )
        out.append("")
    return out


# --------------------------------------------------------------------------
# the external-corpus block
#
# Everything below formats. Nothing below computes: the rates come from
# `eval/run.py::measure_corpus`, which measured them with the same code that measures
# the committed corpora, and the provenance comes from `eval/fetch.py`'s manifest via
# `eval/external.py`. A renderer that could fill in a missing licence by guessing
# would be worse than no renderer, so a missing field raises instead.
# --------------------------------------------------------------------------

#: A substring of the limitation that must survive into the prose. Written as a list
#: of required phrases so the check is about meaning rather than about a field
#: existing - the distinction that made `tests/test_eval.py` assert the shape of a
#: printed percentage instead of calling the function that printed it.
LIMITATION_SENTENCES = (
    "plain text, not RFC 822 messages",
    "NOT the authentication layer",
    "manual_review by construction",
)


def _validate_external_block(block: Any) -> None:
    if not isinstance(block, dict):
        raise MalformedExternalMetrics(
            "the `external` block is not an object, so nothing in it can be trusted. "
            "Regenerate with `python3 eval/run.py --json --external`."
        )
    missing = [key for key in REQUIRED_BLOCK_FIELDS if key not in block]
    if missing:
        raise MalformedExternalMetrics(
            f"the `external` block is missing {missing}; it names what the block must "
            "carry so a rate can never be printed without its licence, revision and "
            "synthesized-envelope limitation. Regenerate with "
            "`python3 eval/run.py --json --external` rather than editing the artifact."
        )
    for phrase in LIMITATION_SENTENCES:
        if phrase not in str(block.get("limitation") or ""):
            raise MalformedExternalMetrics(
                f"the external block's `limitation` does not say {phrase!r}. The text "
                "that names the synthesized-envelope constraint is the thing that has "
                "to be present, not a field with that name."
            )
    tier = block.get("model_tier") or {}
    if "HAS NOT RUN" not in str(tier.get("statement") or ""):
        raise MalformedExternalMetrics(
            "the external block's `model_tier` does not state that the model-tier A/B "
            "has not run. Every disposition in this section comes from the "
            "deterministic layer, because a synthesized message has no replay "
            "recording; a report that prints a `corpus-backed` column without saying so "
            "invites a reader to compare a deterministic layer against a model tier "
            "that was never consulted."
        )
    if not isinstance(block.get("per_dataset"), dict):
        raise MalformedExternalMetrics(
            "the external block carries no `per_dataset` rollup, so the only figures a "
            "reader can compare are per pinned file - and the decision-relevant "
            "denominators (339 benign trigger-word prompts; injection-labelled rows "
            "against not-injection-labelled rows) are sums over those files."
        )


def _validate_descriptor(name: str, metrics: dict[str, Any]) -> dict[str, Any]:
    descriptor = metrics.get("external")
    if not isinstance(descriptor, dict):
        raise MalformedExternalMetrics(
            f"external corpus `{name}` has metrics but no `external` descriptor, so "
            "its licence, revision and envelope are unknown and its numbers would read "
            "as though they described real mail. `eval/run.py --external` attaches one "
            "to every corpus it measures, so this payload was edited by hand or came "
            "from an older harness."
        )
    missing = [
        key for key in REQUIRED_EXTERNAL_FIELDS
        if key != "sample" and descriptor.get(key) in (None, "")
    ]
    if descriptor.get("sample") is None:
        missing.append("sample")
    if missing:
        raise MalformedExternalMetrics(
            f"external corpus `{name}` is missing {missing} on its descriptor. A "
            "number whose provenance is absent is not a smaller number, it is a "
            "different kind of claim, and this renderer will not make it."
        )
    for phrase in LIMITATION_SENTENCES:
        if phrase not in str(descriptor.get("limitation") or ""):
            raise MalformedExternalMetrics(
                f"external corpus `{name}` carries a limitation that does not say "
                f"{phrase!r}, so the synthesized-envelope constraint is missing from "
                "the block that produced these numbers."
            )
    return descriptor


def _external_envelope_lines(wrapper: dict[str, Any]) -> list[str]:
    return [
        "**The synthesized envelope, in full.** Every external row was wrapped in this "
        "before the pipeline saw it, and the wrapper is why the numbers below measure "
        "text rather than mail.",
        "",
        "| Envelope field | Value |",
        "|---|---|",
        f"| Assembled with | `{wrapper.get('assembled_with')}` |",
        "| Headers present | "
        + ", ".join(f"`{h}`" for h in wrapper.get("headers_present", [])) + " |",
        "| Headers absent by construction | "
        + ", ".join(f"`{h}`" for h in wrapper.get("headers_absent_by_construction", []))
        + " |",
        f"| Sender | local part `{wrapper.get('from_local_part')}` at domain `{wrapper.get('from_domain')}` |",
        f"| Recipient | local part `{wrapper.get('to_local_part')}` at domain `{wrapper.get('to_domain')}` |",
        f"| Message-ID | `{wrapper.get('message_id_local_part')}` at domain `{wrapper.get('message_id_domain')}` |",
        f"| Date | `{wrapper.get('date')}` |",
        f"| Attachments | {wrapper.get('attachments')} |",
        f"| Links | {wrapper.get('links')} |",
        f"| Subject | {wrapper.get('subject_rule')} |",
        "",
        f"{wrapper.get('domain_note')}",
        "",
        f"{wrapper.get('date_note')}",
        "",
    ]


def _external_provenance_lines(descriptor: dict[str, Any]) -> list[str]:
    sample = descriptor["sample"]
    licenses = descriptor.get("datasets_server_licenses") or []
    license_text = str(descriptor["license_observed"])
    if licenses and license_text.lower() not in [str(v).lower() for v in licenses]:
        license_text = (
            f"{license_text} - **the two fields disagree:** datasets-server's converted "
            f"metadata for the same dataset reports "
            f"{', '.join(str(v) for v in licenses)}. The gate acts on the card, which is "
            "the declaration the author made in the repository; the disagreement is "
            "printed here rather than resolved by this report"
        )
    out = [
        "| Provenance | Value |",
        "|---|---|",
        f"| Dataset | `{descriptor['dataset']}` |",
        f"| Licence | {license_text} ({descriptor.get('license_field')}, read "
        f"{descriptor['license_verified_on']}) |",
        f"| Revision | `{descriptor['revision']}` |",
        f"| File | `{descriptor['file']}` |",
        f"| Source URL | {descriptor['source_url']} |",
        f"| sha256 | `{descriptor['sha256']}` |",
        f"| Rows in file | {descriptor['row_count_file']} "
        f"(method: {descriptor['row_count_method']}) |",
        f"| Rows in this corpus | {descriptor['rows_in_corpus']} |",
        f"| Rows measured | {descriptor['rows_used']} |",
        f"| Sample | seed `{sample['seed']}`, cap {sample['cap']}, "
        + ("whole corpus, no sampling" if sample["all_rows"] else "sampled") + " |",
        f"| Sampling rule | {sample['rule']} |",
        f"| Label authority | {descriptor['label_source']} |",
        f"| Upstream label kept | `{descriptor.get('upstream_label_kept')}` |",
        "| Rows whose upstream label was not this corpus's label | "
        f"{descriptor.get('rows_with_an_unexpected_upstream_label')} |",
        "| Upstream label distribution over the file or retrieval | "
        + ", ".join(f"`{k}` {v}"
                    for k, v in (descriptor.get("upstream_labels_seen") or {}).items())
        + " |",
        "",
    ]
    out += _text_origin_lines(descriptor)
    surface = descriptor.get("text_surface") or {}
    if surface:
        out += [
            f"**The discriminating number for this corpus: its text flagged "
            f"{surface.get('injection_indicator_rows')} of {surface.get('rows')} rows "
            f"as carrying an injection indicator** "
            f"({_pct(surface.get('injection_indicator_rate'))}). {surface.get('note')}",
            "",
        ]
        if surface.get("rows_with_a_derived_subject"):
            out.append(
                f"{surface['rows_with_a_derived_subject']} of these rows carried a "
                "subject the wrapper could derive into a `Subject` header."
            )
            out.append("")
        if surface.get("rows_truncated_by_the_conversion_service"):
            out.append(
                f"> **{surface['rows_truncated_by_the_conversion_service']} row(s) of "
                "this retrieval came back with a cell the conversion service "
                "truncated**, so the text measured is a prefix of the text upstream. "
                f"{surface.get('truncated_cells_note')}"
            )
            out.append("")
    for limit in descriptor.get("measurement_limits") or []:
        out.append(f"> **Out-of-domain limit:** {limit}")
        out.append("")
    for limit in descriptor.get("license_limits") or []:
        out.append(f"> {limit}")
        out.append("")
    return out


def _text_origin_lines(descriptor: dict[str, Any]) -> list[str]:
    """Where the measured text came from, and which digest describes it.

    Two roads, and they are not the same claim. A corpus read out of the repository file
    has its text hash-verified by the digest printed above. A corpus read through the
    datasets-server ROWS API does not: its text came from Hugging Face's converted
    Parquet, and what the two objects are checked against each other for is the split
    name and the row count. Printing one provenance table for both, with the difference
    unstated, would let a converted-text measurement borrow a repository file's digest
    authority.
    """
    origin = descriptor.get("text_origin") or {}
    if not origin:
        return []
    out = [
        "| Where the measured text came from | Value |",
        "|---|---|",
        f"| Read via | `{origin.get('via')}` |",
        f"| Repository file sha256 (pinned, and NOT the bytes the text was read from "
        f"on the rows path) | `{origin.get('repository_file_sha256')}` |",
        f"| Rows in the repository file | "
        f"{origin.get('rows_read_from_repository_file')} |",
        f"| Conversion service used | {origin.get('conversion_service_used')} |",
    ]
    if origin.get("conversion_service_used"):
        retrieval = descriptor.get("rows_retrieval") or {}
        pagination = retrieval.get("pagination") or {}
        out += [
            f"| Split | `{descriptor.get('split')}` |",
            f"| Rows API URL template | `{retrieval.get('api_url_template')}` |",
            f"| Rows API URL for this split | `{retrieval.get('api_url_for_split')}` |",
            "| Pagination | "
            f"{pagination.get('pages_requested')} page(s), offsets "
            f"{pagination.get('offsets')}, length {pagination.get('length')}, "
            f"service page cap {pagination.get('num_rows_per_page_reported_by_service')} |",
            f"| `num_rows_total` reported by the API | "
            f"{origin.get('num_rows_total_reported')} |",
            f"| Rows retrieved | {origin.get('rows_retrieved')} |",
            "| Retrieved row count == API total | "
            f"{origin.get('rows_retrieved') == origin.get('num_rows_total_reported')} |",
            f"| Row counts agree with the repository file | "
            f"{origin.get('row_counts_agree')} |",
            f"| Row cache (contains the text; gitignored) | "
            f"`{retrieval.get('local_path')}` |",
            f"| Row cache sha256 | `{retrieval.get('sha256')}` |",
            f"| Retrieved at | `{origin.get('retrieved_at')}` |",
        ]
    out += ["", f"{origin.get('statement')}", ""]
    return out


def _external_unavailable_lines(items: list[dict[str, Any]]) -> list[str]:
    if not items:
        return [
            "### Nothing permitted and fetched is left unread",
            "",
            "Phase 1 of this harness listed six Parquet files as pinned but unevaluable, "
            "because reading their text needed a column decoder this stdlib-only build "
            "does not carry. None are listed now: every permitted file whose rows could be "
            "retrieved has been, and both objects - the repository file and the "
            "conversion service's rows - are recorded above, per corpus. An empty list "
            "here means the retrieval covered the allowlist, not that the check was "
            "skipped: `eval/external.py` still refuses to measure a corpus whose pinned "
            "file or row cache fails its digest, and says so in this section when one "
            "does.",
            "",
        ]
    out = [
        "### Permitted and fetched, but not measured here",
        "",
        "These are the corpora the licence gate allows and `eval/fetch.py` pinned, which "
        "this build will not run the pipeline over. They are listed with the row counts "
        "and digests that were read off them, so the gap is on the record: a table of "
        "only the sets that happened to be readable would report coverage that was never "
        "measured.",
        "",
        "| Dataset | File | Rows pinned | Licence | Why not evaluated |",
        "|---|---|---:|---|---|",
    ]
    for item in items:
        rows = item.get("row_count_file")
        out.append(
            f"| `{item.get('dataset')}` | "
            f"`{item.get('file') or item.get('repo_path') or 'not fetched'}` | "
            f"{rows if rows is not None else 'n/a'} | "
            f"{item.get('license_observed') or 'n/a'} | "
            f"{str(item.get('reason'))[:200]} |"
        )
    out.append("")
    return out


def _external_section(block: dict[str, Any], *, include_rows: bool = False,
                      require_selective: bool = True) -> list[str]:
    """The whole external block, rendered. No arithmetic, no invention."""
    _validate_external_block(block)
    out = ["## External corpora: fetched at evaluation time, never committed", ""]
    out.append(f"> {block['headline']}")
    out.append("")

    if block["status"] == "not-fetched":
        out.append("**Nothing was measured here, and that is not a zero.**")
        out.append("")
        for line in block.get("detail") or []:
            out.append(f"> {line}")
            out.append("")

    out += [
        "**The limitation travels with every number in this section, and is repeated "
        "per corpus.**",
        "",
        f"> {block['limitation']}",
        "",
    ]
    out += _external_envelope_lines(block["synthetic_envelope"])

    allowed = block.get("allowlisted") or []
    refused = block.get("refused") or []
    out += [
        "The licence gate is closed: a dataset is fetched only if it is listed in "
        "`eval/fetch.py` with a licence read from `cardData.license` on a recorded "
        "date, and that declaration is re-read at fetch time and compared.",
        "",
        f"- Allowlisted: {', '.join(f'`{d}`' for d in allowed) if allowed else 'none'}",
        f"- Refused by name: {', '.join(f'`{d}`' for d in refused) if refused else 'none'}",
        "",
    ]

    out += _external_dataset_lines(block)

    results = block.get("results") or {}
    for config_name, per_corpus in results.items():
        out += [f"### Configuration: `{config_name}`", ""]
        if not per_corpus:
            out += ["*No external corpus was measurable in this configuration.*", ""]
            continue
        for corpus_name, metrics in per_corpus.items():
            descriptor = _validate_descriptor(corpus_name, metrics)
            # Provenance first, then the numbers, and no heading invented for it: the
            # corpus section below comes from `_corpus_section`, the same renderer the
            # committed corpora use, and its `###` level would sit *under* a `####`
            # this function printed for itself.
            out += [
                f"**External corpus `{corpus_name}` - kind `{metrics['kind']}`. "
                "Provenance, then the numbers.**",
                "",
            ]
            out += _external_provenance_lines(descriptor)
            out += [f"*{descriptor['limitation']}*", ""]
            out += _corpus_section(
                corpus_name, metrics, require_selective=require_selective
            )
            if include_rows:
                out += _rows_section(metrics)

    out += _external_unavailable_lines(block.get("unavailable") or [])
    return out


def _external_dataset_lines(block: dict[str, Any]) -> list[str]:
    """The model-tier position of the whole external run, then the per-dataset sums.

    Every number printed here is a count `eval/run.py` already published for a corpus,
    added up. Nothing is re-measured and nothing is divided here: the rates arrive with
    the rollup, because a reader asked to do this arithmetic in their head will do it in
    whichever direction flatters the result.
    """
    tier = block.get("model_tier") or {}
    out = [
        "### The model tier took part in none of this",
        "",
        f"> {tier.get('statement')}",
        "",
        "| Configuration | External messages | Dispositioned with a model judgment |",
        "|---|---:|---:|",
    ]
    for config_name, counts in (tier.get("per_configuration") or {}).items():
        out.append(
            f"| `{config_name}` | {counts.get('messages')} | "
            f"{counts.get('model_assisted')} |"
        )
    out.append("")

    rollup = block.get("per_dataset") or {}
    if not rollup:
        out += [
            "### Per-dataset totals", "",
            "*Nothing was measured on this host, so there is nothing to sum.* This is a "
            "stated absence, not a zero.",
            "",
        ]
        return out
    out += [
        "### Per-dataset totals, with the denominators",
        "",
        "A corpus is one pinned file, so a dataset that ships several files is reported "
        "several times. The sums below add those corpora back together, and they are the "
        "figures a decision is taken on. The two label sides are kept apart on purpose: "
        "a flag rate over hostile-labelled rows and a flag rate over clean-labelled rows "
        "are two measurements with two denominators, and one rate over both is the "
        "mixing of tasks `docs/EVAL-SUITES.md` forbids.",
        "",
        "| Dataset | Corpora | Rows measured | Injection indicators on hostile-labelled "
        "rows | Injection indicators on clean-labelled rows |",
        "|---|---:|---:|---:|---:|",
    ]
    for dataset_id, item in rollup.items():
        surface = item["text_surface"]
        hostile = (
            f"**{surface['hostile_rows_flagged']} of {surface['hostile_rows']}** "
            f"({_pct(surface['hostile_rows_flagged_rate'])})" if surface["hostile_rows"]
            else "no hostile-labelled rows: this set cannot show coverage at all"
        )
        clean = (
            f"**{surface['clean_rows_flagged']} of {surface['clean_rows']}** "
            f"({_pct(surface['clean_rows_flagged_rate'])})" if surface["clean_rows"]
            else "no clean-labelled rows"
        )
        out.append(
            f"| `{dataset_id}` | {len(item['corpora'])} | {surface['rows']} | "
            f"{hostile} | {clean} |"
        )
    out += [
        "",
        "Read those two columns together. A zero in the clean column is not a detector "
        "that is safe; it is a detector that was given a set it cannot be wrong about, "
        "unless the hostile column on the same row is non-zero. NotInject has no hostile "
        "column to compare against - it is a zero-positive set by construction - and the "
        "Bengali smishing set's hostile column is the number that would have to be "
        "non-zero for this surface to make any detection claim outside English email.",
        "",
        "| Dataset | Configuration | Messages | Cleared | Deferred | Accused |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for dataset_id, item in rollup.items():
        for config_name, counts in sorted(item["configurations"].items()):
            out.append(
                f"| `{dataset_id}` | `{config_name}` | {counts['messages']} | "
                f"{counts['cleared']} | {counts['deferred']} | {counts['accused']} |"
            )
    out.append("")
    for dataset_id, item in rollup.items():
        for limit in item.get("measurement_limits") or []:
            out.append(f"> **`{dataset_id}` is out of domain for this measurement:** "
                       f"{limit}")
            out.append("")
    return out


def _num(value: Any) -> str:
    """A number, or an explicit absence. Never a blank that reads as zero."""
    if value is None:
        return "n/a"
    if isinstance(value, dict):
        # An inconsistent oracle comparison is reported rather than hidden.
        return f"{value['value']:.4f} (inconsistent)" if value.get("inconsistent") \
            else f"{value['value']:.4f}"
    return f"{value:.4f}"


def _rows_section(metrics: dict[str, Any]) -> list[str]:
    rows = metrics.get("rows")
    if not rows:
        return []
    out = ["<details><summary>Per-message results</summary>", ""]
    out.append("| Case | Label | Disposition | Conf. | Band | Attack type | Models |")
    out.append("|---|---|---|---:|---|---|---:|")
    for row in rows:
        out.append(
            f"| `{row['case']}` | {row['label']} | `{row['disposition']}` | "
            f"{row['confidence']:.2f} | {row['confidence_band']} | "
            f"{row['attack_type']} | {len(row['model_judgments'])} |"
        )
    out += ["", "</details>", ""]
    return out


def render_markdown(
    payload: dict[str, Any],
    *,
    include_rows: bool = False,
    require_selective: bool = True,
) -> str:
    lines = ["# Evaluation metrics", ""]
    lines += [
        f"Commit `{payload.get('commit_short') or 'unknown'}`"
        f" on `{payload.get('branch') or 'unknown'}`"
        + (" (working tree dirty)" if payload.get("dirty") else "")
        + ".",
        "",
        f"> {payload['note']}",
        "",
    ]

    for config_name, per_corpus in payload["results"].items():
        lines += [f"## Configuration: `{config_name}`", ""]
        if config_name == "deterministic-only":
            lines += [
                "No model tier is reachable. Every tier records UNAVAILABLE and no "
                "model judgment is emitted, so every disposition below comes from "
                "the deterministic layer alone. This is what a reviewer with no "
                "inference host gets, and it is the configuration the adversarial "
                "corpus attacks.",
                "",
            ]
        elif config_name == "corpus-backed":
            lines += [
                "The same, with the committed recordings in `fixtures/replay/` "
                "answering for the tiers. The recordings are real responses "
                "captured against live endpoints, replayed by content address, so "
                "the run is deterministic without needing those endpoints.",
                "",
            ]
        for corpus_name, metrics in per_corpus.items():
            lines += _corpus_section(
                corpus_name, metrics, require_selective=require_selective
            )
            if include_rows:
                lines += _rows_section(metrics)

    if "external" in payload:
        lines += _external_section(
            payload["external"],
            include_rows=include_rows,
            require_selective=require_selective,
        )
    else:
        # No silence about a section that could have been here. `eval/run.py` writes
        # the block only when --external was asked for, so its absence is a fact about
        # how the artifact was generated - which a reader cannot otherwise tell apart
        # from a run that found nothing.
        lines += [
            "## External corpora: not measured in this artifact",
            "",
            "> The `external` block is absent, which means this artifact was generated "
            "without `--external` - not that the public corpora were measured and came "
            "back empty. Generate it with `python3 eval/run.py --json --external -o "
            "eval/metrics.json` after `python3 eval/fetch.py --all`. Nothing fetched is "
            "committed, so a fresh clone starts in this state by design "
            "(docs/EVAL-SUITES.md).",
            "",
        ]

    lines += [
        "## How to read this",
        "",
        "The two numbers that must be read together are the auto-clearance rate "
        "and the false-negative rate among auto-closed messages. A high clearance "
        "rate with an unreported false-negative rate is not a result, it is an "
        "omission: `docs/EVAL-SUITES.md` records a published prompt-injection "
        "model with F1 0.992 whose false-positive rate was 1.00, meaning it "
        "flagged everything, and reading the headline number alone would have "
        "selected it.",
        "",
        "Equally, a low clearance rate is not a virtue. Escalating everything is "
        "also safe and is useless, which is why "
        "`tests/test_pipeline.py::test_the_clearance_gate_was_tightened_and_not_simply_abandoned` "
        "pins a floor on how many benign fixtures must still clear. Safety and "
        "coverage are reported together or the report is advocacy.",
        "",
        "These corpora are small and constructed. Nothing here is an accuracy "
        "estimate for real mail, and this project makes no accuracy claim in its "
        "README. What the numbers establish is which dispositions the pipeline "
        "reaches, what they cost, and that the answer is reproducible offline by "
        "someone with no access to any inference host.",
        "",
    ]
    return "\n".join(lines)
