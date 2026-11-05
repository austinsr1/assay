# Listing validation - tested against the real validator

Everything in this file was produced by running the actual
`validator.py` from `tenable/cyberagents-exchange`, not by reading it.
Retrieved and executed 2026-11-02. Reproduce with
`tools/validate-listing.sh`.

Environment used: `uv venv`, then `uv pip install python-frontmatter pydantic
rich typer`. Note the dependency trap - installing the PyPI package named
`frontmatter` **breaks** the validator with `module 'frontmatter' has no
attribute 'load'`. The correct package is **`python-frontmatter`**, which
provides the `frontmatter` import name. If both are installed the wrong one
shadows the right one and leaves a namespace-package stub; recreate the venv
rather than trying to uninstall.

Invocation is `python validator.py --path <exchange-root>`, **not** a positional
argument and **not** a `validate` subcommand - Typer collapses the single command
into an option. The root must contain `agents/`, `mcp-servers/`, `skills/` and
`playbooks/`, **all four**, and each must contain only listing files: the
validator iterates every entry and raises on a non-`.md` suffix, so a `.gitkeep`
in a listing directory is a hard error. Directories must be genuinely empty.

`CONTRIBUTING.md` is validated for vocabulary drift only if present in the root.
Omit it when testing a single listing.

Exit code is 1 on any failure.

---

## Verified passing shapes

Two drafts are committed and both pass:

- `docs/listing-drafts/mcp-server.md` - `runtime: python`, `transport: stdio`,
  `auth_method: none`, `domains: [email-collaboration-security,
  security-operations]`, `integrations: [GCP]`, three tools declared
- `docs/listing-drafts/playbook.md` - `playbook_type: standard` with a mandatory
  `agents_used` list using `type: github` refs

## Empirical failure matrix

Each row was executed against the real validator.

| Mutation | Result | Detail |
|---|---|---|
| baseline MCP draft | **pass** | control |
| baseline playbook draft | **pass** | control |
| `integrations: []` | **pass** | empty list is accepted. Matters if the Google adapter is cut - claiming `GCP` while shipping no Google code would fail the reviewer check that metadata reflects repository reality |
| `tools_exposed: []` | **pass** | empty accepted, but a server listing with no tools is self-defeating |
| `contribution_agreement_date: 2026-11-04` (date only) | **pass** | validator is laxer than the docs. CONTRIBUTING.md asks for ISO 8601 date **and time**, so keep the full timestamp |
| `domains: ["ai-security"]` | **pass** | validates, but CONTRIBUTING.md warns this domain means security *of* AI systems and is over-claimed. Expect reviewer pushback. Ours is `email-collaboration-security` |
| `integrations: ["Google Workspace"]` | **fail** | not in the vocabulary. Use `GCP`, or add the value alphabetically to `validator.py` in the same PR |
| `compatible_clients: ["pi"]` | **fail** | not in the vocabulary. Declare only clients actually tested, or propose adding the value in the same PR |
| `transport: "websocket"` | **fail** | must be `stdio`, `http` or `both` |
| `runtime: "python3"` | **fail** | must be `binary`, `bun`, `go`, `node`, `python` or `rust` |
| three `domains` values | **fail** | `domains must have 1-2 values (first is primary)` |
| `tier: "vetted"` | **fail** | `tier 'vetted' requires both vetted_on and vetted_commit_sha`. Always submit `contributed` |
| missing `transport` | **fail** | `Field required` |
| missing `tools_exposed` | **fail** | `Field required` |
| `type: "vendor"` agent in a **standard** playbook | **fail** | `no_vendor_agents` - only `sponsored` playbooks may use vendor agents |
| standard playbook with no `agents_used` | **fail** | required for `standard`; optional only for `n8n` |

## Validator discovered by test, not by reading

The error output exposed a `hexa_mcp_requires_integration()` model validator that
is not mentioned in CONTRIBUTING.md: setting
`works_with_tenable_hexa_mcp: true` requires `Tenable Hexa AI MCP` to appear in
`integrations`. We set it `false`, so it does not bind - but do not flip it
without adding that integration value.

Also present: `vetted_review_fields_match_tier()`, consistent with the `tier`
row above.

## Consequences for Wednesday

- The listing shape is **not** a schedule risk. Both candidate artifacts already
  pass the real validator, and the failure modes are enumerated above.
- `integrations` is the one field that depends on what we actually ship. If the
  Google Alert Center adapter is cut from the 48-hour scope, declare
  `integrations: []` rather than `GCP`.
- `compatible_clients` must name only clients we have actually run against. If we
  cannot test Claude Code or Claude Desktop before the freeze, this needs a
  decision - the vocabulary has no `pi` and a false claim is a reviewer finding.
- Re-run `tools/validate-listing.sh` after any frontmatter edit, and again
  immediately before opening the PR. Validator vocabularies can change upstream.
