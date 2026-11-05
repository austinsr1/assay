# Prior SWARM winners - what actually placed

SWARM Black Hat 2026 winners, announced by the activity coordinator 2026-11-02.
All three listing pages read in full the same day.

| Place | Team | Type | Listing |
|---|---|---|---|
| 1st | Vauban (Zane, Abdellatif) | **playbook** | `exchange.tenable.com/playbooks/chokepoint-remediation-playbook/` |
| 2nd | ShellCodeandChill (Mauricio, Ricky) | **mcp-server** | `exchange.tenable.com/mcp-servers/cxone-tenablewas-correlation/` |
| 3rd | ZeroSignal (Matthew, Julio) | **agent** | `exchange.tenable.com/agents/evidence-backed-vulnerability-investigator/` |

All three MIT. All three added 2026-08-05.

**Playbooks are valid and can win.** This supersedes the earlier reading of
contest rules section 1, which enumerates only agents, skills and MCP servers.
Confirmed by the activity coordinator and by 1st place being a playbook.

---

## 1st place - Chokepoint Remediation Playbook

*"An eight-stage remediation chain from thousands of findings to a handful of
proven fixes, with a human checkpoint before every external mutation and a
runner that enforces the contract offline."*

### The mechanisms that distinguish it

- **`stages.yaml` is the single machine-readable definition of the chain.** Each
  stage declares its capability, who provides it, whether that provider is
  read-only or write, and where approvals bind.
- **The prose playbook and the runnable slash command are validated against that
  file, not trusted to stay in sync.** The validator asserts both documents
  contain exactly the stages of `stages.yaml` in order under the same titles;
  that every named provider exists in the component registry and is classified
  read-only or write; that every referenced MCP tool is one the server actually
  ships; and that every mutating stage declares human approval with matching
  approval language in the text.
- **The test suite proves the validator has teeth by injecting drift** - a
  dropped stage, a renamed tool, a stripped approval - and asserting validation
  fails.
- **A bundled offline state-machine runner enforces the receipt contract without
  calling any live system.** It refuses: skipped stages, pre-gate or altered
  manifests, widened target sets, replayed or stale or mismatched approvals,
  later waves before proof, mismatched source scopes, rescan-digest drift, and
  **simulated evidence offered as closure**.
- **Refused transitions are transactional** - they consume no receipt and leave
  no partial state.
- **Stage owners are deliberately swappable** because interfaces are expressed as
  *capabilities rather than products*. A different scanner, ticketing system or
  patch platform slots in.
- **Every external mutation takes its own explicit approval** - not just the
  infrastructure change. Opening the change ticket, notifying SOC, opening a
  hunt ticket and launching the verification scan each count as mutations and
  each require their own yes.
- **The playbook holds no credentials, no collectors and no write path of its
  own.**
- **It is explicit about the boundary of what the runner can prove:** it
  validates receipt structure and consistency, but does not authenticate the
  claimed human identity and cannot attest that a dishonest connected tool
  behaved as its receipt says. *"Approval identity is only as strong as the
  system that issues and transports the operator receipt."*

### Its agent chain

1. Orchestrator - carries the loop end to end, collapses findings into shared
   fixes, ranks them, gates unsafe targets, and **holds no external write tools**
2. MCP server - provides the typed tools the chain binds to: ingest, rank,
   pre-flight, plan hashing, execution accounting, verification
3. A portable, dependency-free form of the same ranking method, for operators
   running the chain without the MCP server
4. Read-only collection of findings and asset context, plus the authoritative
   re-scan the verification stage diffs against
5. A manual step (AWS MCP Server) - read-only posture collection and the
   execution path for approved changes under the operator's own credentials

## 2nd place - ThreatCorralling (MCP server)

Frontmatter: `transport: stdio`, `runtime: python`, MIT.

Built with a **FastMCP wrapper**. Per its own description it *"sits in the
background and waits for an external AI to ask for a correlation"*, then
*"executes the tools locally and passes the data back to the AI."* Caches
results for performance, and says plainly that the cache *"can be replaced by a
database or any other better persistence method."*

This validates the exact shape recommended for this project: **python + stdio +
FastMCP, with an external model orchestrating and the server holding the typed
tools.** Note also the honest treatment of a known limitation in the listing
body.

## 3rd place - Evidence-Backed Vulnerability Investigator (agent)

A local Streamlit prototype. Loads findings from CSV/JSON **or bundled
samples**. Deterministically matches against local Markdown vendor advisories
using exact CVE/plugin-ID match, product/vendor/version overlap and keyword
scoring - explicitly **"no embeddings"** - then asks Claude to recommend one of
four dispositions: `REMEDIATE`, `RECAST_MITIGATED`, `RECAST_FALSE_POSITIVE`,
`MANUAL_REVIEW`. The analyst reviews, approves, rejects or overrides, then saves
and exports the investigation as JSON/Markdown.

A thin UI sits over **independently unit-tested pure-Python modules** (config,
findings, advisories, matching, prompts, claude_client, investigations, storage,
exports). Evidence matching is deterministic *"so every match is explainable."*
The API is called **only when the analyst explicitly clicks**; API keys are
never logged, displayed, or written to saved results. Single-user, local-only,
human-in-the-loop - it **never writes back to a scanner or production system**.

---

## The pattern across all three

1. **Evidence over opinion.** Two of three have "evidence" or "proven" in the
   pitch. Deterministic, explainable matching beats semantic cleverness - 3rd
   place calls out "no embeddings" as a feature.
2. **A human checkpoint that cannot be skipped**, before every external
   mutation, with each mutation separately approved.
3. **Offline reproducibility.** Bundled samples (3rd) and an offline runner that
   calls no live system (1st). A judge can run it with no credentials.
4. **A machine-readable contract plus a validator that enforces it**, and tests
   that prove the validator fails when the contract drifts.
5. **Volume reduction with a stated ratio:** "thousands of findings to a
   handful of proven fixes."
6. **Capabilities, not products** - swappable providers behind interfaces.
7. **Explicit statements of what cannot be proven.** 1st place devotes a
   paragraph to the limits of its own runner. 3rd states it never writes back.
8. **Structured disposition vocabulary**, not free text.
9. **Credentials handled visibly:** keys never logged, displayed or persisted;
   the orchestrator holds no write tools.
10. **Thin presentation over independently unit-tested pure modules.**

## What this project adopts

| Winner mechanism | Our implementation |
|---|---|
| `stages.yaml` contract | Same. Eight stages, each declaring capability, provider, read-only/write, approval binding |
| Validator enforcing prose-code sync | Same. Assert README, skill text and code all match `stages.yaml` |
| Drift-injection tests | Same. Drop a stage, rename a tool, strip an approval - assert validation fails |
| Offline runner, no live calls | Same. `.eml` directory intake + a receipt-contract runner that needs no Google credentials and no model endpoints |
| Refuse simulated evidence as closure | Same, and it maps directly onto our facts/judgments/unknowns rule: a verdict may not be closed on evidence marked unknown or simulated |
| Transactional refusals | Same. No partial case state on refusal |
| Capabilities not products | Same. Model endpoints, mail provider and writeback target are config, never hardcoded |
| Human checkpoint before mutation | Same. Writeback is a write stage requiring per-action approval |
| Structured dispositions | `THREAT` / `SPAM` / `CLEAN` / `MANUAL_REVIEW` - the first three for reference parity, the fourth for the escalation band |
| Bundled samples | `fixtures/synthetic/` - generated, RFC 2606 reserved domains, known labels |
| Explicit limits section | README "Known limitations": no VLM parity claim beyond OCR-plus-judgment, 3-label internal corpus not publishable, public-corpus numbers only, QR handled deterministically not by the VLM |

Our differentiator against all three: they call Claude or an external AI as the
reasoning engine. We run the cascade on local models and expose the escalation
slot as provider-agnostic. 2nd place proves the "external AI asks, server
executes locally" shape places well - we keep that shape and let the external AI
be optional.
