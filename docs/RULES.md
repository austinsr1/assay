# Contest and Exchange requirements

Distilled from primary sources, all read 2026-11-02. Nothing here is
paraphrased from a third-party summary.

| Source | URL |
|---|---|
| SWARM Global 2026 official rules | `https://exchange.tenable.com/swarm-global-rules-nov2026/` |
| Exchange README | `https://github.com/tenable/cyberagents-exchange` |
| Contribution guide (normative) | `https://github.com/tenable/cyberagents-exchange/blob/main/CONTRIBUTING.md` |
| Validator (source of truth for vocabularies) | `https://github.com/tenable/cyberagents-exchange/blob/main/validator.py` |
| Reference playbook listing | `https://exchange.tenable.com/playbooks/knowbe4-phisher-email-analysis/` |
| Reference playbook source | `https://github.com/disassembledd/knowbe4-phisher-email-analysis` |

---

## Contest facts

- **Window:** begins virtual kickoff **2026-11-02 11:00 ET**, ends at the
  conclusion of the awards broadcast **2026-11-06**.
- **Teams:** 1 to 3 eligible entrants. Each entrant registers individually.
  Each entrant may be on **only one team**; each team may make **only one
  Submission**.
- **Eligible artifact types.** Rules section 1 says *"open-source security
  agents, skills, or MCP servers that address real-world security workflows
  (for example, alert triage, remediation orchestration, and executive
  reporting)."* The Exchange separately indexes a fourth type, **playbooks**.

  **Playbooks are valid submissions.** Confirmed two ways on 2026-11-02: by the
  activity coordinator, and by SWARM Black Hat 2026 **1st place being a
  playbook** (`chokepoint-remediation-playbook`). See `PRIOR-WINNERS.md`. This
  supersedes an earlier narrow reading of section 1's enumeration.

  "Script" is still not a category - a script-only repository must be listed as
  an agent, skill, MCP server or playbook.
- **Submission mechanics:** submit to the CyberAgents Exchange per the
  contribution guidelines, **and** notify Tenable through the method specified
  on the Discord server. Exchange submission alone is insufficient.
- **Contribution Agreement:** every contributing team member must have agreed
  to it. It includes a representation about the contributor's authority,
  *"including any required employer permission."*
- **Costs:** entrants provide their own LLM tokens, compute and tools. No
  reimbursement.
- **Prizes:** Anthropic platform credits ($5,000 / $3,000 / $2,000 per team),
  one EXPOSURE 2027 pass per member (~$995 value), a patch, and featured
  placement on the Exchange.
- **Judging:** panel selected by Tenable, *"which may include Tenable employees
  and representatives of Anthropic."* Decisions final. Published criteria:
  none beyond judges' discretion.
- **Sponsor note:** Anthropic supplies judges and the prize credits. Positioning
  matters - see `README.md`.

## Repository requirements (all enforced at review)

- **Public GitHub repository**, not archived or disabled.
- **Personal GitHub account**, not an Enterprise Managed User. Per
  CONTRIBUTING.md: EMU accounts *"typically follow the `orgname_username`
  pattern (with an underscore). Accounts with hyphens (like `name-tenb`) are
  fine."*
- **Open-source license** file present. **MIT recommended**; Apache 2.0 also
  welcome. GPL v3 and other restrictive licenses only in exceptional cases via
  a GitHub issue first.
- **No secrets anywhere in git history.** Stated as *"scanned automatically."*
- **README** covering purpose, prerequisites, how to run, outputs, and
  **known limitations**.

## Listing file requirements

One markdown file: YAML frontmatter plus a body. Placed in the directory
matching its type. Slug must be lowercase letters, numbers and hyphens only.

Common required fields: `name`, `author`, `github_url`, `description`,
`license`, `tier` (always `contributed` for new submissions), `tags`,
`integrations`, `date_added`, `contribution_agreement_date`,
`works_with_tenable_hexa_mcp`.

`partner_contribution`, `vetted_on` and `vetted_commit_sha` are set by Tenable
during review - **leave them out**.

### MCP server (recommended type)

Additional required: `compatible_clients`, `transport` (`stdio` | `http` |
`both`), `runtime` (`binary` | `bun` | `go` | `node` | `python` | `rust`),
`auth_method` (`api-key` | `none` | `oauth2` | `token`), `tools_exposed` (list
of `{name, description}`), `resources_exposed`, `prompts_exposed`.

`compatible_clients` controlled vocabulary: Antigravity, ChatGPT, Claude Code,
Claude Desktop, Cline, Codex, Continue, Cursor, Gemini CLI, VS Code Copilot,
Windsurf. **No `pi`.** Declare only clients actually tested. New values may be
proposed alphabetically in the same PR.

### Skill

Additional required: `compatible_platforms` (Claude Code, Claude Desktop,
Claude Cowork, Cline, Codex, Cursor, Gemini CLI, GitHub Copilot, LibreChat,
Windsurf - again **no `pi`**) and `invocation` (the slash command or trigger).

### Playbook

Additional required: `playbook_type` (`standard` | `sponsored` | `n8n`) and
`agents_used` - a list of `{name, role, type, ref?}` where `type` is `exchange`,
`github`, `info` or `vendor`.

Structural constraints read from `validator.py`:

- **Only `sponsored` playbooks may include `vendor`-type agents.** Both
  `StandardPlaybook` and `N8nPlaybook` carry a `no_vendor_agents` validator that
  raises otherwise.
- `SponsoredPlaybook` additionally requires `logo` (an `HttpUrl`).
- `N8nPlaybook` additionally requires `workflow_diagram` (a Mermaid diagram) and
  makes `agents_used` **optional**. `StandardPlaybook` requires `agents_used`.

Consequence for us: since we dropped n8n, our type would be **`standard`**, which
means `agents_used` is **mandatory**. `type: github` with `ref` set to a GitHub
URL lets a self-contained project declare its own components without needing
separate Exchange listings first.

### Domains (closed taxonomy - cannot be extended)

One or two values, no duplicates, **first is primary**. Adding a domain
requires a coordinated change across two repositories, so it must be proposed
by issue, never in a submission PR.

Our fit:
- Primary: **`email-collaboration-security`** - defined as *"Phishing analysis,
  email gateway and header forensics, Slack/Teams/SaaS collaboration risk."*
- Secondary: **`security-operations`** - SIEM/EDR work, detection engineering,
  incident response.

Do **not** claim `ai-security`; the taxonomy explicitly warns that means
security *of* AI systems, not "this is an AI agent." Do not reach for
`vulnerability-management` unless VM is genuinely the primary function.

### Integrations (controlled vocabulary)

Current allowed values include: Anthropic, AWS, Azure, Check Point, Cisco,
CrowdStrike, Firebase, Fortinet, **GCP**, IPGeolocation.io, **KnowBe4**,
Microsoft Sentinel, **Mimecast**, Netskope, NVD, PagerDuty, Palo Alto, Qualys,
Rapid7, Recorded Future, SentinelOne, ServiceNow, Snyk, Splunk, Supabase,
Tenable, Tenable Hexa AI MCP, URLScan.io, VirusTotal, Wiz, Checkmarx One,
SecurityScorecard.

**There is no "Google Workspace" and no "Gmail" value.** Either declare `GCP`,
or propose adding "Google Workspace" in alphabetical order in the same PR -
CONTRIBUTING.md explicitly permits this for integrations.

## Automatic rejection triggers

Submissions are rejected outright regardless of formatting if they involve:

- Offensive or weaponized agents (exploit, lateral movement, exfiltration)
- **Hardcoded secrets** - credentials or API keys anywhere in git history
- **Undisclosed outbound calls** - *"all outbound data flows must be
  documented"*
- Competitor targeting
- Weakening security controls (disabling logging, EDR, firewalls) without
  justification

The outbound-calls rule binds us directly: this project calls Google Alert
Center, Gmail, and five internal model endpoints. **Every one must be listed in
the README.**

## Submission process

1. Fork `tenable/cyberagents-exchange`.
2. Branch named `add-<your-slug>`.
3. Copy the matching template from `templates/`, rename to a valid slug, place
   in the correct directory.
4. Write frontmatter (must pass `validator.py`) and a **substantive, original**
   body covering *what it does* and *how it works*. The body must **not** be a
   copy of the README.
5. PR title exactly: **`Add listing: Your Agent Name`**.
6. PR description must contain verbatim:
   > I have reviewed and accept the [CyberAgents Contribution Agreement](https://github.com/tenable/cyberagents-exchange/blob/main/docs/CyberAgents_Contribution_Agreement).
7. Set `contribution_agreement_date` in frontmatter to the ISO 8601 timestamp
   of acceptance, e.g. `2026-11-04T14:30:00Z`.
8. `validator.py` runs automatically on the PR. Then **two maintainers** review
   against `docs/contributing_checklist.md`, item by item.

Validator runs locally with `uv sync && uv run ./validator.py`.

Reviewers additionally verify: repo is public and non-EMU; license present and
matches the declaration; no secrets in history; README covers all five required
topics; **installation instructions are accurate and referenced files, packages
and commands actually exist**; listing metadata matches repository reality;
**claims in the listing body are supported by the README or repository
content**; reasonable coding standards and no malicious, deceptive or
unauthorized behavior.

PRs are **squash-merged only**; the squash commit uses the PR title and
description. Source branch is deleted on merge.

## Optional accelerator

`https://github.com/jtbuchanan-tenb/cyberagent-exchange-submission-builder` -
a Claude Code skill. Run `/cyberagents-exchange-submit` from the project
directory; it validates the repo, captures Contribution Agreement confirmation,
interviews for metadata, generates the listing, forks and opens the PR.

Not yet evaluated. Using it does not remove the need to satisfy the checklist.
