---
name: "Local-First Phish Triage"
author: "austinsr1"
github_url: "https://github.com/austinsr1/assay"
description: "Triages user-reported phishing entirely on local models: deterministic header and link forensics, a CPU classifier cascade, local vision for embedded images, and an LLM only for the ambiguous residual. Nine read-only MCP tools over that chain; no tool writes anything."
license: "MIT"
tier: "contributed"
tags: ["phishing", "email-security", "triage", "local-inference", "deterministic-forensics", "mcp"]
domains: ["email-collaboration-security", "security-operations"]
integrations: ["GCP"]
date_added: 2026-11-04
contribution_agreement_date: 2026-11-04T02:40:00Z
works_with_tenable_hexa_mcp: false
compatible_clients: ["Claude Code", "Claude Desktop"]
transport: "stdio"
runtime: "python"
auth_method: "none"
tools_exposed:
  - name: "analyze_eml"
    description: "Runs the full staged cascade over one RFC 822 message and returns a disposition with its evidence record grouped by provenance. Read-only; carries no message body and no attachment bytes."
  - name: "analyze_eml_directory"
    description: "Batch triage over a directory of .eml files with no credentials and no network access: one line per message, counts per disposition, and label agreement reported with escalation counted separately."
  - name: "explain_verdict"
    description: "Returns the verified facts, model judgments and gaps behind a saved case record, with unknowns and unavailable tiers labelled as gaps rather than as findings of absence."
  - name: "check_auth"
    description: "SPF, DKIM and DMARC as the receiving MTA recorded them, alignment against the sender domain, and the raw header values truncated. Verified facts only - passing authentication does not establish legitimacy."
  - name: "lookalike_domain"
    description: "Deterministic lookalike analysis of any domain against the configured organization profile: edit distance to a protected or vendor label, modifier tokens, and ownership or trust checks."
  - name: "analyze_urls"
    description: "Deterministic link analysis for arbitrary URLs: redirect unwrapping with the resolved destination, anchor-versus-href mismatch, IP-literal hosts, sender/trusted/neither classification, and URL reputation where a tier can answer."
  - name: "classify_local"
    description: "The model tiers' judgments for one message, each with its own stance, score, source and error and nothing merged, so a calling agent can see disagreement instead of receiving an average of it."
  - name: "list_contracts"
    description: "The machine-readable stage chain as data: stage id, title, capability, provider, access class, optionality, model tier and approval requirement."
  - name: "get_case_record"
    description: "One durable case record as JSON and as Markdown, with its verdict and corpus digests, stage history, approval state and closure blockers. Read-only."
resources_exposed: []
prompts_exposed: []
---

# Local-First Phish Triage

Built for Tenable SWARM Global 2026 by **Campus Autonomous Defenders (CAD)**.

## Scope: a triage layer, not primary detection

This reads a message **a human already reported**, or one your secure email gateway
already flagged and handed on. That report is the primary classification, and it is not
ours. Nothing here sits in the mail flow, nothing blocks delivery, and no claim is made
about catching a phishing campaign nobody reported.

The job is the one downstream of that report: settle the large majority of reported mail
that turns out to be nothing, escalate the minority that is something, and defer the rest
to an analyst **with the evidence they need to decide in seconds rather than minutes**.
Automation rate at a bounded error rate is the metric, not detection recall on novel
attacks.

Read the numbers with that boundary in place. "The phishing classifier caught 0 of 18
adversarial fixtures" describes one component's contribution to a triage decision, not
the product's ability to stop a new campaign - stopping it is the gateway's job, and by
the time a message reaches this chain a person has already said it looked wrong. The
figure that carries the claim is **84.2% of 203 real benign business emails auto-cleared
with zero false accusations**, and the figure that carries the risk is **false
clearances** - a reported threat waved through - which is why clearance is gated behind a
veto and every cleared case is written to an append-only ledger a human can overturn.

The economic unit this optimizes is **frontier cost per reported message**, and the
reference design has no way to reduce it. In the published KnowBe4 PhishER playbook, Claude
is not a rung in a ladder - it *is* the last step: every unresolved reported message goes to
Claude Sonnet 4 on Bedrock at `batchSize: 1` on a five-minute schedule and comes back
tagged Clean, Spam or Threat. So the token spend is unconditional, and a reported email that
turns out to be a legitimate invoice costs exactly the same frontier call as one that turns
out to be a credential harvester. That design saved real analyst time - roughly 930 hours a
year by its own published figures - and this does not dispute that. It removes the frontier
spend underneath it.

Measured here: on 203 real benign business emails the local micromodel tier settled **84.2%
with zero false accusations** at ~90 ms a message, leaving ~16% for the adjudicator - and the
adjudicator is a flash-class model on organization-owned hardware, so paid frontier API calls
are **zero** rather than one per message. The reference published no clearance or accuracy
figure, and on its architecture none was available to publish; this one is measured, with the
corpora and licences behind it recorded in `docs/EVAL-SUITES.md` and `eval/PROVENANCE.json`.

Placeholder body for validator testing.
