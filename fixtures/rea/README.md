# Recorded `rea` responses

Four responses recorded from the real `morluto/rea` CLI (npm `rea-agents`, MIT)
by the bundle that added `src/tenable_email/attachments.py`, and committed so the
test stub cannot drift from reality silently.

| File | Command | What it is |
| --- | --- | --- |
| `inspect-artifact-zip.json` | `rea inspect-artifact /tmp/rea-sample/quarterly-summary.zip --json` | A successful static inspection of the ZIP attachment in `fixtures/attachments/attachment_zip_summary.eml`, exit code 0. Verbatim. |
| `inspect-artifact-unsupported-target.json` | `rea inspect-artifact /tmp/rea-sample/invoice-2026-114.txt --json` | The refusal this analyzer returns for a plain-text attachment (`code: target_unavailable`), exit code 1. Verbatim. |
| `inspect-provider-unavailable.json` | `rea inspect /bin/ls --json` | The refusal when every candidate decompiler provider is rejected (`code: provider_unavailable`, ghidra `not_configured`), exit code 1. See the note on `details` below. |
| `capabilities-providers.json` | `rea capabilities --json` | The `capabilities` array of a real response: four providers, each declaring its operations and their side effects. See the note on the envelope below. |

Recording environment: Linux x86_64, Node.js v22.23.1, `rea-agents` 6.8.0 (as
reported by `rea --version`). Note that v22.23.1 is *below* the range `rea`
declares in `engines`
(`^22.23.4 || ^24.22.1 || >=26.12.1`); `engines` is advisory and the CLI ran on
this host anyway. An operator who installs REA at its declared floor gets the behaviour
these recordings describe; this is not a claim about which REA versions work.

## Two edits, both stated

A golden that has been quietly rewritten is worse than no golden, so the
departures from "verbatim" are these, and only these:

1. **`inspect-provider-unavailable.json` lost its `details` block.** The real one
   carries the recording machine's toolchain layout -- `java_command`,
   `java_home`, `install_dir`, a Hopper launcher path -- and the component reads
   `code`, `category`, `message`, `retryable` and `remediation` only, never
   `details`. In place of the block, the file records the candidate provider ids
   and the rejection code for each, which is the part that explains the refusal.
   Everything else in that file is byte-for-byte what the CLI printed.
2. **`capabilities-providers.json` is the `capabilities` array, kept in its
   envelope, with the envelope's other fields dropped.** The real response also
   carries `server_identity.package.root_path` -- an absolute path on the machine
   that recorded it -- plus a 34 KB `analysis_provider_candidates` block of
   provider diagnostics with more such paths. The parser in
   `src/tenable_email/attachments.py` reads `payload["capabilities"]` and nothing
   else, so what is committed here is exactly the part that is consumed.

Nothing else was edited. Digests, ids, entry names, sizes, limitations and
coverage counts are what the tool printed, and
`tests/test_attachments.py::test_the_golden_files_carry_no_host_identity` fails
the build if an absolute path that is not under `/tmp/` ever appears here.

## Why these files exist

`tests/test_attachments.py` installs a stub `rea` on `PATH` so the suite can
exercise the subprocess path, the digest comparison and the safety gate on a host
with no Node.js and no REA. The stub emits **these documents** with the digest
fields replaced by the sha256 of the file it was handed. So the canned answer has
the real shape, and a change to the real shape -- a renamed field, a moved digest
-- is caught by `test_the_committed_golden_is_a_real_rea_response_shape` rather
than discovered in production.

The ZIP golden also anchors one invariant: its `subject.digest.sha256` and
`normalized_result.subject.root_sha256` are the digest of the bytes committed in
`fixtures/attachments/attachment_zip_summary.eml`. That is asserted in
`test_the_golden_response_describes_this_repositorys_zip_fixture`, so the recorded
response and the payload it describes cannot silently stop agreeing.
