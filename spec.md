# surgic: requirements

**Goal:** sanitize restricted documents with local AI on one air-gapped Mac
Studio, with verifiable proof that no data left the machine or persisted on it.

## Scope

| | |
|---|---|
| Hardware | 1× Mac Studio, Apple Silicon, 256 GB unified memory |
| Input | Read-only SMB share: PDF (text or scanned), DOCX, XLSX, images, text |
| Output | Second SMB share: redacted documents, signed audit manifests, network evidence |
| Model | Local open-weight LLM: **Qwen 3.6 27B** (`qwen3.6:27b`) via Ollama; llama.cpp and mlx-lm also supported. ~17 GB of weights, well within a 60–80 GB memory cap |

## Processing requirements

1. **Deterministic redaction first.** Before any LLM call, regex (RE2, Hyperscan prefilter) and Microsoft Presidio (spaCy NER) remove structured data: SSNs, cards, emails, phones, IPs, names, classification markers, employee IDs, project codenames and document control numbers.
2. **Contextual redaction second.** The LLM sees only pre-masked text and flags context-dependent information: indirect identifiers, trade secrets, and client/vendor relationships. It returns only offsets and category codes. Offsets are re-validated, and no document text is ever logged.
3. **True redaction.** Content is removed, not covered: no recoverable text, pixels, metadata, comments or hidden sheets. Nothing hidden is trusted: hidden layers, cropped or off-page content, text drawn as shapes or in images of any size is extracted (full-page OCR) and redacted. Text files must be text, not encoded payloads.
4. **Post-scan before release.** The outputs are re-extracted and re-scanned (the detectors plus gitleaks/trufflehog). Any finding quarantines the document. Outputs are released only after the whole run completes.
5. **Isolated parsing.** Every document parser runs in a sandboxed worker process with no network, no Keychain, no sudo and writes confined to the RAM disk.

## Security requirements

| # | Requirement | Control |
|---|---|---|
| S1 | **Zero network egress** | macOS pf default-deny; the only allowed traffic is TCP 445 to the SMB host IP, on the SMB VLAN interface; SMB 3 encrypted |
| S2 | **Proof of zero egress** | A header-only capture of all non-SMB, non-loopback traffic on every interface must contain 0 packets |
| S3 | **Zero persistence** | All working data lives on a RAM disk that is zero-filled and detached at the end; the airgap stays up until it is |
| S4 | **No cross-document leakage** | Model context is purged between documents and weights are unloaded between batches |
| S5 | **Tamper-evident audit** | A signed manifest with input/output SHA-256 hashes, scan results and security settings, bound to the airgap session's signed closure record |
| S6 | **Fail closed** | Any failed check aborts the run or quarantines the document; nothing unverified is released; an aborted run releases nothing |

## Acceptance

An independent workstation runs `surgic verify` against the manifest, the
closure record and the output share and gets `VERIFIED`, using only the
artifacts on the share and InfoSec's own copy of the public key. Verification
covers S1–S3, S5 and S6, and rejects runs with skipped or weakened controls.
For S4, the verifier checks the recorded unload and context-reset counts. See [`docs/INFOSEC.md`](docs/INFOSEC.md).
