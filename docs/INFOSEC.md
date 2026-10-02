# surgic: InfoSec controls, evidence and residual risks

This document maps each requirement in `spec.md` §4 to the control that
implements it, the artifact that proves it, and how an auditor verifies it.

All evidence is written to the **output SMB share**:

```
<output share>/
  <doc_id>/<doc_id>.redacted.{pdf|xlsx|txt}  (+ .redacted.txt sidecar)
  manifests/<run_id>.manifest.json            canonical JSON
  manifests/<run_id>.manifest.json.sig        base64 Ed25519 signature
  manifests/pubkey.pem
  evidence/<ts>/egress_audit.pcap             tcpdump, all non-SMB, non-loopback traffic
  evidence/<ts>/pflog_blocked.pcap            packets pf blocked (pflog0)
  evidence/<ts>/closure.json(.sig)            signed teardown/closure record
```

To verify, use a separate workstation with the public key that InfoSec
received at provisioning time (not the copy on the share):

```
surgic verify manifests/<run>.manifest.json --pubkey pubkey.pem --outputs <share root>
surgic verify evidence/<ts>/closure.json      --pubkey pubkey.pem
```

`verify` exits non-zero on any failure. It checks the following:
- the signature, the canonical form and the signer fingerprint;
- every released file's SHA-256;
- that no quarantined document has output;
- that every released document passed post-scan;
- that the pcap hashes and packet counts match the recount;
- egress packets == 0;
- that the egress probe was blocked and pf logged at least one blocked packet;
- that the RAM disk zero-fill and detach succeeded and no RAM device remains.

## Control mapping

| Requirement | Control | Proof artifact / audit method |
|---|---|---|
| **Data isolation & locality** | Single Mac Studio. Shares are mounted by IP with `nobrowse,nodev,nosuid` (input adds `rdonly`, verified with `statvfs`). The LLM is bound to 127.0.0.1 and the config rejects any non-loopback host. The model weights' SHA-256 must be on the allowlist. | The manifest records `host`, `software` versions, `llm.model_sha256` and `config_sha256`, plus the preflight results (`input_share_read_only`, `input_share_is_smb`, `llm_loopback_only`, `model_hash_allowlisted`). |
| **Zero network egress** | pf `airgap.rules` is loaded as the **main** ruleset, which drops Apple's `com.apple/*` anchors. It is default-deny in/out with `log`, and its only pass rule is TCP 445 to the SMB IP (stateful). Preflight verifies the loaded ruleset (`pfctl -sr`) **exactly**, with lo0 skip, no anchors and no extra pass rules. It also checks: no non-loopback listeners, Wi-Fi off, Bluetooth off. A TEST-NET-1 egress probe must fail. In-process, `surgic.netguard` refuses non-loopback connect/sendto/DNS (defense in depth; the test suite runs under it). | `egress_audit.pcap` (filter `not host SMB and not host 127.0.0.1 and not host ::1`, on `-i any`) must hold 0 packets. `pflog_blocked.pcap` shows pf blocking, including the probe. The signed `closure.json` holds the hashes and counts; `verify` recounts them. |
| **Zero local data retention** | All documents, extractions, renders, OCR images, LibreOffice profiles and scan files live on an `hdiutil` `ram://` device. Preflight checks it is RAM-backed and that `TMPDIR` and the workspace are on it; Spotlight indexing is off. Per-document work directories are deleted as each document finishes. Core dumps are disabled (`ulimit -c 0`, checked). Teardown runs `diskutil zeroDisk` on the device, then `hdiutil detach`, then verifies that no `ram://` device remains. | `closure.json` → `ramdisk.teardown` steps with exit codes, `ramdisk_devices_remaining == 0`. |
| **Deterministic safety net** | Phase A runs before any LLM call: Hyperscan/Vectorscan prefilter → RE2 exact spans (built-in plus site patterns, Luhn validation), then Presidio with spaCy `en_core_web_trf`. Values are propagated to every occurrence. The LLM sees only masked text (`[US_SSN_1]`…). | The manifest lists per-document counts by `source:category`, and `token_hmacs` holds HMAC-SHA256 of every redacted value under an **ephemeral per-run key**: the hashes correlate within a run but can't be reversed or brute-forced later. The test suite contains planted-value tests for every structured format, plus a property test that the Hyperscan prefilter never drops an RE2 match. |
| **Post-sanitization audit** | Before release, the output **files** are re-extracted: with the primary parser + OCR, with an independent second parser (pdfplumber), and from every decoded PDF object/stream or XLSX XML part. The pipeline checks that (1) no redacted value survives anywhere, (2) Phase A finds nothing new, and (3) gitleaks (`--no-git --redact`) and trufflehog (`--no-update --no-verification`, so it makes no network calls) find nothing. Newly found values are fed back for up to 2 re-render passes; otherwise the document is quarantined. Released files are re-hashed after the copy to SMB. | The signed manifest holds input/output SHA-256 and per-document `postscan` results (checks and rule IDs only, never values). |

## Context isolation between documents (§3.D)

| Backend | Per document | Per batch (`batch_size`, default 1) |
|---|---|---|
| llama.cpp | `cache_prompt=false`, single slot, `POST /slots/0?action=erase` (a failure is fatal) | process terminated; exit and closed port verified |
| Ollama | verified eviction: `keep_alive=0`, then poll `/api/ps` until empty | eviction + private `ollama serve` terminated |
| mlx-lm | server restart (it has no cache-purge API) | process terminated |

Any unload or reset that can't be verified aborts the whole run (fatal error). The manifest records `llm.unloads` and `llm.context_resets`.

## Logging

Pipeline logs go only through `log_event`, which accepts only allowlisted keys and value types. Records from third-party libraries are reduced to `[redacted log from <name>]` at WARNING and above; their arguments, exception text and stack traces are dropped. LLM output can't carry free text: the schema allows only offsets, the exact substring (validated, never logged), a category enum and a rationale enum. Error messages are content-free codes (`SafeError`).

## Fail-closed behavior

- Preflight: if any check fails, or the check list is empty, the run aborts before a document is read.
- Per document: extraction, LLM, rendering or post-scan errors, or "spans found but nothing redacted", quarantine the document. Nothing from it reaches the output share.
- Run-level: unverified unload or reset, a missing secret scanner, a scanner execution failure, or output hash mismatch after copy abort the run.
- The `mock` backend, the file-based signing key and `--skip-preflight` each require an explicit `SURGIC_ALLOW_*` environment variable and are for tests only.

## Residual risks and operator responsibilities

1. **Ed25519 key storage.** The Keychain has no native Ed25519 key type, so the 32-byte seed is stored as a generic-password item. It is accessed through the Security framework and never passes through argv, and the item ACL trusts the creating Python binary. Someone with the user's login and keychain password could export it. If hardware-bound keys are required, consider a Secure Enclave P-256 helper.
2. **macOS swap.** RAM disk pages are wired, but process memory (the Python heap and model context) can be swapped under memory pressure. macOS always encrypts swap with an ephemeral key, which preflight checks (`swap_encrypted`). Keep the model plus context within the ~60–80 GB budget so there is no memory pressure.
3. **BPF vantage point.** tcpdump sees packets pf allowed on egress. Blocked attempts are evidenced through `pflog0` rather than in `egress_audit.pcap`. Packets sent before the capture started, or after it stopped, aren't covered: `up` starts the captures before mounting, and `down` stops them only after the input share is unmounted.
4. **Layer-2 / non-IP traffic** (ARP, IPv6 ND/RA, Bonjour). pf does not filter ARP. Use a static IP on a dedicated SMB VLAN and disable AirDrop, Handoff and AirPlay Receiver; the listener check enforces this.
5. **LLM recall.** Phase B is best-effort contextual redaction. The deterministic net and post-scan cover structured data; unstructured trade secrets depend on model quality. Sample outputs should get human review before a new document class is released.
6. **Prompt injection in documents.** A document can try to instruct the model. The model can only emit spans, so the worst case is under-redaction, which post-scan covers for structured data but not for context-dependent secrets (see item 5).
7. **OCR fidelity.** Text that OCR can't read can't be detected. Image regions are re-OCR'd after redaction and checked, but illegible handwriting may remain unrecognized.
8. **File names.** Input paths are not recorded (`record_input_paths = false`). Outputs are named `<seq>-<sha256 prefix>`.
9. **Third-party phone-home.** One instance was found and fixed during development: Presidio's email recognizer called `tldextract`, which downloads the public-suffix list, and it is now pinned to the bundled snapshot. The in-process guard makes any future instance fail tests rather than leak or hang.
