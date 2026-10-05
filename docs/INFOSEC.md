# surgic: security review brief

Printable version: [PDF](brief/surgic-security-brief.pdf) · [HTML](brief/surgic-security-brief.html)

**What it is.** A pipeline that redacts restricted documents with a local AI
model on one air-gapped Mac Studio. No cloud services are involved. Documents
are read from a read-only SMB share, processed only in RAM, and written back to
a second share with signed proof that nothing left the machine.

**Status.** Implemented and tested: about 130 automated tests, plus CI on macOS and
in a network-disabled Linux container. It has **not yet been run on the target
Mac Studio.**

```
SMB (read-only) ─► RAM disk ─► 1. rules (regex + Presidio) ─► 2. local LLM ─► 3. redact
                                                                              │
SMB (output) ◄── release only if post-scan is clean ◄── 4. re-scan the output files
```

## Controls and evidence

| Requirement | How it's enforced | Evidence (on the output share) |
|---|---|---|
| **No network egress** | pf default-deny; the only pass rule is TCP 445 to the SMB host. Preflight verifies the loaded rules exactly. A test probe to an outside address must be blocked. | `egress_audit.pcap` = **0 packets**; `pflog_blocked.pcap` shows the blocks |
| **No data persistence** | All working files live on a RAM disk, which is zero-filled and detached at the end. Core dumps are off and swap is encrypted. | Signed `closure.json` with teardown steps and exit codes |
| **No cross-document leakage** | Model context is purged per document and the model is unloaded per batch. An unload that can't be verified aborts the run. | Unload and reset counts in the manifest |
| **Structured data never reaches the LLM** | Regex and Presidio redact before the LLM. The LLM sees placeholders such as `[US_SSN_1]`. | Per-document counts in the manifest; values stored as one-time HMACs |
| **Output is actually clean** | Output files are re-extracted and checked for leftover values, re-run through the detectors, gitleaks and trufflehog. A dirty document is quarantined. | Per-document post-scan results; SHA-256 of every input and output |

The manifest and closure record are signed (Ed25519). Logs contain no document
text, and file names aren't recorded.

## How to verify

On a separate workstation, using your own copy of the public key:

```
surgic verify manifests/<run>.manifest.json --pubkey pubkey.pem --outputs <share>
surgic verify evidence/<ts>/closure.json      --pubkey pubkey.pem
```

`VERIFIED` means the signatures are valid, every output hash matches, nothing
quarantined was released, the egress capture holds 0 packets, the firewall
logged blocks, and the RAM disk was wiped.

## Fail-closed behavior

- Any preflight failure (firewall, radios, listeners, RAM disk, read-only input, model hash) stops the run before any document is read.
- Any per-document error quarantines that document; nothing from it is written.
- Test-only shortcuts (mock model, file-based key, skipping preflight) each require an explicit opt-in flag.

## Residual risks

1. **Signing key is software-protected.** It's stored in the login Keychain, so someone with the user's login could export it. *Mitigation available:* a Secure Enclave key via Jamf (in progress).
2. **LLM recall is imperfect.** Unstructured secrets depend on model quality. In testing, Qwen 3.6 27B caught contextual secrets in prose but missed a client name in a spreadsheet cell. *Recommend* human spot-checks when a new document type is introduced.
3. **Prompt injection.** A document could try to steer the model. The worst case is under-redaction, never exfiltration.
4. **OCR limits.** Text that OCR can't read (e.g. poor handwriting) can't be detected.
5. **Memory pressure could cause swapping.** Swap is encrypted with an ephemeral key, and the model (~17 GB) leaves ample headroom.
6. **Layer-2 traffic** (ARP, IPv6 neighbor discovery) isn't filtered by pf. *Requires* a static IP on a dedicated VLAN.

## Requested from Cloud / Infrastructure

- A read-only SMB share (input) and a writable share (output) on **one** host, reachable by IP.
- A dedicated VLAN with a static IP for the Mac Studio, carrying only SMB.
- A service account with access to both shares only.
- Jamf: AirDrop, Handoff and AirPlay Receiver disabled; Wi-Fi and Bluetooth off; FileVault on.

## Decisions requested from InfoSec

1. Accept the software-protected signing key for the pilot, or require the Secure Enclave option.
2. Approve the model, Qwen 3.6 27B (`qwen3.6:27b`), pinned to the exact weight digest recorded at provisioning.
3. Set the human-review sampling rate for released documents.
