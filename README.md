# surgic

Air-gapped, zero-retention document sanitization for a single Apple Silicon
Mac Studio.

Reads restricted documents from a read-only SMB share and redacts them in two phases: deterministic rules (Hyperscan/RE2 and Presidio), then contextual redaction by a local open-weight LLM (llama.cpp, Ollama or mlx-lm).

It verifies the output files, writes cleaned documents, Ed25519-signed manifests and egress evidence to a second SMB share.

See `spec.md` for requirements and `docs/INFOSEC.md` for the control mapping, the evidence it produces, and the residual risks.

## Supported inputs → outputs

| Input | Output |
|---|---|
| PDF (text or scanned) | true-redacted PDF (content removed, image pixels blanked, metadata/annotations/forms/JS/embedded files scrubbed) + `.txt` sidecar |
| DOCX / DOC / ODT / RTF | rendered to PDF via headless LibreOffice, then redacted as PDF + `.txt` |
| XLSX / XLSM (XLS / ODS converted) | cell-level redacted `.xlsx` (values only: formulas, comments, links, names, properties, VBA, charts and pivots removed) + `.txt` |
| PNG / JPEG / TIFF / BMP / GIF | OCR (macOS Vision, Tesseract fallback) → redacted PDF + `.txt` |
| TXT / CSV / MD / JSON / XML / HTML | redacted `.txt` |

## Operator workflow

```zsh
# 1. Online, once: install tools, venv, [spaCy](https://github.com/explosion/spaCy) models, signing key, model hash
scripts/provision.zsh /opt/models/Llama-3.3-70B-Instruct-Q5_K_M.gguf
$EDITOR config/surgic.toml          # smb_share_ip, shares, model_path, model_sha256

# 2. Disconnect everything except the SMB VLAN, then:
scripts/run.zsh config/surgic.toml  # airgap up → preflight → sanitize → teardown

# 3. On a separate workstation, using InfoSec's copy of pubkey.pem:
surgic verify <share>/manifests/<run>.manifest.json --pubkey pubkey.pem --outputs <share>
surgic verify <share>/evidence/<ts>/closure.json   --pubkey pubkey.pem
```

`surgic run` exit codes:
- `0`: every document is clean.
- `3`: some documents were quarantined (see the manifest).
- `2`: the run aborted. This is fail-closed: nothing unverified is released.

## Tests

```zsh
scripts/test.zsh          # native macOS (Vision OCR, Keychain, hdiutil)
scripts/test_docker.zsh   # Linux container, --network none, real gitleaks/trufflehog/LibreOffice
SURGIC_TEST_OLLAMA_MODEL=gemma4:latest scripts/test.zsh -k real   # optional real-model tests
SURGIC_TEST_GGUF=/path/small.gguf      scripts/test.zsh -k real
```

The suite runs under an in-process egress guard, so any network attempt fails
the session. It also fails if fewer than `SURGIC_MIN_TESTS` tests pass, so a
silent or empty run never counts as success. macOS-only facilities are mocked
on Linux; native tests skip on Linux, and each skip gives its reason.
