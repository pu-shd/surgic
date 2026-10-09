# surgic

Zero-retention document sanitization.

Reads restricted documents from a read-only SMB share and redacts them in two phases: deterministic rules (Hyperscan/RE2 and Presidio), then contextual redaction by a local open-weight LLM (llama.cpp, Ollama or mlx-lm).

Every document parser runs in a sandboxed worker process (no network, no Keychain, no sudo). It verifies the output files, writes cleaned documents, Ed25519-signed manifests and egress evidence to a second SMB share.

See `spec.md` for requirements and `docs/INFOSEC.md` for the control mapping, the evidence it produces, and the residual risks.

## Supported inputs → outputs

| Input | Output |
|---|---|
| PDF (text or scanned) | normalized (hidden layers, cropped and off-page content exposed), full-page OCR, true-redacted PDF (content removed, image pixels blanked, metadata/annotations/forms/JS/embedded files/accessibility tree scrubbed) + `.txt` sidecar |
| DOCX / DOC / ODT / RTF | rendered to PDF via headless LibreOffice, then redacted as PDF + `.txt` |
| XLSX / XLSM (XLS / ODS converted) | cell-level redacted `.xlsx` (values only: formulas, comments, links, names, properties, VBA, charts and pivots removed; hidden sheets/rows/columns unhidden; literal-text number formats reset) + `.txt` |
| PNG / JPEG / TIFF / BMP / GIF | OCR (macOS Vision, Tesseract fallback) → redacted PDF + `.txt` |
| TXT / CSV / MD / JSON / XML / HTML | redacted `.txt` (files that aren't really text, or carry data URIs / base64 / hex blobs, are quarantined) |

Every file's leading bytes must match its extension; mismatches are quarantined.

## Operator workflow

```zsh
# 1. Online, once: install tools, hash-locked venv (incl. spaCy models), signing key, model hash
scripts/provision.zsh qwen3.6:27b   # Ollama tag, or a GGUF file / MLX model directory
$EDITOR config/surgic.toml          # smb_share_ip, smb_interface, shares, model_path, model_sha256

# 2. Disconnect everything except the SMB VLAN, then:
scripts/run.zsh config/surgic.toml  # airgap up → preflight → sanitize → teardown

# 3. On a separate workstation, using InfoSec's copy of pubkey.pem:
surgic verify <share>/manifests/<run>.manifest.json --pubkey pubkey.pem --outputs <share> \
    --closure <share>/evidence/<ts>/closure.json --expect-model <approved sha256>
surgic verify <share>/evidence/<ts>/closure.json --pubkey pubkey.pem
```

Outputs land in `<share>/<run_id>/<doc_id>/` by default (`output_names =
"opaque"`), so no input folder or file name leaves the machine. With
`output_names = "original"` the input folder tree and file names are kept, e.g.
`<share>/<run_id>/Clients/REDACTED_VALUE/renewal memo.txt.redacted.txt`: every
folder and file name is run through the detectors and stripped of any value
redacted from the document. `surgic verify --require-opaque-names` enforces the
default. The operator is asked for the sudo password again at teardown; the
airgap stays up until it is given.

To change Python dependencies, edit `pyproject.toml` and run
`scripts/lock_deps.zsh` online to regenerate `requirements/macos-arm64.lock`.

`surgic run` exit codes:
- `0`: every document is clean.
- `3`: some documents were quarantined (see the manifest).
- `2`: the run aborted. This is fail-closed: nothing is released, and a signed manifest records the abort.

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
