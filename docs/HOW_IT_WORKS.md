# surgic: how a document is processed

A companion to [`INFOSEC.md`](INFOSEC.md). That brief covers the controls and the evidence
they produce; this document explains the mechanics behind them: who does what, in which
process, to which copy of the data, and what the signing key does and does not prove.

## The processes involved

| Process | Runs | Touches document files? | Can reach |
|---|---|---|---|
| **Orchestrator** (`surgic run`) | Unsandboxed, as the operator | Only copies bytes and hashes them; never parses | The signing key, the local LLM (loopback), the shares |
| **Analyzer worker** | Sandboxed (`sandbox-exec`) | Yes: extracts, detects, masks, redacts | Only the RAM-disk workspace; no network, no Keychain, no sudo |
| **Scanner worker** | Sandboxed, separate process | Only the *output* files, never the input | Same limits as the analyzer |
| **Local LLM** | Loopback-only server (Ollama, llama.cpp or mlx-lm) | No: receives masked text only | Nothing outside loopback |

The orchestrator talks to the workers by sending them requests and receiving short replies,
and it checks every value a worker returns before using it. The workers are custom code
(`src/surgic/worker.py`) built on standard libraries: PyMuPDF, Pillow, openpyxl,
LibreOffice, macOS Vision / Tesseract OCR, regex (RE2 with Hyperscan) and Presidio (spaCy).

## One document at a time

Documents are processed strictly one after another; there is no parallelism.

- There is one analyzer and one scanner for the whole run. When a document finishes, whatever
  its outcome, the analyzer forgets it and the document's working files on the RAM disk are
  deleted.
- With the default `llm.batch_size = 1`, the model is started for each document and unloaded
  after it, and the unload is verified. With a larger batch the model stays loaded across that
  many documents, but its context is purged between every document.
- Nothing is released while the run is in progress. A clean document's output is staged on the
  RAM disk, and everything is copied to the output share only after the last document is done.
  If the run aborts, nothing is released.

## The four steps

```
Input file ──► 1 find + mask ──► 2 find (LLM) ──► 3 redact ──► 4 re-scan ──► staged ──► output share
              (analyzer)        (orchestrator     (analyzer)   (scanner)
                                 + local LLM)
```

### Finding, masking and redacting are different things

| Term | What changes | Which copy |
|---|---|---|
| **Find** | Nothing. Produces a list of sensitive values and where they are. | — |
| **Mask** | Sensitive values are swapped for placeholders. | A temporary in-memory *text copy*, made only to be shown to the LLM, then discarded |
| **Redact** | Sensitive content is removed. | The actual file that is released |

Only step 1 masks, only step 3 redacts, and the released file is redacted exactly once, using
everything found in steps 1 and 2.

### Step 1: find structured data and mask it (analyzer, first request)

1. **Extract** the text, remembering where every piece came from: page and word box (PDF),
   pixel box (image) or sheet and cell (spreadsheet). PDFs are normalized first (hidden layers
   on, cropped and off-page content brought onto the page) and every page is OCR'd in full.
   Word files are converted to PDF by LibreOffice.
2. **Detect** structured values with the deterministic engines: regex patterns (SSNs, cards,
   emails, phones, IPs, employee IDs, classification markings, codenames, control numbers,
   keys) and Presidio (names, locations, dates and more).
3. **Mask**: in a text copy, replace each value with a stable placeholder:

   ```
   Original text:  Prepared by Margaret Thornbury, SSN 219-09-9999, for Halvorsen Maritime.
   Masked copy:    Prepared by [PERSON_1], SSN [US_SSN_1], for Halvorsen Maritime.
   ```

The analyzer keeps the extracted document and its findings in memory and returns only the
masked copy and finding counts. The original file has not been changed.

### Step 2: find context-dependent secrets (orchestrator + local LLM)

The orchestrator sends the masked copy, in chunks, to the local model, which flags what the
rules cannot know is sensitive: clients and vendors, trade secrets, internal projects,
indirect identifiers. The model returns only a list of strings with categories, for example
`Halvorsen Maritime: client relationship`. Before trusting the result:

- the injection tripwire has already scanned the text for instructions aimed at the model;
- each request wraps the chunk in a fresh random boundary;
- each chunk carried a planted canary, which the model must have found;
- every returned string must actually occur in the chunk, otherwise it is rejected.

See [Prompt-injection defenses](INFOSEC.md#prompt-injection-defenses). Step 2 changes nothing;
it only adds to the list of findings.

### Step 3: redact the file (analyzer, second request)

The orchestrator sends the analyzer the model's accepted strings, which are plain text with no
code or instructions. The analyzer does not run detection again. It:

1. finds every occurrence of each string in the original text (mapping back through the
   placeholders);
2. merges them with step 1's findings and extends every finding to all its occurrences, so a
   client named once in context is removed everywhere;
3. maps each finding to its exact positions in the file and rewrites the file
   (`src/surgic/redact/`):

| Input | Library | What is done |
|---|---|---|
| **PDF**, and Word files (converted to PDF) | PyMuPDF (MuPDF) | Each position is marked for redaction, then the redaction is *applied*: the characters are deleted from the page content, image pixels under them are blanked, vector shapes fully inside the box are removed, and a black box is drawn in their place. The file is then scrubbed (metadata, annotations, forms, scripts, attachments, accessibility tree, hidden text) and rewritten from scratch, so no earlier version survives inside it. |
| **Image** | Pillow | Decoded to raw pixels; each found word is painted over; a brand-new PDF is written from the pixels. The original's metadata is never copied. |
| **Spreadsheet** | openpyxl | Affected cell text becomes `[REDACTED:…]`. Formulas become their stored values; comments, links, named ranges, properties and macros are dropped; hidden sheets, rows and columns are unhidden; number formats that display literal text are reset. |
| **Plain text** | Python | Each value is replaced with `[REDACTED:…]`. |

Every type also gets a plain-text copy (the sidecar) with the same replacements. If anything
was found but nothing in the file was changed, the document is quarantined.

The value is gone from the file, not covered: it cannot be copied out, uncovered or recovered
from the file's internals.

### Step 4: re-scan the output (scanner, a separate process)

The scanner never sees the input. It re-reads the output files from scratch (text extraction,
full-page OCR, a second PDF parser, the files' raw internals) and checks for:

- any value found in steps 1–2 that is still present;
- anything the deterministic detectors find now;
- secrets found by gitleaks and trufflehog.

**The re-scan loop.** If the scanner finds a structured value that is still present (for
example OCR read it differently the second time), the orchestrator sends it back to the
analyzer. The analyzer looks for it in the *original* text; if it is there, it is added to the
findings and the file is redacted again (back to step 3). This happens at most twice
(`MAX_RESCANS = 2`). A value that is not in the original text cannot be fixed, and the
document is quarantined. A document that still fails is quarantined, and nothing from it is
released.

## The signing key

### What it is

An Ed25519 key created once at provisioning (`surgic keygen`) and stored in the Mac's login
Keychain. The public half goes to InfoSec. Only the orchestrator can use it; the sandboxed
workers, which parse untrusted documents, are blocked from the Keychain.

The key plays **no part in redaction** and **encrypts nothing**. Outputs on the share are not
encrypted by it; they are protected in transit by SMB 3 encryption.

### When it is used

| When | What is signed |
|---|---|
| End of `surgic run` | The **manifest**: document IDs, input and output SHA-256 hashes, scan results, security settings, model hash, preflight results |
| Teardown (`surgic down`) | The **closure record**: packet-capture counts and hashes, firewall and RAM-disk teardown steps, the session's manifests |

`surgic verify` checks both signatures against InfoSec's own copy of the public key.

### What a valid signature proves

- **The record is authentic and unaltered.** The manifest and closure were signed by the
  provisioned key and have not been changed since.
- **Each released file is exactly the one the run produced.** Every output file's hash is in
  the signed manifest; a swapped or edited file fails verification.
- **Each output is tied to its input.** The input's hash is recorded too.
- **The run's claims are fixed.** Scan results, settings, model hash and preflight results are
  inside the signed manifest and cannot be edited afterward.

The files themselves are not signed one by one; they are covered through their hashes in the
signed manifest, which is why verification needs both (`surgic verify --outputs`).

### What it does not prove

- **That the redaction was correct.** The signature vouches for what the run *recorded*,
  including "the re-scan passed", not for the quality of detection. That is covered by the
  re-scan, the red team and human spot-checks (residual risk 2, InfoSec decision 3).
- **That the signer behaved.** It proves who signed, not that the software was honest. Anyone
  with the operator's login could export today's software key and sign a fabricated manifest
  elsewhere (InfoSec decision 1). The Secure Enclave key in the Jamf work cannot be exported,
  and its certificate carries an attestation of which device holds it, so a valid signature
  would also prove it came from *that* Mac.

### The other key: per-document HMACs

The manifest also lists one-way fingerprints (HMAC-SHA-256) of the redacted values. They use a
throwaway random key created for each document and wiped right after, so they show *how many*
values were redacted without revealing them or letting two documents be linked. That key is
never stored and has nothing to do with signing.
