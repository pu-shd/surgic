# **Specification Prompt & System Requirements: Secure Local AI Document Sanitization Pipeline**

---

**Purpose:** This document serves as a reusable specification prompt for generating execution plans, implementation code, and architecture designs for an air-gapped, zero-retention document sanitization system. You can supply this document to an LLM to request detailed implementation blueprints, Python scripts, or compliance documentation.

## **1\. Core System Parameters & Constraints**

> * **Hardware Allocation:** Exactly 1x Mac Studio (Apple Silicon, 256GB Unified Memory).  
> * **Target Architecture:** Single-node, fully air-gapped processing pipeline.  
> * **Data Source (Input):** Read-only SMB share located on the local network containing classified/restricted documents (PDFs, DOCX, images, text).  
> * **Data Destination (Output):** Cleaned/redacted document store and cryptographically signed audit manifests.  
> * **Model Parameters:** Local open-weight LLMs (e.g., Llama-3-70B, DeepSeek-R1-Distill-Llama-70B, or Qwen-2.5-70B) running locally via vLLM-MLX, Ollama, or llama.cpp utilizing Apple Silicon Metal acceleration. Unified memory allocation capped at \~60-80GB to allow ample headroom for CPU/RAM tasks.

## **2\. Two-Phase Hybrid Redaction Engine Specification**

### **Phase A: Deterministic & Rule-Based Redaction (Pre-AI)**

To eliminate reliance on LLMs for structured or patterned sensitive data, the pipeline must enforce strict, deterministic pre-filtering using industry-standard tools:

> * **Microsoft Presidio (Analyzer & Anonymizer):** Custom entity recognition engine utilizing spaCy language models (en\_core\_web\_trf or en\_core\_web\_lg) to identify PII, SSNs, credit card numbers, IP addresses, names, and phone numbers.  
> * **Regex Engine:** Highly specific regular expressions for internal classification markers, employee IDs, custom project codenames, and document control numbers.  
> * **Document Extraction Libraries:** High-fidelity parsers including pdfplumber, PyMuPDF (fitz), and local OCR engines (macOS VNRecognizeTextRequest / Vision Framework or Tesseract) for image-based PDFs.  
> * **Hyperscan / RE2:** Ultra-fast pattern scanning across bulk extracted text before LLM context injection.

### **Phase B: AI Contextual Redaction (LLM)**

Pass the pre-sanitized text to the local open-weight model for contextual, unstructured knowledge redaction:

> * Identify indirect identifiers, strategic trade secrets, client/vendor relationships, and context-dependent sensitive information.  
> * Enforce JSON-structured output mapping original character offsets to redact categories without leaking secrets into logs.

## **3\. macOS-Specific Zero Egress Guarantees & Verification Proofs**

To satisfy Information Security requirements, the pipeline must provide cryptographic and verifiable proof that no data leaves the Mac Studio or persists on local non-volatile storage.

### **A. Network Isolation via macOS Packet Filter (pf)**

Create a dedicated pf firewall configuration (/etc/pf.anchors/airgap.rules) that restricts outbound network calls strictly to the designated SMB share IP and blocks all other traffic across all network interfaces (en0, en1, etc.):

\# /etc/pf.anchors/airgap.rules  
\# Default deny all outbound and inbound  
block in all  
block out all

\# Allow local loopback for internal pipeline communication (Ollama API / local processes)  
pass quick on lo0 all

\# Allow SMB traffic strictly to the approved source server IP  
pass out quick proto tcp to \[SMB\_SHARE\_IP\] port 445

### **B. Proof of Zero Network Egress (tcpdump Audit Log)**

Before launching processing, initiate a continuous packet capture that monitors all non-SMB traffic. The resulting .pcap file serves as proof of zero network leakage:

\# Start continuous network audit capture  
sudo tcpdump \-i any \-w /Volumes/RAMDisk/egress\_audit.pcap "not host \[SMB\_SHARE\_IP\] and not host 127.0.0.1"

### **C. Zero Data Persistence via Volatile macOS RAM Disk**

All intermediate text extractions, temporary PDF renders, and working files must exist solely inside volatile RAM (Apple Unified Memory). If power is cut or the process terminates, all data is instantly destroyed.

\# Create a 16GB Volatile RAM Disk in macOS  
diskutil erasevolume HFS+ "RAMDisk" \$(hdid \-nomount ram://33554432)

\# Set environment paths for pipeline processing  
export TMPDIR="/Volumes/RAMDisk"  
export PIPELINE\_WORKSPACE="/Volumes/RAMDisk/workspace"  
mkdir \-p "\$PIPELINE\_WORKSPACE"

### **D. Memory Flushing & Model Unloading**

Ensure the local model runner explicitly unloads weights or purges context memory between document processing batches to prevent context leakage across document boundaries.

## **4\. Information Security Sign-Off Implementation Checklist**

The table below summarizes the compliance controls, technical controls, and proof artifacts required for InfoSec approval:

| InfoSec Requirement | Technical Control / Implementation | Proof Artifact & Audit Method   |
| :---- | :---- | :---- |
| **Data Isolation & Locality** | All processing executes on a single Mac Studio (256GB RAM) connected directly to local network SMB. | System topology log and local network interface status report. |
| **Zero Network Egress** | macOS pf rules block all outbound traffic except port 445 to SMB host IP. Loopback restricted to local APIs. | Zero-byte or non-matching network capture log (egress\_audit.pcap) generated by tcpdump. |
| **Zero Local Data Retention** | Processing and temporary file writes occur exclusively within an unencrypted volatile macOS RAM Disk (/Volumes/RAMDisk). | Verification of RAM Disk mount point and post-execution unmount / zero-fill logs. |
| **Deterministic Safety Net** | Pre-processing pipeline utilizes Microsoft Presidio and custom Regex to strip known structured PII/PHI before LLM analysis. | Presidio entity match logs (hashed tokens) showing 100% detection of known structured formats. |
| **Post-Sanitization Audit** | Automated scanner (Gitleaks, TruffleHog, custom Regex) checks clean output before writing to destination. | Digitally signed audit manifest containing input/output SHA-256 hashes and leak-check scan results. |

