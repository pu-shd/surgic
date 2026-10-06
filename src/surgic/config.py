"""Pipeline configuration (TOML, validated with pydantic)."""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class NetworkConfig(BaseModel):
    smb_share_ip: str
    # Interface the SMB VLAN is on (e.g. "en0"). The pf pass rule is bound to
    # it, and preflight checks the route to the SMB host uses it.
    smb_interface: str = ""
    # SMB3 with encryption is required unless explicitly relaxed (signing is
    # then still required).
    smb_require_encryption: bool = True
    pf_anchor: str = "com.surgic.airgap"
    capture_dir: str = ""          # default: <ramdisk>/audit; must be on the RAM disk
    probe_ip: str = "192.0.2.1"   # RFC 5737 TEST-NET-1: must be blocked by pf

    @field_validator("smb_share_ip")
    @classmethod
    def _ip(cls, v: str) -> str:
        ipaddress.IPv4Address(v)  # by-IP only: no DNS is permitted under the airgap
        return v

    @field_validator("smb_interface")
    @classmethod
    def _iface(cls, v: str) -> str:
        if v and not re.fullmatch(r"[a-z]+[0-9]+", v):
            raise ValueError("smb_interface must be a BSD interface name such as en0")
        return v


class StorageConfig(BaseModel):
    ramdisk_name: str = "RAMDisk"
    ramdisk_size_gb: int = Field(16, ge=1, le=128)
    input_share: str = "//svc_surgic@SMB_HOST/restricted"
    output_share: str = "//svc_surgic@SMB_HOST/sanitized"
    # Empty mount-point directories only; share contents are never cached locally.
    # They sit outside the RAM disk so the output share stays mounted while the
    # RAM disk is zero-filled, letting the signed closure record that step.
    input_mount: str = "~/.surgic/mnt/in"
    output_mount: str = "~/.surgic/mnt/out"
    state_file: str = "~/.surgic/state.json"   # device names/pids/pf token only
    record_input_paths: bool = False  # file names can themselves be sensitive

    @field_validator("input_mount", "output_mount", "state_file")
    @classmethod
    def _expand(cls, v: str) -> str:
        return os.path.expanduser(v)

    @property
    def ramdisk_mount(self) -> str:
        return f"/Volumes/{self.ramdisk_name}"

    @property
    def workspace(self) -> str:
        return f"{self.ramdisk_mount}/workspace"


class LLMConfig(BaseModel):
    backend: Literal["llamacpp", "ollama", "mlx", "mock"] = "llamacpp"
    model_path: str = ""          # GGUF path (llamacpp), model dir (mlx) or tag (ollama)
    model_sha256: list[str] = []  # allowlist of permitted weight hashes
    host: str = "127.0.0.1"
    port: int = 8088
    n_ctx: int = Field(16384, ge=1024)
    chunk_chars: int = Field(6000, ge=500)
    chunk_overlap: int = Field(400, ge=0)
    temperature: float = 0.0
    max_retries: int = Field(2, ge=0, le=5)
    batch_size: int = Field(1, ge=1)  # model unloaded after every batch
    request_timeout_s: float = 600.0
    server_binary: str = ""        # override for llama-server / mlx_lm.server / ollama
    ollama_models_dir: str = "~/.ollama/models"  # weights are hashed from here, not asked of the server

    @field_validator("ollama_models_dir")
    @classmethod
    def _expand(cls, v: str) -> str:
        return os.path.expanduser(v)

    @field_validator("host")
    @classmethod
    def _loopback(cls, v: str) -> str:
        if not ipaddress.ip_address(v).is_loopback:
            raise ValueError("LLM backend must bind to loopback only")
        return v


class DetectConfig(BaseModel):
    spacy_model: str = "en_core_web_trf"
    spacy_fallback: str = "en_core_web_lg"
    presidio_entities: list[str] = [
        "PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "US_SSN", "CREDIT_CARD",
        "IP_ADDRESS", "IBAN_CODE", "US_BANK_NUMBER", "US_PASSPORT",
        "US_DRIVER_LICENSE", "LOCATION", "DATE_TIME", "URL", "MEDICAL_LICENSE",
    ]
    presidio_score_threshold: float = 0.5
    patterns_file: str = ""        # extra YAML pattern file merged with built-ins
    use_hyperscan: bool = True


class PreflightConfig(BaseModel):
    allowed_listeners: list[str] = []   # process names allowed to listen on non-loopback
    require_wifi_off: bool = True
    require_bluetooth_off: bool = True
    verify_model_hash: bool = True


class IsolationConfig(BaseModel):
    # "sandbox": document parsing runs in sandbox-exec'd worker processes with
    # no network, no Keychain, no sudo and writes confined to the workspace.
    # "process": separate worker processes without a sandbox (non-macOS CI).
    # "inprocess": tests only; requires SURGIC_ALLOW_INPROCESS=1.
    mode: Literal["sandbox", "process", "inprocess"] = "sandbox"


class AuditConfig(BaseModel):
    keychain_service: str = "com.surgic.manifest-signing"
    keychain_account: str = "surgic"
    gitleaks_binary: str = "gitleaks"
    trufflehog_binary: str = "trufflehog"
    require_secret_scanners: bool = True


class Config(BaseModel):
    network: NetworkConfig
    storage: StorageConfig = StorageConfig()
    llm: LLMConfig = LLMConfig()
    detect: DetectConfig = DetectConfig()
    audit: AuditConfig = AuditConfig()
    preflight: PreflightConfig = PreflightConfig()
    isolation: IsolationConfig = IsolationConfig()
    source_sha256: str = ""
    source_path: str = ""

    @property
    def capture_dir(self) -> str:
        return self.network.capture_dir or f"{self.storage.ramdisk_mount}/audit"

    def security_flags(self) -> dict:
        """Security-relevant settings, recorded in the signed manifest so the
        verifier can reject runs made with weakened controls."""
        return {
            "isolation": self.isolation.mode,
            "require_secret_scanners": self.audit.require_secret_scanners,
            "verify_model_hash": self.preflight.verify_model_hash,
            "require_wifi_off": self.preflight.require_wifi_off,
            "require_bluetooth_off": self.preflight.require_bluetooth_off,
            "smb_require_encryption": self.network.smb_require_encryption,
            "smb_interface_bound": bool(self.network.smb_interface),
            "allowed_listeners": len(self.preflight.allowed_listeners),
            "extra_patterns_file": bool(self.detect.patterns_file),
        }

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        raw = Path(path).read_bytes()
        cfg = cls.model_validate(tomllib.loads(raw.decode("utf-8")))
        cfg.source_sha256 = hashlib.sha256(raw).hexdigest()
        cfg.source_path = str(Path(path).resolve())
        return cfg
