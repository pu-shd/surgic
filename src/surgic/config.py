"""Pipeline configuration (TOML, validated with pydantic)."""
from __future__ import annotations

import hashlib
import ipaddress
import os
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class NetworkConfig(BaseModel):
    smb_share_ip: str
    pf_anchor: str = "com.surgic.airgap"
    capture_dir: str = "/Volumes/RAMDisk/audit"
    probe_ip: str = "192.0.2.1"   # RFC 5737 TEST-NET-1: must be blocked by pf

    @field_validator("smb_share_ip")
    @classmethod
    def _ip(cls, v: str) -> str:
        ipaddress.IPv4Address(v)  # by-IP only: no DNS is permitted under the airgap
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
    source_sha256: str = ""

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        raw = Path(path).read_bytes()
        cfg = cls.model_validate(tomllib.loads(raw.decode("utf-8")))
        cfg.source_sha256 = hashlib.sha256(raw).hexdigest()
        return cfg
