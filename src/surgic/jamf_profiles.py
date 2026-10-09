"""Generate Jamf-deployable configuration profiles and declarations.

Output (all deterministic for a given config, so they can be diffed/reviewed):
  <prefix>.restrictions.mobileconfig  Restrictions + Application Firewall
  <prefix>.acme.mobileconfig          Secure Enclave ACME identity (attested)
  <prefix>.diskmanagement.json        DDM disk-management declaration
  surgic.sudoers                      /etc/sudoers.d/surgic fragment
  airgap.rules                        pf ruleset (with network.pf_rules_managed)

Restriction keys follow Apple's profile reference at the time of writing;
confirm each against the current reference and your Jamf Pro version. Several
require a supervised (ADE-enrolled) Mac.
"""
from __future__ import annotations

import json
import plistlib
import uuid
from pathlib import Path

from . import jamf

_NS = uuid.UUID("6f1d3c2e-9a51-4b8e-8f0e-5c1a2b3d4e5f")

RESTRICTIONS = {
    "allowAirDrop": False,
    "allowActivityContinuation": False,        # Handoff
    "allowAirPlayIncomingRequests": False,     # AirPlay Receiver
    "allowUniversalControl": False,
    "allowiPhoneMirroring": False,
    "allowBluetoothModification": False,       # locks the setting; power off via policy
    "allowCloudDocumentSync": False,
    "allowCloudDesktopAndDocuments": False,
    "allowCloudKeychainSync": False,
    "allowDiagnosticSubmission": False,
    "allowAssistant": False,                   # Siri
    "forceOnDeviceOnlyDictation": True,
    "allowExternalIntelligenceIntegrations": False,
    "allowWritingTools": False,
    "allowContentCaching": False,
}

FIREWALL = {"EnableFirewall": True, "BlockAllIncoming": True, "EnableStealthMode": True}


def _uuid(name: str) -> str:
    return str(uuid.uuid5(_NS, name)).upper()


def profile_ids(cfg) -> list[str]:
    p = cfg.jamf.profile_prefix
    return [f"{p}.restrictions", f"{p}.acme"]


def _profile(cfg, ident: str, name: str, payloads: list[dict]) -> bytes:
    return plistlib.dumps({
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": ident,
        "PayloadUUID": _uuid(ident),
        "PayloadDisplayName": name,
        "PayloadOrganization": cfg.jamf.organization,
        "PayloadScope": "System",
        "PayloadRemovalDisallowed": True,
        "PayloadContent": payloads,
    }, sort_keys=True)


def restrictions_profile(cfg) -> bytes:
    p = cfg.jamf.profile_prefix
    return _profile(cfg, f"{p}.restrictions", "surgic: airgap restrictions", [
        {"PayloadType": "com.apple.applicationaccess", "PayloadVersion": 1,
         "PayloadIdentifier": f"{p}.restrictions.applicationaccess",
         "PayloadUUID": _uuid(f"{p}.restrictions.applicationaccess"),
         "PayloadDisplayName": "Restrictions", **RESTRICTIONS},
        {"PayloadType": "com.apple.security.firewall", "PayloadVersion": 1,
         "PayloadIdentifier": f"{p}.restrictions.firewall",
         "PayloadUUID": _uuid(f"{p}.restrictions.firewall"),
         "PayloadDisplayName": "Application Firewall", **FIREWALL},
    ])


def acme_profile(cfg) -> bytes:
    p, a = cfg.jamf.profile_prefix, cfg.audit
    return _profile(cfg, f"{p}.acme", "surgic: manifest signing identity", [
        {"PayloadType": "com.apple.security.acme", "PayloadVersion": 1,
         "PayloadIdentifier": f"{p}.acme.identity", "PayloadUUID": _uuid(f"{p}.acme.identity"),
         "PayloadDisplayName": "surgic signing (Secure Enclave)",
         "DirectoryURL": cfg.jamf.acme_directory_url,
         "ClientIdentifier": cfg.jamf.acme_client_identifier,
         "KeyType": "ECSECPrimeRandom", "KeySize": 256,
         "HardwareBound": True, "Attest": True,
         "KeyIsExtractable": False,
         # Required so the surgic Python process can use the key for signing.
         # The key still cannot leave the Secure Enclave; see docs/JAMF.md.
         "AllowAllAppsAccess": True,
         "UsageFlags": 1,                      # digitalSignature
         "Subject": [[["CN", a.acme_subject_cn]]]},
    ])


def disk_declaration(cfg) -> str:
    p = cfg.jamf.profile_prefix
    return json.dumps({
        "Type": "com.apple.configuration.diskmanagement.settings",
        "Identifier": f"{p}.diskmanagement",
        "ServerToken": _uuid(f"{p}.diskmanagement"),
        "Payload": {"Restrictions": {"ExternalStorage": "Disallowed", "NetworkStorage": "Allowed"}},
    }, indent=2, sort_keys=True) + "\n"


def write_all(cfg, out_dir: str) -> list[str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    p = cfg.jamf.profile_prefix
    files = {
        f"{p}.restrictions.mobileconfig": restrictions_profile(cfg),
        f"{p}.acme.mobileconfig": acme_profile(cfg),
        f"{p}.diskmanagement.json": disk_declaration(cfg).encode(),
        "surgic.sudoers": jamf.sudoers(cfg).encode(),
        "airgap.rules": jamf.pf_rules(cfg).encode(),
    }
    written = []
    for name, data in files.items():
        (out / name).write_bytes(data)
        written.append(str(out / name))
    return written
