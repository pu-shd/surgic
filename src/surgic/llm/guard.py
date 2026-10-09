"""Runtime defenses against documents that try to steer the Phase B model.

* Boundaries - every request wraps the chunk in markers carrying a fresh
  random tag, so text inside a document cannot "close" the data block and
  speak as the system (a fixed ``</chunk>`` could be forged).
* Canaries - every chunk carries one synthetic, randomly generated sensitive
  sentence at a random position. A model that has been talked out of
  reporting things misses it; the chunk is then retried once with a fresh
  canary, and the document is quarantined if the canary is missed again.
  Canary findings are discarded and never touch the document.
* Tripwire - deterministic patterns for text addressed to an AI model
  ("ignore previous instructions", "do not redact", fake role tags, ...).
  A hit quarantines the document (default) or flags it for human review.

Limits: canaries catch blanket suppression ("report nothing"), not an
instruction to skip one specific value while reporting everything else; the
tripwire catches common phrasings, not every paraphrase. Neither replaces the
deterministic Phase A rules or the post-scan, which the model cannot affect.
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

import yaml

# ---------------------------------------------------------------- boundaries


def new_boundary(chunk: str) -> str:
    """A 16-hex-digit tag that does not occur in the chunk."""
    while True:
        tag = secrets.token_hex(8)
        if tag not in chunk:
            return tag


# ---------------------------------------------------------------- canaries
_ONSETS = ("br", "c", "d", "f", "g", "h", "k", "l", "m", "n", "p", "r", "s", "t", "v", "z", "dr", "kr", "st", "tr")
_VOWELS = ("a", "e", "i", "o", "u", "ae", "ei", "ou")
_CODAS = ("", "", "n", "r", "s", "l", "x", "k", "th", "nd")
SUFFIXES = ("Holdings", "Logistics", "Biotech", "Shipping", "Analytics", "Partners", "Systems",
            "Laboratories", "Materials", "Capital")
_PROJECTS = ("Aurora", "Basalt", "Cobalt", "Driftwood", "Ember", "Fjord", "Granite", "Harbor", "Juniper",
             "Kestrel", "Lumen", "Meridian", "Nimbus", "Obsidian", "Quarry", "Sable", "Tundra", "Willow")
_TEMPLATES = (
    "{org} is our confidential supplier for the {proj} program under contract {code}.",
    "Under non-public agreement {code}, {org} will license our {proj} process.",
    "{org} remains a key client; renewal terms for {proj} are confidential ({code}).",
    "Margins on the {proj} line depend on undisclosed pricing from {org} (contract {code}).",
    "We are in confidential acquisition talks with {org} about the {proj} unit ({code}).",
)
# Recognizes generated canary organizations. For test doubles only: the
# pipeline knows each canary it planted and never needs to recognize one.
CANARY_RE = re.compile(r"\b[A-Z][a-z]{4,16} (?:" + "|".join(SUFFIXES) + r")\b")


@dataclass(frozen=True)
class Canary:
    sentence: str
    org: str      # e.g. "Draevoth Shipping"
    marker: str   # the distinctive invented word, e.g. "Draevoth"


def _word(rng: secrets.SystemRandom) -> str:
    w = "".join(rng.choice(_ONSETS) + rng.choice(_VOWELS) for _ in range(rng.choice((2, 3))))
    return (w + rng.choice(_CODAS)).capitalize()


def make_canary(rng: secrets.SystemRandom | None = None) -> Canary:
    rng = rng or secrets.SystemRandom()
    marker = _word(rng)
    while len(marker) < 5:
        marker = _word(rng)
    org = f"{marker} {rng.choice(SUFFIXES)}"
    code = f"{rng.choice('ABCDEFGHJKMNPRSTUVWXYZ')}{rng.choice('ABCDEFGHJKMNPRSTUVWXYZ')}-{rng.randrange(1000, 9999)}"
    sentence = rng.choice(_TEMPLATES).format(org=org, proj=rng.choice(_PROJECTS), code=code)
    return Canary(sentence=sentence, org=org, marker=marker)


def insert_canary(chunk: str, canary: Canary, rng: secrets.SystemRandom | None = None) -> tuple[str, int, int]:
    """Place the canary at a random paragraph break, or the start or end of
    the chunk. Never inside a line or between soft-wrapped lines: a value
    wrapped across lines ("cold-fusion\nannealing") must stay contiguous or
    the model could not see it. Returns (probe text, insertion offset,
    inserted length)."""
    rng = rng or secrets.SystemRandom()
    cuts = [0, len(chunk)] + [m.end() for m in re.finditer(r"\n\s*\n", chunk)]
    k = rng.choice(sorted(set(cuts)))
    if k == 0:
        piece = canary.sentence + "\n\n"
    elif k == len(chunk):
        piece = "\n\n" + canary.sentence
    else:
        piece = canary.sentence + "\n\n"
    return chunk[:k] + piece + chunk[k:], k, len(piece)


# ---------------------------------------------------------------- tripwire
@lru_cache(maxsize=1)
def _rules() -> list[tuple[str, object]]:
    import re2
    data = yaml.safe_load(resources.files("surgic.data").joinpath("injection_patterns.yaml").read_text())
    return [(r["id"], re2.compile(r["regex"])) for r in data["rules"]]


def tripwire(text: str) -> dict[str, int]:
    """Counts of injection-pattern hits by rule id (empty: nothing found)."""
    hits: dict[str, int] = {}
    for rid, rx in _rules():
        n = sum(1 for _ in rx.finditer(text))
        if n:
            hits[rid] = n
    return dict(sorted(hits.items()))
