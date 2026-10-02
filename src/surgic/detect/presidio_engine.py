"""Microsoft Presidio analyzer wrapper (spaCy NER + Presidio recognizers)."""
from __future__ import annotations

from .spans import Span

MAX_BLOCK = 50_000  # characters per analyzer call (transformer models are slow on huge inputs)


def _blocks(text: str, size: int = MAX_BLOCK, overlap: int = 200):
    """Yield (offset, block) on newline boundaries with overlap."""
    pos = 0
    n = len(text)
    while pos < n:
        end = min(pos + size, n)
        if end < n:
            nl = text.rfind("\n", pos + size // 2, end)
            if nl != -1:
                end = nl + 1
        yield pos, text[pos:end]
        if end >= n:
            break
        pos = max(end - overlap, pos + 1)


def _pin_tldextract_offline() -> None:
    """Presidio's email recognizer calls tldextract.extract(), whose default
    instance downloads the public-suffix list over the network. Force the
    bundled snapshot, with no on-disk cache."""
    import logging

    import tldextract
    from presidio_analyzer.predefined_recognizers.generic import email_recognizer

    offline = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, fallback_to_snapshot=True)
    email_recognizer.tldextract = type("tld", (), {"extract": staticmethod(offline)})
    logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)


class PresidioEngine:
    def __init__(self, spacy_model: str, fallback: str, entities: list[str], threshold: float) -> None:
        _pin_tldextract_offline()
        import spacy.util
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        model = spacy_model if spacy.util.is_package(spacy_model) else fallback
        if not spacy.util.is_package(model):
            raise RuntimeError("spacy_model_missing")
        self.model_name = model
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": model}],
        })
        self.analyzer = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
        self.entities = entities
        self.threshold = threshold

    def find(self, text: str) -> list[Span]:
        out = []
        for off, block in _blocks(text):
            for r in self.analyzer.analyze(text=block, entities=self.entities, language="en",
                                           score_threshold=self.threshold):
                if r.end > r.start:
                    out.append(Span(off + r.start, off + r.end, r.entity_type, "presidio", float(r.score)))
        return out
