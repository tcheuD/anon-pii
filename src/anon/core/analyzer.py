"""Presidio analyzer setup with custom recognizers."""

from __future__ import annotations

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider

from anon.recognizers.french import get_french_recognizers
from anon.recognizers.aviation import get_aviation_recognizers


def create_analyzer(use_nlp: bool = False) -> AnalyzerEngine:
    """
    Create a Presidio analyzer with custom recognizers.

    Args:
        use_nlp: If True, use spaCy NLP for name detection (requires spacy model).
                 If False, use pattern-based detection only (faster, no extra deps).
    """
    registry = RecognizerRegistry()

    if use_nlp:
        try:
            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "fr", "model_name": "fr_core_news_sm"}],
            })
            nlp_engine = provider.create_engine()
            registry.load_predefined_recognizers(nlp_engine=nlp_engine)
        except Exception:
            registry.load_predefined_recognizers()
    else:
        registry.load_predefined_recognizers()

    for recognizer in get_french_recognizers():
        registry.add_recognizer(recognizer)

    for recognizer in get_aviation_recognizers():
        registry.add_recognizer(recognizer)

    return AnalyzerEngine(registry=registry)


def get_supported_entities(analyzer: AnalyzerEngine) -> list[str]:
    """Get list of all supported entity types."""
    return sorted(analyzer.get_supported_entities())
