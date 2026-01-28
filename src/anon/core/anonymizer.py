"""Anonymizer with token-based replacement."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from presidio_analyzer import AnalyzerEngine, RecognizerResult

from anon.core.mapping import AnonymizationMapping


@dataclass
class DetectedEntity:
    """A detected PII entity."""
    entity_type: str
    text: str
    start: int
    end: int
    score: float
    token: Optional[str] = None


class Anonymizer:
    """Anonymizes text by replacing PII with tokens."""

    def __init__(self, analyzer: AnalyzerEngine, mapping: Optional[AnonymizationMapping] = None):
        self.analyzer = analyzer
        self.mapping = mapping or AnonymizationMapping()

    def anonymize(
        self,
        text: str,
        language: str = "en",
        score_threshold: float = 0.5,
    ) -> tuple[str, list[DetectedEntity]]:
        """
        Anonymize text by replacing PII with tokens.

        Returns:
            Tuple of (anonymized_text, list of detected entities)
        """
        results = self.analyzer.analyze(
            text=text,
            language=language,
            score_threshold=score_threshold,
        )

        results = self._filter_overlapping(results)
        results = sorted(results, key=lambda x: x.start, reverse=True)

        detected: list[DetectedEntity] = []
        anonymized = text

        for result in results:
            original = text[result.start:result.end]
            token = self.mapping.add(result.entity_type, original)

            entity = DetectedEntity(
                entity_type=result.entity_type,
                text=original,
                start=result.start,
                end=result.end,
                score=result.score,
                token=token,
            )
            detected.append(entity)

            anonymized = anonymized[:result.start] + token + anonymized[result.end:]

        detected.reverse()
        return anonymized, detected

    def _filter_overlapping(
        self, results: list[RecognizerResult]
    ) -> list[RecognizerResult]:
        """Filter overlapping detections, keeping highest score or longest span."""
        if not results:
            return []

        sorted_results = sorted(
            results,
            key=lambda x: (x.start, -(x.end - x.start), -x.score)
        )

        filtered: list[RecognizerResult] = []
        for result in sorted_results:
            overlaps = False
            for kept in filtered:
                if result.start < kept.end and result.end > kept.start:
                    overlaps = True
                    break
            if not overlaps:
                filtered.append(result)

        return filtered

    def get_mapping(self) -> AnonymizationMapping:
        """Get the current mapping."""
        return self.mapping
