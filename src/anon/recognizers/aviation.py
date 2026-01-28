"""Aviation-specific PII recognizers."""

from __future__ import annotations

import re
from typing import Optional

from presidio_analyzer import EntityRecognizer, Pattern, PatternRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts


aircraft_registration_recognizer = PatternRecognizer(
    supported_entity="AIRCRAFT_REGISTRATION",
    name="AircraftRegistrationRecognizer",
    patterns=[
        Pattern(
            name="french_registration",
            regex=r"\bF-[A-Z]{4}\b",
            score=0.95,
        ),
        Pattern(
            name="european_registration",
            regex=r"\b(?:D|G|I|EC|HB|OO|PH|OE|SE|LN|OH|CS|EI|9H)-[A-Z]{3,4}\b",
            score=0.9,
        ),
        Pattern(
            name="us_registration",
            regex=r"\bN\d{1,5}[A-Z]{0,2}\b",
            score=0.85,
        ),
    ],
    context=["aircraft", "avion", "registration", "immat", "appareil", "tail", "immatriculation"],
)


flight_number_recognizer = PatternRecognizer(
    supported_entity="FLIGHT_NUMBER",
    name="FlightNumberRecognizer",
    patterns=[
        Pattern(
            name="amelia_flights",
            regex=r"\b(?:IZM|RLA|AME|GJT)[0-9]{1,4}\b",
            score=0.9,
        ),
        Pattern(
            name="iata_flights",
            regex=r"\b[A-Z]{2}[0-9]{1,4}\b",
            score=0.4,
        ),
        Pattern(
            name="icao_flights",
            regex=r"\b[A-Z]{3}[0-9]{1,4}\b",
            score=0.5,
        ),
    ],
    context=["flight", "vol", "departure", "arrival", "schedule", "rotation", "leg", "sector"],
)


class CrewCodeRecognizer(EntityRecognizer):
    """
    Recognizes 3-letter crew codes with aviation context.

    Crew codes are 3 uppercase letters that identify crew members.
    They require context to avoid false positives (e.g., "THE", "AND").
    """

    CREW_CONTEXT = [
        "crew", "equipage", "pilot", "pilote", "captain", "cdb", "commandant",
        "copilot", "copilote", "opl", "cabin", "pnc", "pnt", "steward",
        "hostess", "hotesse", "first officer", "fo", "member", "membre",
        "roster", "planning", "duty", "service",
    ]

    COMMON_WORDS = {
        "THE", "AND", "FOR", "NOT", "YOU", "ALL", "CAN", "HAD", "HER", "WAS",
        "ONE", "OUR", "OUT", "ARE", "BUT", "HIS", "HAS", "NEW", "NOW", "OLD",
        "SEE", "WAY", "WHO", "BOY", "DID", "GET", "LET", "PUT", "SAY", "SHE",
        "TOO", "USE", "DAY", "MAN", "END", "MAY", "SET", "TRY", "ASK", "BIG",
        "VOL", "VIA", "PAX", "ETA", "ETD", "UTC", "GMT", "AOG", "MEL", "CDM",
    }

    def __init__(self):
        super().__init__(
            supported_entities=["CREW_CODE"],
            name="CrewCodeRecognizer",
            supported_language="en",
        )

    def load(self) -> None:
        pass

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: Optional[NlpArtifacts] = None,
    ) -> list[RecognizerResult]:
        results: list[RecognizerResult] = []
        pattern = r"\b[A-Z]{3}\b"

        for match in re.finditer(pattern, text):
            code = match.group()

            if code in self.COMMON_WORDS:
                continue

            start = max(0, match.start() - 80)
            end = min(len(text), match.end() + 80)
            context_window = text[start:end].lower()

            if any(ctx in context_window for ctx in self.CREW_CONTEXT):
                results.append(
                    RecognizerResult(
                        entity_type="CREW_CODE",
                        start=match.start(),
                        end=match.end(),
                        score=0.85,
                    )
                )

        return results


def get_aviation_recognizers() -> list[EntityRecognizer | PatternRecognizer]:
    """Return all aviation PII recognizers."""
    return [
        aircraft_registration_recognizer,
        flight_number_recognizer,
        CrewCodeRecognizer(),
    ]
