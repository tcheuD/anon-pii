"""French PII recognizers."""

from presidio_analyzer import Pattern, PatternRecognizer


french_phone_recognizer = PatternRecognizer(
    supported_entity="FR_PHONE_NUMBER",
    name="FrenchPhoneRecognizer",
    patterns=[
        Pattern(
            name="fr_phone_international",
            regex=r"\+33\s?[1-9](?:[\s\.\-]?\d{2}){4}",
            score=0.9,
        ),
        Pattern(
            name="fr_phone_national",
            regex=r"0[1-9](?:[\s\.\-]?\d{2}){4}",
            score=0.7,
        ),
        Pattern(
            name="fr_phone_compact",
            regex=r"(?<!\d)0[1-9]\d{8}(?!\d)",
            score=0.6,
        ),
    ],
    context=["telephone", "tel", "phone", "mobile", "contact", "appeler", "numero", "portable"],
)


french_iban_recognizer = PatternRecognizer(
    supported_entity="FR_IBAN",
    name="FrenchIBANRecognizer",
    patterns=[
        Pattern(
            name="fr_iban_spaced",
            regex=r"FR\d{2}[\s]?(?:\d{4}[\s]?){5}\d{3}",
            score=0.95,
        ),
        Pattern(
            name="fr_iban_compact",
            regex=r"FR\d{25}",
            score=0.9,
        ),
    ],
    context=["iban", "compte", "account", "virement", "bank", "banque", "bancaire"],
)


french_ssn_recognizer = PatternRecognizer(
    supported_entity="FR_SSN",
    name="FrenchSSNRecognizer",
    patterns=[
        Pattern(
            name="fr_ssn_spaced",
            regex=r"[12]\s?\d{2}\s?(?:0[1-9]|1[0-2]|[2-9]\d)\s?(?:\d{2}|2[AB])\s?\d{3}\s?\d{3}(?:\s?\d{2})?",
            score=0.85,
        ),
        Pattern(
            name="fr_ssn_compact",
            regex=r"[12]\d{2}(?:0[1-9]|1[0-2]|[2-9]\d)(?:\d{2}|2[AB])\d{6}(?:\d{2})?",
            score=0.8,
        ),
    ],
    context=["secu", "securite sociale", "ssn", "nir", "carte vitale", "numero", "immatriculation"],
)


french_passport_recognizer = PatternRecognizer(
    supported_entity="FR_PASSPORT",
    name="FrenchPassportRecognizer",
    patterns=[
        Pattern(
            name="fr_passport",
            regex=r"\b\d{2}[A-Z]{2}\d{5}\b",
            score=0.7,
        ),
    ],
    context=["passeport", "passport", "document", "identite"],
)


def get_french_recognizers() -> list[PatternRecognizer]:
    """Return all French PII recognizers."""
    return [
        french_phone_recognizer,
        french_iban_recognizer,
        french_ssn_recognizer,
        french_passport_recognizer,
    ]
