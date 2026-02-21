//! UK-specific PII patterns.
//!
//! Contains patterns for: UK_NHS, UK_NINO.

use super::PiiPattern;

pub const UK_PATTERNS: &[PiiPattern] = &[
    // ── UK NHS Number ──
    PiiPattern {
        name: "uk_nhs_spaced",
        entity_type: "UK_NHS",
        // Standard display format: 3-3-4 with spaces (e.g. 943 476 5919)
        pattern: r"\b\d{3}\s\d{3}\s\d{4}\b",
        score: 0.7,
        context_keywords: &[
            "nhs",
            "nhs number",
            "health",
            "patient",
            "national health",
            "hospital",
            "medical",
            "gp",
            "surgery",
        ],
        context_required: true,
    },
    PiiPattern {
        name: "uk_nhs_compact",
        entity_type: "UK_NHS",
        // Compact 10-digit format (e.g. 9434765919)
        pattern: r"\b\d{10}\b",
        score: 0.6,
        context_keywords: &[
            "nhs",
            "nhs number",
            "health",
            "patient",
            "national health",
            "hospital",
            "medical",
            "gp",
            "surgery",
        ],
        context_required: true,
    },
    // ── UK National Insurance Number (NINO) ──
    PiiPattern {
        name: "uk_nino_spaced",
        entity_type: "UK_NINO",
        // Standard display: XX 99 99 99 X (e.g. AB 12 34 56 C)
        pattern: r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
        score: 0.7,
        context_keywords: &[
            "nino",
            "national insurance",
            "ni number",
            "insurance number",
            "tax",
            "hmrc",
            "paye",
            "contributions",
        ],
        context_required: true,
    },
];
