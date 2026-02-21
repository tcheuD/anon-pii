//! Spain-specific PII patterns.
//!
//! Contains patterns for: ES_NIF, ES_NIE.

use super::PiiPattern;

pub const ES_PATTERNS: &[PiiPattern] = &[
    // ── ES NIF (Número de Identificación Fiscal) ──
    PiiPattern {
        name: "es_nif",
        entity_type: "ES_NIF",
        // 8 digits + optional separator + control letter (excludes I, O, U)
        pattern: r"\b\d{8}[-\s]?[A-HJ-NP-TV-Z]\b",
        score: 0.7,
        context_keywords: &[
            "dni",
            "nif",
            "documento nacional",
            "identificación",
            "fiscal",
            "documento",
            "identidad",
        ],
        context_required: true,
    },
    // ── ES NIE (Número de Identidad de Extranjero) ──
    PiiPattern {
        name: "es_nie",
        entity_type: "ES_NIE",
        // X/Y/Z + optional separator + 7 digits + optional separator + control letter
        pattern: r"\b[XYZ][-\s]?\d{7}[-\s]?[A-HJ-NP-TV-Z]\b",
        score: 0.7,
        context_keywords: &[
            "nie",
            "extranjero",
            "identificación",
            "residencia",
            "foreigner",
        ],
        context_required: true,
    },
];
