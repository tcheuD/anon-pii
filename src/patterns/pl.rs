//! Poland-specific PII patterns.
//!
//! Contains patterns for: PL_PESEL.

use super::PiiPattern;

pub const PL_PATTERNS: &[PiiPattern] = &[
    // ── PL PESEL (Powszechny Elektroniczny System Ewidencji Ludności) ──
    PiiPattern {
        name: "pl_pesel",
        entity_type: "PL_PESEL",
        // 11 digits, no separators
        pattern: r"\b\d{11}\b",
        score: 0.6,
        context_keywords: &[
            "pesel",
            "nr pesel",
            "numer pesel",
            "identyfikator",
            "polish id",
            "identification number",
            "national id",
            "poland",
        ],
        context_required: true,
    },
];
