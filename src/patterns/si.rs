//! Slovenia-specific PII patterns.
//!
//! Contains patterns for: SI_EMSO, SI_TAX_NUMBER.

use super::PiiPattern;

pub const SI_PATTERNS: &[PiiPattern] = &[
    // ── SI EMSO (Enotna Matična Številka Občana) ──
    PiiPattern {
        name: "si_emso",
        entity_type: "SI_EMSO",
        // 13 digits, no separators
        pattern: r"\b\d{13}\b",
        score: 0.6,
        context_keywords: &[
            "emso",
            "emšo",
            "matična številka",
            "maticna stevilka",
            "jmbg",
            "personal id",
            "identification number",
            "slovenia",
        ],
        context_required: true,
    },
    // ── SI Tax Number (Davčna Številka) ──
    PiiPattern {
        name: "si_tax_number",
        entity_type: "SI_TAX_NUMBER",
        // 8 digits, first digit 1-9
        pattern: r"\b[1-9]\d{7}\b",
        score: 0.6,
        context_keywords: &[
            "davčna",
            "davcna",
            "davčna številka",
            "davcna stevilka",
            "tax number",
            "tax id",
            "ddv",
            "slovenia",
        ],
        context_required: true,
    },
];
