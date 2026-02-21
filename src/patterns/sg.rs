//! Singapore-specific PII patterns.
//!
//! Contains patterns for: SG_NRIC_FIN, SG_UEN.

use super::PiiPattern;

pub const SG_PATTERNS: &[PiiPattern] = &[
    // ── SG NRIC/FIN (National Registration Identity Card / Foreign Identification Number) ──
    PiiPattern {
        name: "sg_nric_fin",
        entity_type: "SG_NRIC_FIN",
        // Prefix [STFGM] + 7 digits + check letter
        pattern: r"\b[STFGM]\d{7}[A-Z]\b",
        score: 0.7,
        context_keywords: &[
            "nric",
            "fin",
            "identity card",
            "ic number",
            "ic no",
            "identification",
            "singapore id",
            "singapore",
        ],
        context_required: true,
    },
    // ── SG UEN — Format C: Other entities ([RST] + 2-digit year + 2-letter type + 4 digits + check) ──
    PiiPattern {
        name: "sg_uen_entity",
        entity_type: "SG_UEN",
        // e.g. T08GA0001L
        pattern: r"\b[RST]\d{2}[A-Z]{2}\d{4}[A-Z]\b",
        score: 0.7,
        context_keywords: &[
            "uen",
            "unique entity",
            "entity number",
            "company",
            "business",
            "singapore",
            "acra",
        ],
        context_required: true,
    },
    // ── SG UEN — Format B: Local company (4-digit year + 5 digits + check letter) ──
    PiiPattern {
        name: "sg_uen_company",
        entity_type: "SG_UEN",
        // e.g. 201912345W
        pattern: r"\b(?:19|20)\d{7}[A-Z]\b",
        score: 0.6,
        context_keywords: &[
            "uen",
            "unique entity",
            "entity number",
            "company",
            "business",
            "singapore",
            "acra",
        ],
        context_required: true,
    },
];
