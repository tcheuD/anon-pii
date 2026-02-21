//! Finland-specific PII patterns.
//!
//! Contains patterns for: FI_PERSONAL_IDENTITY_CODE.

use super::PiiPattern;

pub const FI_PATTERNS: &[PiiPattern] = &[
    // ── FI Personal Identity Code (henkilötunnus / HETU) ──
    // Format: DDMMYYCSSSQ — 11 chars
    // C = century separator (+, -, Y, A)
    // SSS = individual number (002-899)
    // Q = control character (0-9 or letter from mod-31 lookup)
    PiiPattern {
        name: "fi_personal_identity_code",
        entity_type: "FI_PERSONAL_IDENTITY_CODE",
        pattern: r"\b\d{6}[-+AYay]\d{3}[0-9A-Ya-y]\b",
        score: 0.6,
        context_keywords: &[
            "henkilötunnus",
            "henkilotunnus",
            "hetu",
            "personal identity code",
            "personal id",
            "finnish id",
            "identification number",
            "finland",
            "sosiaaliturvatunnus",
        ],
        context_required: true,
    },
];
