//! Thailand-specific PII patterns.
//!
//! Contains patterns for: TH_TNIN.

use super::PiiPattern;

pub const TH_PATTERNS: &[PiiPattern] = &[
    // ── TH TNIN (Thai National Identification Number) ──
    PiiPattern {
        name: "th_tnin",
        entity_type: "TH_TNIN",
        // 13 digits, no separators
        pattern: r"\b\d{13}\b",
        score: 0.6,
        context_keywords: &[
            "thai",
            "thailand",
            "national id",
            "identification number",
            "citizen id",
            "personal id",
            "tnin",
            "บัตรประชาชน",
            "เลขบัตรประชาชน",
            "เลขประจำตัว",
        ],
        context_required: true,
    },
];
