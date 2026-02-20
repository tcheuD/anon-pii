//! US-specific PII patterns.
//!
//! Contains patterns for: US_SSN, MEDICAL_LICENSE.

use super::PiiPattern;

pub const US_PATTERNS: &[PiiPattern] = &[
    // ── US Social Security Number ──
    PiiPattern {
        name: "us_ssn_dash",
        entity_type: "US_SSN",
        // 123-45-6789 format. Validated in detection pipeline for invalid prefixes/groups.
        pattern: r"\b\d{3}-\d{2}-\d{4}\b",
        score: 0.7,
        context_keywords: &["ssn", "social security", "social", "security number", "tax"],
        context_required: true,
    },
    PiiPattern {
        name: "us_ssn_space",
        entity_type: "US_SSN",
        pattern: r"\b\d{3}\s\d{2}\s\d{4}\b",
        score: 0.65,
        context_keywords: &["ssn", "social security", "social", "security number", "tax"],
        context_required: true,
    },
    // ── Medical License ──
    PiiPattern {
        name: "medical_license",
        entity_type: "MEDICAL_LICENSE",
        // Common format: 1-2 letters + 6-10 digits (e.g. ME12345678, D1234567)
        pattern: r"\b[A-Z]{1,2}\d{6,10}\b",
        score: 0.6,
        context_keywords: &[
            "medical",
            "license",
            "licence",
            "physician",
            "doctor",
            "dea",
            "npi",
            "practitioner",
            "provider",
            "prescriber",
        ],
        context_required: true,
    },
];
