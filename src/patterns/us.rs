//! US-specific PII patterns.
//!
//! Contains patterns for: US_SSN, MEDICAL_LICENSE, US_BANK_NUMBER, US_DRIVER_LICENSE,
//! US_ITIN, US_PASSPORT, US_MBI, ABA_ROUTING.

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
    // ── US Bank Account Number ──
    PiiPattern {
        name: "us_bank_number",
        entity_type: "US_BANK_NUMBER",
        // 8-17 digits, context-gated to avoid false positives on random digit strings
        pattern: r"\b\d{8,17}\b",
        score: 0.5,
        context_keywords: &[
            "account number",
            "account",
            "checking",
            "savings",
            "deposit",
            "bank number",
            "wire",
            "ach",
            "direct deposit",
        ],
        context_required: true,
    },
    // ── US Driver License ──
    PiiPattern {
        name: "us_dl_alpha_short",
        entity_type: "US_DRIVER_LICENSE",
        // 1 letter + 5-9 digits (most common format: CA, NY, TX, FL, OH, PA, etc.)
        pattern: r"\b[A-Z]\d{5,9}\b",
        score: 0.5,
        context_keywords: &[
            "driver",
            "license",
            "licence",
            "dl",
            "driving",
            "dmv",
            "permit",
            "motor vehicle",
            "state id",
        ],
        context_required: true,
    },
    PiiPattern {
        name: "us_dl_alpha_long",
        entity_type: "US_DRIVER_LICENSE",
        // 1 letter + 10-12 digits (FL, IL, MD, MI, MN)
        pattern: r"\b[A-Z]\d{10,12}\b",
        score: 0.5,
        context_keywords: &[
            "driver",
            "license",
            "licence",
            "dl",
            "driving",
            "dmv",
            "permit",
            "motor vehicle",
            "state id",
        ],
        context_required: true,
    },
    PiiPattern {
        name: "us_dl_alpha_pair",
        entity_type: "US_DRIVER_LICENSE",
        // 2 letters + 5-7 digits (WA, WI, and similar states)
        pattern: r"\b[A-Z]{2}\d{5,7}\b",
        score: 0.5,
        context_keywords: &[
            "driver",
            "license",
            "licence",
            "dl",
            "driving",
            "dmv",
            "permit",
            "motor vehicle",
            "state id",
        ],
        context_required: true,
    },
    // ── US Individual Taxpayer Identification Number (ITIN) ──
    PiiPattern {
        name: "us_itin_dash",
        entity_type: "US_ITIN",
        // 9XX-XX-XXXX — starts with 9, validated for group range in detection pipeline
        pattern: r"\b9\d{2}-\d{2}-\d{4}\b",
        score: 0.65,
        context_keywords: &[
            "itin",
            "taxpayer",
            "tax id",
            "tax identification",
            "irs",
            "individual taxpayer",
            "tax",
        ],
        context_required: true,
    },
    PiiPattern {
        name: "us_itin_space",
        entity_type: "US_ITIN",
        pattern: r"\b9\d{2}\s\d{2}\s\d{4}\b",
        score: 0.6,
        context_keywords: &[
            "itin",
            "taxpayer",
            "tax id",
            "tax identification",
            "irs",
            "individual taxpayer",
            "tax",
        ],
        context_required: true,
    },
    // ── US Passport Number ──
    PiiPattern {
        name: "us_passport",
        entity_type: "US_PASSPORT",
        // 9 digits, context-gated
        pattern: r"\b\d{9}\b",
        score: 0.6,
        context_keywords: &[
            "passport",
            "travel document",
            "state department",
            "passport number",
        ],
        context_required: true,
    },
    // ── Medicare Beneficiary Identifier (MBI) ──
    PiiPattern {
        name: "us_mbi",
        entity_type: "US_MBI",
        // 11-char positional format: C S AN N L AN N N N L AN
        // Excluded letters: S, L, O, I, B, Z → allowed: [AC-HJKMNP-RT-Y]
        pattern: r"\b[1-9][AC-HJKMNP-RT-Y][0-9AC-HJKMNP-RT-Y]\d[AC-HJKMNP-RT-Y][0-9AC-HJKMNP-RT-Y]\d{3}[AC-HJKMNP-RT-Y][0-9AC-HJKMNP-RT-Y]\b",
        score: 0.75,
        context_keywords: &[
            "medicare",
            "mbi",
            "beneficiary",
            "cms",
            "health insurance",
            "medicaid",
        ],
        context_required: true,
    },
    // ── ABA Routing Number ──
    PiiPattern {
        name: "aba_routing",
        entity_type: "ABA_ROUTING",
        // 9 digits, validated by weighted checksum + prefix in detection pipeline
        pattern: r"\b\d{9}\b",
        score: 0.7,
        context_keywords: &[
            "routing",
            "aba",
            "transit",
            "routing number",
            "wire",
            "fedwire",
        ],
        context_required: true,
    },
];
