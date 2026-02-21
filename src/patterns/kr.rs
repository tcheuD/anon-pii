//! South Korea-specific PII patterns.
//!
//! Contains patterns for: KR_RRN, KR_BRN, KR_DRIVER_LICENSE, KR_FRN, KR_PASSPORT.

use super::PiiPattern;

pub const KR_PATTERNS: &[PiiPattern] = &[
    // ── KR RRN (Resident Registration Number / 주민등록번호) ──
    PiiPattern {
        name: "kr_rrn",
        entity_type: "KR_RRN",
        // YYMMDD-SXXXXXX where S is gender digit 1-4 (citizens)
        pattern: r"\b\d{6}-[1-4]\d{6}\b",
        score: 0.7,
        context_keywords: &[
            "rrn",
            "resident registration",
            "주민등록",
            "주민번호",
            "registration number",
            "resident number",
            "resident",
        ],
        context_required: true,
    },
    // ── KR FRN (Foreign Registration Number / 외국인등록번호) ──
    PiiPattern {
        name: "kr_frn",
        entity_type: "KR_FRN",
        // YYMMDD-SXXXXXX where S is gender digit 5-8 (foreigners)
        pattern: r"\b\d{6}-[5-8]\d{6}\b",
        score: 0.7,
        context_keywords: &[
            "frn",
            "foreign registration",
            "외국인등록",
            "alien registration",
            "foreigner",
            "registration number",
        ],
        context_required: true,
    },
    // ── KR BRN (Business Registration Number / 사업자등록번호) ──
    PiiPattern {
        name: "kr_brn",
        entity_type: "KR_BRN",
        // Standard display: XXX-XX-XXXXX
        pattern: r"\b\d{3}-\d{2}-\d{5}\b",
        score: 0.7,
        context_keywords: &[
            "brn",
            "business registration",
            "사업자등록",
            "사업자번호",
            "business number",
            "tax id",
            "business",
        ],
        context_required: true,
    },
    // ── KR Driver's License (운전면허번호) ──
    PiiPattern {
        name: "kr_driver_license",
        entity_type: "KR_DRIVER_LICENSE",
        // Standard display: AA-BB-CCCCCC-DD (regional code 11-28)
        pattern: r"\b(?:1[1-9]|2[0-8])-\d{2}-\d{6}-\d{2}\b",
        score: 0.7,
        context_keywords: &[
            "driver",
            "license",
            "licence",
            "운전면허",
            "면허번호",
            "driving",
            "dl",
        ],
        context_required: true,
    },
    // ── KR Passport (여권번호) ──
    PiiPattern {
        name: "kr_passport",
        entity_type: "KR_PASSPORT",
        // Type letter + 8 digits (e.g. M12345678)
        pattern: r"\b[MSROD]\d{8}\b",
        score: 0.6,
        context_keywords: &["passport", "여권", "여권번호", "travel document"],
        context_required: true,
    },
];
