//! Australia-specific PII patterns.
//!
//! Contains patterns for: AU_ABN, AU_ACN, AU_TFN, AU_MEDICARE.

use super::PiiPattern;

pub const AU_PATTERNS: &[PiiPattern] = &[
    // ── AU ABN (Australian Business Number) ──
    PiiPattern {
        name: "au_abn_formatted",
        entity_type: "AU_ABN",
        // Standard display: 2-3-3-3 with spaces (e.g. 51 824 753 556)
        pattern: r"\b\d{2}\s\d{3}\s\d{3}\s\d{3}\b",
        score: 0.7,
        context_keywords: &[
            "abn",
            "australian business number",
            "business number",
            "business",
            "gst",
            "tax",
            "ato",
        ],
        context_required: true,
    },
    PiiPattern {
        name: "au_abn_compact",
        entity_type: "AU_ABN",
        // Compact 11-digit format (e.g. 51824753556)
        pattern: r"\b\d{11}\b",
        score: 0.6,
        context_keywords: &[
            "abn",
            "australian business number",
            "business number",
            "business",
            "gst",
            "tax",
            "ato",
        ],
        context_required: true,
    },
    // ── AU ACN (Australian Company Number) ──
    PiiPattern {
        name: "au_acn_formatted",
        entity_type: "AU_ACN",
        // Standard display: 3-3-3 with spaces (e.g. 004 085 616)
        pattern: r"\b\d{3}\s\d{3}\s\d{3}\b",
        score: 0.7,
        context_keywords: &[
            "acn",
            "australian company number",
            "company number",
            "company",
            "asic",
            "corporation",
        ],
        context_required: true,
    },
    PiiPattern {
        name: "au_acn_compact",
        entity_type: "AU_ACN",
        // Compact 9-digit format (e.g. 004085616)
        pattern: r"\b\d{9}\b",
        score: 0.5,
        context_keywords: &[
            "acn",
            "australian company number",
            "company number",
            "company",
            "asic",
            "corporation",
        ],
        context_required: true,
    },
    // ── AU TFN (Tax File Number) ──
    PiiPattern {
        name: "au_tfn_formatted",
        entity_type: "AU_TFN",
        // Standard display: 3-3-3 with spaces (e.g. 123 456 782)
        pattern: r"\b\d{3}\s\d{3}\s\d{3}\b",
        score: 0.7,
        context_keywords: &[
            "tfn",
            "tax file number",
            "tax file",
            "tax number",
            "tax",
            "ato",
        ],
        context_required: true,
    },
    PiiPattern {
        name: "au_tfn_compact",
        entity_type: "AU_TFN",
        // Compact 9-digit format (e.g. 123456782)
        pattern: r"\b\d{9}\b",
        score: 0.5,
        context_keywords: &[
            "tfn",
            "tax file number",
            "tax file",
            "tax number",
            "tax",
            "ato",
        ],
        context_required: true,
    },
    // ── AU Medicare Number ──
    PiiPattern {
        name: "au_medicare_formatted",
        entity_type: "AU_MEDICARE",
        // Standard display: 4-5-1 with spaces (e.g. 2123 45670 1)
        pattern: r"\b[2-6]\d{3}\s\d{5}\s\d\b",
        score: 0.7,
        context_keywords: &[
            "medicare",
            "medicare number",
            "medicare card",
            "health card",
            "health insurance",
        ],
        context_required: true,
    },
    PiiPattern {
        name: "au_medicare_compact",
        entity_type: "AU_MEDICARE",
        // Compact 10-digit format starting with 2-6 (e.g. 2123456701)
        pattern: r"\b[2-6]\d{9}\b",
        score: 0.6,
        context_keywords: &[
            "medicare",
            "medicare number",
            "medicare card",
            "health card",
            "health insurance",
        ],
        context_required: true,
    },
];
