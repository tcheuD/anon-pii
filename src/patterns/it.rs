//! Italy-specific PII patterns.
//!
//! Contains patterns for: IT_FISCAL_CODE, IT_DRIVER_LICENSE, IT_VAT_CODE,
//! IT_PASSPORT, IT_IDENTITY_CARD.

use super::PiiPattern;

pub const IT_PATTERNS: &[PiiPattern] = &[
    // ── IT Fiscal Code (Codice Fiscale) ──
    // 16 chars: 6 letters + 2 digits + 1 month letter + 2 digits + 1 letter + 3 digits + check letter
    PiiPattern {
        name: "it_fiscal_code",
        entity_type: "IT_FISCAL_CODE",
        pattern: r"\b[A-Z]{6}\d{2}[ABCDEHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b",
        score: 0.85,
        context_keywords: &[
            "codice fiscale",
            "fiscal",
            "cf",
            "tax",
            "contribuente",
            "agenzia entrate",
            "fiscale",
        ],
        context_required: false,
    },
    // ── IT Driver License (Patente di Guida) ──
    // 10 chars: 2 letters + 7 digits + 1 letter
    PiiPattern {
        name: "it_driver_license",
        entity_type: "IT_DRIVER_LICENSE",
        pattern: r"\b[A-Z]{2}\d{7}[A-Z]\b",
        score: 0.5,
        context_keywords: &[
            "patente",
            "guida",
            "driver",
            "license",
            "driving",
            "licence",
            "patente di guida",
        ],
        context_required: true,
    },
    // ── IT VAT Code (Partita IVA) ──
    // 11 digits
    PiiPattern {
        name: "it_vat_code",
        entity_type: "IT_VAT_CODE",
        pattern: r"\b\d{11}\b",
        score: 0.5,
        context_keywords: &["partita iva", "p.iva", "piva", "iva", "vat", "partita"],
        context_required: true,
    },
    // ── IT Passport (Passaporto) ──
    // 9 chars: 2 letters + 7 digits
    PiiPattern {
        name: "it_passport",
        entity_type: "IT_PASSPORT",
        pattern: r"\b[A-Z]{2}\d{7}\b",
        score: 0.5,
        context_keywords: &[
            "passaporto",
            "passport",
            "travel document",
            "documento viaggio",
        ],
        context_required: true,
    },
    // ── IT Identity Card (Carta d'Identità Elettronica / CIE) ──
    // 9 chars: 2 letters + 5 digits + 2 letters
    PiiPattern {
        name: "it_identity_card",
        entity_type: "IT_IDENTITY_CARD",
        pattern: r"\b[A-Z]{2}\d{5}[A-Z]{2}\b",
        score: 0.5,
        context_keywords: &[
            "carta d'identità",
            "carta identità",
            "carta identita",
            "identity card",
            "cie",
            "documento",
            "identità",
            "identita",
        ],
        context_required: true,
    },
];
