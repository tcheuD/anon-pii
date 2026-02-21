//! India-specific PII patterns.
//!
//! Contains patterns for: IN_AADHAAR, IN_PAN, IN_VEHICLE_REGISTRATION,
//! IN_PASSPORT, IN_VOTER, IN_GSTIN.

use super::PiiPattern;

pub const IN_PATTERNS: &[PiiPattern] = &[
    // ── IN_AADHAAR (Aadhaar Number) ──
    PiiPattern {
        name: "in_aadhaar_spaced",
        entity_type: "IN_AADHAAR",
        // Standard display: 4-4-4 with spaces (e.g. 2234 5678 9012)
        // First digit must be 2-9 (UIDAI never issues numbers starting with 0 or 1)
        pattern: r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b",
        score: 0.7,
        context_keywords: &[
            "aadhaar",
            "aadhar",
            "uid",
            "uidai",
            "unique identification",
            "identity",
            "biometric",
        ],
        context_required: true,
    },
    PiiPattern {
        name: "in_aadhaar_compact",
        entity_type: "IN_AADHAAR",
        // Compact 12-digit format (e.g. 223456789012)
        pattern: r"\b[2-9]\d{11}\b",
        score: 0.6,
        context_keywords: &[
            "aadhaar",
            "aadhar",
            "uid",
            "uidai",
            "unique identification",
            "identity",
            "biometric",
        ],
        context_required: true,
    },
    // ── IN_PAN (Permanent Account Number) ──
    PiiPattern {
        name: "in_pan",
        entity_type: "IN_PAN",
        // Format: AAAAA9999A — 5 letters + 4 digits + 1 letter
        // 4th char indicates holder type: C, P, H, F, A, T, B, L, J, G
        pattern: r"\b[A-Z]{3}[CPHFATBLJG][A-Z]\d{4}[A-Z]\b",
        score: 0.7,
        context_keywords: &[
            "pan",
            "permanent account",
            "income tax",
            "tax",
            "pan card",
            "pan number",
        ],
        context_required: true,
    },
    // ── IN_VEHICLE_REGISTRATION ──
    PiiPattern {
        name: "in_vehicle_registration",
        entity_type: "IN_VEHICLE_REGISTRATION",
        // Format: XX-99-XX-9999 or XX-99-X-9999 or XX99XX9999
        // State code (2 letters) + district (2 digits) + series (1-2 letters) + number (1-4 digits)
        pattern: r"\b[A-Z]{2}[-\s]?\d{2}[-\s]?[A-Z]{1,2}[-\s]?\d{1,4}\b",
        score: 0.6,
        context_keywords: &[
            "vehicle",
            "registration",
            "rto",
            "car",
            "number plate",
            "license plate",
            "motor",
        ],
        context_required: true,
    },
    // ── IN_PASSPORT ──
    PiiPattern {
        name: "in_passport",
        entity_type: "IN_PASSPORT",
        // Format: 1 letter + 7 digits (e.g. J1234567, K9876543)
        // First letter is typically J, K, L, M, N, P, R, S (series)
        pattern: r"\b[A-Z]\d{7}\b",
        score: 0.6,
        context_keywords: &[
            "passport",
            "travel document",
            "passport number",
            "immigration",
            "visa",
        ],
        context_required: true,
    },
    // ── IN_VOTER (EPIC - Electors Photo Identity Card) ──
    PiiPattern {
        name: "in_voter",
        entity_type: "IN_VOTER",
        // Format: 3 letters + 7 digits (e.g. ABC1234567)
        pattern: r"\b[A-Z]{3}\d{7}\b",
        score: 0.6,
        context_keywords: &[
            "voter",
            "voter id",
            "epic",
            "election",
            "electoral",
            "electors",
            "voter card",
        ],
        context_required: true,
    },
    // ── IN_GSTIN (Goods and Services Tax Identification Number) ──
    PiiPattern {
        name: "in_gstin",
        entity_type: "IN_GSTIN",
        // Format: 2 digits (state) + PAN (10 chars) + 1 digit + Z + 1 alphanumeric
        // State codes 01-37, then 10-char PAN, then entity number digit, 'Z', check char
        pattern: r"\b\d{2}[A-Z]{3}[CPHFATBLJG][A-Z]\d{4}[A-Z]\d[Z][A-Z0-9]\b",
        score: 0.8,
        context_keywords: &[
            "gstin",
            "gst",
            "goods and services",
            "tax identification",
            "gst number",
        ],
        context_required: true,
    },
];
