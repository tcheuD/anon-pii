//! French-specific PII patterns.
//!
//! Contains patterns for: FR_PHONE_NUMBER, FR_IBAN, FR_SSN, FR_PASSPORT.

use super::PiiPattern;

pub const FRENCH_PATTERNS: &[PiiPattern] = &[
    // ── French phone numbers ──
    PiiPattern {
        name: "fr_phone_intl",
        entity_type: "FR_PHONE_NUMBER",
        pattern: r"\+33\s?[1-9](?:[\s.\-]?\d{2}){4}",
        score: 0.9,
        context_keywords: &[
            "telephone",
            "tel",
            "phone",
            "mobile",
            "contact",
            "appeler",
            "numero",
            "portable",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_phone_intl_0033",
        entity_type: "FR_PHONE_NUMBER",
        pattern: r"\b0033\s?[1-9](?:[\s.\-]?\d{2}){4}",
        score: 0.9,
        context_keywords: &[
            "telephone",
            "tel",
            "phone",
            "mobile",
            "contact",
            "appeler",
            "numero",
            "portable",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_phone_national",
        entity_type: "FR_PHONE_NUMBER",
        pattern: r"\b0[1-9](?:[\s.\-]?\d{2}){4}\b",
        score: 0.7,
        context_keywords: &[
            "telephone",
            "tel",
            "phone",
            "mobile",
            "contact",
            "appeler",
            "numero",
            "portable",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_phone_compact",
        entity_type: "FR_PHONE_NUMBER",
        pattern: r"\b0[1-9]\d{8}\b",
        score: 0.6,
        context_keywords: &[
            "telephone",
            "tel",
            "phone",
            "mobile",
            "contact",
            "appeler",
            "numero",
            "portable",
        ],
        context_required: false,
    },
    // ── French IBAN ──
    PiiPattern {
        name: "fr_iban",
        entity_type: "FR_IBAN",
        // Print format: groups of four characters followed by a final group of three.
        // The French BBAN is 5-digit bank + 5-digit branch + 11-character
        // alphanumeric account + 2-digit RIB key.
        pattern: r"\bFR\d{2}[ \t]\d{4}[ \t]\d{4}[ \t]\d{2}[A-Z0-9]{2}[ \t][A-Z0-9]{4}[ \t][A-Z0-9]{4}[ \t][A-Z0-9]\d{2}\b",
        score: 0.95,
        context_keywords: &[
            "iban", "compte", "account", "virement", "bank", "banque", "bancaire",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_iban_compact",
        entity_type: "FR_IBAN",
        pattern: r"\bFR\d{2}\d{5}\d{5}[A-Z0-9]{11}\d{2}\b",
        score: 0.9,
        context_keywords: &[
            "iban", "compte", "account", "virement", "bank", "banque", "bancaire",
        ],
        context_required: false,
    },
    // ── French SSN (NIR) ──
    PiiPattern {
        name: "fr_ssn",
        entity_type: "FR_SSN",
        pattern: r"[12]\s?\d{2}\s?(?:0[1-9]|1[0-2]|[2-9]\d)\s?(?:\d{2}|2[AB])\s?\d{3}\s?\d{3}(?:\s?\d{2})?",
        score: 0.85,
        context_keywords: &[
            "secu",
            "securite sociale",
            "ssn",
            "nir",
            "carte vitale",
            "numero",
            "immatriculation",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_ssn_compact",
        entity_type: "FR_SSN",
        pattern: r"[12]\d{2}(?:0[1-9]|1[0-2]|[2-9]\d)(?:\d{2}|2[AB])\d{6}(?:\d{2})?",
        score: 0.8,
        context_keywords: &[
            "secu",
            "securite sociale",
            "ssn",
            "nir",
            "carte vitale",
            "numero",
            "immatriculation",
        ],
        context_required: false,
    },
    // ── French passport ──
    PiiPattern {
        name: "fr_passport",
        entity_type: "FR_PASSPORT",
        pattern: r"\b\d{2}[A-Z]{2}\d{5}\b",
        score: 0.7,
        context_keywords: &["passeport", "passport", "document", "identite", "identité"],
        context_required: true,
    },
];

#[cfg(test)]
mod tests {
    use regex::Regex;

    use super::FRENCH_PATTERNS;

    fn exact_pattern(name: &str) -> Regex {
        let pattern = FRENCH_PATTERNS
            .iter()
            .find(|pattern| pattern.name == name)
            .expect("French pattern should exist");
        Regex::new(&format!("^(?:{})$", pattern.pattern)).expect("pattern should compile")
    }

    #[test]
    fn fr_iban_patterns_enforce_official_field_structure() {
        let compact = exact_pattern("fr_iban_compact");
        let print = exact_pattern("fr_iban");

        assert!(compact.is_match("FR1420041010050500013M02606"));
        assert!(compact.is_match("FR7630006000011234567890189"));
        assert!(print.is_match("FR14 2004 1010 0505 0001 3M02 606"));

        for invalid in [
            "FR142A041010050500013M02606",  // bank code must be numeric
            "FR1420041A10050500013M02606",  // branch code must be numeric
            "FR1420041010050500013M0260A",  // RIB key must be numeric
            "FR1420041010050500013M026060", // exactly 27 characters
        ] {
            assert!(
                !compact.is_match(invalid),
                "invalid French IBAN structure matched: {invalid}"
            );
        }
    }
}
