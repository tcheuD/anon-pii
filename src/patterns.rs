pub struct PiiPattern {
    pub name: &'static str,
    pub entity_type: &'static str,
    pub pattern: &'static str,
    pub score: f64,
    pub context_keywords: &'static [&'static str],
    /// If true, context keywords are required (no keyword = no match).
    /// If false and context_keywords is non-empty, keywords boost the score.
    pub context_required: bool,
}

pub const PATTERNS: &[PiiPattern] = &[
    // ── Email ──
    PiiPattern {
        name: "email",
        entity_type: "EMAIL_ADDRESS",
        pattern: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    // ── URL ──
    PiiPattern {
        name: "url",
        entity_type: "URL",
        pattern: r#"https?://[^\s\)\]>"']+[^\s\)\]>"'.,;:!?]"#,
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    // ── French phone numbers ──
    PiiPattern {
        name: "fr_phone_intl",
        entity_type: "FR_PHONE_NUMBER",
        pattern: r"\+33\s?[1-9](?:[\s.\-]?\d{2}){4}",
        score: 0.9,
        context_keywords: &[
            "telephone", "tel", "phone", "mobile", "contact", "appeler", "numero", "portable",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_phone_national",
        entity_type: "FR_PHONE_NUMBER",
        pattern: r"\b0[1-9](?:[\s.\-]?\d{2}){4}\b",
        score: 0.7,
        context_keywords: &[
            "telephone", "tel", "phone", "mobile", "contact", "appeler", "numero", "portable",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_phone_compact",
        entity_type: "FR_PHONE_NUMBER",
        pattern: r"\b0[1-9]\d{8}\b",
        score: 0.6,
        context_keywords: &[
            "telephone", "tel", "phone", "mobile", "contact", "appeler", "numero", "portable",
        ],
        context_required: false,
    },
    // ── French IBAN ──
    PiiPattern {
        name: "fr_iban",
        entity_type: "FR_IBAN",
        pattern: r"FR\d{2}[\s]?(?:\d{4}[\s]?){5}\d{3}",
        score: 0.95,
        context_keywords: &[
            "iban", "compte", "account", "virement", "bank", "banque", "bancaire",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_iban_compact",
        entity_type: "FR_IBAN",
        pattern: r"FR\d{25}",
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
            "secu", "securite sociale", "ssn", "nir", "carte vitale", "numero", "immatriculation",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_ssn_compact",
        entity_type: "FR_SSN",
        pattern: r"[12]\d{2}(?:0[1-9]|1[0-2]|[2-9]\d)(?:\d{2}|2[AB])\d{6}(?:\d{2})?",
        score: 0.8,
        context_keywords: &[
            "secu", "securite sociale", "ssn", "nir", "carte vitale", "numero", "immatriculation",
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
    // ── Aircraft registration ──
    PiiPattern {
        name: "aircraft_fr",
        entity_type: "AIRCRAFT_REGISTRATION",
        pattern: r"\bF-[A-Z]{4}\b",
        score: 0.95,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "aircraft_eu",
        entity_type: "AIRCRAFT_REGISTRATION",
        pattern: r"\b(?:D|G|I|EC|HB|OO|PH|OE|SE|LN|OH|CS|EI|9H)-[A-Z]{3,4}\b",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "aircraft_us",
        entity_type: "AIRCRAFT_REGISTRATION",
        pattern: r"\bN[1-9][0-9]{0,4}[A-Z]{0,2}\b",
        score: 0.85,
        context_keywords: &[
            "aircraft", "avion", "registration", "immat", "appareil", "tail", "immatriculation",
        ],
        context_required: true,
    },
    // ── Flight numbers ──
    PiiPattern {
        name: "flight_amelia",
        entity_type: "FLIGHT_NUMBER",
        pattern: r"\b(?:IZM|RLA|AME|GJT|AF)[0-9]{1,4}\b",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "flight_iata",
        entity_type: "FLIGHT_NUMBER",
        pattern: r"\b[A-Z]{2}[0-9]{1,4}\b",
        score: 0.4,
        context_keywords: &[
            "flight", "vol", "departure", "arrival", "schedule", "rotation", "leg", "sector",
        ],
        context_required: true,
    },
    PiiPattern {
        name: "flight_icao",
        entity_type: "FLIGHT_NUMBER",
        pattern: r"\b[A-Z]{3}[0-9]{1,4}\b",
        score: 0.5,
        context_keywords: &[
            "flight", "vol", "departure", "arrival", "schedule", "rotation", "leg", "sector",
        ],
        context_required: true,
    },
    // ── Crew codes ──
    PiiPattern {
        name: "crew_code",
        entity_type: "CREW_CODE",
        pattern: r"\b[A-Z]{3}\b",
        score: 0.85,
        context_keywords: &[
            "crew", "equipage", "équipage", "pilot", "pilote", "captain", "cdb",
            "commandant", "copilot", "copilote", "opl", "cabin", "pnc", "pnt",
            "steward", "hostess", "hôtesse", "hotesse", "first officer", "fo",
            "member", "membre", "roster", "planning", "duty", "service",
        ],
        context_required: true,
    },
    // ── IP addresses ──
    PiiPattern {
        name: "ipv4",
        entity_type: "IP_ADDRESS",
        pattern: r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    // ── Credit card ──
    PiiPattern {
        name: "credit_card",
        entity_type: "CREDIT_CARD",
        pattern: r"\b(?:\d{4}[\s\-]?){3}\d{4}\b",
        score: 0.7,
        context_keywords: &[
            "card", "credit", "payment", "cc", "visa", "mastercard", "amex",
            "cb", "carte", "bancaire", "debit", "paiement",
        ],
        context_required: true,
    },
    // ── UUID ──
    PiiPattern {
        name: "uuid",
        entity_type: "UUID",
        pattern: r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        score: 0.95,
        context_keywords: &[],
        context_required: false,
    },
    // ── Cryptocurrency ──
    PiiPattern {
        name: "crypto_bitcoin",
        entity_type: "CRYPTO",
        pattern: r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "crypto_ethereum",
        entity_type: "CRYPTO",
        pattern: r"\b0x[0-9a-fA-F]{40}\b",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
];

pub const CREW_CODE_BLOCKLIST: &[&str] = &[
    "THE", "AND", "FOR", "NOT", "YOU", "ALL", "CAN", "HAD", "HER", "WAS",
    "ONE", "OUR", "OUT", "ARE", "BUT", "HIS", "HAS", "NEW", "NOW", "OLD",
    "SEE", "WAY", "WHO", "BOY", "DID", "GET", "LET", "PUT", "SAY", "SHE",
    "TOO", "USE", "DAY", "MAN", "END", "MAY", "SET", "TRY", "ASK", "BIG",
    "VOL", "VIA", "PAX", "ETA", "ETD", "UTC", "GMT", "AOG", "MEL", "CDM",
    "IZM", "RLA", "AME", "GJT",
];

pub const CONTEXT_WINDOW: usize = 80;
pub const CONTEXT_SCORE_BOOST: f64 = 0.15;
pub const MAX_INPUT_SIZE: u64 = 50 * 1024 * 1024; // 50 MB

pub fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 13 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

/// Validate that a matched number starts with a known card issuer prefix (IIN/BIN).
/// Covers Visa, Mastercard, Amex, Discover, Diners Club, JCB, UnionPay, and Maestro.
pub fn valid_card_prefix(number: &str) -> bool {
    let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 13 {
        return false;
    }

    let d = digits.as_bytes();
    let d1 = d[0];
    let d2 = &digits[..2];
    let d4 = if digits.len() >= 4 { &digits[..4] } else { "" };
    let d6 = if digits.len() >= 6 { &digits[..6] } else { "" };

    // Visa: starts with 4
    if d1 == b'4' {
        return true;
    }

    // Mastercard: 51-55 or 2221-2720
    if let Ok(n2) = d2.parse::<u32>() {
        if (51..=55).contains(&n2) {
            return true;
        }
    }
    if d4.len() == 4 {
        if let Ok(n4) = d4.parse::<u32>() {
            if (2221..=2720).contains(&n4) {
                return true;
            }
        }
    }

    // Amex: 34, 37
    if d2 == "34" || d2 == "37" {
        return true;
    }

    // Discover: 6011, 622126-622925, 644-649, 65
    if d4 == "6011" || d2 == "65" {
        return true;
    }
    if let Ok(n3) = digits[..3].parse::<u32>() {
        if (644..=649).contains(&n3) {
            return true;
        }
    }
    if d6.len() == 6 {
        if let Ok(n6) = d6.parse::<u64>() {
            if (622126..=622925).contains(&n6) {
                return true;
            }
        }
    }

    // JCB: 3528-3589
    if d4.len() == 4 {
        if let Ok(n4) = d4.parse::<u32>() {
            if (3528..=3589).contains(&n4) {
                return true;
            }
        }
    }

    // UnionPay: 62
    if d2 == "62" {
        return true;
    }

    // Maestro: 5018, 5020, 5038, 5893, 6304, 6759, 6761, 6762, 6763
    if matches!(
        d4,
        "5018" | "5020" | "5038" | "5893" | "6304" | "6759" | "6761" | "6762" | "6763"
    ) {
        return true;
    }

    // Diners Club: 300-305, 36, 38
    if d2 == "36" || d2 == "38" {
        return true;
    }
    if digits.len() >= 3 {
        if let Ok(n3) = digits[..3].parse::<u32>() {
            if (300..=305).contains(&n3) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_valid_cards() {
        // Known valid test card numbers
        assert!(luhn_check("4111111111111111")); // Visa
        assert!(luhn_check("5500000000000004")); // Mastercard
        assert!(luhn_check("340000000000009"));  // Amex (15 digits)
        assert!(luhn_check("6011000000000004")); // Discover
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!luhn_check("4111111111111112")); // off by one
        assert!(!luhn_check("1234567890123456")); // random
        assert!(!luhn_check("123"));              // too short
    }

    #[test]
    fn test_valid_card_prefix_known_issuers() {
        assert!(valid_card_prefix("4111111111111111")); // Visa
        assert!(valid_card_prefix("5100000000000000")); // Mastercard 51
        assert!(valid_card_prefix("5500000000000000")); // Mastercard 55
        assert!(valid_card_prefix("2221000000000000")); // Mastercard 2221
        assert!(valid_card_prefix("2720000000000000")); // Mastercard 2720
        assert!(valid_card_prefix("340000000000000"));  // Amex 34
        assert!(valid_card_prefix("370000000000000"));  // Amex 37
        assert!(valid_card_prefix("6011000000000000")); // Discover
        assert!(valid_card_prefix("6500000000000000")); // Discover 65
        assert!(valid_card_prefix("3528000000000000")); // JCB
        assert!(valid_card_prefix("6200000000000000")); // UnionPay
        assert!(valid_card_prefix("3600000000000000")); // Diners 36
    }

    #[test]
    fn test_valid_card_prefix_rejects_unknown() {
        // Numbers starting with digits not assigned to any major issuer
        assert!(!valid_card_prefix("0000000000000000"));
        assert!(!valid_card_prefix("1000000000000000"));
        assert!(!valid_card_prefix("7000000000000000"));
        assert!(!valid_card_prefix("8000000000000000"));
        assert!(!valid_card_prefix("9000000000000000"));
    }

    #[test]
    fn test_valid_card_prefix_with_separators() {
        // Digits are filtered, so separators shouldn't matter
        assert!(valid_card_prefix("4111 1111 1111 1111"));
        assert!(valid_card_prefix("4111-1111-1111-1111"));
    }

    #[test]
    fn test_combined_luhn_and_prefix_rejects_random_16_digit() {
        // 9999999999999999 — no valid prefix, even if it somehow passed Luhn
        assert!(!valid_card_prefix("9999999999999999"));
        // 1234567890123456 — prefix 1 is not a known issuer
        assert!(!valid_card_prefix("1234567890123456"));
    }

    #[test]
    fn test_max_input_size_is_50mb() {
        assert_eq!(MAX_INPUT_SIZE, 50 * 1024 * 1024);
        assert!(MAX_INPUT_SIZE <= 100 * 1024 * 1024, "MAX_INPUT_SIZE should not exceed 100MB");
    }
}
