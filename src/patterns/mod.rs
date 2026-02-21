//! PII pattern definitions and validators.
//!
//! This module organizes patterns by category:
//! - `global`: Common patterns (email, URL, IP, phone, IBAN, credit card, etc.)
//! - `french`: French-specific patterns (FR phone, FR IBAN, FR SSN, FR passport)
//! - `aviation`: Aviation patterns (aircraft registration, flight number, crew code)
//! - `us`: US-specific patterns (US SSN, medical license)
//! - `secrets`: Secret/credential patterns (API keys, tokens, passwords)
//! - `validators`: Validation functions (Luhn, mod-97, SSN validation, etc.)
//!
//! The master `PATTERNS` constant aggregates all patterns in a single slice.

mod au;
mod aviation;
mod es;
mod french;
mod global;
mod secrets;
mod uk;
mod us;
pub mod validators;

pub use aviation::CREW_CODE_BLOCKLIST;
pub use validators::{
    iban_mod97, luhn_check, valid_aba_routing, valid_au_abn, valid_au_acn, valid_au_medicare,
    valid_au_tfn, valid_card_prefix, valid_es_nie, valid_es_nif, valid_mac, valid_uk_nhs,
    valid_uk_nino, valid_us_itin, valid_us_ssn,
};

/// A PII pattern definition with regex, entity type, score, and context configuration.
#[derive(Clone, Copy)]
pub struct PiiPattern {
    /// Human-readable pattern name (e.g., "email", "fr_phone_intl")
    pub name: &'static str,
    /// Entity type in Presidio style (e.g., "EMAIL_ADDRESS", "FR_PHONE_NUMBER")
    pub entity_type: &'static str,
    /// Regex pattern to match
    pub pattern: &'static str,
    /// Base confidence score (0.0-1.0)
    pub score: f64,
    /// Keywords that boost confidence when found nearby
    pub context_keywords: &'static [&'static str],
    /// If true, context keywords are required (no keyword = no match).
    /// If false and context_keywords is non-empty, keywords boost the score.
    pub context_required: bool,
}

/// Number of characters to search for context keywords around a match.
pub const CONTEXT_WINDOW: usize = 80;

/// Score boost when context keywords are found (for non-required context patterns).
pub const CONTEXT_SCORE_BOOST: f64 = 0.15;

/// Maximum input file size (50 MB).
pub const MAX_INPUT_SIZE: u64 = 50 * 1024 * 1024;

// Import category patterns
use au::AU_PATTERNS;
use aviation::AVIATION_PATTERNS;
use es::ES_PATTERNS;
use french::FRENCH_PATTERNS;
use global::GLOBAL_PATTERNS;
use secrets::SECRETS_PATTERNS;
use uk::UK_PATTERNS;
use us::US_PATTERNS;

/// All PII patterns aggregated into a single slice.
///
/// Pattern order affects overlap resolution: when two patterns match at the same position,
/// the one appearing earlier in the array wins. Categories are ordered from most specific
/// to most general.
pub const PATTERNS: &[PiiPattern] = &{
    // Use const array concatenation to build the master PATTERNS array.
    // This preserves the &[PiiPattern] type and zero runtime cost.
    const TOTAL_LEN: usize = GLOBAL_PATTERNS.len()
        + FRENCH_PATTERNS.len()
        + AVIATION_PATTERNS.len()
        + US_PATTERNS.len()
        + UK_PATTERNS.len()
        + ES_PATTERNS.len()
        + AU_PATTERNS.len()
        + SECRETS_PATTERNS.len();

    const fn build_patterns() -> [PiiPattern; TOTAL_LEN] {
        let mut result: [PiiPattern; TOTAL_LEN] = [PiiPattern {
            name: "",
            entity_type: "",
            pattern: "",
            score: 0.0,
            context_keywords: &[],
            context_required: false,
        }; TOTAL_LEN];

        let mut i = 0;

        // Global patterns
        let mut j = 0;
        while j < GLOBAL_PATTERNS.len() {
            result[i] = PiiPattern {
                name: GLOBAL_PATTERNS[j].name,
                entity_type: GLOBAL_PATTERNS[j].entity_type,
                pattern: GLOBAL_PATTERNS[j].pattern,
                score: GLOBAL_PATTERNS[j].score,
                context_keywords: GLOBAL_PATTERNS[j].context_keywords,
                context_required: GLOBAL_PATTERNS[j].context_required,
            };
            i += 1;
            j += 1;
        }

        // French patterns
        j = 0;
        while j < FRENCH_PATTERNS.len() {
            result[i] = PiiPattern {
                name: FRENCH_PATTERNS[j].name,
                entity_type: FRENCH_PATTERNS[j].entity_type,
                pattern: FRENCH_PATTERNS[j].pattern,
                score: FRENCH_PATTERNS[j].score,
                context_keywords: FRENCH_PATTERNS[j].context_keywords,
                context_required: FRENCH_PATTERNS[j].context_required,
            };
            i += 1;
            j += 1;
        }

        // Aviation patterns
        j = 0;
        while j < AVIATION_PATTERNS.len() {
            result[i] = PiiPattern {
                name: AVIATION_PATTERNS[j].name,
                entity_type: AVIATION_PATTERNS[j].entity_type,
                pattern: AVIATION_PATTERNS[j].pattern,
                score: AVIATION_PATTERNS[j].score,
                context_keywords: AVIATION_PATTERNS[j].context_keywords,
                context_required: AVIATION_PATTERNS[j].context_required,
            };
            i += 1;
            j += 1;
        }

        // US patterns
        j = 0;
        while j < US_PATTERNS.len() {
            result[i] = PiiPattern {
                name: US_PATTERNS[j].name,
                entity_type: US_PATTERNS[j].entity_type,
                pattern: US_PATTERNS[j].pattern,
                score: US_PATTERNS[j].score,
                context_keywords: US_PATTERNS[j].context_keywords,
                context_required: US_PATTERNS[j].context_required,
            };
            i += 1;
            j += 1;
        }

        // UK patterns
        j = 0;
        while j < UK_PATTERNS.len() {
            result[i] = PiiPattern {
                name: UK_PATTERNS[j].name,
                entity_type: UK_PATTERNS[j].entity_type,
                pattern: UK_PATTERNS[j].pattern,
                score: UK_PATTERNS[j].score,
                context_keywords: UK_PATTERNS[j].context_keywords,
                context_required: UK_PATTERNS[j].context_required,
            };
            i += 1;
            j += 1;
        }

        // ES patterns
        j = 0;
        while j < ES_PATTERNS.len() {
            result[i] = PiiPattern {
                name: ES_PATTERNS[j].name,
                entity_type: ES_PATTERNS[j].entity_type,
                pattern: ES_PATTERNS[j].pattern,
                score: ES_PATTERNS[j].score,
                context_keywords: ES_PATTERNS[j].context_keywords,
                context_required: ES_PATTERNS[j].context_required,
            };
            i += 1;
            j += 1;
        }

        // AU patterns
        j = 0;
        while j < AU_PATTERNS.len() {
            result[i] = PiiPattern {
                name: AU_PATTERNS[j].name,
                entity_type: AU_PATTERNS[j].entity_type,
                pattern: AU_PATTERNS[j].pattern,
                score: AU_PATTERNS[j].score,
                context_keywords: AU_PATTERNS[j].context_keywords,
                context_required: AU_PATTERNS[j].context_required,
            };
            i += 1;
            j += 1;
        }

        // Secrets patterns
        j = 0;
        while j < SECRETS_PATTERNS.len() {
            result[i] = PiiPattern {
                name: SECRETS_PATTERNS[j].name,
                entity_type: SECRETS_PATTERNS[j].entity_type,
                pattern: SECRETS_PATTERNS[j].pattern,
                score: SECRETS_PATTERNS[j].score,
                context_keywords: SECRETS_PATTERNS[j].context_keywords,
                context_required: SECRETS_PATTERNS[j].context_required,
            };
            i += 1;
            j += 1;
        }

        result
    }

    // Build at compile time
    const BUILT: [PiiPattern; TOTAL_LEN] = build_patterns();
    BUILT
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patterns_count() {
        // Current count: 72 patterns. Update this if patterns are added/removed.
        assert_eq!(
            PATTERNS.len(),
            72,
            "PATTERNS count changed - update this test if intentional"
        );
    }

    #[test]
    fn test_entity_types_count() {
        use std::collections::HashSet;
        let entity_types: HashSet<&str> = PATTERNS.iter().map(|p| p.entity_type).collect();
        // Current count: 40 unique entity types
        assert_eq!(
            entity_types.len(),
            40,
            "Entity type count changed - update this test if intentional"
        );
    }

    #[test]
    fn test_all_expected_entity_types_present() {
        use std::collections::HashSet;
        let expected = [
            "ABA_ROUTING",
            "AIRCRAFT_REGISTRATION",
            "AU_ABN",
            "AU_ACN",
            "AU_MEDICARE",
            "AU_TFN",
            "AUTH_TOKEN",
            "CONNECTION_STRING",
            "CREDIT_CARD",
            "CREW_CODE",
            "CRYPTO",
            "DATE_TIME",
            "EMAIL_ADDRESS",
            "EMPLOYEE_ID",
            "ES_NIE",
            "ES_NIF",
            "FLIGHT_NUMBER",
            "FR_IBAN",
            "FR_PASSPORT",
            "FR_PHONE_NUMBER",
            "FR_SSN",
            "IBAN_CODE",
            "IP_ADDRESS",
            "JOB_TITLE",
            "MAC_ADDRESS",
            "MEDICAL_LICENSE",
            "PASSWORD",
            "PHONE_EXTENSION",
            "PHONE_NUMBER",
            "SECRET_KEY",
            "UK_NHS",
            "UK_NINO",
            "URL",
            "US_BANK_NUMBER",
            "US_DRIVER_LICENSE",
            "US_ITIN",
            "US_MBI",
            "US_PASSPORT",
            "US_SSN",
            "UUID",
        ];
        let actual: HashSet<&str> = PATTERNS.iter().map(|p| p.entity_type).collect();

        for et in &expected {
            assert!(actual.contains(et), "Missing expected entity type: {et}");
        }
    }

    #[test]
    fn test_pii_pattern_struct_fields_accessible() {
        // Verify PiiPattern struct has all expected fields
        let first = &PATTERNS[0];
        let _name: &str = first.name;
        let _entity_type: &str = first.entity_type;
        let _pattern: &str = first.pattern;
        let _score: f64 = first.score;
        let _context_keywords: &[&str] = first.context_keywords;
        let _context_required: bool = first.context_required;
    }

    #[test]
    fn test_crew_code_blocklist_not_empty() {
        assert!(
            !CREW_CODE_BLOCKLIST.is_empty(),
            "CREW_CODE_BLOCKLIST should not be empty"
        );
        // Minimum expected size (currently ~250 entries)
        assert!(
            CREW_CODE_BLOCKLIST.len() >= 200,
            "CREW_CODE_BLOCKLIST seems too small: {}",
            CREW_CODE_BLOCKLIST.len()
        );
    }

    #[test]
    fn test_crew_code_blocklist_contains_known_entries() {
        // Spot-check some known blocklist entries
        let known = ["THE", "AND", "URL", "API", "JFK", "CDG", "UTC", "AOG"];
        for word in &known {
            assert!(
                CREW_CODE_BLOCKLIST.contains(word),
                "CREW_CODE_BLOCKLIST should contain {word}"
            );
        }
    }

    #[test]
    fn test_constants_values() {
        assert_eq!(CONTEXT_WINDOW, 80, "CONTEXT_WINDOW changed");
        assert!(
            (CONTEXT_SCORE_BOOST - 0.15).abs() < f64::EPSILON,
            "CONTEXT_SCORE_BOOST changed"
        );
        assert_eq!(MAX_INPUT_SIZE, 50 * 1024 * 1024, "MAX_INPUT_SIZE changed");
    }

    #[test]
    fn test_validators_accessible() {
        // Just verify these functions exist and compile
        let _ = valid_us_ssn("123-45-6789");
        let _ = valid_mac("00:11:22:33:44:55");
        let _ = iban_mod97("DE89370400440532013000");
        let _ = luhn_check("4111111111111111");
        let _ = valid_card_prefix("4111111111111111");
        let _ = valid_aba_routing("021000021");
        let _ = valid_us_itin("912-70-1234");
        let _ = valid_uk_nhs("9434765919");
        let _ = valid_uk_nino("AB 12 34 56 C");
        let _ = valid_es_nif("12345678Z");
        let _ = valid_es_nie("X1234567L");
        let _ = valid_au_abn("51824753556");
        let _ = valid_au_acn("004085616");
        let _ = valid_au_tfn("123456782");
        let _ = valid_au_medicare("2123456701");
    }

    #[test]
    fn test_all_patterns_have_valid_regex() {
        use regex::Regex;
        for p in PATTERNS {
            let result = Regex::new(p.pattern);
            assert!(
                result.is_ok(),
                "Invalid regex for pattern '{}': {}",
                p.name,
                result.unwrap_err()
            );
        }
    }

    #[test]
    fn test_all_patterns_have_valid_scores() {
        for p in PATTERNS {
            assert!(
                p.score > 0.0 && p.score <= 1.0,
                "Pattern '{}' has invalid score: {}",
                p.name,
                p.score
            );
        }
    }

    #[test]
    fn test_context_required_patterns_have_keywords() {
        for p in PATTERNS {
            if p.context_required {
                assert!(
                    !p.context_keywords.is_empty(),
                    "Pattern '{}' has context_required=true but no keywords",
                    p.name
                );
            }
        }
    }

    #[test]
    fn test_max_input_size_is_50mb() {
        assert_eq!(MAX_INPUT_SIZE, 50 * 1024 * 1024);
        assert!(
            MAX_INPUT_SIZE <= 100 * 1024 * 1024,
            "MAX_INPUT_SIZE should not exceed 100MB"
        );
    }
}
