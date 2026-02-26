use std::borrow::Cow;

use clap::ValueEnum;
use regex::Regex;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Operator {
    /// Replace PII with tokens like [EMAIL_ADDRESS_a1b2c3d4] (default)
    #[default]
    Token,
    /// Remove PII entirely (empty string)
    Redact,
    /// Keep original PII unchanged (detection-only / dry-run)
    Keep,
    /// Replace PII with masking characters (e.g. *****)
    Mask,
    /// Replace PII with a cryptographic hash
    Hash,
    /// AES-CBC encrypt PII (reversible without mapping file)
    Encrypt,
    /// Replace PII with a custom format string (e.g. '<{entity_type}>' or 'REDACTED')
    Custom,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum HashAlgo {
    #[default]
    Sha256,
    Sha512,
    Md5,
}

#[derive(Clone, Copy, Debug)]
pub struct MaskConfig {
    pub mask_char: char,
    pub fixed_count: Option<usize>,
    pub from_end: bool,
}

impl Default for MaskConfig {
    fn default() -> Self {
        Self {
            mask_char: '*',
            fixed_count: None,
            from_end: false,
        }
    }
}

pub struct CompiledPattern {
    pub entity_type: Cow<'static, str>,
    #[allow(dead_code)]
    pub name: Cow<'static, str>,
    pub regex: Regex,
    pub score: f64,
    pub context_keywords: Cow<'static, [&'static str]>,
    pub context_required: bool,
}

#[derive(Debug)]
pub struct Detection {
    pub entity_type: Cow<'static, str>,
    pub original: String,
    pub start: usize,
    pub end: usize,
    pub score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn test_compiled_pattern_with_borrowed_strings() {
        let pattern = CompiledPattern {
            entity_type: Cow::Borrowed("EMAIL_ADDRESS"),
            name: Cow::Borrowed("email"),
            regex: Regex::new(r"test@example\.com").unwrap(),
            score: 0.9,
            context_keywords: Cow::Borrowed(&["email", "contact"]),
            context_required: false,
        };

        assert_eq!(pattern.entity_type.as_ref(), "EMAIL_ADDRESS");
        assert_eq!(pattern.name.as_ref(), "email");
        assert_eq!(pattern.score, 0.9);
        assert_eq!(pattern.context_keywords.len(), 2);
        assert!(!pattern.context_required);
        assert!(matches!(pattern.entity_type, Cow::Borrowed(_)));
        assert!(matches!(pattern.name, Cow::Borrowed(_)));
        assert!(matches!(pattern.context_keywords, Cow::Borrowed(_)));
    }

    #[test]
    fn test_compiled_pattern_with_owned_strings() {
        let pattern = CompiledPattern {
            entity_type: Cow::Owned(String::from("CUSTOM_ENTITY")),
            name: Cow::Owned(String::from("custom_pattern")),
            regex: Regex::new(r"\d{4}-\d{4}").unwrap(),
            score: 0.85,
            context_keywords: Cow::Owned(vec!["keyword1", "keyword2"]),
            context_required: true,
        };

        assert_eq!(pattern.entity_type.as_ref(), "CUSTOM_ENTITY");
        assert_eq!(pattern.name.as_ref(), "custom_pattern");
        assert_eq!(pattern.score, 0.85);
        assert_eq!(pattern.context_keywords.len(), 2);
        assert!(pattern.context_required);
        assert!(matches!(pattern.entity_type, Cow::Owned(_)));
        assert!(matches!(pattern.name, Cow::Owned(_)));
        assert!(matches!(pattern.context_keywords, Cow::Owned(_)));
    }

    #[test]
    fn test_detection_with_borrowed_entity_type() {
        let detection = Detection {
            entity_type: Cow::Borrowed("EMAIL_ADDRESS"),
            original: "test@example.com".to_string(),
            start: 0,
            end: 16,
            score: 0.95,
        };

        assert_eq!(detection.entity_type.as_ref(), "EMAIL_ADDRESS");
        assert_eq!(detection.original, "test@example.com");
        assert!(matches!(detection.entity_type, Cow::Borrowed(_)));
    }

    #[test]
    fn test_detection_with_owned_entity_type() {
        let detection = Detection {
            entity_type: Cow::Owned(String::from("CUSTOM_ENTITY")),
            original: "custom-value-123".to_string(),
            start: 10,
            end: 26,
            score: 0.80,
        };

        assert_eq!(detection.entity_type.as_ref(), "CUSTOM_ENTITY");
        assert_eq!(detection.original, "custom-value-123");
        assert!(matches!(detection.entity_type, Cow::Owned(_)));
    }

    #[test]
    fn test_context_keywords_mixed_usage() {
        static STATIC_KEYWORDS: &[&str] = &["email", "mail", "contact"];
        let borrowed_kw: Cow<'static, [&'static str]> = Cow::Borrowed(STATIC_KEYWORDS);
        assert_eq!(borrowed_kw.len(), 3);
        assert!(matches!(borrowed_kw, Cow::Borrowed(_)));

        let owned_kw: Cow<'static, [&'static str]> = Cow::Owned(vec!["custom", "user-defined"]);
        assert_eq!(owned_kw.len(), 2);
        assert!(matches!(owned_kw, Cow::Owned(_)));
    }
}
