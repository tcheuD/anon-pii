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
    pub entity_type: &'static str,
    #[allow(dead_code)]
    pub name: &'static str,
    pub regex: Regex,
    pub score: f64,
    pub context_keywords: &'static [&'static str],
    pub context_required: bool,
}

#[derive(Debug)]
pub struct Detection {
    pub entity_type: &'static str,
    pub original: String,
    pub start: usize,
    pub end: usize,
    pub score: f64,
}
