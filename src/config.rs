//! YAML-based recognizer configuration.
//!
//! This module provides the ability to define custom PII recognizers in YAML files.
//! Users can specify entity types, regex patterns, context keywords, and scores
//! without writing Rust code.

use regex::RegexBuilder;
use serde::Deserialize;
use std::path::Path;

/// Error type for recognizer configuration loading.
#[derive(Debug)]
pub enum ConfigError {
    /// Error reading the configuration file.
    Io(std::io::Error),
    /// Error parsing YAML syntax.
    Yaml(serde_yaml::Error),
    /// Invalid regex pattern in a recognizer.
    InvalidRegex {
        recognizer_name: String,
        pattern: String,
        error: String,
    },
    /// Score out of valid range [0.0, 1.0].
    InvalidScore { recognizer_name: String, score: f64 },
    /// Entity type does not follow UPPER_SNAKE_CASE convention.
    InvalidEntityType {
        recognizer_name: String,
        entity_type: String,
    },
    /// Config path is a symlink.
    SymlinkPath(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "Failed to read config file: {e}"),
            ConfigError::Yaml(e) => write!(f, "Failed to parse YAML: {e}"),
            ConfigError::InvalidRegex {
                recognizer_name,
                pattern,
                error,
            } => write!(
                f,
                "Invalid regex in recognizer '{recognizer_name}': pattern '{pattern}' - {error}"
            ),
            ConfigError::InvalidScore {
                recognizer_name,
                score,
            } => write!(
                f,
                "Invalid score in recognizer '{recognizer_name}': {score} (must be 0.0-1.0)"
            ),
            ConfigError::InvalidEntityType {
                recognizer_name,
                entity_type,
            } => write!(
                f,
                "Invalid entity_type in recognizer '{recognizer_name}': '{entity_type}' (must be UPPER_SNAKE_CASE)"
            ),
            ConfigError::SymlinkPath(path) => {
                write!(f, "Refusing to follow symlink: {path}")
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Io(e) => Some(e),
            ConfigError::Yaml(e) => Some(e),
            _ => None,
        }
    }
}

/// A single pattern within a recognizer.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PatternConfig {
    /// The regex pattern to match.
    pub regex: String,
    /// Confidence score for this pattern (0.0-1.0).
    pub score: f64,
}

/// A recognizer definition that can detect a specific entity type.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RecognizerConfig {
    /// Human-readable name for this recognizer.
    pub name: String,
    /// Entity type in Presidio style (e.g., "FR_LICENSE_PLATE").
    pub entity_type: String,
    /// Regex patterns for this recognizer.
    pub patterns: Vec<PatternConfig>,
    /// Keywords that boost confidence when found nearby.
    #[serde(default)]
    pub context_keywords: Vec<String>,
    /// If true, context keywords are required for a match.
    #[serde(default)]
    pub context_required: bool,
}

/// Root configuration structure for YAML recognizer definitions.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RecognizerConfigFile {
    /// List of recognizer definitions.
    pub recognizers: Vec<RecognizerConfig>,
}

impl RecognizerConfigFile {
    /// Load and validate recognizer configuration from a YAML file.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if:
    /// - The file cannot be read
    /// - The YAML is malformed
    /// - Any regex pattern is invalid
    /// - Any score is outside [0.0, 1.0]
    /// - Any entity_type is not UPPER_SNAKE_CASE
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let meta = std::fs::symlink_metadata(path).map_err(ConfigError::Io)?;
        if meta.file_type().is_symlink() {
            return Err(ConfigError::SymlinkPath(path.display().to_string()));
        }
        let content = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        Self::from_yaml(&content)
    }

    /// Parse and validate recognizer configuration from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, ConfigError> {
        let config: RecognizerConfigFile = serde_yaml::from_str(yaml).map_err(ConfigError::Yaml)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate all recognizers in the configuration.
    fn validate(&self) -> Result<(), ConfigError> {
        for recognizer in &self.recognizers {
            // Validate entity_type is UPPER_SNAKE_CASE
            if !is_upper_snake_case(&recognizer.entity_type) {
                return Err(ConfigError::InvalidEntityType {
                    recognizer_name: recognizer.name.clone(),
                    entity_type: recognizer.entity_type.clone(),
                });
            }

            for pattern in &recognizer.patterns {
                // Validate score range
                if !(0.0..=1.0).contains(&pattern.score) {
                    return Err(ConfigError::InvalidScore {
                        recognizer_name: recognizer.name.clone(),
                        score: pattern.score,
                    });
                }

                // Validate regex compiles within a size budget (1 MiB compiled DFA limit)
                if let Err(e) = RegexBuilder::new(&pattern.regex)
                    .size_limit(1 << 20)
                    .build()
                {
                    return Err(ConfigError::InvalidRegex {
                        recognizer_name: recognizer.name.clone(),
                        pattern: pattern.regex.clone(),
                        error: e.to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Check if a string follows UPPER_SNAKE_CASE convention.
fn is_upper_snake_case(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && !s.starts_with('_')
        && !s.ends_with('_')
        && !s.contains("__")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_valid_config() {
        let yaml = r#"
recognizers:
  - name: "French license plate"
    entity_type: "FR_LICENSE_PLATE"
    patterns:
      - regex: '\b[A-Z]{2}-\d{3}-[A-Z]{2}\b'
        score: 0.85
    context_keywords: ["plaque", "immatriculation", "vehicule"]
    context_required: false
"#;
        let config = RecognizerConfigFile::from_yaml(yaml).unwrap();
        assert_eq!(config.recognizers.len(), 1);
        assert_eq!(config.recognizers[0].name, "French license plate");
        assert_eq!(config.recognizers[0].entity_type, "FR_LICENSE_PLATE");
        assert_eq!(config.recognizers[0].patterns.len(), 1);
        assert_eq!(config.recognizers[0].patterns[0].score, 0.85);
        assert_eq!(config.recognizers[0].context_keywords.len(), 3);
        assert!(!config.recognizers[0].context_required);
    }

    #[test]
    fn test_parse_multiple_recognizers() {
        let yaml = r#"
recognizers:
  - name: "Pattern A"
    entity_type: "TYPE_A"
    patterns:
      - regex: 'A\d+'
        score: 0.9
  - name: "Pattern B"
    entity_type: "TYPE_B"
    patterns:
      - regex: 'B\d+'
        score: 0.8
"#;
        let config = RecognizerConfigFile::from_yaml(yaml).unwrap();
        assert_eq!(config.recognizers.len(), 2);
        assert_eq!(config.recognizers[0].entity_type, "TYPE_A");
        assert_eq!(config.recognizers[1].entity_type, "TYPE_B");
    }

    #[test]
    fn test_parse_multiple_patterns_per_recognizer() {
        let yaml = r#"
recognizers:
  - name: "Multi pattern"
    entity_type: "MULTI_PATTERN"
    patterns:
      - regex: 'pattern1'
        score: 0.9
      - regex: 'pattern2'
        score: 0.7
"#;
        let config = RecognizerConfigFile::from_yaml(yaml).unwrap();
        assert_eq!(config.recognizers[0].patterns.len(), 2);
        assert_eq!(config.recognizers[0].patterns[0].score, 0.9);
        assert_eq!(config.recognizers[0].patterns[1].score, 0.7);
    }

    #[test]
    fn test_context_keywords_default_empty() {
        let yaml = r#"
recognizers:
  - name: "No context"
    entity_type: "NO_CONTEXT"
    patterns:
      - regex: 'test'
        score: 0.5
"#;
        let config = RecognizerConfigFile::from_yaml(yaml).unwrap();
        assert!(config.recognizers[0].context_keywords.is_empty());
        assert!(!config.recognizers[0].context_required);
    }

    #[test]
    fn test_context_required_true() {
        let yaml = r#"
recognizers:
  - name: "Context required"
    entity_type: "CONTEXT_REQUIRED"
    patterns:
      - regex: 'test'
        score: 0.5
    context_keywords: ["keyword"]
    context_required: true
"#;
        let config = RecognizerConfigFile::from_yaml(yaml).unwrap();
        assert!(config.recognizers[0].context_required);
    }

    #[test]
    fn test_invalid_regex_error() {
        let yaml = r#"
recognizers:
  - name: "Bad regex"
    entity_type: "BAD_REGEX"
    patterns:
      - regex: '[invalid('
        score: 0.5
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRegex { .. }));
        let msg = err.to_string();
        assert!(msg.contains("Bad regex"));
        assert!(msg.contains("[invalid("));
    }

    #[test]
    fn test_score_too_high_error() {
        let yaml = r#"
recognizers:
  - name: "High score"
    entity_type: "HIGH_SCORE"
    patterns:
      - regex: 'test'
        score: 1.5
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigError::InvalidScore { .. }));
        let msg = err.to_string();
        assert!(msg.contains("High score"));
        assert!(msg.contains("1.5"));
    }

    #[test]
    fn test_score_negative_error() {
        let yaml = r#"
recognizers:
  - name: "Negative score"
    entity_type: "NEG_SCORE"
    patterns:
      - regex: 'test'
        score: -0.1
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigError::InvalidScore { .. }));
    }

    #[test]
    fn test_score_boundary_zero_valid() {
        let yaml = r#"
recognizers:
  - name: "Zero score"
    entity_type: "ZERO_SCORE"
    patterns:
      - regex: 'test'
        score: 0.0
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_score_boundary_one_valid() {
        let yaml = r#"
recognizers:
  - name: "One score"
    entity_type: "ONE_SCORE"
    patterns:
      - regex: 'test'
        score: 1.0
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_entity_type_lowercase() {
        let yaml = r#"
recognizers:
  - name: "Lowercase entity"
    entity_type: "lowercase_type"
    patterns:
      - regex: 'test'
        score: 0.5
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigError::InvalidEntityType { .. }));
        let msg = err.to_string();
        assert!(msg.contains("lowercase_type"));
        assert!(msg.contains("UPPER_SNAKE_CASE"));
    }

    #[test]
    fn test_invalid_entity_type_mixed_case() {
        let yaml = r#"
recognizers:
  - name: "Mixed case entity"
    entity_type: "Mixed_Case"
    patterns:
      - regex: 'test'
        score: 0.5
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_entity_type_starts_with_underscore() {
        let yaml = r#"
recognizers:
  - name: "Leading underscore"
    entity_type: "_LEADING"
    patterns:
      - regex: 'test'
        score: 0.5
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_entity_type_ends_with_underscore() {
        let yaml = r#"
recognizers:
  - name: "Trailing underscore"
    entity_type: "TRAILING_"
    patterns:
      - regex: 'test'
        score: 0.5
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_entity_type_double_underscore() {
        let yaml = r#"
recognizers:
  - name: "Double underscore"
    entity_type: "DOUBLE__UNDERSCORE"
    patterns:
      - regex: 'test'
        score: 0.5
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_entity_type_with_numbers_valid() {
        let yaml = r#"
recognizers:
  - name: "With numbers"
    entity_type: "TYPE_V2_CODE"
    patterns:
      - regex: 'test'
        score: 0.5
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_missing_required_field_name() {
        let yaml = r#"
recognizers:
  - entity_type: "MISSING_NAME"
    patterns:
      - regex: 'test'
        score: 0.5
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::Yaml(_)));
    }

    #[test]
    fn test_missing_required_field_entity_type() {
        let yaml = r#"
recognizers:
  - name: "Missing entity type"
    patterns:
      - regex: 'test'
        score: 0.5
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::Yaml(_)));
    }

    #[test]
    fn test_missing_required_field_patterns() {
        let yaml = r#"
recognizers:
  - name: "Missing patterns"
    entity_type: "MISSING_PATTERNS"
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::Yaml(_)));
    }

    #[test]
    fn test_missing_pattern_regex() {
        let yaml = r#"
recognizers:
  - name: "Missing regex"
    entity_type: "MISSING_REGEX"
    patterns:
      - score: 0.5
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::Yaml(_)));
    }

    #[test]
    fn test_missing_pattern_score() {
        let yaml = r#"
recognizers:
  - name: "Missing score"
    entity_type: "MISSING_SCORE"
    patterns:
      - regex: 'test'
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::Yaml(_)));
    }

    #[test]
    fn test_invalid_yaml_syntax() {
        let yaml = r#"
recognizers:
  - name: "Bad YAML
    entity_type: "MISSING_QUOTE
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::Yaml(_)));
    }

    #[test]
    fn test_empty_recognizers_list() {
        let yaml = r#"
recognizers: []
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_ok());
        assert!(result.unwrap().recognizers.is_empty());
    }

    #[test]
    fn test_load_from_file() {
        let yaml = r#"
recognizers:
  - name: "File test"
    entity_type: "FILE_TEST"
    patterns:
      - regex: 'test'
        score: 0.5
"#;
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "{}", yaml).unwrap();

        let config = RecognizerConfigFile::load(temp_file.path()).unwrap();
        assert_eq!(config.recognizers.len(), 1);
        assert_eq!(config.recognizers[0].name, "File test");
    }

    #[test]
    fn test_load_nonexistent_file() {
        let result = RecognizerConfigFile::load("/nonexistent/path/config.yaml");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::Io(_)));
    }

    #[test]
    fn test_error_display() {
        let io_err = ConfigError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(io_err.to_string().contains("Failed to read config file"));

        let regex_err = ConfigError::InvalidRegex {
            recognizer_name: "test".to_string(),
            pattern: "[bad".to_string(),
            error: "unclosed bracket".to_string(),
        };
        let msg = regex_err.to_string();
        assert!(msg.contains("test"));
        assert!(msg.contains("[bad"));
        assert!(msg.contains("unclosed bracket"));

        let score_err = ConfigError::InvalidScore {
            recognizer_name: "test".to_string(),
            score: 1.5,
        };
        let msg = score_err.to_string();
        assert!(msg.contains("test"));
        assert!(msg.contains("1.5"));
        assert!(msg.contains("0.0-1.0"));

        let entity_err = ConfigError::InvalidEntityType {
            recognizer_name: "test".to_string(),
            entity_type: "bad_type".to_string(),
        };
        let msg = entity_err.to_string();
        assert!(msg.contains("test"));
        assert!(msg.contains("bad_type"));
        assert!(msg.contains("UPPER_SNAKE_CASE"));
    }

    #[test]
    fn test_regex_size_limit_rejects_huge_pattern() {
        // A bounded quantifier {1,N} creates ~N NFA states. With N=1_000_000
        // and each state taking several bytes, this exceeds the 1 MiB limit.
        let yaml = r#"
recognizers:
  - name: "Huge regex"
    entity_type: "HUGE_REGEX"
    patterns:
      - regex: '\w{1,1000000}'
        score: 0.5
"#;
        let result = RecognizerConfigFile::from_yaml(yaml);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::InvalidRegex { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn test_load_rejects_symlink() {
        let dir = std::env::temp_dir().join("anon-test-config-symlink");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let real_file = dir.join("real.yaml");
        std::fs::write(&real_file, "recognizers: []\n").unwrap();

        let link = dir.join("link.yaml");
        std::os::unix::fs::symlink(&real_file, &link).unwrap();

        let result = RecognizerConfigFile::load(&link);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::SymlinkPath(_)));

        // Non-symlink should still work
        let result = RecognizerConfigFile::load(&real_file);
        assert!(result.is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_is_upper_snake_case() {
        assert!(is_upper_snake_case("EMAIL_ADDRESS"));
        assert!(is_upper_snake_case("FR_LICENSE_PLATE"));
        assert!(is_upper_snake_case("TYPE_V2"));
        assert!(is_upper_snake_case("A"));
        assert!(is_upper_snake_case("AB"));
        assert!(is_upper_snake_case("A_B"));
        assert!(is_upper_snake_case("TYPE123"));

        assert!(!is_upper_snake_case(""));
        assert!(!is_upper_snake_case("email_address"));
        assert!(!is_upper_snake_case("Email_Address"));
        assert!(!is_upper_snake_case("_LEADING"));
        assert!(!is_upper_snake_case("TRAILING_"));
        assert!(!is_upper_snake_case("DOUBLE__UNDERSCORE"));
        assert!(!is_upper_snake_case("has space"));
        assert!(!is_upper_snake_case("has-dash"));
    }
}
