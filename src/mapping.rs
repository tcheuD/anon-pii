use crate::encoding::encode_lower_hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;

const MAPPING_INTEGRITY_VERSION: u8 = 1;
const MAPPING_INTEGRITY_ALGORITHM: &str = "sha256";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingIntegrity {
    pub version: u8,
    pub algorithm: String,
    pub digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingLoadStatus {
    Verified,
    LegacyUnsigned,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MappingIntegrityError {
    InvalidJson(String),
    MissingIntegrity,
    UnsupportedVersion(u8),
    UnsupportedAlgorithm(String),
    Mismatch,
}

impl fmt::Display for MappingIntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson(e) => write!(f, "invalid mapping JSON: {e}"),
            Self::MissingIntegrity => write!(f, "mapping integrity metadata is missing"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported mapping integrity version: {version}")
            }
            Self::UnsupportedAlgorithm(algorithm) => {
                write!(f, "unsupported mapping integrity algorithm: {algorithm}")
            }
            Self::Mismatch => write!(f, "mapping integrity check failed"),
        }
    }
}

impl std::error::Error for MappingIntegrityError {}

#[derive(Debug, Serialize, Deserialize)]
pub struct Mapping {
    pub session_id: String,
    pub created_at: String,
    pub mappings: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<MappingIntegrity>,
    #[serde(skip)]
    pub reverse: HashMap<(String, String), String>,
    #[serde(skip)]
    pub max_entries: Option<usize>,
    #[serde(skip)]
    insertion_order: VecDeque<String>,
    #[serde(skip)]
    has_warned_eviction: bool,
    /// Number of entries evicted this session because `max_entries` was hit.
    /// A restore of an evicted token silently no-ops, so callers that need to
    /// guarantee full restorability should check this is zero.
    #[serde(skip)]
    evicted_count: usize,
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Howard Hinnant's civil calendar algorithm
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 {
        yoe + era * 400 + 1
    } else {
        yoe + era * 400
    };
    (y, m, d)
}

/// Generate a hex string of `n_bytes` random bytes from the OS CSPRNG.
pub fn crypto_random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    getrandom::fill(&mut buf).expect("OS CSPRNG unavailable");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

impl Default for Mapping {
    fn default() -> Self {
        Self::new()
    }
}

impl Mapping {
    pub fn new() -> Self {
        let session_id = crypto_random_hex(8);

        // Wall-clock time is unavailable on bare wasm32 (SystemTime::now panics);
        // created_at is informational metadata, so epoch-zero is fine there.
        #[cfg(not(target_arch = "wasm32"))]
        let secs = {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        };
        #[cfg(target_arch = "wasm32")]
        let secs: u64 = 0;
        let day_secs = secs % 86400;
        let (year, month, day) = days_to_ymd(secs / 86400);
        let created_at = format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}+00:00",
            day_secs / 3600,
            (day_secs % 3600) / 60,
            day_secs % 60
        );

        Self {
            session_id,
            created_at,
            mappings: HashMap::new(),
            integrity: None,
            reverse: HashMap::new(),
            max_entries: None,
            insertion_order: VecDeque::new(),
            has_warned_eviction: false,
            evicted_count: 0,
        }
    }

    /// Number of mappings evicted this session due to the `max_entries` cap.
    /// Non-zero means some tokens are no longer restorable.
    pub fn evicted_count(&self) -> usize {
        self.evicted_count
    }

    pub fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = Some(max);
        self
    }

    pub fn add(&mut self, entity_type: &str, original: &str) -> String {
        let key = (entity_type.to_string(), original.to_string());
        if let Some(token) = self.reverse.get(&key) {
            return token.clone();
        }

        if let Some(max) = self.max_entries {
            while self.mappings.len() >= max {
                if !self.has_warned_eviction {
                    eprintln!(
                        "Warning: mapping cache reached limit ({max}), evicting oldest entries"
                    );
                    self.has_warned_eviction = true;
                }
                self.evict_oldest();
            }
        }

        let token = self.generate_token(entity_type);

        self.mappings.insert(token.clone(), original.to_string());
        self.reverse.insert(key, token.clone());
        self.insertion_order.push_back(token.clone());
        token
    }

    fn generate_token(&self, entity_type: &str) -> String {
        loop {
            let hex = crypto_random_hex(4);
            let token = format!("[{entity_type}_{hex}]");
            if !self.mappings.contains_key(&token) {
                return token;
            }
        }
    }

    fn evict_oldest(&mut self) {
        if let Some(old_token) = self.insertion_order.pop_front() {
            self.evicted_count += 1;
            if let Some(original) = self.mappings.remove(&old_token) {
                if let Some(inner) = old_token
                    .strip_prefix('[')
                    .and_then(|t| t.strip_suffix(']'))
                {
                    if let Some(pos) = inner.rfind('_') {
                        let entity_type = &inner[..pos];
                        self.reverse.remove(&(entity_type.to_string(), original));
                    }
                }
            }
        }
    }

    pub fn rebuild_caches(&mut self) {
        self.reverse.clear();
        self.insertion_order.clear();

        let mut tokens: Vec<String> = Vec::new();

        for (token, original) in &self.mappings {
            if let Some(inner) = token.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
                if let Some(pos) = inner.rfind('_') {
                    let entity_type = &inner[..pos];
                    self.reverse
                        .insert((entity_type.to_string(), original.clone()), token.clone());
                    tokens.push(token.clone());
                }
            }
        }

        // Stable alphabetical order for eviction after deserialization
        tokens.sort();
        for token in tokens {
            self.insertion_order.push_back(token);
        }
    }

    pub fn to_persisted_json_pretty(&self) -> serde_json::Result<String> {
        let mut value = serde_json::to_value(self)?;
        if let serde_json::Value::Object(ref mut object) = value {
            object.insert(
                "integrity".to_string(),
                serde_json::to_value(self.integrity_metadata())?,
            );
        }
        serde_json::to_string_pretty(&value)
    }

    pub fn from_persisted_json(content: &str) -> Result<Self, MappingIntegrityError> {
        let mut mapping = Self::parse_persisted_json(content)?;
        mapping.verify_integrity()?;
        mapping.rebuild_caches();
        Ok(mapping)
    }

    pub fn from_persisted_json_allow_legacy(
        content: &str,
    ) -> Result<(Self, MappingLoadStatus), MappingIntegrityError> {
        let mut mapping = Self::parse_persisted_json(content)?;

        let status = match mapping.verify_integrity() {
            Ok(()) => MappingLoadStatus::Verified,
            Err(MappingIntegrityError::MissingIntegrity) => MappingLoadStatus::LegacyUnsigned,
            Err(e) => return Err(e),
        };

        mapping.rebuild_caches();
        Ok((mapping, status))
    }

    fn parse_persisted_json(content: &str) -> Result<Self, MappingIntegrityError> {
        serde_json::from_str(content).map_err(|e| MappingIntegrityError::InvalidJson(e.to_string()))
    }

    fn verify_integrity(&self) -> Result<(), MappingIntegrityError> {
        let integrity = self
            .integrity
            .as_ref()
            .ok_or(MappingIntegrityError::MissingIntegrity)?;

        if integrity.version != MAPPING_INTEGRITY_VERSION {
            return Err(MappingIntegrityError::UnsupportedVersion(integrity.version));
        }
        if integrity.algorithm != MAPPING_INTEGRITY_ALGORITHM {
            return Err(MappingIntegrityError::UnsupportedAlgorithm(
                integrity.algorithm.clone(),
            ));
        }

        let expected = self.integrity_digest();
        if constant_time_eq(integrity.digest.as_bytes(), expected.as_bytes()) {
            Ok(())
        } else {
            Err(MappingIntegrityError::Mismatch)
        }
    }

    fn integrity_metadata(&self) -> MappingIntegrity {
        MappingIntegrity {
            version: MAPPING_INTEGRITY_VERSION,
            algorithm: MAPPING_INTEGRITY_ALGORITHM.to_string(),
            digest: self.integrity_digest(),
        }
    }

    fn integrity_digest(&self) -> String {
        let payload = self.integrity_payload();
        let bytes =
            serde_json::to_vec(&payload).expect("mapping integrity payload should serialize");
        let digest = Sha256::digest(&bytes);
        encode_lower_hex(&digest)
    }

    fn integrity_payload(&self) -> serde_json::Value {
        let mappings: BTreeMap<&str, &str> = self
            .mappings
            .iter()
            .map(|(token, original)| (token.as_str(), original.as_str()))
            .collect();

        serde_json::json!({
            "version": MAPPING_INTEGRITY_VERSION,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "mappings": mappings,
        })
    }

    /// Build a lookup of bare tokens (without brackets) for fuzzy restore.
    fn bare_token_map(&self) -> HashMap<String, String> {
        self.mappings
            .iter()
            .filter_map(|(token, original)| {
                token
                    .strip_prefix('[')
                    .and_then(|t| t.strip_suffix(']'))
                    .map(|bare| (bare.to_string(), original.clone()))
            })
            .collect()
    }

    /// Restore only bracket-delimited tokens: `[EMAIL_ADDRESS_a1b2c3d4]` → original.
    /// Safe for use in proxy responses where bare token injection is a risk.
    pub fn restore_bracketed_with_count(&self, text: &str) -> (String, usize) {
        let mut result = String::with_capacity(text.len());
        let bytes = text.as_bytes();
        let mut i = 0;
        let mut replacements = 0;

        while i < bytes.len() {
            if bytes[i] == b'[' {
                if let Some(close) = text[i..].find(']') {
                    let candidate = &text[i..i + close + 1];
                    if let Some(original) = self.mappings.get(candidate) {
                        result.push_str(original);
                        i += close + 1;
                        replacements += 1;
                        continue;
                    }
                }
            }
            let ch = text[i..].chars().next().unwrap();
            result.push(ch);
            i += ch.len_utf8();
        }

        (result, replacements)
    }

    pub fn restore_bracketed(&self, text: &str) -> String {
        self.restore_bracketed_with_count(text).0
    }

    /// Restore both bracket-delimited and bare tokens.
    /// Bare tokens use word-boundary matching to avoid partial/injected replacements.
    /// Use for CLI restore where the user explicitly wants full restoration.
    pub fn restore_with_count(&self, text: &str) -> (String, usize) {
        let (mut result, mut replacements) = self.restore_bracketed_with_count(text);

        let bare_map = self.bare_token_map();
        if !bare_map.is_empty() {
            let patterns: Vec<&str> = bare_map.keys().map(|s| s.as_str()).collect();
            let mut builder = aho_corasick::AhoCorasick::builder();
            builder.match_kind(aho_corasick::MatchKind::LeftmostLongest);
            if let Ok(ac) = builder.build(&patterns) {
                let mut output = String::with_capacity(result.len());
                let mut last = 0;
                for mat in ac.find_iter(&result) {
                    let start = mat.start();
                    let end = mat.end();
                    let before_ok =
                        start == 0 || !result.as_bytes()[start - 1].is_ascii_alphanumeric();
                    let after_ok =
                        end == result.len() || !result.as_bytes()[end].is_ascii_alphanumeric();
                    if before_ok && after_ok {
                        output.push_str(&result[last..start]);
                        let matched = &result[start..end];
                        if let Some(original) = bare_map.get(matched) {
                            output.push_str(original);
                            replacements += 1;
                        } else {
                            output.push_str(matched);
                        }
                        last = end;
                    }
                }
                output.push_str(&result[last..]);
                result = output;
            }
        }

        (result, replacements)
    }

    pub fn restore(&self, text: &str) -> String {
        self.restore_with_count(text).0
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Helper: check if a token matches the expected format [ENTITY_TYPE_xxxxxxxx]
    fn is_valid_token(token: &str, entity_type: &str) -> bool {
        let prefix = format!("[{entity_type}_");
        token.starts_with(&prefix)
            && token.ends_with(']')
            && token.len() == prefix.len() + 9 // 8 hex chars + ]
            && token[prefix.len()..token.len() - 1]
                .chars()
                .all(|c| c.is_ascii_hexdigit())
    }

    /// Helper: create a mapping with one email entry via add()
    fn make_mapping_with_email() -> (Mapping, String) {
        let mut m = Mapping::new();
        let token = m.add("EMAIL_ADDRESS", "john@example.com");
        (m, token)
    }

    #[test]
    fn test_session_id_is_hex_and_correct_length() {
        let m = Mapping::new();
        assert_eq!(m.session_id.len(), 16);
        assert!(m.session_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_session_id_uniqueness() {
        let ids: HashSet<String> = (0..100).map(|_| Mapping::new().session_id).collect();
        assert!(ids.len() >= 95);
    }

    #[test]
    fn test_token_is_hex_format() {
        let mut m = Mapping::new();
        let t1 = m.add("EMAIL_ADDRESS", "john@example.com");
        let t2 = m.add("PERSON", "Jean Dupont");
        assert!(is_valid_token(&t1, "EMAIL_ADDRESS"), "got: {t1}");
        assert!(is_valid_token(&t2, "PERSON"), "got: {t2}");
    }

    #[test]
    fn test_token_uniqueness() {
        let mut m = Mapping::new();
        let tokens: Vec<String> = (0..1000)
            .map(|i| m.add("EMAIL_ADDRESS", &format!("user{i}@test.com")))
            .collect();
        let unique: HashSet<&String> = tokens.iter().collect();
        assert_eq!(unique.len(), 1000, "all tokens must be unique");
    }

    #[test]
    fn test_token_not_sequential() {
        let mut m = Mapping::new();
        let t1 = m.add("EMAIL_ADDRESS", "a@test.com");
        let t2 = m.add("EMAIL_ADDRESS", "b@test.com");
        assert!(is_valid_token(&t1, "EMAIL_ADDRESS"));
        assert!(is_valid_token(&t2, "EMAIL_ADDRESS"));
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_restore_bracketed_replaces_bracket_tokens() {
        let (m, token) = make_mapping_with_email();
        let input = format!("Contact {token} now");
        let result = m.restore_bracketed(&input);
        assert_eq!(result, "Contact john@example.com now");
    }

    #[test]
    fn test_restore_bracketed_with_count_counts_occurrences() {
        let (m, token) = make_mapping_with_email();
        let input = format!("{token}, then {token}; unknown [EMAIL_ADDRESS_cafebabe]");
        let (result, count) = m.restore_bracketed_with_count(&input);
        assert_eq!(
            result,
            "john@example.com, then john@example.com; unknown [EMAIL_ADDRESS_cafebabe]"
        );
        assert_eq!(count, 2);
    }

    #[test]
    fn test_restore_bracketed_with_count_preserves_utf8() {
        let (m, token) = make_mapping_with_email();
        let input = format!("Réponse pour {token} — 東京");
        let (result, count) = m.restore_bracketed_with_count(&input);
        assert_eq!(result, "Réponse pour john@example.com — 東京");
        assert_eq!(count, 1);
    }

    #[test]
    fn test_restore_bracketed_ignores_bare_tokens() {
        let (m, token) = make_mapping_with_email();
        let bare = &token[1..token.len() - 1];
        let input = format!("The entity {bare} was detected");
        let result = m.restore_bracketed(&input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_restore_full_replaces_bare_at_word_boundary() {
        let (m, token) = make_mapping_with_email();
        let bare = &token[1..token.len() - 1];
        let input = format!("The entity {bare} was detected");
        let result = m.restore(&input);
        assert_eq!(result, "The entity john@example.com was detected");
    }

    #[test]
    fn test_restore_with_count_totals_bracketed_and_bare() {
        let (m, token) = make_mapping_with_email();
        let bare = &token[1..token.len() - 1];
        let input = format!("Bracketed {token}; legacy {bare}; partial {bare}X");
        let (result, count) = m.restore_with_count(&input);
        assert_eq!(
            result,
            format!("Bracketed john@example.com; legacy john@example.com; partial {bare}X")
        );
        assert_eq!(count, 2);
    }

    #[test]
    fn test_restore_full_bare_no_substring_collision() {
        let mut m = Mapping::new();
        m.mappings
            .insert("[IP_ADDRESS_aaa11111]".to_string(), "10.0.0.1".to_string());
        m.mappings
            .insert("[IP_ADDRESS_aaa11112]".to_string(), "10.0.0.2".to_string());
        m.rebuild_caches();

        let result = m.restore("IP_ADDRESS_aaa11112 and IP_ADDRESS_aaa11111");
        assert_eq!(result, "10.0.0.2 and 10.0.0.1");
    }

    #[test]
    fn test_restore_full_bare_word_boundary_prevents_partial() {
        let (m, token) = make_mapping_with_email();
        let bare = &token[1..token.len() - 1];
        let input = format!("prefix {bare}X suffix");
        let result = m.restore(&input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_restore_injection_attack_via_llm() {
        let (m, token) = make_mapping_with_email();
        let bare = &token[1..token.len() - 1];
        let llm_response = format!(
            "I detected a token called {bare} in your input. The bracketed form is {token}."
        );
        let result = m.restore_bracketed(&llm_response);
        assert!(result.contains("john@example.com"));
        assert!(result.contains(&format!("{bare} in your input")));
    }

    #[test]
    fn test_restore_no_double_replacement() {
        let mut m = Mapping::new();
        let t1 = m.add("EMAIL_ADDRESS", "EMAIL_ADDRESS_fake@test.com");
        let t2 = m.add("EMAIL_ADDRESS", "real@secret.com");
        let bare1 = &t1[1..t1.len() - 1];
        let bare2 = &t2[1..t2.len() - 1];

        let input = format!("Found {bare1} and {bare2}");
        let result = m.restore(&input);
        assert!(result.contains("EMAIL_ADDRESS_fake@test.com"));
        assert!(result.contains("real@secret.com"));
    }

    #[test]
    fn test_add_same_value_different_entity_types() {
        let mut m = Mapping::new();
        let token1 = m.add("UUID", "550e8400-e29b-41d4-a716-446655440000");
        let token2 = m.add("CRYPTO", "550e8400-e29b-41d4-a716-446655440000");
        assert!(is_valid_token(&token1, "UUID"));
        assert!(is_valid_token(&token2, "CRYPTO"));
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_add_same_value_same_entity_type_is_consistent() {
        let mut m = Mapping::new();
        let token1 = m.add("EMAIL_ADDRESS", "john@example.com");
        let token2 = m.add("EMAIL_ADDRESS", "john@example.com");
        assert_eq!(token1, token2);
        assert!(is_valid_token(&token1, "EMAIL_ADDRESS"));
    }

    #[test]
    fn test_eviction_at_capacity() {
        let mut m = Mapping::new().with_max_entries(3);
        let t1 = m.add("EMAIL_ADDRESS", "a@test.com");
        let t2 = m.add("EMAIL_ADDRESS", "b@test.com");
        let t3 = m.add("EMAIL_ADDRESS", "c@test.com");
        assert_eq!(m.mappings.len(), 3);

        let t4 = m.add("EMAIL_ADDRESS", "d@test.com");
        assert_eq!(m.mappings.len(), 3);
        assert!(!m.mappings.contains_key(&t1));
        assert!(m.mappings.contains_key(&t2));
        assert!(m.mappings.contains_key(&t3));
        assert!(m.mappings.contains_key(&t4));
    }

    #[test]
    fn test_evicted_count_signals_lost_tokens() {
        let mut m = Mapping::new().with_max_entries(2);
        assert_eq!(m.evicted_count(), 0);
        m.add("EMAIL_ADDRESS", "a@test.com");
        m.add("EMAIL_ADDRESS", "b@test.com");
        assert_eq!(m.evicted_count(), 0, "no eviction under capacity");
        m.add("EMAIL_ADDRESS", "c@test.com");
        m.add("EMAIL_ADDRESS", "d@test.com");
        assert!(
            m.evicted_count() >= 2,
            "eviction must be programmatically observable, got {}",
            m.evicted_count()
        );
    }

    #[test]
    fn test_evicted_token_not_restored() {
        let mut m = Mapping::new().with_max_entries(1);
        let t1 = m.add("EMAIL_ADDRESS", "a@test.com");
        m.add("EMAIL_ADDRESS", "b@test.com");
        let input = format!("Contact {t1} please");
        let result = m.restore_bracketed(&input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_dedup_within_capacity() {
        let mut m = Mapping::new().with_max_entries(3);
        let t1 = m.add("EMAIL_ADDRESS", "a@test.com");
        let t2 = m.add("EMAIL_ADDRESS", "a@test.com");
        assert_eq!(t1, t2);
        assert_eq!(m.mappings.len(), 1);
    }

    #[test]
    fn test_no_eviction_when_unlimited() {
        let mut m = Mapping::new();
        for i in 0..1000 {
            m.add("EMAIL_ADDRESS", &format!("user{i}@test.com"));
        }
        assert_eq!(m.mappings.len(), 1000);
    }

    #[test]
    fn test_eviction_clears_reverse() {
        let mut m = Mapping::new().with_max_entries(1);
        let t1 = m.add("EMAIL_ADDRESS", "a@test.com");
        m.add("EMAIL_ADDRESS", "b@test.com");
        let t3 = m.add("EMAIL_ADDRESS", "a@test.com");
        assert_ne!(t1, t3, "re-added value should get a new token");
        assert!(is_valid_token(&t3, "EMAIL_ADDRESS"));
    }

    #[test]
    fn test_rebuild_caches_preserves_restore() {
        let mut m = Mapping::new();
        let t1 = m.add("EMAIL_ADDRESS", "a@test.com");
        let t2 = m.add("EMAIL_ADDRESS", "b@test.com");
        let t3 = m.add("EMAIL_ADDRESS", "c@test.com");

        let json = serde_json::to_string(&m).unwrap();
        let mut restored: Mapping = serde_json::from_str(&json).unwrap();
        restored.rebuild_caches();

        assert_eq!(restored.restore_bracketed(&t1), "a@test.com");
        assert_eq!(restored.restore_bracketed(&t2), "b@test.com");
        assert_eq!(restored.restore_bracketed(&t3), "c@test.com");

        let t1_again = restored.add("EMAIL_ADDRESS", "a@test.com");
        assert_eq!(t1_again, t1);
    }

    #[test]
    fn test_rebuild_caches_eviction_works() {
        let mut m = Mapping::new();
        m.add("EMAIL_ADDRESS", "a@test.com");
        m.add("EMAIL_ADDRESS", "b@test.com");
        m.add("EMAIL_ADDRESS", "c@test.com");

        let json = serde_json::to_string(&m).unwrap();
        let mut restored: Mapping = serde_json::from_str(&json).unwrap();
        restored.rebuild_caches();
        restored.max_entries = Some(3);

        let t4 = restored.add("EMAIL_ADDRESS", "d@test.com");
        assert_eq!(restored.mappings.len(), 3);
        assert!(is_valid_token(&t4, "EMAIL_ADDRESS"));
    }

    #[test]
    fn test_persisted_json_includes_verified_integrity_metadata() {
        let (mapping, token) = make_mapping_with_email();

        let json = mapping.to_persisted_json_pretty().unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["integrity"]["version"], 1);
        assert_eq!(value["integrity"]["algorithm"], "sha256");
        assert_eq!(value["integrity"]["digest"].as_str().unwrap().len(), 64);

        let loaded = Mapping::from_persisted_json(&json).unwrap();
        assert_eq!(loaded.restore_bracketed(&token), "john@example.com");
    }

    #[test]
    fn test_persisted_json_rejects_tampered_original_value() {
        let (mapping, _token) = make_mapping_with_email();
        let json = mapping.to_persisted_json_pretty().unwrap();
        let tampered = json.replace("john@example.com", "attacker@example.com");

        assert_eq!(
            Mapping::from_persisted_json(&tampered).unwrap_err(),
            MappingIntegrityError::Mismatch
        );
    }

    #[test]
    fn test_persisted_json_rejects_tampered_token_and_session_metadata() {
        let (mapping, token) = make_mapping_with_email();
        let json = mapping.to_persisted_json_pretty().unwrap();
        let tampered_token = json.replace(&token, "[EMAIL_ADDRESS_deadbeef]");
        let tampered_session = json.replace(&mapping.session_id, "0000000000000000");

        assert_eq!(
            Mapping::from_persisted_json(&tampered_token).unwrap_err(),
            MappingIntegrityError::Mismatch
        );
        assert_eq!(
            Mapping::from_persisted_json(&tampered_session).unwrap_err(),
            MappingIntegrityError::Mismatch
        );
    }

    #[test]
    fn test_legacy_unsigned_mapping_rejected_by_default() {
        let (mapping, token) = make_mapping_with_email();
        let json = serde_json::to_string_pretty(&mapping).unwrap();

        assert_eq!(
            Mapping::from_persisted_json(&json).unwrap_err(),
            MappingIntegrityError::MissingIntegrity
        );

        let (loaded, status) = Mapping::from_persisted_json_allow_legacy(&json).unwrap();
        assert_eq!(status, MappingLoadStatus::LegacyUnsigned);
        assert_eq!(loaded.restore_bracketed(&token), "john@example.com");
    }

    #[test]
    fn test_crypto_random_hex_length() {
        assert_eq!(crypto_random_hex(4).len(), 8);
        assert_eq!(crypto_random_hex(8).len(), 16);
        assert_eq!(crypto_random_hex(16).len(), 32);
    }

    #[test]
    fn test_crypto_random_hex_is_not_degenerate() {
        let hex = crypto_random_hex(16);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(hex, "0".repeat(32));
    }

    #[test]
    fn test_crypto_random_hex_cross_platform() {
        for size in [1, 4, 8, 16, 32] {
            let hex = crypto_random_hex(size);
            assert_eq!(hex.len(), size * 2);
        }
    }
}
