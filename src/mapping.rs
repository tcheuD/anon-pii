use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct Mapping {
    pub session_id: String,
    pub created_at: String,
    pub mappings: HashMap<String, String>,
    #[serde(skip)]
    pub reverse: HashMap<String, String>,
    #[serde(skip)]
    pub counters: HashMap<String, usize>,
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
    let y = if m <= 2 { yoe + era * 400 + 1 } else { yoe + era * 400 };
    (y, m, d)
}

/// Generate a hex string of `n_bytes` random bytes from the OS CSPRNG.
fn crypto_random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    getrandom::getrandom(&mut buf).expect("OS CSPRNG unavailable");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

impl Mapping {
    pub fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let session_id = crypto_random_hex(8);

        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
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
            reverse: HashMap::new(),
            counters: HashMap::new(),
        }
    }

    pub fn add(&mut self, entity_type: &str, original: &str) -> String {
        if let Some(token) = self.reverse.get(original) {
            return token.clone();
        }

        let counter = self.counters.entry(entity_type.to_string()).or_insert(0);
        *counter += 1;
        let token = format!("[{}_{counter}]", entity_type);

        self.mappings.insert(token.clone(), original.to_string());
        self.reverse.insert(original.to_string(), token.clone());
        token
    }

    pub fn rebuild_caches(&mut self) {
        self.reverse.clear();
        self.counters.clear();
        for (token, original) in &self.mappings {
            self.reverse.insert(original.clone(), token.clone());
            if let Some(inner) = token.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
                if let Some(pos) = inner.rfind('_') {
                    if let Ok(n) = inner[pos + 1..].parse::<usize>() {
                        let counter = self.counters.entry(inner[..pos].to_string()).or_insert(0);
                        *counter = (*counter).max(n);
                    }
                }
            }
        }
    }

    /// Build a lookup of bare tokens (without brackets) for fuzzy restore.
    /// E.g. "EMAIL_ADDRESS_1" -> "john@example.com"
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

    /// Restore only bracket-delimited tokens: `[EMAIL_ADDRESS_1]` → original.
    /// Safe for use in proxy responses where bare token injection is a risk.
    pub fn restore_bracketed(&self, text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let bytes = text.as_bytes();
        let mut i = 0;

        while i < bytes.len() {
            if bytes[i] == b'[' {
                if let Some(close) = text[i..].find(']') {
                    let candidate = &text[i..i + close + 1];
                    if let Some(original) = self.mappings.get(candidate) {
                        result.push_str(original);
                        i += close + 1;
                        continue;
                    }
                }
            }
            let ch = text[i..].chars().next().unwrap();
            result.push(ch);
            i += ch.len_utf8();
        }

        result
    }

    /// Restore both bracket-delimited and bare tokens.
    /// Bare tokens use word-boundary matching to avoid partial/injected replacements.
    /// Use for CLI restore where the user explicitly wants full restoration.
    pub fn restore(&self, text: &str) -> String {
        let mut result = self.restore_bracketed(text);

        // Second pass: restore bare tokens using single-pass aho-corasick.
        // This prevents double-replacement where a restored value contains
        // another bare token (e.g. EMAIL_ADDRESS_1 → "EMAIL_ADDRESS_2@test.com").
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
                    // Word-boundary check: ensure match is not mid-word
                    let before_ok = start == 0
                        || !result.as_bytes()[start - 1].is_ascii_alphanumeric();
                    let after_ok = end == result.len()
                        || !result.as_bytes()[end].is_ascii_alphanumeric();
                    if before_ok && after_ok {
                        output.push_str(&result[last..start]);
                        let matched = &result[start..end];
                        if let Some(original) = bare_map.get(matched) {
                            output.push_str(original);
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

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_session_id_is_hex_and_correct_length() {
        let m = Mapping::new();
        assert_eq!(m.session_id.len(), 16, "session_id should be 16 hex chars (8 bytes)");
        assert!(
            m.session_id.chars().all(|c| c.is_ascii_hexdigit()),
            "session_id should contain only hex characters: {}",
            m.session_id
        );
    }

    #[test]
    fn test_session_id_uniqueness() {
        let ids: HashSet<String> = (0..100).map(|_| Mapping::new().session_id).collect();
        assert!(
            ids.len() >= 95,
            "100 session IDs should be nearly all unique, got {} distinct",
            ids.len()
        );
    }

    fn make_mapping_with_email() -> Mapping {
        let mut m = Mapping::new();
        m.mappings.insert("[EMAIL_ADDRESS_1]".to_string(), "john@example.com".to_string());
        m.rebuild_caches();
        m
    }

    #[test]
    fn test_restore_bracketed_replaces_bracket_tokens() {
        let m = make_mapping_with_email();
        let result = m.restore_bracketed("Contact [EMAIL_ADDRESS_1] now");
        assert_eq!(result, "Contact john@example.com now");
    }

    #[test]
    fn test_restore_bracketed_ignores_bare_tokens() {
        let m = make_mapping_with_email();
        // Bare token must NOT be restored via restore_bracketed — this is the
        // token injection defense. An LLM emitting "EMAIL_ADDRESS_1" in prose
        // should not cause PII disclosure in the proxy path.
        let result = m.restore_bracketed("The entity EMAIL_ADDRESS_1 was detected");
        assert_eq!(result, "The entity EMAIL_ADDRESS_1 was detected");
    }

    #[test]
    fn test_restore_full_replaces_bare_at_word_boundary() {
        let m = make_mapping_with_email();
        let result = m.restore("The entity EMAIL_ADDRESS_1 was detected");
        assert_eq!(result, "The entity john@example.com was detected");
    }

    #[test]
    fn test_restore_full_bare_no_substring_collision() {
        let mut m = Mapping::new();
        m.mappings.insert("[IP_ADDRESS_1]".to_string(), "10.0.0.1".to_string());
        m.mappings.insert("[IP_ADDRESS_10]".to_string(), "10.0.0.2".to_string());
        m.rebuild_caches();

        let result = m.restore("IP_ADDRESS_10 and IP_ADDRESS_1");
        assert_eq!(result, "10.0.0.2 and 10.0.0.1");
    }

    #[test]
    fn test_restore_full_bare_word_boundary_prevents_partial() {
        let m = make_mapping_with_email();
        // "EMAIL_ADDRESS_1X" should NOT trigger a bare match because
        // the trailing X breaks the word boundary.
        let result = m.restore("prefix EMAIL_ADDRESS_1X suffix");
        assert_eq!(result, "prefix EMAIL_ADDRESS_1X suffix");
    }

    #[test]
    fn test_restore_injection_attack_via_llm() {
        let m = make_mapping_with_email();
        // Simulates an LLM response in the proxy path — restore_bracketed
        // must not replace the bare token the LLM emitted.
        let llm_response = "I detected a token called EMAIL_ADDRESS_1 in your input. \
            The bracketed form is [EMAIL_ADDRESS_1].";
        let result = m.restore_bracketed(llm_response);
        // Bracketed token is restored, bare token is left intact
        assert!(result.contains("john@example.com"));
        assert!(result.contains("EMAIL_ADDRESS_1 in your input"));
    }

    #[test]
    fn test_restore_no_double_replacement() {
        // EMAIL_ADDRESS_1 restores to a value containing "EMAIL_ADDRESS_2"
        // which should NOT be replaced again by the EMAIL_ADDRESS_2 mapping.
        let mut m = Mapping::new();
        m.mappings.insert("[EMAIL_ADDRESS_1]".to_string(), "EMAIL_ADDRESS_2@test.com".to_string());
        m.mappings.insert("[EMAIL_ADDRESS_2]".to_string(), "real@secret.com".to_string());
        m.rebuild_caches();

        let result = m.restore("Found EMAIL_ADDRESS_1 and EMAIL_ADDRESS_2");
        assert_eq!(
            result,
            "Found EMAIL_ADDRESS_2@test.com and real@secret.com",
            "Single-pass replacement must not revisit already-replaced regions"
        );
    }

    #[test]
    fn test_crypto_random_hex_length() {
        assert_eq!(crypto_random_hex(4).len(), 8);
        assert_eq!(crypto_random_hex(8).len(), 16);
        assert_eq!(crypto_random_hex(16).len(), 32);
    }

    #[test]
    fn test_crypto_random_hex_is_not_degenerate() {
        // Verify output is valid hex and not all zeros (broken RNG)
        let hex = crypto_random_hex(16);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(hex, "0".repeat(32), "CSPRNG should not produce all zeros");
    }

    #[test]
    fn test_crypto_random_hex_cross_platform() {
        // getrandom works on all platforms — this test simply confirms
        // it doesn't panic and returns the correct length
        for size in [1, 4, 8, 16, 32] {
            let hex = crypto_random_hex(size);
            assert_eq!(hex.len(), size * 2);
        }
    }
}
