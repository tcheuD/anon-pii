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

/// Generate a hex string of `n_bytes` random bytes from a cryptographic source.
/// Uses /dev/urandom on Unix; falls back to RandomState (non-crypto) on other platforms.
fn crypto_random_hex(n_bytes: usize) -> String {
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let mut buf = vec![0u8; n_bytes];
            if f.read_exact(&mut buf).is_ok() {
                return buf.iter().map(|b| format!("{b:02x}")).collect();
            }
        }
    }
    // Fallback for non-Unix or if /dev/urandom fails
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let h = RandomState::new().build_hasher().finish();
    format!("{h:016x}")[..n_bytes * 2].to_string()
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

    pub fn restore(&self, text: &str) -> String {
        let bare_map = self.bare_token_map();

        // First pass: restore [TOKEN] patterns
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

        // Second pass: restore bare tokens (EMAIL_ADDRESS_1, CREW_CODE_1, etc.)
        // Handles cases where LLMs strip brackets in markdown output.
        // Sort by token length descending so IP_ADDRESS_10 is replaced before
        // IP_ADDRESS_1 (avoids substring collision).
        if !bare_map.is_empty() {
            let mut sorted_bare: Vec<_> = bare_map.into_iter().collect();
            sorted_bare.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
            for (bare, original) in &sorted_bare {
                result = result.replace(bare.as_str(), original);
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

    #[test]
    fn test_crypto_random_hex_length() {
        assert_eq!(crypto_random_hex(4).len(), 8);
        assert_eq!(crypto_random_hex(8).len(), 16);
        assert_eq!(crypto_random_hex(16).len(), 32);
    }
}
