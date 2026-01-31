use crate::mapping::Mapping;

const BUFFER_HARD_CAP: usize = 64;

/// Trait for resolving tokens — allows both snapshot-based and live mapping.
pub trait TokenResolver {
    fn restore(&self, text: &str) -> String;
}

impl TokenResolver for Mapping {
    fn restore(&self, text: &str) -> String {
        Mapping::restore(self, text)
    }
}

/// Bracket-detecting buffer for SSE token restoration.
///
/// The problem: SSE streams deliver text in small chunks. A token like
/// `[EMAIL_ADDRESS_1]` might be split across events:
///   event 1: "The email ["
///   event 2: "EMAIL_ADDRESS_1]"
///
/// TokenBuffer accumulates text when an open bracket is seen,
/// restores complete tokens, and flushes on close bracket or overflow.
pub struct TokenBuffer<R: TokenResolver> {
    buf: String,
    in_bracket: bool,
    resolver: R,
}

impl<R: TokenResolver> TokenBuffer<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            buf: String::new(),
            in_bracket: false,
            resolver,
        }
    }

    /// Feed a chunk of text from an SSE event.
    /// Returns the text to emit (with tokens restored).
    pub fn feed(&mut self, chunk: &str) -> String {
        let mut output = String::new();

        for ch in chunk.chars() {
            if self.in_bracket {
                self.buf.push(ch);
                if ch == ']' {
                    let restored = self.resolver.restore(&self.buf);
                    output.push_str(&restored);
                    self.buf.clear();
                    self.in_bracket = false;
                } else if self.buf.len() >= BUFFER_HARD_CAP {
                    // Overflow: flush as-is (not a real token)
                    output.push_str(&self.buf);
                    self.buf.clear();
                    self.in_bracket = false;
                }
            } else if ch == '[' {
                self.in_bracket = true;
                self.buf.push(ch);
            } else {
                output.push(ch);
            }
        }

        output
    }

    /// Flush any remaining buffered content (call at end of stream).
    pub fn flush(&mut self) -> String {
        let remaining = std::mem::take(&mut self.buf);
        self.in_bracket = false;
        remaining
    }
}

/// Parse an SSE data line and extract the text delta if present.
///
/// Anthropic SSE events for streaming:
/// - `content_block_delta` with `delta.type == "text_delta"` and `delta.text`
///
/// Returns `Some(text)` if this event contains a text delta, `None` otherwise.
pub fn extract_text_delta(data: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(data).ok()?;

    let event_type = value.get("type")?.as_str()?;
    if event_type != "content_block_delta" {
        return None;
    }

    let delta = value.get("delta")?;
    let delta_type = delta.get("type")?.as_str()?;
    if delta_type != "text_delta" {
        return None;
    }

    delta.get("text")?.as_str().map(|s| s.to_string())
}

/// Rebuild an SSE data line with a replaced text delta.
pub fn replace_text_delta(data: &str, new_text: &str) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(data).ok()?;

    let event_type = value.get("type")?.as_str()?.to_string();
    if event_type != "content_block_delta" {
        return None;
    }

    if let Some(delta) = value.get_mut("delta") {
        if let Some(text) = delta.get_mut("text") {
            *text = serde_json::Value::String(new_text.to_string());
        }
    }

    serde_json::to_string(&value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mapping() -> Mapping {
        let mut m = Mapping::new();
        m.mappings
            .insert("[EMAIL_ADDRESS_1]".to_string(), "john@example.com".to_string());
        m.mappings
            .insert("[IP_ADDRESS_1]".to_string(), "192.168.1.100".to_string());
        m.rebuild_caches();
        m
    }

    #[test]
    fn test_token_buffer_complete_token() {
        let mapping = make_mapping();
        let mut buf = TokenBuffer::new(mapping);

        let out = buf.feed("The email [EMAIL_ADDRESS_1] was found");
        assert_eq!(out, "The email john@example.com was found");
    }

    #[test]
    fn test_token_buffer_split_across_chunks() {
        let mapping = make_mapping();
        let mut buf = TokenBuffer::new(mapping);

        let out1 = buf.feed("The email [EMAIL");
        assert_eq!(out1, "The email ");

        let out2 = buf.feed("_ADDRESS_1] was found");
        assert_eq!(out2, "john@example.com was found");
    }

    #[test]
    fn test_token_buffer_overflow() {
        let mapping = make_mapping();
        let mut buf = TokenBuffer::new(mapping);

        // Create a string that exceeds BUFFER_HARD_CAP without closing bracket
        let long_text = format!("[{}", "A".repeat(BUFFER_HARD_CAP));
        let out = buf.feed(&long_text);

        // Should flush the overflowed content as-is
        assert!(out.contains(&"A".repeat(BUFFER_HARD_CAP - 1)));
        assert!(!buf.in_bracket);
    }

    #[test]
    fn test_token_buffer_flush() {
        let mapping = make_mapping();
        let mut buf = TokenBuffer::new(mapping);

        let out = buf.feed("text [partial");
        assert_eq!(out, "text ");

        let remaining = buf.flush();
        assert_eq!(remaining, "[partial");
    }

    #[test]
    fn test_token_buffer_no_tokens() {
        let mapping = make_mapping();
        let mut buf = TokenBuffer::new(mapping);

        let out = buf.feed("just regular text here");
        assert_eq!(out, "just regular text here");
    }

    #[test]
    fn test_token_buffer_multiple_tokens() {
        let mapping = make_mapping();
        let mut buf = TokenBuffer::new(mapping);

        let out = buf.feed("[EMAIL_ADDRESS_1] at [IP_ADDRESS_1]");
        assert_eq!(out, "john@example.com at 192.168.1.100");
    }

    #[test]
    fn test_extract_text_delta() {
        let data = r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}"#;
        assert_eq!(extract_text_delta(data), Some("Hello".to_string()));
    }

    #[test]
    fn test_extract_text_delta_non_text() {
        let data = r#"{"type":"message_start","message":{}}"#;
        assert_eq!(extract_text_delta(data), None);
    }

    #[test]
    fn test_replace_text_delta() {
        let data = r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"[EMAIL_ADDRESS_1]"}}"#;
        let replaced = replace_text_delta(data, "john@example.com").unwrap();
        let v: serde_json::Value = serde_json::from_str(&replaced).unwrap();
        assert_eq!(v["delta"]["text"], "john@example.com");
    }
}
