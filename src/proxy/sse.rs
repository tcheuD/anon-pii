use crate::mapping::Mapping;

const BUFFER_HARD_CAP: usize = 64;

/// Trait for resolving tokens — allows both snapshot-based and live mapping.
pub trait TokenResolver {
    fn restore(&self, text: &str) -> String;
}

impl TokenResolver for Mapping {
    fn restore(&self, text: &str) -> String {
        self.restore_bracketed(text)
    }
}

/// Bracket-detecting buffer for SSE token restoration.
///
/// The problem: SSE streams deliver text in small chunks. A token like
/// `[EMAIL_ADDRESS_a1b2c3d4]` might be split across events:
///   event 1: "The email ["
///   event 2: "EMAIL_ADDRESS_a1b2c3d4]"
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

/// Parse an OpenAI SSE data line and extract the text delta if present.
///
/// OpenAI SSE events for streaming:
/// - `choices[].delta.content` for text content
/// - `choices[].delta.tool_calls[].function.arguments` for tool call arguments
///
/// Returns `Some(text)` if this event contains a text delta, `None` otherwise.
pub fn extract_text_delta_openai(data: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(data).ok()?;

    let choices = value.get("choices")?.as_array()?;
    let first_choice = choices.first()?;
    let delta = first_choice.get("delta")?;

    // Try content first (regular text streaming)
    if let Some(content) = delta.get("content").and_then(|c| c.as_str()) {
        return Some(content.to_string());
    }

    // Try tool_calls[].function.arguments (tool call streaming)
    if let Some(tool_calls) = delta.get("tool_calls").and_then(|tc| tc.as_array()) {
        if let Some(first_tc) = tool_calls.first() {
            if let Some(func) = first_tc.get("function") {
                if let Some(args) = func.get("arguments").and_then(|a| a.as_str()) {
                    return Some(args.to_string());
                }
            }
        }
    }

    None
}

/// Rebuild an OpenAI SSE data line with a replaced text delta.
///
/// Handles both `choices[].delta.content` and `choices[].delta.tool_calls[].function.arguments`.
pub fn replace_text_delta_openai(data: &str, new_text: &str) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(data).ok()?;

    let choices = value.get_mut("choices")?.as_array_mut()?;
    let first_choice = choices.first_mut()?;
    let delta = first_choice.get_mut("delta")?;

    // Try content first (regular text streaming)
    if let Some(content) = delta.get_mut("content") {
        if content.is_string() {
            *content = serde_json::Value::String(new_text.to_string());
            return serde_json::to_string(&value).ok();
        }
    }

    // Try tool_calls[].function.arguments (tool call streaming)
    if let Some(tool_calls) = delta.get_mut("tool_calls").and_then(|tc| tc.as_array_mut()) {
        if let Some(first_tc) = tool_calls.first_mut() {
            if let Some(func) = first_tc.get_mut("function") {
                if let Some(args) = func.get_mut("arguments") {
                    if args.is_string() {
                        *args = serde_json::Value::String(new_text.to_string());
                        return serde_json::to_string(&value).ok();
                    }
                }
            }
        }
    }

    None
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
        m.mappings.insert(
            "[EMAIL_ADDRESS_a1b2c3d4]".to_string(),
            "john@example.com".to_string(),
        );
        m.mappings.insert(
            "[IP_ADDRESS_e5f6a7b8]".to_string(),
            "192.168.1.100".to_string(),
        );
        m.rebuild_caches();
        m
    }

    #[test]
    fn test_token_buffer_complete_token() {
        let mapping = make_mapping();
        let mut buf = TokenBuffer::new(mapping);

        let out = buf.feed("The email [EMAIL_ADDRESS_a1b2c3d4] was found");
        assert_eq!(out, "The email john@example.com was found");
    }

    #[test]
    fn test_token_buffer_split_across_chunks() {
        let mapping = make_mapping();
        let mut buf = TokenBuffer::new(mapping);

        let out1 = buf.feed("The email [EMAIL");
        assert_eq!(out1, "The email ");

        let out2 = buf.feed("_ADDRESS_a1b2c3d4] was found");
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

        let out = buf.feed("[EMAIL_ADDRESS_a1b2c3d4] at [IP_ADDRESS_e5f6a7b8]");
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
        let data = r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"[EMAIL_ADDRESS_a1b2c3d4]"}}"#;
        let replaced = replace_text_delta(data, "john@example.com").unwrap();
        let v: serde_json::Value = serde_json::from_str(&replaced).unwrap();
        assert_eq!(v["delta"]["text"], "john@example.com");
    }

    // ============================================================================
    // OPENAI SSE DELTA TESTS
    // ============================================================================

    #[test]
    fn test_extract_text_delta_openai_content() {
        // OpenAI streams text via choices[].delta.content
        let data = r#"{"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}"#;
        assert_eq!(extract_text_delta_openai(data), Some("Hello".to_string()));
    }

    #[test]
    fn test_extract_text_delta_openai_first_chunk_role_only() {
        // First chunk may contain role but no content
        let data = r#"{"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}"#;
        assert_eq!(extract_text_delta_openai(data), None);
    }

    #[test]
    fn test_extract_text_delta_openai_empty_delta() {
        // Final chunk often has empty delta with finish_reason
        let data = r#"{"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#;
        assert_eq!(extract_text_delta_openai(data), None);
    }

    #[test]
    fn test_extract_text_delta_openai_tool_calls_arguments() {
        // OpenAI streams tool call arguments via choices[].delta.tool_calls[].function.arguments
        let data = r#"{"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"email\":"}}]},"finish_reason":null}]}"#;
        assert_eq!(
            extract_text_delta_openai(data),
            Some(r#"{"email":"#.to_string())
        );
    }

    #[test]
    fn test_extract_text_delta_openai_no_choices() {
        let data = r#"{"id":"chatcmpl-abc","object":"chat.completion.chunk"}"#;
        assert_eq!(extract_text_delta_openai(data), None);
    }

    #[test]
    fn test_replace_text_delta_openai_content() {
        let data = r#"{"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"[EMAIL_ADDRESS_a1b2c3d4]"},"finish_reason":null}]}"#;
        let replaced = replace_text_delta_openai(data, "john@example.com").unwrap();
        let v: serde_json::Value = serde_json::from_str(&replaced).unwrap();
        assert_eq!(v["choices"][0]["delta"]["content"], "john@example.com");
    }

    #[test]
    fn test_replace_text_delta_openai_tool_calls_arguments() {
        let data = r#"{"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"[EMAIL_ADDRESS_a1b2c3d4]"}}]},"finish_reason":null}]}"#;
        let replaced = replace_text_delta_openai(data, "john@example.com").unwrap();
        let v: serde_json::Value = serde_json::from_str(&replaced).unwrap();
        assert_eq!(
            v["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            "john@example.com"
        );
    }

    #[test]
    fn test_replace_text_delta_openai_preserves_structure() {
        let data = r#"{"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"test"},"finish_reason":null}]}"#;
        let replaced = replace_text_delta_openai(data, "restored").unwrap();
        let v: serde_json::Value = serde_json::from_str(&replaced).unwrap();

        // Verify structure is preserved
        assert_eq!(v["id"], "chatcmpl-abc");
        assert_eq!(v["object"], "chat.completion.chunk");
        assert_eq!(v["created"], 1700000000);
        assert_eq!(v["model"], "gpt-4");
        assert_eq!(v["choices"][0]["index"], 0);
        assert_eq!(v["choices"][0]["delta"]["content"], "restored");
        assert!(v["choices"][0]["finish_reason"].is_null());
    }

    #[test]
    fn test_replace_text_delta_openai_empty_delta_returns_none() {
        // When delta has no content/arguments, replace should return None
        let data =
            r#"{"id":"chatcmpl-abc","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#;
        assert!(replace_text_delta_openai(data, "test").is_none());
    }
}
