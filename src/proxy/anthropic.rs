use serde_json::Value;

use crate::detection::Anonymizer;
use crate::mapping::Mapping;

/// Anonymize PII in an Anthropic Messages API request body.
///
/// Walks the schema-specific fields:
/// - `system` (string or array of content blocks)
/// - `messages[].content` (string or array of content blocks)
///
/// Content blocks have `type: "text"` with a `text` field,
/// or `type: "tool_result"` with `content` (string or array).
pub fn anonymize_request(body: &mut Value, anonymizer: &mut Anonymizer) {
    // system field
    if let Some(system) = body.get_mut("system") {
        anonymize_field(system, anonymizer);
    }

    // messages array
    if let Some(Value::Array(messages)) = body.get_mut("messages") {
        for msg in messages.iter_mut() {
            if let Some(content) = msg.get_mut("content") {
                anonymize_field(content, anonymizer);
            }
        }
    }
}

/// Restore tokens in an Anthropic Messages API response body (non-streaming).
///
/// Walks:
/// - `content[]` (array of content blocks with `text` fields)
pub fn restore_response(body: &mut Value, mapping: &Mapping) {
    if let Some(Value::Array(content)) = body.get_mut("content") {
        for block in content.iter_mut() {
            if let Some(Value::String(text)) = block.get_mut("text") {
                *text = mapping.restore_bracketed(text);
            }
        }
    }
}

/// Anonymize a field that can be either a string or an array of content blocks.
fn anonymize_field(field: &mut Value, anonymizer: &mut Anonymizer) {
    match field {
        Value::String(s) => {
            let (anon, _) = anonymizer.anonymize_text(s);
            *s = anon;
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                anonymize_content_block(item, anonymizer);
            }
        }
        _ => {}
    }
}

/// Anonymize a single content block.
///
/// Handles:
/// - `{ "type": "text", "text": "..." }`
/// - `{ "type": "tool_result", "content": "..." | [...] }`
fn anonymize_content_block(block: &mut Value, anonymizer: &mut Anonymizer) {
    let block_type = block
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();

    match block_type.as_str() {
        "text" => {
            if let Some(Value::String(text)) = block.get_mut("text") {
                let (anon, _) = anonymizer.anonymize_text(text);
                *text = anon;
            }
        }
        "tool_result" => {
            if let Some(content) = block.get_mut("content") {
                anonymize_field(content, anonymizer);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_anonymize_simple_message() {
        let mut body = json!({
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {
                    "role": "user",
                    "content": "My email is john@example.com"
                }
            ]
        });
        let mut anonymizer = Anonymizer::new(0.0);
        anonymize_request(&mut body, &mut anonymizer);

        let content = body["messages"][0]["content"].as_str().unwrap();
        assert!(content.contains("[EMAIL_ADDRESS_1]"));
        assert!(!content.contains("john@example.com"));
    }

    #[test]
    fn test_anonymize_system_string() {
        let mut body = json!({
            "model": "claude-sonnet-4-20250514",
            "system": "Contact support at help@company.com",
            "messages": []
        });
        let mut anonymizer = Anonymizer::new(0.0);
        anonymize_request(&mut body, &mut anonymizer);

        let system = body["system"].as_str().unwrap();
        assert!(system.contains("[EMAIL_ADDRESS_1]"));
    }

    #[test]
    fn test_anonymize_content_blocks() {
        let mut body = json!({
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        { "type": "text", "text": "Server at 192.168.1.100" }
                    ]
                }
            ]
        });
        let mut anonymizer = Anonymizer::new(0.0);
        anonymize_request(&mut body, &mut anonymizer);

        let text = body["messages"][0]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("[IP_ADDRESS_1]"));
    }

    #[test]
    fn test_anonymize_tool_result() {
        let mut body = json!({
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "abc",
                            "content": "Found email: test@secret.org"
                        }
                    ]
                }
            ]
        });
        let mut anonymizer = Anonymizer::new(0.0);
        anonymize_request(&mut body, &mut anonymizer);

        let content = body["messages"][0]["content"][0]["content"]
            .as_str()
            .unwrap();
        assert!(content.contains("[EMAIL_ADDRESS_1]"));
    }

    #[test]
    fn test_restore_response() {
        let mut anonymizer = Anonymizer::new(0.0);
        let _ = anonymizer.anonymize_text("john@example.com");
        let mapping = &anonymizer.mapping;

        let mut response = json!({
            "content": [
                { "type": "text", "text": "The email [EMAIL_ADDRESS_1] was found" }
            ]
        });
        restore_response(&mut response, mapping);

        let text = response["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("john@example.com"));
        assert!(!text.contains("[EMAIL_ADDRESS_1]"));
    }

    #[test]
    fn test_model_and_non_text_fields_preserved() {
        let mut body = json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "temperature": 0.7,
            "messages": [
                {
                    "role": "user",
                    "content": "hello"
                }
            ]
        });
        let mut anonymizer = Anonymizer::new(0.0);
        anonymize_request(&mut body, &mut anonymizer);

        assert_eq!(body["model"], "claude-sonnet-4-20250514");
        assert_eq!(body["max_tokens"], 1024);
        assert_eq!(body["temperature"], 0.7);
    }
}
