//! Generic provider: whole-body anonymization for any LLM API.
//!
//! Unlike Anthropic/OpenAI providers which walk schema-specific fields,
//! this provider anonymizes the entire JSON request body using `anonymize_json_value()`
//! and restores the entire JSON response body.
//!
//! This is the fallback mode for any LLM API that isn't explicitly supported.

use serde_json::Value;

use crate::detection::Anonymizer;
use crate::mapping::Mapping;

/// Anonymize PII in an entire JSON request body.
///
/// Walks all string values recursively using `anonymize_json_value()`.
/// Non-JSON request bodies should be passed through without anonymization
/// (handled by the caller with a warning log).
pub fn anonymize_request(body: &mut Value, anonymizer: &mut Anonymizer) {
    let (anonymized, _) = anonymizer.anonymize_json_value(body);
    *body = anonymized;
}

/// Restore tokens in an entire JSON response body.
///
/// Walks all string values recursively and restores bracketed tokens.
pub fn restore_response(body: &mut Value, mapping: &Mapping) {
    walk_and_restore(body, mapping);
}

/// Recursively walk JSON and restore bracketed tokens in all strings.
fn walk_and_restore(value: &mut Value, mapping: &Mapping) {
    match value {
        Value::String(s) => {
            *s = mapping.restore_bracketed(s);
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                walk_and_restore(item, mapping);
            }
        }
        Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                walk_and_restore(v, mapping);
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
    fn test_anonymize_request_basic() {
        let mut body = json!({
            "text": "Contact john@example.com"
        });
        let mut anonymizer = Anonymizer::new(0.0);
        anonymize_request(&mut body, &mut anonymizer);

        let text = body["text"].as_str().unwrap();
        assert!(
            text.contains("[EMAIL_ADDRESS_"),
            "Email should be anonymized, got: {text}"
        );
    }

    #[test]
    fn test_restore_response_basic() {
        let mut mapping = Mapping::new();
        mapping.mappings.insert(
            "[EMAIL_ADDRESS_test1234]".to_string(),
            "user@example.com".to_string(),
        );
        mapping.rebuild_caches();

        let mut response = json!({
            "output": "[EMAIL_ADDRESS_test1234]"
        });
        restore_response(&mut response, &mapping);

        let output = response["output"].as_str().unwrap();
        assert!(
            output.contains("user@example.com"),
            "Email should be restored, got: {output}"
        );
    }
}
