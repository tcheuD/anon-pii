//! OpenAI-compatible API request/response anonymization.
//!
//! Walks the OpenAI chat completions schema:
//! - Request: `messages[].content` (string or array of content parts)
//! - Request: `messages[].tool_calls[].function.arguments` (JSON string)
//! - Request: `tools[].function.parameters` (descriptions in schema)
//! - Response: `choices[].message.content`
//! - Response: `choices[].message.tool_calls[].function.arguments`

use serde_json::Value;

use crate::detection::Anonymizer;
use crate::mapping::Mapping;

/// Anonymize PII in an OpenAI Chat Completions API request body.
///
/// Walks the schema-specific fields:
/// - `messages[].content` (string or array of content parts)
/// - `messages[].tool_calls[].function.arguments` (JSON string -> parse -> anonymize -> re-serialize)
/// - `tools[].function.parameters` (descriptions in JSON schema)
pub fn anonymize_request(body: &mut Value, anonymizer: &mut Anonymizer) {
    // messages array
    if let Some(Value::Array(messages)) = body.get_mut("messages") {
        for msg in messages.iter_mut() {
            // Handle content field (string or array)
            if let Some(content) = msg.get_mut("content") {
                anonymize_content(content, anonymizer);
            }

            // Handle tool_calls[].function.arguments (JSON string)
            if let Some(Value::Array(tool_calls)) = msg.get_mut("tool_calls") {
                for tool_call in tool_calls.iter_mut() {
                    anonymize_tool_call(tool_call, anonymizer);
                }
            }
        }
    }

    // tools[].function.parameters (descriptions in JSON schema)
    if let Some(Value::Array(tools)) = body.get_mut("tools") {
        for tool in tools.iter_mut() {
            if let Some(func) = tool.get_mut("function") {
                if let Some(params) = func.get_mut("parameters") {
                    anonymize_json_schema_descriptions(params, anonymizer);
                }
            }
        }
    }
}

/// Restore tokens in an OpenAI Chat Completions API response body (non-streaming).
///
/// Walks:
/// - `choices[].message.content` (string)
/// - `choices[].message.tool_calls[].function.arguments` (JSON string)
pub fn restore_response(body: &mut Value, mapping: &Mapping) {
    if let Some(Value::Array(choices)) = body.get_mut("choices") {
        for choice in choices.iter_mut() {
            if let Some(message) = choice.get_mut("message") {
                // Restore content string
                if let Some(Value::String(content)) = message.get_mut("content") {
                    *content = mapping.restore_bracketed(content);
                }

                // Restore tool_calls[].function.arguments
                if let Some(Value::Array(tool_calls)) = message.get_mut("tool_calls") {
                    for tool_call in tool_calls.iter_mut() {
                        restore_tool_call(tool_call, mapping);
                    }
                }
            }
        }
    }
}

/// Anonymize content field which can be a string or array of content parts.
fn anonymize_content(content: &mut Value, anonymizer: &mut Anonymizer) {
    match content {
        Value::String(s) => {
            let (anon, _) = anonymizer.anonymize_text(s);
            *s = anon;
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                anonymize_content_part(item, anonymizer);
            }
        }
        _ => {}
    }
}

/// Anonymize a single content part (text, image_url, etc.).
fn anonymize_content_part(part: &mut Value, anonymizer: &mut Anonymizer) {
    // Only process text parts; image_url and other types are preserved as-is
    let is_text = part.get("type").and_then(|t| t.as_str()) == Some("text");

    if is_text {
        if let Some(Value::String(text)) = part.get_mut("text") {
            let (anon, _) = anonymizer.anonymize_text(text);
            *text = anon;
        }
    }
}

/// Anonymize a tool_call's function.arguments (JSON string).
fn anonymize_tool_call(tool_call: &mut Value, anonymizer: &mut Anonymizer) {
    if let Some(func) = tool_call.get_mut("function") {
        if let Some(Value::String(args_str)) = func.get_mut("arguments") {
            // Parse the JSON string, anonymize it, re-serialize
            if let Ok(mut args_value) = serde_json::from_str::<Value>(args_str) {
                let (anon_value, _) = anonymizer.anonymize_json_value(&args_value);
                args_value = anon_value;
                if let Ok(anon_str) = serde_json::to_string(&args_value) {
                    *args_str = anon_str;
                }
            }
        }
    }
}

/// Recursively anonymize "description" fields in a JSON schema.
fn anonymize_json_schema_descriptions(schema: &mut Value, anonymizer: &mut Anonymizer) {
    if let Some(Value::String(desc)) = schema.get_mut("description") {
        let (anon, _) = anonymizer.anonymize_text(desc);
        *desc = anon;
    }

    // Recurse into properties
    if let Some(Value::Object(props)) = schema.get_mut("properties") {
        for (_, prop_schema) in props.iter_mut() {
            anonymize_json_schema_descriptions(prop_schema, anonymizer);
        }
    }

    // Recurse into items (for arrays)
    if let Some(items) = schema.get_mut("items") {
        anonymize_json_schema_descriptions(items, anonymizer);
    }

    // Recurse into anyOf, oneOf, allOf
    for keyword in ["anyOf", "oneOf", "allOf"] {
        if let Some(Value::Array(arr)) = schema.get_mut(keyword) {
            for item in arr.iter_mut() {
                anonymize_json_schema_descriptions(item, anonymizer);
            }
        }
    }
}

/// Restore tokens in a tool_call's function.arguments (JSON string).
fn restore_tool_call(tool_call: &mut Value, mapping: &Mapping) {
    if let Some(func) = tool_call.get_mut("function") {
        if let Some(Value::String(args_str)) = func.get_mut("arguments") {
            *args_str = mapping.restore_bracketed(args_str);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ============================================================================
    // REQUEST ANONYMIZATION TESTS
    // ============================================================================

    #[test]
    fn test_anonymize_simple_string_content() {
        let mut body = json!({
            "model": "gpt-4",
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
        assert!(
            content.contains("[EMAIL_ADDRESS_"),
            "Email should be anonymized, got: {content}"
        );
        assert!(
            !content.contains("john@example.com"),
            "Original email should not appear"
        );
    }

    #[test]
    fn test_anonymize_array_content_text_part() {
        let mut body = json!({
            "model": "gpt-4",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": "Server at 192.168.1.100"
                        }
                    ]
                }
            ]
        });
        let mut anonymizer = Anonymizer::new(0.0);
        anonymize_request(&mut body, &mut anonymizer);

        let text = body["messages"][0]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("[IP_ADDRESS_"),
            "IP should be anonymized, got: {text}"
        );
        assert!(
            !text.contains("192.168.1.100"),
            "Original IP should not appear"
        );
    }

    #[test]
    fn test_anonymize_array_content_with_image_url_preserved() {
        let mut body = json!({
            "model": "gpt-4-vision-preview",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": "Email: test@secret.org"
                        },
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": "https://example.com/image.png"
                            }
                        }
                    ]
                }
            ]
        });
        let mut anonymizer = Anonymizer::new(0.0);
        anonymize_request(&mut body, &mut anonymizer);

        // Text part should be anonymized
        let text = body["messages"][0]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("[EMAIL_ADDRESS_"),
            "Email should be anonymized"
        );

        // image_url part should be preserved
        let image_url = &body["messages"][0]["content"][1];
        assert_eq!(image_url["type"], "image_url");
        assert_eq!(
            image_url["image_url"]["url"], "https://example.com/image.png",
            "Image URL should not be modified"
        );
    }

    #[test]
    fn test_anonymize_tool_calls_function_arguments() {
        let mut body = json!({
            "model": "gpt-4",
            "messages": [
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [
                        {
                            "id": "call_abc123",
                            "type": "function",
                            "function": {
                                "name": "get_user",
                                "arguments": "{\"email\": \"john@example.com\", \"phone\": \"+33 6 12 34 56 78\"}"
                            }
                        }
                    ]
                }
            ]
        });
        let mut anonymizer = Anonymizer::new(0.0);
        anonymize_request(&mut body, &mut anonymizer);

        let args_str = body["messages"][0]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        let args: Value = serde_json::from_str(args_str).expect("arguments should be valid JSON");

        let email = args["email"].as_str().unwrap();
        assert!(
            email.contains("[EMAIL_ADDRESS_"),
            "Email in tool call should be anonymized, got: {email}"
        );
        assert!(
            !email.contains("john@example.com"),
            "Original email should not appear in tool call"
        );

        // id and function name should be preserved
        assert_eq!(
            body["messages"][0]["tool_calls"][0]["id"], "call_abc123",
            "Tool call ID should be preserved"
        );
        assert_eq!(
            body["messages"][0]["tool_calls"][0]["function"]["name"], "get_user",
            "Function name should be preserved"
        );
    }

    #[test]
    fn test_anonymize_tools_function_parameters_descriptions() {
        let mut body = json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello"}],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "description": "Get weather for a location",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "location": {
                                    "type": "string",
                                    "description": "City name, e.g. contact admin@weather.com for help"
                                },
                                "unit": {
                                    "type": "string",
                                    "enum": ["celsius", "fahrenheit"]
                                }
                            }
                        }
                    }
                }
            ]
        });
        let mut anonymizer = Anonymizer::new(0.0);
        anonymize_request(&mut body, &mut anonymizer);

        let location_desc = body["tools"][0]["function"]["parameters"]["properties"]["location"]
            ["description"]
            .as_str()
            .unwrap();
        assert!(
            location_desc.contains("[EMAIL_ADDRESS_"),
            "Email in parameter description should be anonymized, got: {location_desc}"
        );

        // Function name and structure should be preserved
        assert_eq!(
            body["tools"][0]["function"]["name"], "get_weather",
            "Function name should be preserved"
        );
        assert_eq!(
            body["tools"][0]["function"]["parameters"]["type"], "object",
            "Parameters type should be preserved"
        );
    }

    #[test]
    fn test_non_text_fields_preserved() {
        let mut body = json!({
            "model": "gpt-4-turbo",
            "max_tokens": 1024,
            "temperature": 0.7,
            "top_p": 0.9,
            "n": 1,
            "stream": false,
            "messages": [
                {
                    "role": "user",
                    "content": "hello"
                }
            ]
        });
        let mut anonymizer = Anonymizer::new(0.0);
        anonymize_request(&mut body, &mut anonymizer);

        assert_eq!(body["model"], "gpt-4-turbo", "model should be preserved");
        assert_eq!(body["max_tokens"], 1024, "max_tokens should be preserved");
        assert_eq!(body["temperature"], 0.7, "temperature should be preserved");
        assert_eq!(body["top_p"], 0.9, "top_p should be preserved");
        assert_eq!(body["n"], 1, "n should be preserved");
        assert_eq!(body["stream"], false, "stream should be preserved");
    }

    #[test]
    fn test_anonymize_multiple_messages() {
        let mut body = json!({
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "My email is user@test.com"},
                {"role": "assistant", "content": "I see your email user@test.com"},
                {"role": "user", "content": "My phone is +1 555-123-4567"}
            ]
        });
        let mut anonymizer = Anonymizer::new(0.0);
        anonymize_request(&mut body, &mut anonymizer);

        // Check user message
        let user_content = body["messages"][1]["content"].as_str().unwrap();
        assert!(
            user_content.contains("[EMAIL_ADDRESS_"),
            "User email should be anonymized"
        );

        // Check assistant message
        let assistant_content = body["messages"][2]["content"].as_str().unwrap();
        assert!(
            assistant_content.contains("[EMAIL_ADDRESS_"),
            "Assistant email should be anonymized"
        );

        // Check second user message with phone
        let user2_content = body["messages"][3]["content"].as_str().unwrap();
        assert!(
            user2_content.contains("[PHONE_NUMBER_") || user2_content.contains("[US_PHONE_NUMBER_"),
            "User phone should be anonymized, got: {user2_content}"
        );
    }

    #[test]
    fn test_anonymize_tool_result_message() {
        let mut body = json!({
            "model": "gpt-4",
            "messages": [
                {
                    "role": "tool",
                    "tool_call_id": "call_abc123",
                    "content": "User found: email=admin@secret.org, ip=10.0.0.42"
                }
            ]
        });
        let mut anonymizer = Anonymizer::new(0.0);
        anonymize_request(&mut body, &mut anonymizer);

        let content = body["messages"][0]["content"].as_str().unwrap();
        assert!(
            content.contains("[EMAIL_ADDRESS_"),
            "Email in tool result should be anonymized"
        );
        assert!(
            content.contains("[IP_ADDRESS_"),
            "IP in tool result should be anonymized"
        );

        // tool_call_id should be preserved
        assert_eq!(
            body["messages"][0]["tool_call_id"], "call_abc123",
            "tool_call_id should be preserved"
        );
    }

    // ============================================================================
    // RESPONSE RESTORATION TESTS
    // ============================================================================

    #[test]
    fn test_restore_response_content() {
        let mut anonymizer = Anonymizer::new(0.0);
        let _ = anonymizer.anonymize_text("john@example.com");
        let token = anonymizer
            .mapping
            .mappings
            .keys()
            .find(|k| k.starts_with("[EMAIL_ADDRESS_"))
            .unwrap()
            .clone();
        let mapping = &anonymizer.mapping;

        let mut response = json!({
            "id": "chatcmpl-abc123",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": format!("The email {token} was found")
                    },
                    "finish_reason": "stop"
                }
            ]
        });
        restore_response(&mut response, mapping);

        let content = response["choices"][0]["message"]["content"]
            .as_str()
            .unwrap();
        assert!(
            content.contains("john@example.com"),
            "Email should be restored, got: {content}"
        );
        assert!(
            !content.contains("[EMAIL_ADDRESS_"),
            "Token should not appear in restored content"
        );
    }

    #[test]
    fn test_restore_response_tool_calls() {
        let mut anonymizer = Anonymizer::new(0.0);
        let _ = anonymizer.anonymize_text("admin@secret.org");
        let token = anonymizer
            .mapping
            .mappings
            .keys()
            .find(|k| k.starts_with("[EMAIL_ADDRESS_"))
            .unwrap()
            .clone();
        let mapping = &anonymizer.mapping;

        let mut response = json!({
            "id": "chatcmpl-xyz789",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [
                            {
                                "id": "call_def456",
                                "type": "function",
                                "function": {
                                    "name": "send_email",
                                    "arguments": format!("{{\"to\": \"{token}\"}}")
                                }
                            }
                        ]
                    },
                    "finish_reason": "tool_calls"
                }
            ]
        });
        restore_response(&mut response, mapping);

        let args_str = response["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        assert!(
            args_str.contains("admin@secret.org"),
            "Email in tool call arguments should be restored, got: {args_str}"
        );
        assert!(
            !args_str.contains("[EMAIL_ADDRESS_"),
            "Token should not appear in restored arguments"
        );
    }

    #[test]
    fn test_restore_response_multiple_choices() {
        let mut anonymizer = Anonymizer::new(0.0);
        let _ = anonymizer.anonymize_text("user@test.com");
        let token = anonymizer
            .mapping
            .mappings
            .keys()
            .find(|k| k.starts_with("[EMAIL_ADDRESS_"))
            .unwrap()
            .clone();
        let mapping = &anonymizer.mapping;

        let mut response = json!({
            "id": "chatcmpl-multi",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": format!("First choice: {token}")
                    }
                },
                {
                    "index": 1,
                    "message": {
                        "role": "assistant",
                        "content": format!("Second choice also mentions {token}")
                    }
                }
            ]
        });
        restore_response(&mut response, mapping);

        let content0 = response["choices"][0]["message"]["content"]
            .as_str()
            .unwrap();
        let content1 = response["choices"][1]["message"]["content"]
            .as_str()
            .unwrap();

        assert!(
            content0.contains("user@test.com"),
            "First choice should be restored"
        );
        assert!(
            content1.contains("user@test.com"),
            "Second choice should be restored"
        );
    }

    #[test]
    fn test_restore_response_preserves_metadata() {
        let mapping = Mapping::new();

        let mut response = json!({
            "id": "chatcmpl-abc123",
            "object": "chat.completion",
            "created": 1677652288,
            "model": "gpt-4-turbo",
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 20,
                "total_tokens": 30
            },
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Hello!"
                    },
                    "finish_reason": "stop"
                }
            ]
        });
        restore_response(&mut response, &mapping);

        assert_eq!(response["id"], "chatcmpl-abc123");
        assert_eq!(response["object"], "chat.completion");
        assert_eq!(response["created"], 1677652288);
        assert_eq!(response["model"], "gpt-4-turbo");
        assert_eq!(response["usage"]["prompt_tokens"], 10);
        assert_eq!(response["choices"][0]["finish_reason"], "stop");
    }

    #[test]
    fn test_restore_response_null_content_handled() {
        let mapping = Mapping::new();

        let mut response = json!({
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": []
                    }
                }
            ]
        });

        // Should not panic on null content
        restore_response(&mut response, &mapping);
        assert!(response["choices"][0]["message"]["content"].is_null());
    }
}
