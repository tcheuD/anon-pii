use super::super::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

fn synthetic_secret(parts: &[&str]) -> String {
    parts.concat()
}

// -- SECRET_KEY tests --

#[test]
fn test_secret_key_stripe_underscore() {
    let mut a = Anonymizer::new(0.0);
    let key = synthetic_secret(&["sk", "_live_", "51N7xRgAv8bN2xT9mW5qJ7pL3kYz"]);
    let input = format!("STRIPE_SECRET = \"{key}\"");
    let (result, dets) = a.anonymize_text(&input);
    assert!(
        dets.iter().any(|d| d.entity_type == "SECRET_KEY"),
        "Stripe key with underscores should be detected.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("[SECRET_KEY_"));
}

#[test]
fn test_secret_key_stripe_dash() {
    let mut a = Anonymizer::new(0.0);
    let key = synthetic_secret(&["sk", "-live-", "Rg4v8bN2xT9mW5qJ7pL3kYz6hD1fA0cE8iU2wX"]);
    let input = format!("key = {key}");
    let (result, dets) = a.anonymize_text(&input);
    assert!(
        dets.iter().any(|d| d.entity_type == "SECRET_KEY"),
        "Stripe key with dashes should be detected.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("[SECRET_KEY_"));
}

#[test]
fn test_secret_key_github_pat() {
    let mut a = Anonymizer::new(0.0);
    let key = synthetic_secret(&["ghp", "_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"]);
    let input = format!("export GH_TOKEN={key}");
    let (result, dets) = a.anonymize_text(&input);
    assert!(
        dets.iter().any(|d| d.entity_type == "SECRET_KEY"),
        "GitHub PAT should be detected.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("[SECRET_KEY_"));
}

#[test]
fn test_secret_key_aws() {
    let mut a = Anonymizer::new(0.0);
    let key = synthetic_secret(&["AKIA", "IOSFODNN7", "EXAMPLE"]);
    let input = format!("aws_access_key_id = {key}");
    let (result, dets) = a.anonymize_text(&input);
    assert!(
        dets.iter().any(|d| d.entity_type == "SECRET_KEY"),
        "AWS access key should be detected.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("[SECRET_KEY_"));
}

#[test]
fn test_secret_key_slack() {
    let mut a = Anonymizer::new(0.0);
    let key = synthetic_secret(&["xox", "b-", "1234567890-abcdefghij"]);
    let input = format!("SLACK_TOKEN={key}");
    let (result, dets) = a.anonymize_text(&input);
    assert!(
        dets.iter().any(|d| d.entity_type == "SECRET_KEY"),
        "Slack bot token should be detected.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("[SECRET_KEY_"));
}

#[test]
fn test_secret_key_openai() {
    let mut a = Anonymizer::new(0.0);
    let key = synthetic_secret(&[
        "sk",
        "-proj-",
        "abc123def456ghi789jkl012mno345pqr678stu901vwx",
    ]);
    let input = format!("OPENAI_API_KEY={key}");
    let (result, dets) = a.anonymize_text(&input);
    assert!(
        dets.iter().any(|d| d.entity_type == "SECRET_KEY"),
        "OpenAI key should be detected.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("[SECRET_KEY_"));
}

#[test]
fn test_secret_key_private_key_header() {
    let mut a = Anonymizer::new(0.0);
    let input = synthetic_secret(&["-----BEGIN ", "RSA ", "PRIVATE KEY-----"]);
    let (result, dets) = a.anonymize_text(&input);
    assert!(
        dets.iter().any(|d| d.entity_type == "SECRET_KEY"),
        "PEM private key header should be detected.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("[SECRET_KEY_"));
}

#[test]
fn test_secret_key_private_key_header_generic() {
    let mut a = Anonymizer::new(0.0);
    let input = synthetic_secret(&["-----BEGIN ", "PRIVATE ", "KEY-----"]);
    let (result, dets) = a.anonymize_text(&input);
    assert!(
        dets.iter().any(|d| d.entity_type == "SECRET_KEY"),
        "Generic PEM private key header should be detected.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("[SECRET_KEY_"));
}

#[test]
fn test_secret_key_short_not_detected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("prefix sk-live-abc");
    assert!(
        !dets
            .iter()
            .any(|d| d.entity_type == "SECRET_KEY" && d.original.contains("sk-live-abc")),
        "Short key-like strings should not be detected as SECRET_KEY.\nDetections: {:?}",
        dets
    );
}

// -- CONNECTION_STRING tests --

#[test]
fn test_connection_string_postgresql() {
    let mut a = Anonymizer::new(0.0);
    let input =
        r#"DATABASE_URL = "postgresql://admin:F1eet$ecret2024@db.internal:5432/fleet_prod""#;
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "CONNECTION_STRING"),
        "PostgreSQL connection string should be detected.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("[CONNECTION_STRING_"));
}

#[test]
fn test_connection_string_redis() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("REDIS_URL=redis://:password@cache.internal:6379/0");
    assert!(
        dets.iter().any(|d| d.entity_type == "CONNECTION_STRING"),
        "Redis connection string should be detected.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("[CONNECTION_STRING_"));
}

#[test]
fn test_connection_string_mongodb_srv() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text(
        "MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/mydb?retryWrites=true",
    );
    assert!(
        dets.iter().any(|d| d.entity_type == "CONNECTION_STRING"),
        "MongoDB+SRV connection string should be detected.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("[CONNECTION_STRING_"));
}

#[test]
fn test_connection_string_mysql() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("mysql://root:s3cret@localhost:3306/app_db");
    assert!(
        dets.iter().any(|d| d.entity_type == "CONNECTION_STRING"),
        "MySQL connection string should be detected.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("[CONNECTION_STRING_"));
}

// -- PASSWORD tests --

#[test]
fn test_password_quoted() {
    let mut a = Anonymizer::new(0.0);
    let input = r#"SMTP_PASSWORD = "Sm7p!M4il2024""#;
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "PASSWORD"),
        "Quoted password assignment should be detected.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("[PASSWORD_"));
}

#[test]
fn test_password_single_quoted() {
    let mut a = Anonymizer::new(0.0);
    let input = "secret_key = 'MyS3cretV4lue!!'";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "PASSWORD"),
        "Single-quoted secret assignment should be detected.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("[PASSWORD_"));
}

#[test]
fn test_password_env_unquoted() {
    let mut a = Anonymizer::new(0.0);
    let input = "DB_PASSWORD=F1eet$ecret2024";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "PASSWORD"),
        "Unquoted env-file password should be detected.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("[PASSWORD_"));
}

#[test]
fn test_password_json_style() {
    let mut a = Anonymizer::new(0.0);
    let input = r#""password": "MyS3cretP4ssword!""#;
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "PASSWORD"),
        "JSON-style password should be detected.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("[PASSWORD_"));
}

#[test]
fn test_password_short_value_not_detected() {
    let mut a = Anonymizer::new(0.0);
    let input = r#"password = "short""#;
    let (_, dets) = a.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "PASSWORD"),
        "Short password values (<8 chars) should not be detected.\nDetections: {:?}",
        dets
    );
}

#[test]
fn test_password_no_keyword_not_detected() {
    let mut a = Anonymizer::new(0.0);
    let input = r#"username = "johndoe12345""#;
    let (_, dets) = a.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "PASSWORD"),
        "Non-password keyword assignments should not be detected.\nDetections: {:?}",
        dets
    );
}

#[test]
fn test_password_prefixed_keyword() {
    let mut a = Anonymizer::new(0.0);
    let input = r#"MY_APP_SECRET = "longEnoughSecretValue""#;
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "PASSWORD"),
        "Prefixed secret keyword should be detected.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("[PASSWORD_"));
}

#[test]
fn test_password_containing_detected_fragments_is_masked_completely() {
    let key = synthetic_secret(&["ghp", "_", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]);
    let jwt = synthetic_secret(&["eyJhbGciOiJub25lIn0", ".", "eyJzdWIiOiJleGFtcGxlIn0"]);
    for assignment in [
        r#"password="private-prefix ada@example.invalid private-suffix""#.to_string(),
        "pwd='private-prefix 192.0.2.20 private-suffix'".to_string(),
        "DB_PASSWORD=private-prefix192.0.2.20private-suffix".to_string(),
        format!("secret=\"private-prefix {key} private-suffix\""),
        format!("token=\" {jwt} \""),
        // '&' can be part of a credential: do not assume a query delimiter.
        format!("token={jwt}&cc_last4=4242"),
    ] {
        let prefix = "Échec 📨 — ";
        let suffix = "\nplease investigate.";
        let input = format!("{prefix}{assignment}{suffix}");
        let mut a = Anonymizer::new(0.5);
        let (output, detections) = a.anonymize_text(&input);
        assert_eq!(detections.len(), 1, "{assignment}: {detections:?}");
        let detection = &detections[0];
        assert_eq!(detection.entity_type, "PASSWORD", "{assignment}");
        assert_eq!(detection.original, assignment);
        assert_eq!(detection.start, prefix.len());
        assert_eq!(detection.end, prefix.len() + assignment.len());
        let token = a.mapping.mappings.keys().next().unwrap();
        assert_eq!(output, format!("{prefix}{token}{suffix}"));
        assert_eq!(a.mapping.restore_bracketed(&output), input);
    }
}

#[test]
fn test_password_normalized_assignment_syntax_keeps_complete_masking() {
    for assignment in [
        "password%3Dada@example.invalid",
        "password＝ada@example.invalid",
        "password=%22ada@example.invalid%22",
        "password%3Dprivate-prefix:ada@example.invalid",
        "password＝private-prefix:ada@example.invalid",
        r"password\u003Dprivate-prefix:ada@example.invalid",
        "password%3Dprivate-prefix=ada@example.invalid",
    ] {
        let mut a = Anonymizer::new(0.5);
        let (output, detections) = a.anonymize_text(assignment);
        assert_eq!(detections.len(), 1, "{assignment}: {detections:?}");
        assert_eq!(detections[0].entity_type, "PASSWORD", "{assignment}");
        assert_eq!(detections[0].original, assignment);
        let token = a.mapping.mappings.keys().next().unwrap();
        assert_eq!(&output, token, "{assignment}");
        assert_eq!(a.mapping.restore_bracketed(&output), assignment);
    }
}

#[test]
fn test_password_complete_value_keeps_specific_detection() {
    let key = synthetic_secret(&["ghp", "_", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]);
    let jwt = synthetic_secret(&["eyJhbGciOiJub25lIn0", ".", "eyJzdWIiOiJleGFtcGxlIn0"]);
    for (value, entity_type) in [
        (key.as_str(), "SECRET_KEY"),
        (jwt.as_str(), "AUTH_TOKEN"),
        ("ada@example.invalid", "EMAIL_ADDRESS"),
    ] {
        for (prefix, suffix) in [("token=", ""), ("secret = '", "'"), ("password=\"", "\"")] {
            let input = format!("{prefix}{value}{suffix}");
            let mut a = Anonymizer::new(0.5);
            let (output, detections) = a.anonymize_text(&input);
            assert_eq!(detections.len(), 1, "{input}: {detections:?}");
            let detection = &detections[0];
            assert_eq!(detection.entity_type, entity_type, "{input}");
            assert_eq!(detection.original, value);
            assert_eq!(detection.start, prefix.len());
            assert_eq!(detection.end, prefix.len() + value.len());
            let token = a.mapping.mappings.keys().next().unwrap();
            assert_eq!(output, format!("{prefix}{token}{suffix}"));
            assert_eq!(a.mapping.restore_bracketed(&output), input);
        }
    }
}

// -- AUTH_TOKEN (JWT) tests --

#[test]
fn test_jwt_three_segments_detected() {
    let mut a = Anonymizer::new(0.0);
    let jwt = synthetic_secret(&[
        "eyJhbGciOiJIUzI1NiJ9",
        ".",
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        ".",
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ]);
    let input = format!("Authorization: Bearer {jwt}");
    let (result, dets) = a.anonymize_text(&input);
    assert!(
        dets.iter().any(|d| d.entity_type == "AUTH_TOKEN"),
        "JWT with 3 segments should be detected: {:?}",
        dets
    );
    assert!(result.contains("[AUTH_TOKEN_"));
}

#[test]
fn test_jwt_two_segments_detected() {
    let mut a = Anonymizer::new(0.0);
    // JWT without signature (2 segments), covering the complete assigned value.
    let jwt = synthetic_secret(&[
        "eyJhbGciOiJIUzI1NiJ9",
        ".",
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0",
    ]);
    let input = format!("token={jwt}");
    let (result, dets) = a.anonymize_text(&input);
    assert!(
        dets.iter().any(|d| d.entity_type == "AUTH_TOKEN"),
        "JWT with 2 segments should be detected: {:?}",
        dets
    );
    assert!(result.contains("[AUTH_TOKEN_"));
}

#[test]
fn test_jwt_not_detected_single_segment() {
    let mut a = Anonymizer::new(0.0);
    // Only 1 segment — not a JWT
    let (_, dets) = a.anonymize_text("version=eyJub3QiOiJhIHRva2VuIn0");
    assert!(
        !dets.iter().any(|d| d.entity_type == "AUTH_TOKEN"),
        "Single base64 segment should not be detected as JWT"
    );
}

#[test]
fn test_jwt_not_detected_short_segments() {
    let mut a = Anonymizer::new(0.0);
    // Segments too short (< 10 chars each)
    let (_, dets) = a.anonymize_text("file.name.extension");
    assert!(
        !dets.iter().any(|d| d.entity_type == "AUTH_TOKEN"),
        "Short dot-separated words should not be detected as JWT"
    );
}

#[test]
fn test_basic_auth_preserves_header_and_exact_encoded_source_spans() {
    let encoded = STANDARD.encode(b"debug:example-password");
    for value in [
        encoded.clone(),
        encoded.trim_end_matches('=').to_string(),
        encoded.replace('=', "%3D"),
        encoded.replace('=', r"\u003D"),
        STANDARD.encode(b":"),
        STANDARD.encode(b"debug:"),
        STANDARD.encode(b":example-password"),
        STANDARD.encode(b"debug:example:password"),
        STANDARD.encode("utilisateur:exemple-é".as_bytes()),
        STANDARD.encode([0xfb, b':', 0xff]),
    ] {
        for prefix in [
            "Authorization: Basic ",
            "Proxy-Authorization: bAsIc\t  ",
            "🧪 request header=\"Basic ",
        ] {
            let input = format!("{prefix}{value}\"\r\n");
            let mut a = Anonymizer::new(0.5);
            let (result, detections) = a.anonymize_text(&input);
            assert_eq!(detections.len(), 1, "{input:?}: {detections:?}");
            let detected = &detections[0];
            assert_eq!(detected.entity_type, "AUTH_TOKEN");
            assert_eq!(detected.original, value);
            assert_eq!(detected.start, prefix.len());
            assert_eq!(detected.end, prefix.len() + value.len());
            assert_eq!(&input[detected.start..detected.end], value);
            assert!(result.starts_with(&format!("{prefix}[AUTH_TOKEN_")));
            assert!(result.ends_with("]\"\r\n"));
            assert_eq!(a.mapping.restore_bracketed(&result), input);
        }
    }
}

#[test]
fn test_basic_auth_rejects_prose_missing_scheme_and_invalid_credentials() {
    let credential = STANDARD.encode(b"debug:example-password");
    let inputs = [
        "Basic authentication is supported".to_string(),
        "WWW-Authenticate: Basic realm=\"example\"".to_string(),
        format!("Authorization: Bearer {credential}"),
        format!("MyBasic {credential}"),
        format!("Basic\n{credential}"),
        credential.clone(),
        format!("Basic {}", STANDARD.encode(b"not-a-credential")),
        format!("Basic {}", STANDARD.encode(b"debug:example\npassword")),
        format!("Basic {}", STANDARD.encode(b"debug:\0example")),
        format!("Basic {credential}EXTRA"),
        format!("Basic {credential}_suffix"),
        format!("Basic {credential}-suffix"),
        format!("Basic {credential}=="),
        "Basic Oh==".to_string(), // Non-canonical trailing bits for ':'.
        "Basic Og=".to_string(),  // Incorrect padding.
    ];
    let mut a = Anonymizer::new(0.0);
    for input in inputs {
        let (output, detections) = a.anonymize_text(&input);
        assert!(detections.is_empty(), "{input:?}: {detections:?}");
        assert_eq!(output, input);
    }
}

#[test]
fn test_basic_auth_respects_threshold_and_reuses_tokens() {
    let credential = STANDARD.encode(b"debug:example-password");
    let input = format!("Basic {credential}\nBasic {credential}");
    let mut a = Anonymizer::new(0.95);
    let (output, detections) = a.anonymize_text(&input);
    assert_eq!(detections.len(), 2);
    assert_eq!(a.mapping.mappings.len(), 1);
    assert_eq!(a.mapping.restore_bracketed(&output), input);

    let mut a = Anonymizer::new(0.96);
    let (output, detections) = a.anonymize_text(&input);
    assert!(detections.is_empty());
    assert_eq!(output, input);
}

#[test]
fn test_basic_auth_in_structured_values_roundtrips() {
    let credential = STANDARD.encode(b"debug:example-password");
    let mut a = Anonymizer::new(0.5);
    let input = serde_json::json!({"Authorization": format!("Basic {credential}"), "count": 42});
    let (output, detections) = a.anonymize_json_value(&input);
    assert_eq!(detections.len(), 1);
    assert!(
        output["Authorization"]
            .as_str()
            .unwrap()
            .starts_with("Basic [AUTH_TOKEN_")
    );
    let restored = a.mapping.restore_bracketed(&output.to_string());
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&restored).unwrap(),
        input
    );

    for (format, input) in [
        ("csv", format!("header\r\n\"Basic {credential}\"\r\n")),
        ("sql", format!("SELECT 'Basic {credential}' AS auth;")),
    ] {
        let (output, detections) = if format == "csv" {
            a.anonymize_csv(&input)
        } else {
            a.anonymize_sql(&input)
        };
        assert_eq!(detections.len(), 1);
        assert!(!output.contains(&credential));
        assert!(output.contains("Basic [AUTH_TOKEN_"));
        assert_eq!(a.mapping.restore_bracketed(&output), input);
    }
}
