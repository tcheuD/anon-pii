use super::super::*;

// -- SECRET_KEY tests --

#[test]
fn test_secret_key_stripe_underscore() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) =
        a.anonymize_text("STRIPE_SECRET = \"sk_live_51N7xRgAv8bN2xT9mW5qJ7pL3kYz\"");
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
    let (result, dets) = a.anonymize_text("key = sk-live-Rg4v8bN2xT9mW5qJ7pL3kYz6hD1fA0cE8iU2wX");
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
    let (result, dets) =
        a.anonymize_text("export GH_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn");
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
    let (result, dets) = a.anonymize_text("aws_access_key_id = AKIAIOSFODNN7EXAMPLE");
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
    let (result, dets) = a.anonymize_text("SLACK_TOKEN=xoxb-1234567890-abcdefghij");
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
    let (result, dets) =
        a.anonymize_text("OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx");
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
    let (result, dets) = a.anonymize_text("-----BEGIN RSA PRIVATE KEY-----");
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
    let (result, dets) = a.anonymize_text("-----BEGIN PRIVATE KEY-----");
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

// -- AUTH_TOKEN (JWT) tests --

#[test]
fn test_jwt_three_segments_detected() {
    let mut a = Anonymizer::new(0.0);
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
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
    // JWT without signature (2 segments) — common in URL params
    let input = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0&cc_last4=4242";
    let (result, dets) = a.anonymize_text(input);
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
