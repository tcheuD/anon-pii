//! Secret and credential patterns.
//!
//! Contains patterns for: AUTH_TOKEN, SECRET_KEY, CONNECTION_STRING, PASSWORD.

use super::PiiPattern;

pub const SECRETS_PATTERNS: &[PiiPattern] = &[
    // ── JWT / Auth tokens ──
    PiiPattern {
        name: "jwt",
        entity_type: "AUTH_TOKEN",
        pattern: r"eyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,}){1,2}",
        score: 0.95,
        context_keywords: &[
            "token",
            "bearer",
            "authorization",
            "auth",
            "jwt",
            "session",
            "cookie",
        ],
        context_required: false,
    },
    // ── Secret keys (API keys, tokens with well-known prefixes) ──
    PiiPattern {
        name: "secret_key_stripe",
        entity_type: "SECRET_KEY",
        // Stripe: sk_live_xxx, sk-live-xxx, pk_test_xxx, rk_live_xxx
        pattern: r"\b(?:sk|pk|rk)[-_](?:live|test)[-_][A-Za-z0-9_\-]{10,}",
        score: 0.95,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "secret_key_openai",
        entity_type: "SECRET_KEY",
        // OpenAI: sk-proj-xxx, sk-svcacct-xxx, or older sk-xxxxxxx (20+ chars)
        pattern: r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}",
        score: 0.95,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "secret_key_github",
        entity_type: "SECRET_KEY",
        // GitHub: ghp_ (PAT), gho_ (OAuth), ghu_ (user-to-server), ghs_ (server-to-server), ghr_ (refresh)
        pattern: r"\bgh[pousr]_[A-Za-z0-9]{36,}",
        score: 0.95,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "secret_key_aws",
        entity_type: "SECRET_KEY",
        // AWS access key ID: AKIA + 16 uppercase alphanumeric chars
        pattern: r"\bAKIA[0-9A-Z]{16}\b",
        score: 0.95,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "secret_key_slack",
        entity_type: "SECRET_KEY",
        // Slack: xoxb- (bot), xoxp- (user), xoxa- (app), xoxs- (session)
        pattern: r"\bxox[bpas]-[A-Za-z0-9\-]{10,}",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "secret_key_private_key_header",
        entity_type: "SECRET_KEY",
        // PEM private key headers
        pattern: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        score: 0.95,
        context_keywords: &[],
        context_required: false,
    },
    // ── Connection strings (database/broker URLs with credentials) ──
    PiiPattern {
        name: "connection_string",
        entity_type: "CONNECTION_STRING",
        pattern: r#"(?i)\b(?:postgresql|postgres|mysql|mariadb|redis|rediss|mongodb|mongodb\+srv|amqp|amqps|mssql)://[^\s"'<>]+[^\s"'<>.,;:!?)]"#,
        score: 0.95,
        context_keywords: &[],
        context_required: false,
    },
    // ── Passwords (in variable assignments) ──
    PiiPattern {
        name: "password_quoted",
        entity_type: "PASSWORD",
        // keyword = "value" or keyword: "value" (quoted, 8+ chars)
        pattern: r#"(?i)\b(?:[A-Za-z0-9]+[-_]){0,10}(?:password|passwd|pwd|secret(?:_?key)?|token|api_?key|auth_?token|access_?token|private_?key|client_?secret|app_?secret)\b["']?\s*[=:]\s*["'][^"'\n]{8,}["']"#,
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "password_env",
        entity_type: "PASSWORD",
        // Unquoted env-file style: PASSWORD=value (8+ non-whitespace chars)
        pattern: r#"(?i)\b(?:[A-Za-z0-9]+[-_]){0,10}(?:password|passwd|pwd|secret(?:_?key)?|token|api_?key|auth_?token|access_?token|private_?key|client_?secret|app_?secret)\b\s*=\s*[^\s"']{8,}"#,
        score: 0.85,
        context_keywords: &[],
        context_required: false,
    },
];
