//! Global patterns for common PII types.
//!
//! Contains patterns for: EMAIL_ADDRESS, URL, IP_ADDRESS, PHONE_NUMBER, PHONE_EXTENSION,
//! IBAN_CODE, CREDIT_CARD, CRYPTO, MAC_ADDRESS, DATE_TIME, UUID, JOB_TITLE.

use super::PiiPattern;

pub const GLOBAL_PATTERNS: &[PiiPattern] = &[
    // ── Email ──
    PiiPattern {
        name: "email",
        entity_type: "EMAIL_ADDRESS",
        pattern: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    // ── URL ──
    PiiPattern {
        name: "url",
        entity_type: "URL",
        pattern: r#"https?://[^\s\)\]>"']+[^\s\)\]>"'.,;:!?]"#,
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    // ── International phone numbers (non-French) ──
    PiiPattern {
        name: "intl_phone",
        entity_type: "PHONE_NUMBER",
        // +<country_code> followed by 7-14 digits with optional separators and optional (area)
        // French +33 overlap is resolved by overlap resolution (FR_PHONE_NUMBER has higher score)
        pattern: r"\+[1-9]\d{0,2}\s?(?:\(\d{1,4}\)\s?)?(?:\d[\s.\-]?){6,14}\d",
        score: 0.6,
        context_keywords: &[
            "telephone",
            "tel",
            "phone",
            "mobile",
            "contact",
            "call",
            "number",
            "appeler",
            "numero",
            "portable",
            "whatsapp",
            "sms",
            "cell",
            "fax",
        ],
        context_required: true,
    },
    // ── Phone extension ──
    PiiPattern {
        name: "phone_extension",
        entity_type: "PHONE_EXTENSION",
        pattern: r"(?i)\b(?:poste|ext\.?|extension)\s+\d{3,5}\b",
        score: 0.85,
        context_keywords: &[],
        context_required: false,
    },
    // ── Generic IBAN (all countries) ──
    PiiPattern {
        name: "iban_generic",
        entity_type: "IBAN_CODE",
        // 2 uppercase country letters + 2 check digits + 11-30 alphanumeric BBAN
        // With optional spaces every 4 chars. Validated by mod-97 in detection pipeline.
        pattern: r"\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}(?:[\s]?[\dA-Z]{4}){2,7}(?:[\s]?[\dA-Z]{1,4})?\b",
        score: 0.7,
        context_keywords: &[
            "iban", "compte", "account", "virement", "bank", "banque", "bancaire", "transfer",
            "swift", "bic", "payment", "paiement",
        ],
        context_required: true,
    },
    // ── IP addresses ──
    PiiPattern {
        name: "ipv4",
        entity_type: "IP_ADDRESS",
        pattern: r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "ipv6",
        entity_type: "IP_ADDRESS",
        // Full (8 groups), collapsed (::), link-local (fe80::), loopback (::1),
        // IPv4-mapped (::ffff:192.168.1.1). Requires word boundary or :: at start.
        pattern: concat!(
            "(?i)",
            "(?:",
            r"\b[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){7}\b", // full 8-group
            r"|\b(?:[0-9a-f]{1,4}:){1,7}:",            // trailing ::
            r"|\b(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}\b", // 6+::1
            r"|\b(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}\b", // 5+::2
            r"|\b(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}\b", // 4+::3
            r"|\b(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}\b", // 3+::4
            r"|\b(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}\b", // 2+::5
            r"|\b[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}\b", // 1+::6
            r"|::(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}\b", // ::prefix
            r"|::(?:ffff:)?(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}", // ::ffff:IPv4
            r"(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])",
            ")",
        ),
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    // ── Date / Time ──
    PiiPattern {
        name: "date_iso8601",
        entity_type: "DATE_TIME",
        // 2024-01-15 optionally with Thh:mm:ss and timezone
        pattern: r"\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\b",
        score: 0.6,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "date_eu_slash",
        entity_type: "DATE_TIME",
        // dd/mm/yyyy or dd.mm.yyyy - ambiguous format, context-gated
        pattern: r"\b(?:0[1-9]|[12]\d|3[01])[/.](?:0[1-9]|1[0-2])[/.](?:19|20)\d{2}\b",
        score: 0.5,
        context_keywords: &[
            "date",
            "naissance",
            "birth",
            "born",
            "dob",
            "expir",
            "valid",
            "depart",
            "departure",
            "arrive",
            "arrival",
            "le",
            "du",
            "au",
            "issued",
            "delivre",
            "émis",
        ],
        context_required: true,
    },
    PiiPattern {
        name: "date_written_fr",
        entity_type: "DATE_TIME",
        // "15 janvier 2024" or "1er mars 2023"
        pattern: r"(?i)\b(?:0?[1-9]|[12]\d|3[01])(?:er)?\s+(?:janvier|février|fevrier|mars|avril|mai|juin|juillet|août|aout|septembre|octobre|novembre|décembre|decembre)\s+(?:19|20)\d{2}\b",
        score: 0.8,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "date_written_en",
        entity_type: "DATE_TIME",
        // "January 15, 2024" or "Jan 15 2024"
        pattern: r"(?i)\b(?:january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|oct|nov|dec)\.?\s+(?:0?[1-9]|[12]\d|3[01])(?:st|nd|rd|th)?,?\s+(?:19|20)\d{2}\b",
        score: 0.8,
        context_keywords: &[],
        context_required: false,
    },
    // ── MAC address ──
    PiiPattern {
        name: "mac_colon",
        entity_type: "MAC_ADDRESS",
        // aa:bb:cc:dd:ee:ff (colon-separated)
        pattern: r"(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b",
        score: 0.85,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "mac_hyphen",
        entity_type: "MAC_ADDRESS",
        // aa-bb-cc-dd-ee-ff (hyphen-separated)
        pattern: r"(?i)\b[0-9a-f]{2}(?:-[0-9a-f]{2}){5}\b",
        score: 0.85,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "mac_cisco",
        entity_type: "MAC_ADDRESS",
        // aabb.ccdd.eeff (Cisco dot notation)
        pattern: r"(?i)\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b",
        score: 0.85,
        context_keywords: &[],
        context_required: false,
    },
    // ── Credit card ──
    PiiPattern {
        name: "credit_card",
        entity_type: "CREDIT_CARD",
        pattern: r"\b(?:\d{4}[\s\-]?){3}\d{4}\b",
        score: 0.7,
        context_keywords: &[
            "card",
            "credit",
            "payment",
            "cc",
            "visa",
            "mastercard",
            "amex",
            "cb",
            "carte",
            "bancaire",
            "debit",
            "paiement",
        ],
        context_required: true,
    },
    // ── UUID ──
    PiiPattern {
        name: "uuid",
        entity_type: "UUID",
        pattern: r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        score: 0.95,
        context_keywords: &[],
        context_required: false,
    },
    // ── Cryptocurrency ──
    PiiPattern {
        name: "crypto_bitcoin",
        entity_type: "CRYPTO",
        pattern: r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "crypto_ethereum",
        entity_type: "CRYPTO",
        pattern: r"\b0x[0-9a-fA-F]{40}\b",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    // ── Job titles (signature blocks only) ──
    PiiPattern {
        name: "job_title_role",
        entity_type: "JOB_TITLE",
        pattern: r"(?i)\b(?:(?:senior|junior|lead|head|chief|deputy|associate|executive|managing|principal|full[- ]stack|front[- ]end|back[- ]end|devops|crew|flight|ground|cabin|operations|commercial|hr|it|software|data|product|project|quality|safety|security|training|maintenance|aviation|business|technical)\s+)+(?:director|manager|developer|engineer|officer|planner|planning|specialist|coordinator|architect|consultant|administrator|supervisor|pilot|instructor|examiner|dispatcher|controller)\b",
        score: 0.7,
        context_keywords: &[
            "example-air",
            "linkedin",
            "mobile",
            "tel",
            "amelia",
            "cordialement",
            "cdlt",
        ],
        context_required: true,
    },
    PiiPattern {
        name: "job_title_csuite",
        entity_type: "JOB_TITLE",
        pattern: r"\b(?:DSI|CIO|CEO|CFO|CTO|COO|CMO|CHRO|CPO|VP)\s*(?:/\s*(?:DSI|CIO|CEO|CFO|CTO|COO|CMO|CHRO|CPO|VP))*\b",
        score: 0.7,
        context_keywords: &[
            "example-air",
            "linkedin",
            "mobile",
            "tel",
            "amelia",
            "cordialement",
            "cdlt",
        ],
        context_required: true,
    },
];
