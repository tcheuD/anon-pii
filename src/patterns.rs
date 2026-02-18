pub struct PiiPattern {
    pub name: &'static str,
    pub entity_type: &'static str,
    pub pattern: &'static str,
    pub score: f64,
    pub context_keywords: &'static [&'static str],
    /// If true, context keywords are required (no keyword = no match).
    /// If false and context_keywords is non-empty, keywords boost the score.
    pub context_required: bool,
}

pub const PATTERNS: &[PiiPattern] = &[
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
    // ── French phone numbers ──
    PiiPattern {
        name: "fr_phone_intl",
        entity_type: "FR_PHONE_NUMBER",
        pattern: r"\+33\s?[1-9](?:[\s.\-]?\d{2}){4}",
        score: 0.9,
        context_keywords: &[
            "telephone",
            "tel",
            "phone",
            "mobile",
            "contact",
            "appeler",
            "numero",
            "portable",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_phone_intl_0033",
        entity_type: "FR_PHONE_NUMBER",
        pattern: r"\b0033\s?[1-9](?:[\s.\-]?\d{2}){4}",
        score: 0.9,
        context_keywords: &[
            "telephone",
            "tel",
            "phone",
            "mobile",
            "contact",
            "appeler",
            "numero",
            "portable",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_phone_national",
        entity_type: "FR_PHONE_NUMBER",
        pattern: r"\b0[1-9](?:[\s.\-]?\d{2}){4}\b",
        score: 0.7,
        context_keywords: &[
            "telephone",
            "tel",
            "phone",
            "mobile",
            "contact",
            "appeler",
            "numero",
            "portable",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_phone_compact",
        entity_type: "FR_PHONE_NUMBER",
        pattern: r"\b0[1-9]\d{8}\b",
        score: 0.6,
        context_keywords: &[
            "telephone",
            "tel",
            "phone",
            "mobile",
            "contact",
            "appeler",
            "numero",
            "portable",
        ],
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
    // ── French IBAN ──
    PiiPattern {
        name: "fr_iban",
        entity_type: "FR_IBAN",
        pattern: r"FR\d{2}[\s]?(?:\d{4}[\s]?){5}\d{3}",
        score: 0.95,
        context_keywords: &[
            "iban", "compte", "account", "virement", "bank", "banque", "bancaire",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_iban_compact",
        entity_type: "FR_IBAN",
        pattern: r"FR\d{25}",
        score: 0.9,
        context_keywords: &[
            "iban", "compte", "account", "virement", "bank", "banque", "bancaire",
        ],
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
    // ── French SSN (NIR) ──
    PiiPattern {
        name: "fr_ssn",
        entity_type: "FR_SSN",
        pattern: r"[12]\s?\d{2}\s?(?:0[1-9]|1[0-2]|[2-9]\d)\s?(?:\d{2}|2[AB])\s?\d{3}\s?\d{3}(?:\s?\d{2})?",
        score: 0.85,
        context_keywords: &[
            "secu",
            "securite sociale",
            "ssn",
            "nir",
            "carte vitale",
            "numero",
            "immatriculation",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_ssn_compact",
        entity_type: "FR_SSN",
        pattern: r"[12]\d{2}(?:0[1-9]|1[0-2]|[2-9]\d)(?:\d{2}|2[AB])\d{6}(?:\d{2})?",
        score: 0.8,
        context_keywords: &[
            "secu",
            "securite sociale",
            "ssn",
            "nir",
            "carte vitale",
            "numero",
            "immatriculation",
        ],
        context_required: false,
    },
    // ── US Social Security Number ──
    PiiPattern {
        name: "us_ssn_dash",
        entity_type: "US_SSN",
        // 123-45-6789 format. Validated in detection pipeline for invalid prefixes/groups.
        pattern: r"\b\d{3}-\d{2}-\d{4}\b",
        score: 0.7,
        context_keywords: &["ssn", "social security", "social", "security number", "tax"],
        context_required: true,
    },
    PiiPattern {
        name: "us_ssn_space",
        entity_type: "US_SSN",
        pattern: r"\b\d{3}\s\d{2}\s\d{4}\b",
        score: 0.65,
        context_keywords: &["ssn", "social security", "social", "security number", "tax"],
        context_required: true,
    },
    // ── Medical License ──
    PiiPattern {
        name: "medical_license",
        entity_type: "MEDICAL_LICENSE",
        // Common format: 1-2 letters + 6-10 digits (e.g. ME12345678, D1234567)
        pattern: r"\b[A-Z]{1,2}\d{6,10}\b",
        score: 0.6,
        context_keywords: &[
            "medical",
            "license",
            "licence",
            "physician",
            "doctor",
            "dea",
            "npi",
            "practitioner",
            "provider",
            "prescriber",
        ],
        context_required: true,
    },
    // ── French passport ──
    PiiPattern {
        name: "fr_passport",
        entity_type: "FR_PASSPORT",
        pattern: r"\b\d{2}[A-Z]{2}\d{5}\b",
        score: 0.7,
        context_keywords: &["passeport", "passport", "document", "identite", "identité"],
        context_required: true,
    },
    // ── Aircraft registration ──
    PiiPattern {
        name: "aircraft_fr",
        entity_type: "AIRCRAFT_REGISTRATION",
        pattern: r"\bF-[A-Z]{4}\b",
        score: 0.95,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "aircraft_eu",
        entity_type: "AIRCRAFT_REGISTRATION",
        pattern: r"\b(?:D|G|I|EC|HB|OO|PH|OE|SE|LN|OH|CS|EI|9H)-[A-Z]{3,4}\b",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "aircraft_us",
        entity_type: "AIRCRAFT_REGISTRATION",
        pattern: r"\bN[1-9][0-9]{0,4}[A-Z]{0,2}\b",
        score: 0.85,
        context_keywords: &[
            "aircraft",
            "avion",
            "registration",
            "immat",
            "appareil",
            "tail",
            "immatriculation",
        ],
        context_required: true,
    },
    // ── Employee matricule ──
    PiiPattern {
        name: "employee_matricule",
        entity_type: "EMPLOYEE_ID",
        pattern: r"\b[A-Z]{2,3}-\d{3,5}\b",
        score: 0.7,
        context_keywords: &[
            "matricule",
            "employee",
            "employé",
            "employée",
            "badge",
            "agent",
            "personnel",
            "capitaine",
            "copilote",
            "pilote",
            "commandant",
            "officier",
        ],
        context_required: true,
    },
    // ── Flight numbers ──
    PiiPattern {
        name: "flight_amelia",
        entity_type: "FLIGHT_NUMBER",
        pattern: r"\b(?:IZM|RLA|AME|AML|GJT|AF)-?[0-9]{1,4}\b",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "flight_iata",
        entity_type: "FLIGHT_NUMBER",
        pattern: r"\b[A-Z]{2}-?[0-9]{1,4}\b",
        score: 0.4,
        context_keywords: &[
            "flight",
            "vol",
            "departure",
            "arrival",
            "schedule",
            "rotation",
            "leg",
            "sector",
        ],
        context_required: true,
    },
    PiiPattern {
        name: "flight_icao",
        entity_type: "FLIGHT_NUMBER",
        pattern: r"\b[A-Z]{3}-?[0-9]{1,4}\b",
        score: 0.5,
        context_keywords: &[
            "flight",
            "vol",
            "departure",
            "arrival",
            "schedule",
            "rotation",
            "leg",
            "sector",
        ],
        context_required: true,
    },
    // ── Crew codes ──
    PiiPattern {
        name: "crew_code",
        entity_type: "CREW_CODE",
        pattern: r"\b[A-Z]{3}\b",
        score: 0.85,
        context_keywords: &[
            "crew",
            "equipage",
            "équipage",
            "pilot",
            "pilote",
            "captain",
            "cdb",
            "commandant",
            "copilot",
            "copilote",
            "opl",
            "cabin",
            "pnc",
            "pnt",
            "steward",
            "hostess",
            "hôtesse",
            "hotesse",
            "first officer",
            "fo",
            "member",
            "membre",
            "roster",
            "planning",
            "duty",
            "service",
            "login",
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
        // dd/mm/yyyy or dd.mm.yyyy — ambiguous format, context-gated
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

pub const CREW_CODE_BLOCKLIST: &[&str] = &[
    // Common English words
    "THE", "AND", "FOR", "NOT", "YOU", "ALL", "CAN", "HAD", "HER", "WAS", "ONE", "OUR", "OUT",
    "ARE", "BUT", "HIS", "HAS", "NEW", "NOW", "OLD", "SEE", "WAY", "WHO", "BOY", "DID", "GET",
    "LET", "PUT", "SAY", "SHE", "TOO", "USE", "DAY", "MAN", "END", "MAY", "SET", "TRY", "ASK",
    "BIG", "ADD", "RUN", "OWN", "ANY", "AGO", "FEW", "GOT", "TOP", "YET", "RED", "HOW", "ITS",
    "OUR", "TWO", "FAR", "YES", "RAW", "LOW", "CUT", "FIT", "RAN", "AGE", "AIR", "BAD", "BAR",
    "BED", "BIT", "BOX", "BUS", "CAR", "CUP", "DOG", "EAR", "EAT", "EGG", "EYE", "FLY", "GAS",
    "GUN", "HAT", "HIT", "HOT", "ICE", "JOB", "KEY", "LAW", "LAY", "LEG", "LIE", "LOT", "MAP",
    "MIX", "NET", "NOR", "NUT", "ODD", "OIL", "PAY", "PEN", "PIG", "PIN", "POT", "ROW", "RUB",
    "SAD", "SAT", "SEA", "SIT", "SIX", "SKI", "SKY", "SON", "SUN", "TEN", "TIE", "TIN", "TON",
    "WAR", "WAS", "WET", "WIN", "WON", "YEA", // Tech / IT abbreviations
    "URL", "API", "CSS", "DNS", "FTP", "GPS", "GUI", "IDE", "PDF", "PHP", "RAM", "ROM", "SDK",
    "SQL", "SSH", "SSL", "TCP", "UDP", "USB", "VPN", "XML", "ZIP", "CSV", "DOM", "GIT", "HEX",
    "IMG", "INT", "JAR", "LOG", "MAC", "NAT", "ORM", "PEM", "PKI", "PNG", "POP", "RPM", "SCP",
    "SVG", "SVN", "TLS", "TTL", "TTY", "VIM", "WAP", "WWW", "XSS", "YML", "CLI",
    // Security / data abbreviations
    "PII", "SSN", "DOB", "DOC", "REF", "KYC", "MFA", "OTP", "PIN",
    // Logging / system terms
    "ERR", "MSG", "SRC", "ENV", "VAR", "VAL", "COL", "TMP", "BIN", "LIB", "OBJ", "CMD", "BAT",
    "EXE", "DLL", "SYS", "EOF", "NUL", "NIL", "MAX", "MIN", "AVG", "SUM", "CNT", "LEN", "IDX",
    "ACK", "NAK", "SYN", "FIN", "RST", "DEV", "OPS", "QPS", "RPS", "SLA", "CPU",
    // Common placeholder / generic abbreviations
    "XYZ", "ABC", "DEF", "QRS", "FOO", "BAZ", "TBD", "ETC", "FYI", "DIY", "FAQ", "CEO", "CFO",
    "CTO", "COO", "EVP", "SVP",
    // IATA airport codes (major hubs likely in aviation logs)
    "JFK", "LAX", "CDG", "ORY", "LHR", "AMS", "FRA", "BCN", "MAD", "MUC", "FCO", "ZRH", "BRU",
    "LIS", "OSL", "ARN", "CPH", "HEL", "WAW", "PRG", "VIE", "ATH", "IST", "DXB", "SIN", "HKG",
    "NRT", "ICN", "PEK", "SYD", "YYZ", "YUL", "GRU", "EZE", "SCL", "BOG", "MIA", "ATL", "ORD",
    "DFW", "DEN", "SFO", "SEA", "BOS", "IAD", "EWR", "MSP", "DTW", "PHX", "CLT", "TPA", "MCO",
    "SAN", "PDX", "BNA", "AUS", "RDU", "BWI", "DCA", "PHL", "STL", "MCI", "OAK", "SJC", "SMF",
    "LGA", "MDW", "DAL", "HOU", "FLL", "RSW", "PBI", "JAX", "BUF", "PIT", "CLE", "CMH", "IND",
    "MKE", "OMA", "MEM", "BHM", "SAT", "MSY", "TUS", "ABQ", "SDF", "OKC", "BOI", "GEG", "BHX",
    "MAN", "EDI", "GLA", "DUB", "NCE", "LYS", "TLS", "MRS", "BOD", "NTE", "MPL", "BIQ", "RNS",
    // Amelia / aviation operations (not crew members)
    "VOL", "VIA", "PAX", "ETA", "ETD", "UTC", "GMT", "AOG", "MEL", "CDM", "IZM", "RLA", "AME",
    "AML", "GJT", "OPS", "ATC", "VFR", "IFR", "ILS", "VOR", "DME", "NDB", "RWY", "TWR", "APP",
    "DEP", "ARR", "SID", "TAF", "QNH", "MSL", "AGL", "TAS", "CAS", "IAS", "HDG", "FPL", "NOC",
    "SAF", "MEL", "CDL", "STD", "STA", "ATD", "ATA", "OFP", "APU",
    // Duty/schedule status codes
    "OFF", "RST", // Common French abbreviations
    "STP", "SVP", "RDV",
];

pub const CONTEXT_WINDOW: usize = 80;
pub const CONTEXT_SCORE_BOOST: f64 = 0.15;
pub const MAX_INPUT_SIZE: u64 = 50 * 1024 * 1024; // 50 MB

/// Validate US SSN: reject invalid area numbers (000, 666, 900-999),
/// zero middle group (00), and zero serial group (0000).
pub fn valid_us_ssn(ssn: &str) -> bool {
    let digits: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 9 {
        return false;
    }
    let area: u32 = digits[0..3].parse().unwrap_or(0);
    let group: u32 = digits[3..5].parse().unwrap_or(0);
    let serial: u32 = digits[5..9].parse().unwrap_or(0);
    // Area 000, 666, 900-999 are invalid
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }
    if group == 0 || serial == 0 {
        return false;
    }
    true
}

/// Reject broadcast (ff:ff:ff:ff:ff:ff) and null (00:00:00:00:00:00) MAC addresses.
pub fn valid_mac(mac: &str) -> bool {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase();
    hex.len() == 12 && hex != "000000000000" && hex != "ffffffffffff"
}

/// IBAN mod-97 validation (ISO 7064).
/// Move first 4 chars to end, convert letters (A=10..Z=35), compute mod 97 == 1.
pub fn iban_mod97(iban: &str) -> bool {
    let clean: String = iban.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if clean.len() < 5 {
        return false;
    }
    // Rearrange: move first 4 chars to end
    let rearranged = format!("{}{}", &clean[4..], &clean[..4]);
    // Convert to digit string: letters become two-digit numbers (A=10..Z=35)
    let mut digits = String::with_capacity(rearranged.len() * 2);
    for c in rearranged.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else {
            let val = (c.to_ascii_uppercase() as u32) - b'A' as u32 + 10;
            digits.push_str(&val.to_string());
        }
    }
    // Compute mod 97 on the large number (process in chunks to avoid bigint)
    let mut remainder: u64 = 0;
    for ch in digits.chars() {
        remainder = remainder * 10 + ch.to_digit(10).unwrap() as u64;
        remainder %= 97;
    }
    remainder == 1
}

pub fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 13 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Validate that a matched number starts with a known card issuer prefix (IIN/BIN).
/// Covers Visa, Mastercard, Amex, Discover, Diners Club, JCB, UnionPay, and Maestro.
pub fn valid_card_prefix(number: &str) -> bool {
    let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 13 {
        return false;
    }

    let d = digits.as_bytes();
    let d1 = d[0];
    let d2 = &digits[..2];
    let d4 = if digits.len() >= 4 { &digits[..4] } else { "" };
    let d6 = if digits.len() >= 6 { &digits[..6] } else { "" };

    // Visa: starts with 4
    if d1 == b'4' {
        return true;
    }

    // Mastercard: 51-55 or 2221-2720
    if let Ok(n2) = d2.parse::<u32>() {
        if (51..=55).contains(&n2) {
            return true;
        }
    }
    if d4.len() == 4 {
        if let Ok(n4) = d4.parse::<u32>() {
            if (2221..=2720).contains(&n4) {
                return true;
            }
        }
    }

    // Amex: 34, 37
    if d2 == "34" || d2 == "37" {
        return true;
    }

    // Discover: 6011, 622126-622925, 644-649, 65
    if d4 == "6011" || d2 == "65" {
        return true;
    }
    if let Ok(n3) = digits[..3].parse::<u32>() {
        if (644..=649).contains(&n3) {
            return true;
        }
    }
    if d6.len() == 6 {
        if let Ok(n6) = d6.parse::<u64>() {
            if (622126..=622925).contains(&n6) {
                return true;
            }
        }
    }

    // JCB: 3528-3589
    if d4.len() == 4 {
        if let Ok(n4) = d4.parse::<u32>() {
            if (3528..=3589).contains(&n4) {
                return true;
            }
        }
    }

    // UnionPay: 62
    if d2 == "62" {
        return true;
    }

    // Maestro: 5018, 5020, 5038, 5893, 6304, 6759, 6761, 6762, 6763
    if matches!(
        d4,
        "5018" | "5020" | "5038" | "5893" | "6304" | "6759" | "6761" | "6762" | "6763"
    ) {
        return true;
    }

    // Diners Club: 300-305, 36, 38
    if d2 == "36" || d2 == "38" {
        return true;
    }
    if digits.len() >= 3 {
        if let Ok(n3) = digits[..3].parse::<u32>() {
            if (300..=305).contains(&n3) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iban_mod97_valid() {
        assert!(iban_mod97("DE89370400440532013000"));
        assert!(iban_mod97("GB29NWBK60161331926819"));
        assert!(iban_mod97("ES9121000418450200051332"));
        assert!(iban_mod97("FR7630006000011234567890189"));
        // With spaces
        assert!(iban_mod97("DE89 3704 0044 0532 0130 00"));
        assert!(iban_mod97("GB29 NWBK 6016 1331 9268 19"));
    }

    #[test]
    fn test_iban_mod97_invalid() {
        assert!(!iban_mod97("DE00370400440532013000")); // bad check digits
        assert!(!iban_mod97("XX12345")); // too short / garbage
        assert!(!iban_mod97("DE89370400440532013001")); // off by one
    }

    #[test]
    fn test_luhn_valid_cards() {
        // Known valid test card numbers
        assert!(luhn_check("4111111111111111")); // Visa
        assert!(luhn_check("5500000000000004")); // Mastercard
        assert!(luhn_check("340000000000009")); // Amex (15 digits)
        assert!(luhn_check("6011000000000004")); // Discover
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!luhn_check("4111111111111112")); // off by one
        assert!(!luhn_check("1234567890123456")); // random
        assert!(!luhn_check("123")); // too short
    }

    #[test]
    fn test_valid_card_prefix_known_issuers() {
        assert!(valid_card_prefix("4111111111111111")); // Visa
        assert!(valid_card_prefix("5100000000000000")); // Mastercard 51
        assert!(valid_card_prefix("5500000000000000")); // Mastercard 55
        assert!(valid_card_prefix("2221000000000000")); // Mastercard 2221
        assert!(valid_card_prefix("2720000000000000")); // Mastercard 2720
        assert!(valid_card_prefix("340000000000000")); // Amex 34
        assert!(valid_card_prefix("370000000000000")); // Amex 37
        assert!(valid_card_prefix("6011000000000000")); // Discover
        assert!(valid_card_prefix("6500000000000000")); // Discover 65
        assert!(valid_card_prefix("3528000000000000")); // JCB
        assert!(valid_card_prefix("6200000000000000")); // UnionPay
        assert!(valid_card_prefix("3600000000000000")); // Diners 36
    }

    #[test]
    fn test_valid_card_prefix_rejects_unknown() {
        // Numbers starting with digits not assigned to any major issuer
        assert!(!valid_card_prefix("0000000000000000"));
        assert!(!valid_card_prefix("1000000000000000"));
        assert!(!valid_card_prefix("7000000000000000"));
        assert!(!valid_card_prefix("8000000000000000"));
        assert!(!valid_card_prefix("9000000000000000"));
    }

    #[test]
    fn test_valid_card_prefix_with_separators() {
        // Digits are filtered, so separators shouldn't matter
        assert!(valid_card_prefix("4111 1111 1111 1111"));
        assert!(valid_card_prefix("4111-1111-1111-1111"));
    }

    #[test]
    fn test_combined_luhn_and_prefix_rejects_random_16_digit() {
        // 9999999999999999 — no valid prefix, even if it somehow passed Luhn
        assert!(!valid_card_prefix("9999999999999999"));
        // 1234567890123456 — prefix 1 is not a known issuer
        assert!(!valid_card_prefix("1234567890123456"));
    }

    #[test]
    fn test_max_input_size_is_50mb() {
        assert_eq!(MAX_INPUT_SIZE, 50 * 1024 * 1024);
        assert!(
            MAX_INPUT_SIZE <= 100 * 1024 * 1024,
            "MAX_INPUT_SIZE should not exceed 100MB"
        );
    }
}
