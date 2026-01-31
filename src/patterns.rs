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
            "telephone", "tel", "phone", "mobile", "contact", "appeler", "numero", "portable",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_phone_national",
        entity_type: "FR_PHONE_NUMBER",
        pattern: r"\b0[1-9](?:[\s.\-]?\d{2}){4}\b",
        score: 0.7,
        context_keywords: &[
            "telephone", "tel", "phone", "mobile", "contact", "appeler", "numero", "portable",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_phone_compact",
        entity_type: "FR_PHONE_NUMBER",
        pattern: r"\b0[1-9]\d{8}\b",
        score: 0.6,
        context_keywords: &[
            "telephone", "tel", "phone", "mobile", "contact", "appeler", "numero", "portable",
        ],
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
    // ── French SSN (NIR) ──
    PiiPattern {
        name: "fr_ssn",
        entity_type: "FR_SSN",
        pattern: r"[12]\s?\d{2}\s?(?:0[1-9]|1[0-2]|[2-9]\d)\s?(?:\d{2}|2[AB])\s?\d{3}\s?\d{3}(?:\s?\d{2})?",
        score: 0.85,
        context_keywords: &[
            "secu", "securite sociale", "ssn", "nir", "carte vitale", "numero", "immatriculation",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_ssn_compact",
        entity_type: "FR_SSN",
        pattern: r"[12]\d{2}(?:0[1-9]|1[0-2]|[2-9]\d)(?:\d{2}|2[AB])\d{6}(?:\d{2})?",
        score: 0.8,
        context_keywords: &[
            "secu", "securite sociale", "ssn", "nir", "carte vitale", "numero", "immatriculation",
        ],
        context_required: false,
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
            "aircraft", "avion", "registration", "immat", "appareil", "tail", "immatriculation",
        ],
        context_required: true,
    },
    // ── Flight numbers ──
    PiiPattern {
        name: "flight_amelia",
        entity_type: "FLIGHT_NUMBER",
        pattern: r"\b(?:IZM|RLA|AME|GJT|AF)[0-9]{1,4}\b",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "flight_iata",
        entity_type: "FLIGHT_NUMBER",
        pattern: r"\b[A-Z]{2}[0-9]{1,4}\b",
        score: 0.4,
        context_keywords: &[
            "flight", "vol", "departure", "arrival", "schedule", "rotation", "leg", "sector",
        ],
        context_required: true,
    },
    PiiPattern {
        name: "flight_icao",
        entity_type: "FLIGHT_NUMBER",
        pattern: r"\b[A-Z]{3}[0-9]{1,4}\b",
        score: 0.5,
        context_keywords: &[
            "flight", "vol", "departure", "arrival", "schedule", "rotation", "leg", "sector",
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
            "crew", "equipage", "équipage", "pilot", "pilote", "captain", "cdb",
            "commandant", "copilot", "copilote", "opl", "cabin", "pnc", "pnt",
            "steward", "hostess", "hôtesse", "hotesse", "first officer", "fo",
            "member", "membre", "roster", "planning", "duty", "service",
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
    // ── Credit card ──
    PiiPattern {
        name: "credit_card",
        entity_type: "CREDIT_CARD",
        pattern: r"\b(?:\d{4}[\s\-]?){3}\d{4}\b",
        score: 0.7,
        context_keywords: &[
            "card", "credit", "payment", "cc", "visa", "mastercard", "amex",
            "cb", "carte", "bancaire", "debit", "paiement",
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
];

pub const CREW_CODE_BLOCKLIST: &[&str] = &[
    "THE", "AND", "FOR", "NOT", "YOU", "ALL", "CAN", "HAD", "HER", "WAS",
    "ONE", "OUR", "OUT", "ARE", "BUT", "HIS", "HAS", "NEW", "NOW", "OLD",
    "SEE", "WAY", "WHO", "BOY", "DID", "GET", "LET", "PUT", "SAY", "SHE",
    "TOO", "USE", "DAY", "MAN", "END", "MAY", "SET", "TRY", "ASK", "BIG",
    "VOL", "VIA", "PAX", "ETA", "ETD", "UTC", "GMT", "AOG", "MEL", "CDM",
    "IZM", "RLA", "AME", "GJT",
];

pub const CONTEXT_WINDOW: usize = 80;
pub const CONTEXT_SCORE_BOOST: f64 = 0.15;
pub const MAX_INPUT_SIZE: u64 = 512 * 1024 * 1024; // 512 MB

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
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}
