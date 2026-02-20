//! Aviation-specific PII patterns.
//!
//! Contains patterns for: AIRCRAFT_REGISTRATION, FLIGHT_NUMBER, CREW_CODE, EMPLOYEE_ID.

use super::PiiPattern;

pub const AVIATION_PATTERNS: &[PiiPattern] = &[
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
];

/// Blocklist for crew codes - common English words, tech abbreviations, airport codes, etc.
/// These 3-letter sequences are too common to be treated as crew codes even in context.
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
