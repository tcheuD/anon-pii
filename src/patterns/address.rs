//! Conservative French street-address recognition.
//!
//! This is a shape recognizer, not a postal database: it does not establish
//! that a street exists or that the postcode belongs to the stated city.

use super::PiiPattern;

pub const ADDRESS_PATTERNS: &[PiiPattern] = &[PiiPattern {
    name: "fr_street_address",
    entity_type: "FR_ADDRESS",
    // Require the entire compound shape, never a postcode or street by itself.
    // House numbers are 1–9999, with an optional attached/separate bis or ter.
    // Street names have 1–8 tokens; a standalone numeric token is at most four
    // digits so an earlier postcode cannot be swallowed as part of the street.
    // Horizontal whitespace keeps adjacent log lines from being combined.
    // Full street types avoid ambiguous initials.
    // Metropolitan postcode prefixes are 01–95, including Corsica's 20.
    // The city is one lexical token (hyphens/apostrophes allowed), optionally
    // preceded by a fixed article or Saint/Sainte. This deliberately leaves
    // arbitrary space-separated multiword communes unsupported rather than
    // greedily absorbing prose after a lowercase city such as "paris today".
    pattern: concat!(
        r"\b[1-9][0-9]{0,3}(?:[ \t]*(?i:bis|ter))?[ \t]+",
        r"(?i:rue|avenue|boulevard|all[ée]e|chemin|impasse|place|route|quai|passage|square|cours)[ \t]+",
        r"(?:[\p{L}\p{M}][\p{L}\p{M}0-9]*|[0-9]{1,4})(?:['’\-][\p{L}\p{M}0-9]+)*",
        r"(?:[ \t]+(?:[\p{L}\p{M}][\p{L}\p{M}0-9]*|[0-9]{1,4})(?:['’\-][\p{L}\p{M}0-9]+)*){0,7}",
        r"(?:[ \t]+|[ \t]*,[ \t]*)",
        r"(?:0[1-9]|[1-8][0-9]|9[0-5])[0-9]{3}[ \t]+",
        r"(?:(?i:le|la|les|saint|sainte)[ \t]+)?",
        r"[\p{L}\p{M}]+(?:['’\-][\p{L}\p{M}]+)*\b",
    ),
    score: 0.85,
    context_keywords: &[
        "adresse",
        "address",
        "domicile",
        "habite",
        "livraison",
        "delivery",
    ],
    context_required: false,
}];
