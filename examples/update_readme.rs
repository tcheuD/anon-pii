//! README.md auto-updater for anon.
//!
//! Parses marker sections (`<!-- BEGIN X -->...<!-- END X -->`) and replaces
//! them with dynamically generated content from the codebase.

// Functions will be wired in main() in Task 9
#![allow(dead_code)]

use std::collections::HashSet;
use std::fs;
use std::process;

use anon::patterns::PATTERNS;

/// Known 2-letter country prefixes for entity types.
const COUNTRY_PREFIXES: &[&str] = &[
    "FR", "US", "UK", "ES", "IT", "IN", "AU", "KR", "SG", "PL", "SI", "FI", "TH",
];

/// Replaces content between `<!-- BEGIN {name} -->` and `<!-- END {name} -->`
/// markers with new content.
///
/// Returns `Some(updated_string)` if markers are found, `None` otherwise.
/// The markers themselves are preserved; only the content between them is replaced.
fn replace_marker(readme: &str, name: &str, new_content: &str) -> Option<String> {
    let begin_marker = format!("<!-- BEGIN {} -->", name);
    let end_marker = format!("<!-- END {} -->", name);

    let begin_pos = readme.find(&begin_marker)?;
    let end_pos = readme.find(&end_marker)?;

    // Sanity check: BEGIN must come before END
    if begin_pos >= end_pos {
        return None;
    }

    let before = &readme[..begin_pos + begin_marker.len()];
    let after = &readme[end_pos..];

    Some(format!("{}\n{}\n{}", before, new_content, after))
}

/// Extracts a country code from an entity type prefix if it matches a known country.
///
/// Returns `Some("FR")` for `FR_SSN`, `None` for `EMAIL_ADDRESS`.
fn country_from_prefix(entity_type: &str) -> Option<&'static str> {
    // Split on first underscore
    let prefix = entity_type.split('_').next()?;

    // Check if it's a known 2-letter country prefix
    if prefix.len() == 2 {
        for &country in COUNTRY_PREFIXES {
            if prefix.eq_ignore_ascii_case(country) {
                return Some(country);
            }
        }
    }
    None
}

/// Generates the entities section paragraph for README.md.
///
/// Introspects `PATTERNS` to compute counts and produce a formatted description.
fn generate_entities_section() -> String {
    // Collect unique entity types
    let entity_types: HashSet<&str> = PATTERNS.iter().map(|p| p.entity_type).collect();
    let entity_count = entity_types.len();
    let pattern_count = PATTERNS.len();

    // Extract unique countries
    let countries: HashSet<&str> = entity_types
        .iter()
        .filter_map(|et| country_from_prefix(et))
        .collect();
    let country_count = countries.len();

    // Sort countries alphabetically
    let mut country_list: Vec<&str> = countries.into_iter().collect();
    country_list.sort();
    let country_list_str = country_list.join(", ");

    format!(
        "{} entity types across {} patterns covering {} countries: emails, URLs, IPs, UUIDs, \
         credit cards, IBANs, phones, dates, crypto addresses, MAC addresses, secrets/tokens, \
         and person names (with `--ner`). Country-specific patterns include SSNs, passports, \
         driver's licenses, tax IDs, and national IDs for {} \u{2014} each with checksum \
         validation where applicable. Detection works through URL-encoded and Unicode-escaped text.\n\n\
         See [docs/entities.md](docs/entities.md) for the full reference with confidence scores and context keywords.",
        entity_count, pattern_count, country_count, country_list_str
    )
}

fn main() {
    // Placeholder for now — will be wired in Task 9
    let readme_path = "README.md";
    let readme = fs::read_to_string(readme_path).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", readme_path, e);
        process::exit(2);
    });
    let _ = readme;
    println!("update_readme: ready (entities + marker parser)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace_marker_basic() {
        let input = "before\n<!-- BEGIN FOO -->\nold content\n<!-- END FOO -->\nafter";
        let result = replace_marker(input, "FOO", "new content").unwrap();
        assert_eq!(
            result,
            "before\n<!-- BEGIN FOO -->\nnew content\n<!-- END FOO -->\nafter"
        );
    }

    #[test]
    fn test_replace_marker_not_found() {
        assert!(replace_marker("no markers here", "FOO", "content").is_none());
    }

    #[test]
    fn test_replace_marker_multiline_content() {
        let input = "<!-- BEGIN X -->\nold\n<!-- END X -->";
        let result = replace_marker(input, "X", "line1\nline2\nline3").unwrap();
        assert!(result.contains("line1\nline2\nline3"));
        assert!(result.starts_with("<!-- BEGIN X -->\n"));
        assert!(result.ends_with("\n<!-- END X -->"));
    }

    #[test]
    fn test_replace_marker_preserves_surrounding() {
        let input = "header\n\n<!-- BEGIN TEST -->\nwill be replaced\n<!-- END TEST -->\n\nfooter";
        let result = replace_marker(input, "TEST", "new stuff").unwrap();
        assert!(result.starts_with("header\n\n<!-- BEGIN TEST -->\n"));
        assert!(result.ends_with("\n<!-- END TEST -->\n\nfooter"));
        assert!(result.contains("new stuff"));
    }

    #[test]
    fn test_replace_marker_end_before_begin_returns_none() {
        let input = "<!-- END FOO -->\n<!-- BEGIN FOO -->";
        assert!(replace_marker(input, "FOO", "content").is_none());
    }

    #[test]
    fn test_replace_marker_missing_begin() {
        let input = "text\n<!-- END FOO -->";
        assert!(replace_marker(input, "FOO", "content").is_none());
    }

    #[test]
    fn test_replace_marker_missing_end() {
        let input = "<!-- BEGIN FOO -->\ntext";
        assert!(replace_marker(input, "FOO", "content").is_none());
    }

    #[test]
    fn test_country_from_prefix_known() {
        assert_eq!(country_from_prefix("FR_SSN"), Some("FR"));
        assert_eq!(country_from_prefix("US_PASSPORT"), Some("US"));
        assert_eq!(country_from_prefix("UK_NHS"), Some("UK"));
        assert_eq!(country_from_prefix("AU_ABN"), Some("AU"));
        assert_eq!(country_from_prefix("KR_RRN"), Some("KR"));
        assert_eq!(country_from_prefix("SG_NRIC_FIN"), Some("SG"));
        assert_eq!(country_from_prefix("PL_PESEL"), Some("PL"));
        assert_eq!(country_from_prefix("SI_EMSO"), Some("SI"));
        assert_eq!(country_from_prefix("FI_PERSONAL_IDENTITY_CODE"), Some("FI"));
        assert_eq!(country_from_prefix("TH_TNIN"), Some("TH"));
    }

    #[test]
    fn test_country_from_prefix_global() {
        assert_eq!(country_from_prefix("EMAIL_ADDRESS"), None);
        assert_eq!(country_from_prefix("CREDIT_CARD"), None);
        assert_eq!(country_from_prefix("AUTH_TOKEN"), None);
        assert_eq!(country_from_prefix("IP_ADDRESS"), None);
        assert_eq!(country_from_prefix("IBAN_CODE"), None);
    }

    #[test]
    fn test_country_from_prefix_no_underscore() {
        assert_eq!(country_from_prefix("UUID"), None);
        assert_eq!(country_from_prefix("URL"), None);
    }

    #[test]
    fn test_generate_entities_section() {
        let section = generate_entities_section();
        assert!(section.contains("entity types across"));
        assert!(section.contains("patterns covering"));
        assert!(section.contains("countries"));
        assert!(section.contains("emails"));
        assert!(section.contains("IBANs"));
        assert!(section.contains("docs/entities.md"));
    }

    #[test]
    fn test_generate_entities_section_has_country_list() {
        let section = generate_entities_section();
        // Should contain comma-separated country codes
        assert!(section.contains("AU"));
        assert!(section.contains("FR"));
        assert!(section.contains("US"));
    }

    #[test]
    fn test_generate_entities_section_counts_match_patterns() {
        let entity_types: HashSet<&str> = PATTERNS.iter().map(|p| p.entity_type).collect();
        let section = generate_entities_section();

        // The section should contain the actual counts from PATTERNS
        let entity_count_str = format!("{} entity types", entity_types.len());
        let pattern_count_str = format!("{} patterns", PATTERNS.len());

        assert!(
            section.contains(&entity_count_str),
            "Expected '{}' in section",
            entity_count_str
        );
        assert!(
            section.contains(&pattern_count_str),
            "Expected '{}' in section",
            pattern_count_str
        );
    }
}
