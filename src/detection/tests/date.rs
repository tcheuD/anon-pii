use super::super::*;

// -- DATE_TIME tests --

#[test]
fn test_date_iso8601() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("created on 2024-01-15");
    assert!(
        dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "ISO date not detected: {dets:?}"
    );
    assert!(result.contains("[DATE_TIME_"));
}

#[test]
fn test_date_iso8601_with_time() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("timestamp 2024-01-15T14:30:00Z");
    assert!(
        dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "ISO datetime not detected: {dets:?}"
    );
    assert!(result.contains("[DATE_TIME_"));
}

#[test]
fn test_date_french_format() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("date de naissance 15/01/1990");
    assert!(
        dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "French date not detected: {dets:?}"
    );
    assert!(result.contains("[DATE_TIME_"));
}

#[test]
fn test_date_french_format_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    // dd/mm/yyyy without context — ambiguous, could be a path or version
    let (_, dets) = a.anonymize_text("value 15/01/1990 here");
    assert!(
        !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "French date without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_date_written_french() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("le 15 janvier 2024");
    assert!(
        dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "written French date not detected: {dets:?}"
    );
    assert!(result.contains("[DATE_TIME_"));
}

#[test]
fn test_date_written_english() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("born January 15, 2024");
    assert!(
        dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "written English date not detected: {dets:?}"
    );
    assert!(result.contains("[DATE_TIME_"));
}

#[test]
fn test_date_does_not_match_version_numbers() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("version 3.14.159");
    assert!(
        !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "version numbers should not be dates: {dets:?}"
    );
}

#[test]
fn test_date_does_not_match_ip() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("server at 192.168.1.100");
    // IP should be detected as IP, not as a date
    assert!(
        !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "IP addresses should not be dates: {dets:?}"
    );
}

#[test]
fn test_date_iso8601_with_offset() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("sent at 2024-06-15T09:30:00+02:00");
    assert!(
        dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "ISO date with offset not detected: {dets:?}"
    );
    assert!(result.contains("[DATE_TIME_"));
}

#[test]
fn test_date_iso8601_with_milliseconds() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("logged at 2024-01-15T14:30:00.123Z");
    assert!(
        dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "ISO date with ms not detected: {dets:?}"
    );
    assert!(result.contains("[DATE_TIME_"));
}

#[test]
fn test_date_iso8601_date_only() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("born 1990-05-20");
    assert!(
        dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "ISO date-only not detected: {dets:?}"
    );
    assert!(result.contains("[DATE_TIME_"));
}

#[test]
fn test_date_rejects_impossible_calendar_days() {
    for input in [
        "created 2026-02-31",
        "created 2025-02-29",
        "created 2026-04-31",
        "birth date 31/04/2026",
    ] {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "impossible date detected in {input:?}: {dets:?}"
        );
    }
}

#[test]
fn test_date_accepts_valid_leap_day() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("created 2024-02-29");

    assert!(
        dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "valid leap day was rejected: {dets:?}"
    );
}

#[test]
fn test_date_iso8601_space_separator() {
    let mut a = Anonymizer::new(0.0);
    // Space instead of T between date and time (common in logs)
    let (result, dets) = a.anonymize_text("created 2024-01-15 14:30:00Z");
    assert!(
        dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "ISO date with space separator not detected: {dets:?}"
    );
    assert!(result.contains("[DATE_TIME_"));
}

#[test]
fn test_date_eu_dot_format_with_context() {
    let mut a = Anonymizer::new(0.0);
    // dd.mm.yyyy with context
    let (result, dets) = a.anonymize_text("date de naissance: 25.12.1990");
    assert!(
        dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "EU dot date not detected: {dets:?}"
    );
    assert!(result.contains("[DATE_TIME_"));
}

#[test]
fn test_date_eu_various_contexts() {
    let contexts = [
        "departure 15/03/2024",
        "arrival date 15/03/2024",
        "dob: 15/03/1990",
        "né le 15/03/1990",
        "émis le 15/03/2024",
    ];
    for input in &contexts {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "EU date not detected in '{input}': {dets:?}"
        );
    }
}

#[test]
fn test_date_written_french_premier() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("publié le 1er mars 2023");
    assert!(
        dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "'1er mars' not detected: {dets:?}"
    );
    assert!(result.contains("[DATE_TIME_"));
}

#[test]
fn test_date_written_french_all_months() {
    let months = [
        "janvier",
        "février",
        "mars",
        "avril",
        "mai",
        "juin",
        "juillet",
        "août",
        "septembre",
        "octobre",
        "novembre",
        "décembre",
    ];
    for month in &months {
        let input = format!("le 15 {month} 2024");
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text(&input);
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "French month '{month}' not detected: {dets:?}"
        );
    }
}

#[test]
fn test_date_written_french_alt_spelling() {
    let mut a = Anonymizer::new(0.0);
    // "fevrier" without accent and "aout" without accent
    let (_, dets) = a.anonymize_text("le 15 fevrier 2024");
    assert!(
        dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "'fevrier' (no accent) not detected: {dets:?}"
    );
    let mut a2 = Anonymizer::new(0.0);
    let (_, dets2) = a2.anonymize_text("le 15 aout 2024");
    assert!(
        dets2.iter().any(|d| d.entity_type == "DATE_TIME"),
        "'aout' (no accent) not detected: {dets2:?}"
    );
}

#[test]
fn test_date_written_english_all_months() {
    let months = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    for month in &months {
        let input = format!("{month} 15, 2024");
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text(&input);
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "English month '{month}' not detected: {dets:?}"
        );
    }
}

#[test]
fn test_date_written_english_abbreviated() {
    let abbrevs = [
        "Jan", "Feb", "Mar", "Apr", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    for abbr in &abbrevs {
        let input = format!("{abbr} 15, 2024");
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text(&input);
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "English abbreviated month '{abbr}' not detected: {dets:?}"
        );
    }
}

#[test]
fn test_date_written_english_ordinal() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("born March 3rd, 2024");
    assert!(
        dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "ordinal date not detected: {dets:?}"
    );
    assert!(result.contains("[DATE_TIME_"));
}

#[test]
fn test_date_invalid_month_rejected() {
    let mut a = Anonymizer::new(0.0);
    // Month 13 doesn't exist
    let (_, dets) = a.anonymize_text("2024-13-01");
    assert!(
        !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "invalid month 13 should be rejected: {dets:?}"
    );
}

#[test]
fn test_date_invalid_day_rejected() {
    let mut a = Anonymizer::new(0.0);
    // Day 32 doesn't exist
    let (_, dets) = a.anonymize_text("2024-01-32");
    assert!(
        !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "invalid day 32 should be rejected: {dets:?}"
    );
}

#[test]
fn test_date_year_boundary() {
    let mut a = Anonymizer::new(0.0);
    // Year 1899 — out of 19xx/20xx range for EU format
    let (_, dets) = a.anonymize_text("date 15/01/1899");
    assert!(
        !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "year 1899 should not match dd/mm/yyyy pattern: {dets:?}"
    );
}

#[test]
fn test_date_not_confused_with_semver() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("version 2.11.3");
    assert!(
        !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "semver should not match as date: {dets:?}"
    );
}

#[test]
fn test_date_not_confused_with_decimal() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("temperature 98.6.50 degrees");
    assert!(
        !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "decimal-like number should not be a date: {dets:?}"
    );
}

#[test]
fn test_date_iso_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let input = "created at 2024-06-15T09:30:00Z";
    let (anon, _) = a.anonymize_text(input);
    let restored = a.mapping.restore(&anon);
    assert_eq!(
        restored, input,
        "ISO date roundtrip should restore original"
    );
}
