use super::super::*;

// -- URL tests --

#[test]
fn test_url() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("visit https://example.com/path?q=1 now");
    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].entity_type, "URL");
    assert!(result.contains("[URL_"));
}

#[test]
fn test_url_inner_pii_reported_in_detections() {
    let mut a = Anonymizer::new(0.0);
    let input = "Referer: https://site.com/search?email=user%40example.com&id=123";
    let (result, dets) = a.anonymize_text(input);
    // URL should be masked in output
    assert!(result.contains("[URL_"));
    assert!(!result.contains("example.com"));
    // Both URL and inner EMAIL_ADDRESS should be in detections
    assert!(
        dets.iter().any(|d| d.entity_type == "URL"),
        "URL detection missing"
    );
    let expected = "user%40example.com";
    let start = input.find(expected).unwrap();
    assert!(
        dets.iter().any(|d| {
            d.entity_type == "EMAIL_ADDRESS"
                && d.original == expected
                && d.start == start
                && d.end == start + expected.len()
        }),
        "Inner email did not retain its exact raw source span: {:?}",
        dets
    );
}

#[test]
fn test_url_inner_pii_phone_reported() {
    let mut a = Anonymizer::new(0.0);
    let input = "visit https://example.com/contact?tel=%2B33612345678";
    let (result, dets) = a.anonymize_text(input);
    assert!(result.contains("[URL_"));
    let expected = "%2B33612345678";
    let start = input.find(expected).unwrap();
    assert!(
        dets.iter().any(|d| {
            d.entity_type == "FR_PHONE_NUMBER"
                && d.original == expected
                && d.start == start
                && d.end == start + expected.len()
        }),
        "Inner phone did not retain its exact raw source span: {:?}",
        dets
    );
}

#[test]
fn test_url_inner_invalid_calendar_date_is_rejected() {
    let mut a = Anonymizer::new(0.0);
    let input = "See https://example.com/debug?date=2026-02-31";
    let (_, dets) = a.anonymize_text(input);

    assert!(dets.iter().any(|d| d.entity_type == "URL"));
    assert!(
        !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "invalid URL query date reported: {dets:?}"
    );
}

#[test]
fn test_url_without_query_no_inner_detections() {
    let mut a = Anonymizer::new(0.0);
    let input = "visit https://example.com/page";
    let (_, dets) = a.anonymize_text(input);
    // Only the URL detection, no extras
    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].entity_type, "URL");
}

#[test]
fn test_url_inner_pii_no_false_detections() {
    let mut a = Anonymizer::new(0.0);
    let input = "visit https://example.com/page?id=123&sort=asc";
    let (_, dets) = a.anonymize_text(input);
    // Only the URL detection — no PII in these params
    assert_eq!(
        dets.iter().filter(|d| d.entity_type != "URL").count(),
        0,
        "Should not detect PII in non-PII URL params: {:?}",
        dets
    );
}
