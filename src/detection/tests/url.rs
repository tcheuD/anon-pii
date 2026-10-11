use super::super::*;

// -- URL tests --

fn assert_complete_url(a: &mut Anonymizer, input: &str, url: &str) -> Vec<Detection> {
    let (prepared, detections) = a.anonymize_text(input);
    let urls: Vec<_> = detections
        .iter()
        .filter(|d| d.entity_type == "URL")
        .collect();
    assert_eq!(urls.len(), 1, "{input:?}: {detections:?}");
    let start = input.find(url).unwrap();
    assert_eq!(urls[0].original, url, "{input:?}");
    assert_eq!((urls[0].start, urls[0].end), (start, start + url.len()));
    let token = &a.mapping.reverse[&("URL".to_string(), url.to_string())];
    assert_eq!(prepared, input.replacen(url, token, 1));
    assert_eq!(a.mapping.restore_bracketed(&prepared), input);
    for detection in &detections {
        assert_eq!(
            input.get(detection.start..detection.end),
            Some(detection.original.as_str()),
            "{detection:?}"
        );
    }
    detections
}

#[test]
fn url_encoded_grouped_iban_masks_the_complete_original_url() {
    let mut a = Anonymizer::new(0.5);
    let prefix = "Échec 🧪 — ";
    let url = "https://example.invalid/?account=GB82%20WEST%201234%205698%207654%2032";
    let input = format!("{prefix}{url}");
    let (prepared, detections) = a.anonymize_text(&input);
    let urls: Vec<_> = detections
        .iter()
        .filter(|d| d.entity_type == "URL")
        .collect();
    assert_eq!(urls.len(), 1, "{detections:?}");
    let detected_url = urls[0];
    assert_eq!(detected_url.original, url);
    assert_eq!(
        (detected_url.start, detected_url.end),
        (prefix.len(), input.len())
    );
    assert_eq!(detected_url.score, 0.9);
    assert_eq!(a.mapping.mappings.len(), 1);
    let (token, original) = a.mapping.mappings.iter().next().unwrap();
    assert_eq!(original, url);
    assert_eq!(prepared, format!("{prefix}{token}"));
    assert_eq!(a.mapping.restore_bracketed(&prepared), input);

    let raw_iban = "GB82%20WEST%201234%205698%207654%2032";
    let start = input.find(raw_iban).unwrap();
    assert!(
        detections.iter().any(|d| {
            d.entity_type == "IBAN_CODE"
                && d.original == raw_iban
                && (d.start, d.end) == (start, input.len())
        }),
        "missing exact URL-inner IBAN audit: {detections:?}"
    );
}

#[test]
fn url_encoded_delimiters_remain_inside_the_original_url() {
    let mut a = Anonymizer::new(0.5);
    for separator in [
        "%20", "%09", "%0A", "%0D%0A", "%22", "%27", "%29", "%5D", "%3e",
    ] {
        let url = format!("https://example.invalid/?note=before{separator}after");
        let input = format!("Échec 🧪 — {url}, then retry.");
        assert_complete_url(&mut a, &input, &url);
    }
}

#[test]
fn url_percent_decoding_does_not_extend_literal_boundaries() {
    let mut a = Anonymizer::new(0.5);
    let url = "https://example.invalid/?note=before%20after";
    for suffix in [
        " now",
        "\tnext",
        "\nnext",
        "\r\nnext",
        "\")",
        "'].",
        ">",
        ", then retry.",
    ] {
        let input = format!("Échec 🧪 — {url}{suffix}");
        assert_complete_url(&mut a, &input, url);
    }
}

#[test]
fn url_query_audits_decode_values_after_splitting_original_delimiters() {
    let mut a = Anonymizer::new(0.5);
    // This anchored recognizer can match only the intact decoded parameter,
    // proving encoded '&', '=' and '?' were not treated as query syntax.
    a.patterns.push(CompiledPattern {
        name: "query_value".into(),
        entity_type: "QUERY_VALUE".into(),
        regex: Regex::new(r"^a&b=c\?d$").unwrap(),
        score: 0.9,
        context_keywords: Cow::Borrowed(&[]),
        context_required: false,
    });
    let url = "https://example.invalid/?note=a%26b%3Dc%3Fd&email=%22ada%40example.invalid%22&tel=%2B33639980001%0Anext";
    let input = format!("Échec 🧪 — {url} done");
    let detections = assert_complete_url(&mut a, &input, url);
    for (entity, raw) in [
        ("QUERY_VALUE", "a%26b%3Dc%3Fd"),
        ("EMAIL_ADDRESS", "ada%40example.invalid"),
        ("FR_PHONE_NUMBER", "%2B33639980001"),
    ] {
        let matches: Vec<_> = detections
            .iter()
            .filter(|d| d.entity_type == entity)
            .collect();
        assert_eq!(matches.len(), 1, "{entity}: {detections:?}");
        assert_eq!(matches[0].original, raw);
        let start = input.find(raw).unwrap();
        assert_eq!(
            (matches[0].start, matches[0].end),
            (start, start + raw.len())
        );
    }
    assert_eq!(
        a.mapping.mappings.len(),
        1,
        "audit spans must not allocate tokens"
    );

    let url = "https://example.invalid/?value=ada%26blair%40example.invalid&tel=%2B33639980001";
    let input = format!("Échec 🧪 — {url}");
    let detections = assert_complete_url(&mut a, &input, url);
    let emails: Vec<_> = detections
        .iter()
        .filter(|d| d.entity_type == "EMAIL_ADDRESS")
        .collect();
    assert_eq!(emails.len(), 1, "{detections:?}");
    assert_eq!(emails[0].original, "blair%40example.invalid");
    assert!(
        detections
            .iter()
            .any(|d| d.entity_type == "FR_PHONE_NUMBER" && d.original == "%2B33639980001")
    );

    // An encoded '?' belongs to the path, not to the original query syntax.
    let url = "https://example.invalid/path%3Femail=ada%40example.invalid";
    let detections = assert_complete_url(&mut a, url, url);
    assert_eq!(
        detections.len(),
        1,
        "must not invent a query audit: {detections:?}"
    );
}

#[test]
fn url_boundary_view_does_not_change_custom_recognizer_collisions() {
    let input = "https://example.invalid/?note=before%20after";
    let truncated = "https://example.invalid/?note=before";
    for collision in ["regex", "entity", "context"] {
        let mut a = Anonymizer::new(0.5);
        a.patterns.retain(|p| p.name == "url");
        let pattern = &mut a.patterns[0];
        match collision {
            "regex" => pattern.regex = Regex::new(r"https://example\.invalid/[^\s]+").unwrap(),
            "entity" => pattern.entity_type = "CUSTOM_URL".into(),
            "context" => {
                pattern.context_keywords = Cow::Borrowed(&["allowed"]);
                pattern.context_required = true;
            }
            _ => unreachable!(),
        }
        let (prepared, detections) = a.anonymize_text(input);
        if collision == "context" {
            assert_eq!(prepared, input);
            assert!(detections.is_empty());
            assert!(a.mapping.mappings.is_empty());
        } else {
            assert_eq!(detections.len(), 1, "{collision}: {detections:?}");
            assert_eq!(detections[0].original, truncated, "{collision}");
            assert!(prepared.ends_with("%20after"));
            assert_eq!(a.mapping.restore_bracketed(&prepared), input);
        }
    }
}

#[test]
fn url_percent_encoded_scheme_keeps_the_decoded_fallback() {
    let mut a = Anonymizer::new(0.5);
    let url = "https%3A%2F%2Fexample.invalid%2Fpath%3Femail%3Dada%40example.invalid";
    assert_complete_url(&mut a, &format!("Échec 🧪 — {url} done"), url);

    let mut strict = Anonymizer::new(0.95);
    let input = "https://example.invalid/?note=before%20after";
    let (prepared, detections) = strict.anonymize_text(input);
    assert_eq!(prepared, input);
    assert!(detections.is_empty());
    assert!(strict.mapping.mappings.is_empty());
}

#[test]
fn url_boundary_candidates_respect_selection_and_enclosing_password() {
    let mut a = Anonymizer::new(0.5);
    let url = "https://example.invalid/?note=before%20after";
    assert!(a.analyze_with_entities(url, Some(&[])).is_empty());
    assert!(a.mapping.mappings.is_empty());

    let input = format!(r#"password="private-prefix {url} private-suffix""#);
    let (prepared, detections) = a.anonymize_text(&input);
    assert_eq!(detections.len(), 1, "{detections:?}");
    assert_eq!(detections[0].entity_type, "PASSWORD");
    assert_eq!(detections[0].original, input);
    assert_eq!((detections[0].start, detections[0].end), (0, input.len()));
    assert_eq!(a.mapping.mappings.len(), 1);
    let (token, original) = a.mapping.mappings.iter().next().unwrap();
    assert_eq!(original, &input);
    assert_eq!(&prepared, token);
    assert_eq!(a.mapping.restore_bracketed(&prepared), input);
}

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
