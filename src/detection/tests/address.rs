use super::super::*;

fn assert_address_span(input: &str, expected: &str) {
    let mut anonymizer = Anonymizer::new(0.5);
    let (output, detections) = anonymizer.anonymize_text(input);
    let addresses: Vec<_> = detections
        .iter()
        .filter(|detection| detection.entity_type == "FR_ADDRESS")
        .collect();
    assert_eq!(
        addresses.len(),
        1,
        "input: {input}; detections: {detections:?}"
    );
    let address = addresses[0];
    assert_eq!(address.original, expected, "input: {input}");
    let start = input.find(expected).unwrap();
    assert_eq!(address.start, start);
    assert_eq!(address.end, start + expected.len());
    assert_eq!(&input[address.start..address.end], expected);
    assert!(
        output.contains("[FR_ADDRESS_"),
        "input: {input}; output: {output}"
    );
    assert!(
        !output.contains(expected),
        "address remained in output: {output}"
    );
    assert_eq!(anonymizer.mapping.restore_bracketed(&output), input);
}

#[test]
fn french_address_requires_no_context_or_name_detector() {
    // Invented street/house combinations; postcode/city names exercise syntax.
    for address in [
        "72 avenue des etoiles 92160 antony",
        "12 rue des Nuages, 75016 Paris",
        "12bis boulevard des Comètes 69003 Lyon",
        "8 ter allée des Aurores 31000 Toulouse",
        "7 CHEMIN DES LANTERNES 20000 AJACCIO",
        "19 impasse de l'Orbite 01000 Bourg-en-Bresse",
        "3 place des Météores 94240 L'Haÿ-les-Roses",
        "42 route de l’Éclipse,06100 Nice",
        "6 quai des Brumes 76600 Le Havre",
        "5 passage des Planètes 42000 Saint Étienne",
        "9 square du 8 Mai 1945 59000 Lille",
        "4 cours des Satellites 44000 Nantes",
    ] {
        assert_address_span(address, address);
    }
}

#[test]
fn french_address_preserves_surrounding_prose_and_unicode_offsets() {
    for (input, address) in [
        (
            "i live at 72 avenue des etoiles 92160 antony and work remotely.",
            "72 avenue des etoiles 92160 antony",
        ),
        (
            "🏡 Adresse : 12 rue des Nuages, 75016 Paris. Livraison demain.",
            "12 rue des Nuages, 75016 Paris",
        ),
        (
            "Envoyer au 3 place des Météores 94240 L’Haÿ-les-Roses; merci.",
            "3 place des Météores 94240 L’Haÿ-les-Roses",
        ),
        (
            "Contact: 6 quai des Brumes 76600 le havre today",
            "6 quai des Brumes 76600 le havre",
        ),
        (
            "address=\"12\true\tdes\tNuages,\t75016\tParis\"; status=open",
            "12\true\tdes\tNuages,\t75016\tParis",
        ),
        (
            "address='12 rue des Nuages 75016 Paris'; status=open",
            "12 rue des Nuages 75016 Paris",
        ),
    ] {
        assert_address_span(input, address);
    }
}

#[test]
fn french_address_preserves_normalized_source_spelling() {
    for address in [
        "１２ rue des Nuages ７５０１６ Paris",
        "12%20rue%20des%20Nuages%2075016%20Paris",
        r"12 rue des Nuages 75016 Par\u0069s",
        "8 alle\u{301}e des Aurores 31000 Toulouse",
    ] {
        let input = format!("Préfixe 🏡 [{address}] fin.");
        assert_address_span(&input, address);
    }
}

#[test]
fn french_address_rejects_incomplete_shapes_and_numeric_near_misses() {
    for input in [
        "postal code 75016 Paris",
        "12 rue des Nuages",
        "12 rue 75016 Paris",
        "rue des Nuages 75016 Paris",
        "12 avenue des Nuages Paris",
        "12 av. des Nuages 75016 Paris",
        "12 street des Nuages 75016 Paris",
        "12 avenues were considered; 75016 retries completed",
        "12 rue des Nuages 7501 Paris",
        "12 rue des Nuages 750160 Paris",
        "12 rue des Nuages 00000 Paris",
        "12 rue des Nuages 96000 Paris",
        "12 rue des Nuages 99999 Paris",
        "12 rue des Nuages 75016 1234",
        "10000 rue des Nuages 75016 Paris",
        "012 rue des Nuages 75016 Paris",
        "item12 rue des Nuages 75016 Paris",
        "12 rue des Nuages\n75016 Paris",
        "12 rue des Nuages 75016\nParis",
        "12 rue des Nuages; 75016 Paris",
        "12 rue un deux trois quatre cinq six sept huit neuf 75016 Paris",
    ] {
        let mut anonymizer = Anonymizer::new(0.0);
        let (_, detections) = anonymizer.anonymize_text(input);
        assert!(
            !detections
                .iter()
                .any(|detection| detection.entity_type == "FR_ADDRESS"),
            "unexpected address for {input}: {detections:?}"
        );
    }
}

#[test]
fn french_address_rejects_truncated_city_tokens_but_preserves_closing_quotes() {
    for city in [
        "Paris123",
        "Paris-123",
        "Paris--Centre",
        "Paris-",
        "Paris'123",
        "Paris''Centre",
        "Paris’123",
        "Paris\u{2010}Centre",
        "Paris\u{2011}Centre",
        "Paris_123",
    ] {
        let input = format!("12 rue des Nuages 75016 {city}");
        let mut anonymizer = Anonymizer::new(0.0);
        let (_, detections) = anonymizer.anonymize_text(&input);
        assert!(
            !detections
                .iter()
                .any(|detection| detection.entity_type == "FR_ADDRESS"),
            "city token was partially detected for {input}: {detections:?}"
        );
    }

    let address = "12 rue des Nuages 75016 Paris";
    for input in [
        format!("'{address}'"),
        format!("“{address}”"),
        format!("‘{address}’; done"),
    ] {
        assert_address_span(&input, address);
    }
}

#[test]
fn french_address_scores_respect_threshold_and_context() {
    let address = "12 rue des Nuages 75016 Paris";
    let mut strict = Anonymizer::new(0.9);
    let (_, detections) = strict.anonymize_text(address);
    assert!(
        !detections
            .iter()
            .any(|detection| detection.entity_type == "FR_ADDRESS")
    );

    let mut contextual = Anonymizer::new(0.9);
    let input = format!("Adresse: {address}");
    let (_, detections) = contextual.anonymize_text(&input);
    let detection = detections
        .iter()
        .find(|detection| detection.entity_type == "FR_ADDRESS")
        .expect("address context should raise the score above the strict threshold");
    assert_eq!(detection.score, 1.0);
    assert_eq!(detection.original, address);
}

#[test]
fn french_address_reuses_mapping_for_repeated_values() {
    let address = "12 rue des Nuages 75016 Paris";
    let input = format!("Delivery: {address}; billing: {address}.");
    let mut anonymizer = Anonymizer::new(0.5);
    let (output, detections) = anonymizer.anonymize_text(&input);
    assert_eq!(
        detections
            .iter()
            .filter(|d| d.entity_type == "FR_ADDRESS")
            .count(),
        2
    );
    assert_eq!(anonymizer.mapping.mappings.len(), 1);
    assert_eq!(anonymizer.mapping.restore_bracketed(&output), input);
}

#[test]
fn french_address_does_not_swallow_an_earlier_postcode() {
    let first = "12 rue des Nuages 75016 Paris";
    let second = "24 rue des Lanternes 59000 Lille";
    let input = format!("{first} {second}");
    let mut anonymizer = Anonymizer::new(0.5);
    let (output, detections) = anonymizer.anonymize_text(&input);
    let addresses: Vec<_> = detections
        .iter()
        .filter(|detection| detection.entity_type == "FR_ADDRESS")
        .map(|detection| detection.original.as_str())
        .collect();
    assert_eq!(addresses, vec![first, second]);
    assert_eq!(anonymizer.mapping.restore_bracketed(&output), input);
}

#[test]
fn french_address_survives_json_csv_and_sql_roundtrips() {
    let address = "12 rue de l'Orbite, 75016 Paris";
    let json = serde_json::json!({"address": address, "count": 3});
    let mut anonymizer = Anonymizer::new(0.5);
    let (output, detections) = anonymizer.anonymize_json_value(&json);
    assert!(
        detections
            .iter()
            .any(|detection| detection.entity_type == "FR_ADDRESS")
    );
    assert_eq!(output["count"], 3);
    assert_eq!(
        anonymizer
            .mapping
            .restore_bracketed(output["address"].as_str().unwrap()),
        address
    );

    for (format, input) in [
        ("csv", format!("id,address\r\n1,\"{address}\"\r\n")),
        (
            "sql",
            format!(
                "INSERT INTO contacts VALUES ('{}');\r\n",
                address.replace('\'', "''")
            ),
        ),
    ] {
        let mut anonymizer = Anonymizer::new(0.5);
        let (output, detections) = if format == "csv" {
            anonymizer.anonymize_csv(&input)
        } else {
            anonymizer.anonymize_sql(&input)
        };
        assert!(
            detections
                .iter()
                .any(|detection| detection.entity_type == "FR_ADDRESS"),
            "format {format}: {detections:?}"
        );
        assert_eq!(anonymizer.mapping.restore_bracketed(&output), input);
    }
}
