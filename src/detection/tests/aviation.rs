use super::super::*;

// -- AIRCRAFT_REGISTRATION tests --

#[test]
fn test_aircraft_fr() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("aircraft F-TEST ready");
    assert!(result.contains("[AIRCRAFT_REGISTRATION_"));
}

#[test]
fn test_aircraft_us_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("aircraft N12345 ready");
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "AIRCRAFT_REGISTRATION")
    );
    assert!(result.contains("[AIRCRAFT_REGISTRATION_"));
}

#[test]
fn test_aircraft_us_two_letter_suffix() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("aircraft N12345AB ready");
    assert!(result.contains("[AIRCRAFT_REGISTRATION_"));
    assert!(!result.contains("N12345AB"));
}

// -- CREW_CODE tests --

#[test]
fn test_crew_code_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("pilot: ZKP is on duty");
    assert!(dets.iter().any(|d| d.entity_type == "CREW_CODE"));
    assert!(result.contains("[CREW_CODE_"));
}

#[test]
fn test_crew_code_without_context() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("hello ZKP world");
    assert!(!dets.iter().any(|d| d.entity_type == "CREW_CODE"));
}

#[test]
fn test_crew_code_blocklist() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("crew member THE");
    assert!(
        !dets
            .iter()
            .any(|d| d.entity_type == "CREW_CODE" && d.original == "THE")
    );
}

#[test]
fn test_crew_code_blocklist_tech_abbreviations() {
    let mut a = Anonymizer::new(0.0);
    // Tech abbreviations near crew context should still be blocked
    let (_, dets) = a.anonymize_text("crew member handles URL API SQL requests on duty");
    let crew_dets: Vec<_> = dets
        .iter()
        .filter(|d| d.entity_type == "CREW_CODE")
        .collect();
    for d in &crew_dets {
        assert!(
            !["URL", "API", "SQL"].contains(&d.original.as_str()),
            "Tech abbreviation '{}' should be blocklisted, not detected as CREW_CODE",
            d.original
        );
    }
}

#[test]
fn test_crew_code_blocklist_stress_test_cases() {
    let mut a = Anonymizer::new(0.0);
    // Exact cases from stress test that produced false positives
    let (_, dets) = a.anonymize_text("sensitive tokens in a URL string");
    assert!(
        !dets
            .iter()
            .any(|d| d.entity_type == "CREW_CODE" && d.original == "URL")
    );

    let mut a2 = Anonymizer::new(0.0);
    let (_, dets2) = a2.anonymize_text("PII split across lines");
    assert!(
        !dets2
            .iter()
            .any(|d| d.entity_type == "CREW_CODE" && d.original == "PII")
    );

    let mut a3 = Anonymizer::new(0.0);
    let (_, dets3) = a3.anonymize_text("Auth-Token=XYZ-123");
    assert!(
        !dets3
            .iter()
            .any(|d| d.entity_type == "CREW_CODE" && d.original == "XYZ")
    );
}

#[test]
fn test_crew_code_blocklist_airport_codes() {
    let mut a = Anonymizer::new(0.0);
    // Airport codes near crew context should be blocked
    let (_, dets) = a.anonymize_text("crew roster: departure CDG arrival ORY duty JFK");
    let crew_originals: Vec<&str> = dets
        .iter()
        .filter(|d| d.entity_type == "CREW_CODE")
        .map(|d| d.original.as_str())
        .collect();
    for code in &["CDG", "ORY", "JFK"] {
        assert!(
            !crew_originals.contains(code),
            "Airport code '{}' should be blocklisted, not detected as CREW_CODE",
            code
        );
    }
}

#[test]
fn test_crew_code_real_codes_still_detected() {
    let mut a = Anonymizer::new(0.0);
    // Real crew codes with context should still work
    let (result, dets) = a.anonymize_text("pilote ZKP en service avec copilote WQD");
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "CREW_CODE" && d.original == "ZKP"),
        "Crew code ZKP should still be detected"
    );
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "CREW_CODE" && d.original == "WQD"),
        "Real crew code WQD should still be detected"
    );
    assert!(result.contains("[CREW_CODE_"));
}

#[test]
fn test_utf8_context_window() {
    let mut a = Anonymizer::new(0.0);
    // French accented text with crew code context — should not panic
    let input = "L'équipage était composé du pilote ZKP et du copilote André résumé";
    let (result, dets) = a.anonymize_text(input);
    assert!(dets.iter().any(|d| d.entity_type == "CREW_CODE"));
    assert!(result.contains("[CREW_CODE_"));
}

#[test]
fn test_off_not_detected_as_crew_code() {
    let mut a = Anonymizer::new(0.0);
    // "OFF" in duty schedule context — should NOT be a crew code
    let input = "les journées de OFF/Duty/X-D/... sont qualifiées comme absences";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        !dets
            .iter()
            .any(|d| d.entity_type == "CREW_CODE" && d.original == "OFF"),
        "OFF should be blocklisted as CREW_CODE.\nDetections: {:?}",
        dets
    );
    assert!(result.contains("OFF"), "OFF should remain in output");
}

// -- FLIGHT_NUMBER tests --

#[test]
fn test_flight_number_with_dash() {
    let mut a = Anonymizer::new(0.0);
    let input = "incident sur le vol AML-317 Paris-CDG";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "FLIGHT_NUMBER" && d.original == "AML-317"),
        "AML-317 should be detected as FLIGHT_NUMBER.\nDetections: {:?}",
        dets
    );
    assert!(
        !result.contains("AML-317"),
        "Flight number should be anonymized"
    );
    // AML should NOT be detected separately as CREW_CODE
    assert!(
        !dets
            .iter()
            .any(|d| d.entity_type == "CREW_CODE" && d.original == "AML"),
        "AML should not be detected as CREW_CODE when part of flight number.\nDetections: {:?}",
        dets
    );
}

// -- EMPLOYEE_ID tests --

#[test]
fn test_employee_matricule_detected_with_context() {
    let mut a = Anonymizer::new(0.0);
    let input = "Le Capitaine (matricule AM-4872) a signalé un incident";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "EMPLOYEE_ID" && d.original == "AM-4872"),
        "AM-4872 should be detected as EMPLOYEE_ID with 'matricule' context.\nDetections: {:?}",
        dets
    );
    assert!(
        !result.contains("AM-4872"),
        "Matricule should be anonymized"
    );
}

#[test]
fn test_employee_matricule_not_detected_without_context() {
    let mut a = Anonymizer::new(0.0);
    let input = "reference AM-4872 in the system";
    let (_, dets) = a.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "EMPLOYEE_ID"),
        "EMPLOYEE_ID should not match without context keywords.\nDetections: {:?}",
        dets
    );
}

// -- Aviation incident report regression --

#[test]
fn test_aviation_incident_report_regression() {
    // Regression test: realistic aviation incident report with mixed PII
    let mut a = Anonymizer::new(0.0);
    let input = "Le Capitaine Jean-Marc Dubois (matricule AM-4872) a signalé un incident \
        technique sur le vol AML-317 Paris-CDG → Beyrouth le 14/03/2025. Son copilote \
        Marie Lefèvre a confirmé. Contact RH : j.dupont@example-air.com, poste 2241. Le rapport \
        a été transmis à Dr. Philippe Nasser pour évaluation médicale.";
    let (result, dets) = a.anonymize_text(input);
    // Email must be detected
    assert!(
        dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
        "Email should be detected.\nDetections: {:?}",
        dets
    );
    // Matricule must be detected
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "EMPLOYEE_ID" && d.original == "AM-4872"),
        "Matricule AM-4872 should be detected as EMPLOYEE_ID.\nDetections: {:?}",
        dets
    );
    assert!(
        !result.contains("AM-4872"),
        "Matricule should be anonymized in output"
    );
    // Flight number AML-317 must be detected as flight, not crew code
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "FLIGHT_NUMBER" && d.original == "AML-317"),
        "AML-317 should be detected as FLIGHT_NUMBER.\nDetections: {:?}",
        dets
    );
    assert!(
        !dets
            .iter()
            .any(|d| d.entity_type == "CREW_CODE" && d.original == "AML"),
        "AML should not be a CREW_CODE.\nDetections: {:?}",
        dets
    );
}
