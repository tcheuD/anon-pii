use super::super::*;

// -- IP_ADDRESS tests --

#[test]
fn test_ip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("server at 192.168.1.100");
    assert!(result.contains("[IP_ADDRESS_"));
}

#[test]
fn test_ipv6_full() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("host 2001:0db8:85a3:0000:0000:8a2e:0370:7334 down");
    assert!(
        dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
        "full IPv6 not detected: {dets:?}"
    );
    assert!(result.contains("[IP_ADDRESS_"));
}

#[test]
fn test_ipv6_collapsed() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("server at 2001:db8::1");
    assert!(
        dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
        "collapsed IPv6 not detected: {dets:?}"
    );
    assert!(result.contains("[IP_ADDRESS_"));
    assert_eq!(
        dets.iter()
            .find(|d| d.entity_type == "IP_ADDRESS")
            .map(|d| d.original.as_str()),
        Some("2001:db8::1"),
        "collapsed IPv6 detection must cover the complete address"
    );
}

#[test]
fn test_ipv6_loopback() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("localhost is ::1");
    assert!(
        dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
        "loopback ::1 not detected: {dets:?}"
    );
    assert!(result.contains("[IP_ADDRESS_"));
}

#[test]
fn test_ipv6_link_local() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("interface fe80::1%eth0");
    assert!(
        dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
        "link-local IPv6 not detected: {dets:?}"
    );
    assert!(result.contains("[IP_ADDRESS_"));
}

#[test]
fn test_ipv6_mapped_v4() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("mapped ::ffff:192.168.1.1");
    assert!(
        dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
        "IPv4-mapped IPv6 not detected: {dets:?}"
    );
    assert!(result.contains("[IP_ADDRESS_"));
    assert_eq!(
        dets.iter()
            .find(|d| d.entity_type == "IP_ADDRESS")
            .map(|d| d.original.as_str()),
        Some("::ffff:192.168.1.1"),
        "IPv4-mapped IPv6 detection must cover the complete address"
    );
}

#[test]
fn test_ipv6_does_not_match_random_hex() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("token abcd:ef01:2345");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
        "short hex groups should not be IPv6: {dets:?}"
    );
}

#[test]
fn test_ipv4_still_works() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("server at 10.0.0.1");
    assert!(
        dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
        "IPv4 should still work: {dets:?}"
    );
    assert!(result.contains("[IP_ADDRESS_"));
}

#[test]
fn test_ipv6_real_world_dns() {
    let mut a = Anonymizer::new(0.0);
    // Google public DNS
    let (result, dets) = a.anonymize_text("dns server 2001:4860:4860::8888");
    assert!(
        dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
        "Google DNS IPv6 not detected: {dets:?}"
    );
    assert!(result.contains("[IP_ADDRESS_"));
}

#[test]
fn test_ipv6_documentation_prefix() {
    let mut a = Anonymizer::new(0.0);
    // 2001:db8::/32 is documentation prefix
    let (result, dets) = a.anonymize_text("example 2001:db8:1::ab9:C0A8:102");
    assert!(
        dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
        "documentation IPv6 not detected: {dets:?}"
    );
    assert!(result.contains("[IP_ADDRESS_"));
}

#[test]
fn test_ipv6_uppercase() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("host 2001:0DB8:85A3:0000:0000:8A2E:0370:7334");
    assert!(
        dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
        "uppercase IPv6 not detected: {dets:?}"
    );
    assert!(result.contains("[IP_ADDRESS_"));
}

#[test]
fn test_ipv6_trailing_double_colon() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("prefix 2001:db8::");
    assert!(
        dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
        "trailing :: IPv6 not detected: {dets:?}"
    );
    assert!(result.contains("[IP_ADDRESS_"));
}

#[test]
fn test_ipv6_mapped_v4_private() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("mapped ::ffff:10.0.0.1");
    assert!(
        dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
        "IPv4-mapped private not detected: {dets:?}"
    );
    assert!(result.contains("[IP_ADDRESS_"));
}

#[test]
fn test_ipv6_in_url_bracket() {
    let mut a = Anonymizer::new(0.0);
    // IPv6 in URL brackets — URL should be detected
    let (result, dets) = a.anonymize_text("visit http://[2001:db8::1]:8080/path");
    assert!(
        dets.iter().any(|d| d.entity_type == "URL"),
        "URL with IPv6 not detected: {dets:?}"
    );
    assert!(result.contains("[URL_"));
}

#[test]
fn test_ipv6_and_ipv4_together() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("primary 192.168.1.1 secondary 2001:db8::1");
    let ip_dets: Vec<_> = dets
        .iter()
        .filter(|d| d.entity_type == "IP_ADDRESS")
        .collect();
    assert_eq!(
        ip_dets.len(),
        2,
        "should detect both IPv4 and IPv6: {ip_dets:?}"
    );
    assert!(result.contains("[IP_ADDRESS_"));
}

#[test]
fn test_ipv6_not_hex_string() {
    let mut a = Anonymizer::new(0.0);
    // Random hex without colons should not match
    let (_, dets) = a.anonymize_text("hash 0db885a30000000008a2e03707334");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
        "hex string without colons should not be IPv6: {dets:?}"
    );
}

#[test]
fn test_ipv6_consistency() {
    let mut a = Anonymizer::new(0.0);
    let (_, _) = a.anonymize_text("host 2001:db8::1 and 2001:db8::1");
    let tokens: Vec<_> = a
        .mapping
        .mappings
        .keys()
        .filter(|k| k.starts_with("[IP_ADDRESS_"))
        .collect();
    assert_eq!(tokens.len(), 1, "same IPv6 should map to one token");
}
