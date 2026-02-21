//! Validation functions for PII patterns.
//!
//! These validators are used by the detection pipeline to filter out false positives
//! based on checksum validation (Luhn, mod-97, etc.) or structural rules.

/// Validate US SSN: reject invalid area numbers (000, 666, 900-999),
/// zero middle group (00), and zero serial group (0000).
pub fn valid_us_ssn(ssn: &str) -> bool {
    let digits: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 9 {
        return false;
    }
    let area: u32 = digits[0..3].parse().unwrap_or(0);
    let group: u32 = digits[3..5].parse().unwrap_or(0);
    let serial: u32 = digits[5..9].parse().unwrap_or(0);
    // Area 000, 666, 900-999 are invalid
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }
    if group == 0 || serial == 0 {
        return false;
    }
    true
}

/// Reject broadcast (ff:ff:ff:ff:ff:ff) and null (00:00:00:00:00:00) MAC addresses.
pub fn valid_mac(mac: &str) -> bool {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase();
    hex.len() == 12 && hex != "000000000000" && hex != "ffffffffffff"
}

/// IBAN mod-97 validation (ISO 7064).
/// Move first 4 chars to end, convert letters (A=10..Z=35), compute mod 97 == 1.
pub fn iban_mod97(iban: &str) -> bool {
    let clean: String = iban.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if clean.len() < 5 {
        return false;
    }
    // Rearrange: move first 4 chars to end
    let rearranged = format!("{}{}", &clean[4..], &clean[..4]);
    // Convert to digit string: letters become two-digit numbers (A=10..Z=35)
    let mut digits = String::with_capacity(rearranged.len() * 2);
    for c in rearranged.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else {
            let val = (c.to_ascii_uppercase() as u32) - b'A' as u32 + 10;
            digits.push_str(&val.to_string());
        }
    }
    // Compute mod 97 on the large number (process in chunks to avoid bigint)
    let mut remainder: u64 = 0;
    for ch in digits.chars() {
        remainder = remainder * 10 + ch.to_digit(10).unwrap() as u64;
        remainder %= 97;
    }
    remainder == 1
}

/// Luhn algorithm validation for credit card numbers.
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
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Validate that a matched number starts with a known card issuer prefix (IIN/BIN).
/// Covers Visa, Mastercard, Amex, Discover, Diners Club, JCB, UnionPay, and Maestro.
pub fn valid_card_prefix(number: &str) -> bool {
    let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 13 {
        return false;
    }

    let d = digits.as_bytes();
    let d1 = d[0];
    let d2 = &digits[..2];
    let d4 = if digits.len() >= 4 { &digits[..4] } else { "" };
    let d6 = if digits.len() >= 6 { &digits[..6] } else { "" };

    // Visa: starts with 4
    if d1 == b'4' {
        return true;
    }

    // Mastercard: 51-55 or 2221-2720
    if let Ok(n2) = d2.parse::<u32>() {
        if (51..=55).contains(&n2) {
            return true;
        }
    }
    if d4.len() == 4 {
        if let Ok(n4) = d4.parse::<u32>() {
            if (2221..=2720).contains(&n4) {
                return true;
            }
        }
    }

    // Amex: 34, 37
    if d2 == "34" || d2 == "37" {
        return true;
    }

    // Discover: 6011, 622126-622925, 644-649, 65
    if d4 == "6011" || d2 == "65" {
        return true;
    }
    if let Ok(n3) = digits[..3].parse::<u32>() {
        if (644..=649).contains(&n3) {
            return true;
        }
    }
    if d6.len() == 6 {
        if let Ok(n6) = d6.parse::<u64>() {
            if (622126..=622925).contains(&n6) {
                return true;
            }
        }
    }

    // JCB: 3528-3589
    if d4.len() == 4 {
        if let Ok(n4) = d4.parse::<u32>() {
            if (3528..=3589).contains(&n4) {
                return true;
            }
        }
    }

    // UnionPay: 62
    if d2 == "62" {
        return true;
    }

    // Maestro: 5018, 5020, 5038, 5893, 6304, 6759, 6761, 6762, 6763
    if matches!(
        d4,
        "5018" | "5020" | "5038" | "5893" | "6304" | "6759" | "6761" | "6762" | "6763"
    ) {
        return true;
    }

    // Diners Club: 300-305, 36, 38
    if d2 == "36" || d2 == "38" {
        return true;
    }
    if digits.len() >= 3 {
        if let Ok(n3) = digits[..3].parse::<u32>() {
            if (300..=305).contains(&n3) {
                return true;
            }
        }
    }

    false
}

/// ABA routing number validation: 9-digit, valid Federal Reserve prefix, weighted checksum.
/// Weights `[3,7,1,3,7,1,3,7,1]` mod-10 must equal 0.
pub fn valid_aba_routing(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 9 {
        return false;
    }
    // Valid Federal Reserve routing symbol (first 2 digits)
    let prefix = digits[0] * 10 + digits[1];
    let valid_prefix = (1..=12).contains(&prefix)
        || (21..=32).contains(&prefix)
        || (61..=72).contains(&prefix)
        || prefix == 80;
    if !valid_prefix {
        return false;
    }
    let weights = [3u32, 7, 1, 3, 7, 1, 3, 7, 1];
    let sum: u32 = digits
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    sum.is_multiple_of(10)
}

/// Validate US ITIN: must start with 9, group digits (4th-5th) in valid ranges
/// (50-65, 70-88, 90-92, 94-99).
pub fn valid_us_itin(s: &str) -> bool {
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 9 {
        return false;
    }
    if !digits.starts_with('9') {
        return false;
    }
    let group: u32 = digits[3..5].parse().unwrap_or(0);
    matches!(group, 50..=65 | 70..=88 | 90..=92 | 94..=99)
}

/// UK NHS Number mod-11 checksum validation.
/// Weights `[10,9,8,7,6,5,4,3,2]` applied to first 9 digits.
/// `(11 - sum % 11)` must equal the 10th digit. Result of 11 → check digit 0; result of 10 → invalid.
pub fn valid_uk_nhs(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 10 {
        return false;
    }
    let weights = [10u32, 9, 8, 7, 6, 5, 4, 3, 2];
    let sum: u32 = digits[..9]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let remainder = 11 - (sum % 11);
    if remainder == 11 {
        digits[9] == 0
    } else if remainder == 10 {
        false // invalid number
    } else {
        digits[9] == remainder
    }
}

/// Shared mod-23 letter table for Spanish NIF/NIE validation.
const ES_NIF_LETTERS: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";

/// ES NIF validation: `8_digits % 23` must match the control letter.
pub fn valid_es_nif(s: &str) -> bool {
    let upper = s.to_ascii_uppercase();
    let digits: String = upper.chars().filter(|c| c.is_ascii_digit()).collect();
    let letter: Option<char> = upper.chars().rfind(|c| c.is_ascii_alphabetic());
    if digits.len() != 8 {
        return false;
    }
    let Some(letter) = letter else {
        return false;
    };
    let num: u32 = match digits.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let expected = ES_NIF_LETTERS[(num % 23) as usize] as char;
    letter == expected
}

/// ES NIE validation: replace prefix X→0, Y→1, Z→2, then same mod-23 check.
pub fn valid_es_nie(s: &str) -> bool {
    let upper = s.to_ascii_uppercase();
    let chars: Vec<char> = upper
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if chars.is_empty() {
        return false;
    }
    let prefix_digit = match chars[0] {
        'X' => '0',
        'Y' => '1',
        'Z' => '2',
        _ => return false,
    };
    let digits: String = std::iter::once(prefix_digit)
        .chain(chars[1..].iter().filter(|c| c.is_ascii_digit()).copied())
        .collect();
    let letter: Option<char> = chars.iter().rfind(|c| c.is_ascii_alphabetic()).copied();
    if digits.len() != 8 {
        return false;
    }
    let Some(letter) = letter else {
        return false;
    };
    let num: u32 = match digits.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let expected = ES_NIF_LETTERS[(num % 23) as usize] as char;
    letter == expected
}

/// Italian fiscal code (codice fiscale) checksum validation.
/// 16-char code: positions use different value tables for odd (1st, 3rd, …) and even (2nd, 4th, …)
/// positions. Sum mod 26 must equal the 16th character (check letter).
pub fn valid_it_fiscal_code(s: &str) -> bool {
    let upper: Vec<u8> = s
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric())
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if upper.len() != 16 {
        return false;
    }

    // Odd-position values (1-indexed positions 1,3,5,…15 → 0-indexed 0,2,4,…14)
    fn odd_value(c: u8) -> Option<u32> {
        match c {
            b'0' | b'A' => Some(1),
            b'1' | b'B' => Some(0),
            b'2' | b'C' => Some(5),
            b'3' | b'D' => Some(7),
            b'4' | b'E' => Some(9),
            b'5' | b'F' => Some(13),
            b'6' | b'G' => Some(15),
            b'7' | b'H' => Some(17),
            b'8' | b'I' => Some(19),
            b'9' | b'J' => Some(21),
            b'K' => Some(2),
            b'L' => Some(4),
            b'M' => Some(18),
            b'N' => Some(20),
            b'O' => Some(11),
            b'P' => Some(3),
            b'Q' => Some(6),
            b'R' => Some(8),
            b'S' => Some(12),
            b'T' => Some(14),
            b'U' => Some(16),
            b'V' => Some(10),
            b'W' => Some(22),
            b'X' => Some(25),
            b'Y' => Some(24),
            b'Z' => Some(23),
            _ => None,
        }
    }

    // Even-position values: letters A=0..Z=25, digits 0..9
    fn even_value(c: u8) -> Option<u32> {
        match c {
            b'0'..=b'9' => Some((c - b'0') as u32),
            b'A'..=b'Z' => Some((c - b'A') as u32),
            _ => None,
        }
    }

    let mut sum: u32 = 0;
    for (i, &c) in upper[..15].iter().enumerate() {
        let val = if i % 2 == 0 {
            // 0-indexed even = 1-indexed odd
            odd_value(c)
        } else {
            even_value(c)
        };
        match val {
            Some(v) => sum += v,
            None => return false,
        }
    }

    let expected = b'A' + (sum % 26) as u8;
    upper[15] == expected
}

/// UK NINO prefix blocklist validation.
/// Rejects invalid prefix pairs: BG, GB, NK, KN, NT, TN, ZZ.
pub fn valid_uk_nino(s: &str) -> bool {
    let prefix: String = s
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .take(2)
        .collect::<String>()
        .to_ascii_uppercase();
    if prefix.len() != 2 {
        return false;
    }
    !matches!(
        prefix.as_str(),
        "BG" | "GB" | "NK" | "KN" | "NT" | "TN" | "ZZ"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iban_mod97_valid() {
        assert!(iban_mod97("DE89370400440532013000"));
        assert!(iban_mod97("GB29NWBK60161331926819"));
        assert!(iban_mod97("ES9121000418450200051332"));
        assert!(iban_mod97("FR7630006000011234567890189"));
        // With spaces
        assert!(iban_mod97("DE89 3704 0044 0532 0130 00"));
        assert!(iban_mod97("GB29 NWBK 6016 1331 9268 19"));
    }

    #[test]
    fn test_iban_mod97_invalid() {
        assert!(!iban_mod97("DE00370400440532013000")); // bad check digits
        assert!(!iban_mod97("XX12345")); // too short / garbage
        assert!(!iban_mod97("DE89370400440532013001")); // off by one
    }

    #[test]
    fn test_luhn_valid_cards() {
        // Known valid test card numbers
        assert!(luhn_check("4111111111111111")); // Visa
        assert!(luhn_check("5500000000000004")); // Mastercard
        assert!(luhn_check("340000000000009")); // Amex (15 digits)
        assert!(luhn_check("6011000000000004")); // Discover
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!luhn_check("4111111111111112")); // off by one
        assert!(!luhn_check("1234567890123456")); // random
        assert!(!luhn_check("123")); // too short
    }

    #[test]
    fn test_valid_card_prefix_known_issuers() {
        assert!(valid_card_prefix("4111111111111111")); // Visa
        assert!(valid_card_prefix("5100000000000000")); // Mastercard 51
        assert!(valid_card_prefix("5500000000000000")); // Mastercard 55
        assert!(valid_card_prefix("2221000000000000")); // Mastercard 2221
        assert!(valid_card_prefix("2720000000000000")); // Mastercard 2720
        assert!(valid_card_prefix("340000000000000")); // Amex 34
        assert!(valid_card_prefix("370000000000000")); // Amex 37
        assert!(valid_card_prefix("6011000000000000")); // Discover
        assert!(valid_card_prefix("6500000000000000")); // Discover 65
        assert!(valid_card_prefix("3528000000000000")); // JCB
        assert!(valid_card_prefix("6200000000000000")); // UnionPay
        assert!(valid_card_prefix("3600000000000000")); // Diners 36
    }

    #[test]
    fn test_valid_card_prefix_rejects_unknown() {
        // Numbers starting with digits not assigned to any major issuer
        assert!(!valid_card_prefix("0000000000000000"));
        assert!(!valid_card_prefix("1000000000000000"));
        assert!(!valid_card_prefix("7000000000000000"));
        assert!(!valid_card_prefix("8000000000000000"));
        assert!(!valid_card_prefix("9000000000000000"));
    }

    #[test]
    fn test_valid_card_prefix_with_separators() {
        // Digits are filtered, so separators shouldn't matter
        assert!(valid_card_prefix("4111 1111 1111 1111"));
        assert!(valid_card_prefix("4111-1111-1111-1111"));
    }

    #[test]
    fn test_combined_luhn_and_prefix_rejects_random_16_digit() {
        // 9999999999999999 - no valid prefix, even if it somehow passed Luhn
        assert!(!valid_card_prefix("9999999999999999"));
        // 1234567890123456 - prefix 1 is not a known issuer
        assert!(!valid_card_prefix("1234567890123456"));
    }

    // ── iban_mod97 battle tests ──

    #[test]
    fn test_iban_mod97_all_countries() {
        // Real IBANs from various countries (all pass mod-97)
        let valid = [
            "GB29NWBK60161331926819",      // UK
            "DE89370400440532013000",      // Germany
            "FR7630006000011234567890189", // France
            "ES9121000418450200051332",    // Spain
            "IT60X0542811101000000123456", // Italy
            "NL91ABNA0417164300",          // Netherlands
            "BE68539007547034",            // Belgium
            "CH9300762011623852957",       // Switzerland
            "AT611904300234573201",        // Austria
            "PT50000201231234567890154",   // Portugal
        ];
        for iban in &valid {
            assert!(iban_mod97(iban), "valid IBAN rejected: {iban}");
        }
    }

    #[test]
    fn test_iban_mod97_with_various_spacing() {
        // Same IBAN with different spacing styles
        assert!(iban_mod97("DE89 3704 0044 0532 0130 00"));
        assert!(iban_mod97("DE89370400440532013000"));
        assert!(iban_mod97("DE 89 37 04 00 44 05 32 01 30 00"));
    }

    #[test]
    fn test_iban_mod97_check_digit_variations() {
        // Only check digit 89 is valid for this BBAN
        assert!(iban_mod97("DE89370400440532013000"));
        assert!(!iban_mod97("DE88370400440532013000"));
        assert!(!iban_mod97("DE90370400440532013000"));
        assert!(!iban_mod97("DE00370400440532013000"));
        assert!(!iban_mod97("DE99370400440532013000"));
    }

    #[test]
    fn test_iban_mod97_edge_too_short() {
        assert!(!iban_mod97("DE89"));
        assert!(!iban_mod97(""));
        assert!(!iban_mod97("AB"));
    }

    // ── valid_mac battle tests ──

    #[test]
    fn test_valid_mac_normal() {
        assert!(valid_mac("00:1A:2B:3C:4D:5E"));
        assert!(valid_mac("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn test_valid_mac_all_formats() {
        assert!(valid_mac("00:1A:2B:3C:4D:5E")); // colon
        assert!(valid_mac("00-1A-2B-3C-4D-5E")); // hyphen
        assert!(valid_mac("001A.2B3C.4D5E")); // cisco
    }

    #[test]
    fn test_valid_mac_rejects_special() {
        assert!(!valid_mac("ff:ff:ff:ff:ff:ff")); // broadcast
        assert!(!valid_mac("00:00:00:00:00:00")); // null
        assert!(!valid_mac("FF:FF:FF:FF:FF:FF")); // broadcast uppercase
    }

    #[test]
    fn test_valid_mac_near_boundaries() {
        assert!(valid_mac("00:00:00:00:00:01")); // just above null
        assert!(valid_mac("ff:ff:ff:ff:ff:fe")); // just below broadcast
    }

    // ── valid_us_ssn battle tests ──

    #[test]
    fn test_valid_us_ssn_good_numbers() {
        assert!(valid_us_ssn("123-45-6789"));
        assert!(valid_us_ssn("001-01-0001")); // minimum valid
        assert!(valid_us_ssn("899-99-9999")); // max area < 900
        assert!(valid_us_ssn("123 45 6789")); // spaces
        assert!(valid_us_ssn("123456789")); // compact
    }

    #[test]
    fn test_valid_us_ssn_all_invalid_areas() {
        assert!(!valid_us_ssn("000-12-3456")); // area 000
        assert!(!valid_us_ssn("666-12-3456")); // area 666
        assert!(!valid_us_ssn("900-12-3456")); // area 900
        assert!(!valid_us_ssn("999-12-3456")); // area 999
    }

    #[test]
    fn test_valid_us_ssn_zero_groups() {
        assert!(!valid_us_ssn("123-00-6789")); // zero middle
        assert!(!valid_us_ssn("123-45-0000")); // zero serial
        assert!(!valid_us_ssn("123-00-0000")); // both zero
    }

    #[test]
    fn test_valid_us_ssn_wrong_length() {
        assert!(!valid_us_ssn("12-34-5678")); // too few digits
        assert!(!valid_us_ssn("1234-56-78901")); // too many digits
        assert!(!valid_us_ssn("")); // empty
    }

    // ── valid_aba_routing tests ──

    #[test]
    fn test_valid_aba_routing_known_good() {
        // Chase Manhattan: 021000021 → 0*3+2*7+1*1+0*3+0*7+0*1+0*3+2*7+1*1 = 0+14+1+0+0+0+0+14+1 = 30
        assert!(valid_aba_routing("021000021"));
        // Bank of America: 026009593
        assert!(valid_aba_routing("026009593"));
        // Wells Fargo: 121000248
        assert!(valid_aba_routing("121000248"));
    }

    #[test]
    fn test_valid_aba_routing_rejects_bad_checksum() {
        assert!(!valid_aba_routing("021000022")); // off by one
        assert!(!valid_aba_routing("123456789")); // random
    }

    #[test]
    fn test_valid_aba_routing_rejects_bad_prefix() {
        assert!(!valid_aba_routing("002000021")); // prefix 00 invalid
        assert!(!valid_aba_routing("132000021")); // prefix 13 invalid (gap 13-20)
        assert!(!valid_aba_routing("992000021")); // prefix 99 invalid
    }

    #[test]
    fn test_valid_aba_routing_rejects_wrong_length() {
        assert!(!valid_aba_routing("02100002")); // 8 digits
        assert!(!valid_aba_routing("0210000210")); // 10 digits
        assert!(!valid_aba_routing(""));
    }

    // ── valid_us_itin tests ──

    #[test]
    fn test_valid_us_itin_good_numbers() {
        assert!(valid_us_itin("912-70-1234")); // group 70
        assert!(valid_us_itin("999-88-5678")); // group 88
        assert!(valid_us_itin("900-50-0001")); // group 50
        assert!(valid_us_itin("950-94-9999")); // group 94
        assert!(valid_us_itin("912701234")); // compact
    }

    #[test]
    fn test_valid_us_itin_rejects_non_nine_prefix() {
        assert!(!valid_us_itin("123-70-1234")); // doesn't start with 9
        assert!(!valid_us_itin("800-70-1234")); // starts with 8
    }

    #[test]
    fn test_valid_us_itin_rejects_invalid_groups() {
        assert!(!valid_us_itin("900-00-1234")); // group 00
        assert!(!valid_us_itin("900-49-1234")); // group 49 (below 50)
        assert!(!valid_us_itin("900-66-1234")); // group 66 (gap 66-69)
        assert!(!valid_us_itin("900-89-1234")); // group 89 (gap 89)
        assert!(!valid_us_itin("900-93-1234")); // group 93 (gap 93)
    }

    #[test]
    fn test_valid_us_itin_wrong_length() {
        assert!(!valid_us_itin("912-70-123")); // 8 digits
        assert!(!valid_us_itin("912-70-12345")); // 10 digits
    }

    // ── valid_uk_nhs tests ──

    #[test]
    fn test_valid_uk_nhs_known_good() {
        // 943 476 5919: sum = 9*10+4*9+3*8+4*7+7*6+6*5+5*4+9*3+1*2 = 90+36+24+28+42+30+20+27+2 = 299
        // 11 - (299 % 11) = 11 - 2 = 9 → check digit 9 ✓
        assert!(valid_uk_nhs("9434765919"));
        assert!(valid_uk_nhs("943 476 5919")); // spaced format
    }

    #[test]
    fn test_valid_uk_nhs_check_digit_zero() {
        // sum=0 → 0%11=0 → 11-0=11 → check digit 0
        assert!(valid_uk_nhs("0000000000"));
    }

    #[test]
    fn test_valid_uk_nhs_rejects_bad_checksum() {
        // Flip last digit
        assert!(!valid_uk_nhs("9434765910"));
        assert!(!valid_uk_nhs("9434765918"));
    }

    #[test]
    fn test_valid_uk_nhs_rejects_remainder_10() {
        // 4*10+3*9=67 → 67%11=1 → 11-1=10 → no valid check digit
        assert!(!valid_uk_nhs("4300000000"));
        assert!(!valid_uk_nhs("4300000001"));
    }

    #[test]
    fn test_valid_uk_nhs_wrong_length() {
        assert!(!valid_uk_nhs("943476591")); // 9 digits
        assert!(!valid_uk_nhs("94347659199")); // 11 digits
        assert!(!valid_uk_nhs(""));
    }

    // ── valid_uk_nino tests ──

    #[test]
    fn test_valid_uk_nino_good_prefixes() {
        assert!(valid_uk_nino("AB 12 34 56 C"));
        assert!(valid_uk_nino("CE123456A"));
        assert!(valid_uk_nino("WR 99 99 99 D"));
    }

    #[test]
    fn test_valid_uk_nino_rejects_blocklisted_prefixes() {
        assert!(!valid_uk_nino("BG 12 34 56 A"));
        assert!(!valid_uk_nino("GB 12 34 56 A"));
        assert!(!valid_uk_nino("NK 12 34 56 A"));
        assert!(!valid_uk_nino("KN 12 34 56 A"));
        assert!(!valid_uk_nino("NT 12 34 56 A"));
        assert!(!valid_uk_nino("TN 12 34 56 A"));
        assert!(!valid_uk_nino("ZZ 12 34 56 A"));
    }

    #[test]
    fn test_valid_uk_nino_case_insensitive() {
        assert!(valid_uk_nino("ab 12 34 56 c"));
        assert!(!valid_uk_nino("bg 12 34 56 a"));
    }

    #[test]
    fn test_valid_uk_nino_no_alpha() {
        assert!(!valid_uk_nino("12345678")); // no prefix letters at all
    }

    // ── valid_es_nif tests ──

    #[test]
    fn test_valid_es_nif_known_good() {
        // 12345678 % 23 = 14 → 'Z'
        assert!(valid_es_nif("12345678Z"));
        // 00000000 % 23 = 0 → 'T'
        assert!(valid_es_nif("00000000T"));
        // 00000001 % 23 = 1 → 'R'
        assert!(valid_es_nif("00000001R"));
        // With separator
        assert!(valid_es_nif("12345678-Z"));
    }

    #[test]
    fn test_valid_es_nif_rejects_bad_letter() {
        assert!(!valid_es_nif("12345678A")); // expected Z
        assert!(!valid_es_nif("00000000R")); // expected T
    }

    #[test]
    fn test_valid_es_nif_wrong_length() {
        assert!(!valid_es_nif("1234567Z")); // 7 digits
        assert!(!valid_es_nif("123456789Z")); // 9 digits
        assert!(!valid_es_nif("")); // empty
    }

    #[test]
    fn test_valid_es_nif_case_insensitive() {
        assert!(valid_es_nif("12345678z")); // lowercase
    }

    // ── valid_es_nie tests ──

    #[test]
    fn test_valid_es_nie_known_good() {
        // X1234567: X→0, 01234567 % 23 = 1234567 % 23 = 19 → 'L'
        assert!(valid_es_nie("X1234567L"));
        // Y1234567: Y→1, 11234567 % 23 = 10 → 'X'
        assert!(valid_es_nie("Y1234567X"));
        // Z1234567: Z→2, 21234567 % 23 = 1 → 'R'
        assert!(valid_es_nie("Z1234567R"));
    }

    #[test]
    fn test_valid_es_nie_with_separators() {
        assert!(valid_es_nie("X-1234567-L"));
        assert!(valid_es_nie("X 1234567 L"));
    }

    #[test]
    fn test_valid_es_nie_rejects_bad_letter() {
        assert!(!valid_es_nie("X1234567A")); // expected L
        assert!(!valid_es_nie("Y1234567A")); // expected X
    }

    #[test]
    fn test_valid_es_nie_rejects_bad_prefix() {
        assert!(!valid_es_nie("A1234567L")); // must be X, Y, or Z
        assert!(!valid_es_nie("W1234567L"));
    }

    #[test]
    fn test_valid_es_nie_wrong_length() {
        assert!(!valid_es_nie("X123456L")); // 6 digits
        assert!(!valid_es_nie("X12345678L")); // 8 digits
        assert!(!valid_es_nie("")); // empty
    }

    #[test]
    fn test_valid_es_nie_case_insensitive() {
        assert!(valid_es_nie("x1234567l")); // lowercase
    }

    // ── valid_it_fiscal_code tests ──

    #[test]
    fn test_valid_it_fiscal_code_constructed() {
        // AAABBB00A00A000: all positions computed manually
        // Odd (0,2,4,6,8,10,12,14): A(1)+A(1)+B(0)+0(1)+A(1)+0(1)+0(1)+0(1) = 7
        // Even (1,3,5,7,9,11,13): A(0)+B(1)+B(1)+0(0)+0(0)+A(0)+0(0) = 2
        // Total=9, 9%26=9 → 'J'
        assert!(valid_it_fiscal_code("AAABBB00A00A000J"));
    }

    #[test]
    fn test_valid_it_fiscal_code_wrong_check() {
        assert!(!valid_it_fiscal_code("AAABBB00A00A000K")); // expected J
        assert!(!valid_it_fiscal_code("AAABBB00A00A000A")); // expected J
    }

    #[test]
    fn test_valid_it_fiscal_code_wrong_length() {
        assert!(!valid_it_fiscal_code("AAABBB00A00A00J")); // 15 chars
        assert!(!valid_it_fiscal_code("AAABBB00A00A0000J")); // 17 chars
        assert!(!valid_it_fiscal_code("")); // empty
    }

    #[test]
    fn test_valid_it_fiscal_code_case_insensitive() {
        assert!(valid_it_fiscal_code("aaabbb00a00a000j")); // lowercase
        assert!(valid_it_fiscal_code("AaAbBb00A00a000J")); // mixed case
    }

    #[test]
    fn test_valid_it_fiscal_code_various_valid() {
        // BNCLRD99A01H501: B(0)+N(13)+C(5)+L(11)+R(8)+D(3)+9(21)+9(9)+A(1)+0(0)+1(0)+H(7)+5(13)+0(0)+1(0) = 91
        // Odd: B(0)+C(5)+R(8)+9(21)+A(1)+1(0)+5(13)+1(0) = 48
        // Even: N(13)+L(11)+D(3)+9(9)+0(0)+H(7)+0(0) = 43
        // Total=91, 91%26=13 → 'N'
        assert!(valid_it_fiscal_code("BNCLRD99A01H501N"));
    }
}
