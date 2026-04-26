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
                if doubled > 9 { doubled - 9 } else { doubled }
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

/// AU ABN (Australian Business Number) weighted checksum validation.
/// Subtract 1 from first digit, multiply by weights `[10,1,3,5,7,9,11,13,15,17,19]`,
/// sum mod 89 must equal 0.
pub fn valid_au_abn(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 11 {
        return false;
    }
    let weights: [u32; 11] = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
    let mut adjusted = digits.clone();
    adjusted[0] = adjusted[0].wrapping_sub(1); // subtract 1 from first digit
    let sum: u32 = adjusted
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    sum.is_multiple_of(89)
}

/// AU ACN (Australian Company Number) checksum validation.
/// Weights `[8,7,6,5,4,3,2,1]` on first 8 digits, check digit = `(10 - sum % 10) % 10`.
pub fn valid_au_acn(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 9 {
        return false;
    }
    let weights: [u32; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
    let sum: u32 = digits[..8]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let check = (10 - (sum % 10)) % 10;
    digits[8] == check
}

/// AU TFN (Tax File Number) weighted checksum validation.
/// Weights `[1,4,3,7,5,8,6,9,10]`, sum mod 11 must equal 0.
pub fn valid_au_tfn(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 9 {
        return false;
    }
    let weights: [u32; 9] = [1, 4, 3, 7, 5, 8, 6, 9, 10];
    let sum: u32 = digits
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    sum.is_multiple_of(11)
}

/// AU Medicare number checksum validation.
/// Weights `[1,3,7,9,1,3,7,9]` on first 8 digits, check digit (9th) = sum % 10.
pub fn valid_au_medicare(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 10 {
        return false;
    }
    let weights: [u32; 8] = [1, 3, 7, 9, 1, 3, 7, 9];
    let sum: u32 = digits[..8]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    digits[8] == sum % 10
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

/// Verhoeff algorithm tables for IN_AADHAAR validation.
/// Based on the dihedral group D5 — catches all single-digit and adjacent transposition errors.
///
/// Verhoeff multiplication table (D5 group).
const VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

/// Verhoeff permutation table.
const VERHOEFF_P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// Verhoeff checksum validation: processes digits right-to-left, result must be 0.
pub fn verhoeff_check(s: &str) -> bool {
    let digits: Vec<u8> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();
    if digits.is_empty() {
        return false;
    }
    let mut c: u8 = 0;
    for (i, &d) in digits.iter().rev().enumerate() {
        let p_idx = i % 8;
        let p_val = VERHOEFF_P[p_idx][d as usize];
        c = VERHOEFF_D[c as usize][p_val as usize];
    }
    c == 0
}

/// IN_AADHAAR validation: Verhoeff checksum + palindrome rejection + first digit 2-9.
pub fn valid_in_aadhaar(s: &str) -> bool {
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 12 {
        return false;
    }
    // First digit must be 2-9
    if digits.as_bytes()[0] < b'2' {
        return false;
    }
    // Reject palindromes (e.g. 123456654321)
    let rev: String = digits.chars().rev().collect();
    if digits == rev {
        return false;
    }
    // Reject repeated digits (e.g. 222222222222)
    if digits.chars().all(|c| c == digits.as_bytes()[0] as char) {
        return false;
    }
    verhoeff_check(&digits)
}

/// IN_GSTIN validation: state code 01-37 (+ 97 for other territory).
pub fn valid_in_gstin(s: &str) -> bool {
    let clean: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase();
    if clean.len() != 15 {
        return false;
    }
    // First 2 digits = state code
    let state: u32 = match clean[..2].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    if !(1..=37).contains(&state) && state != 97 {
        return false;
    }
    true
}

/// KR_RRN (Resident Registration Number) checksum validation.
/// 13 digits: YYMMDD-SBBCCNN. Weights `[2,3,4,5,6,7,8,9,2,3,4,5]` on first 12,
/// check digit = `(11 - sum % 11) % 10`. Gender digit (pos 7) must be 1-4.
pub fn valid_kr_rrn(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 13 {
        return false;
    }
    // Gender digit (7th digit, 0-indexed 6) must be 1-4 for citizens
    if !(1..=4).contains(&digits[6]) {
        return false;
    }
    kr_rrn_checksum(&digits)
}

/// KR_FRN (Foreign Registration Number) checksum validation.
/// Same checksum as KR_RRN but gender digit (pos 7) must be 5-8.
pub fn valid_kr_frn(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 13 {
        return false;
    }
    // Gender digit must be 5-8 for foreigners
    if !(5..=8).contains(&digits[6]) {
        return false;
    }
    kr_rrn_checksum(&digits)
}

/// Shared RRN/FRN checksum: weights [2,3,4,5,6,7,8,9,2,3,4,5], check = (11 - sum%11) % 10.
fn kr_rrn_checksum(digits: &[u32]) -> bool {
    let weights: [u32; 12] = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
    let sum: u32 = digits[..12]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let check = (11 - (sum % 11)) % 10;
    digits[12] == check
}

/// KR_BRN (Business Registration Number) weighted checksum validation.
/// 10 digits: XXX-XX-XXXXX. Weights `[1,3,7,1,3,7,1,3,5]` on first 9.
/// Position 9 has special carry: add `floor(digit[8] * 5 / 10)`.
/// Check digit = `(10 - sum % 10) % 10`.
pub fn valid_kr_brn(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 10 {
        return false;
    }
    let weights: [u32; 9] = [1, 3, 7, 1, 3, 7, 1, 3, 5];
    let mut sum: u32 = digits[..9]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    // Special carry for position 9 (0-indexed 8)
    sum += (digits[8] * 5) / 10;
    let check = (10 - (sum % 10)) % 10;
    digits[9] == check
}

/// SG NRIC/FIN checksum validation.
/// Prefix [STFGM] + 7 digits + check letter. Weights `[2,7,6,5,4,3,2]`,
/// prefix-dependent offset and check letter table.
pub fn valid_sg_nric_fin(s: &str) -> bool {
    let upper = s.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    if bytes.len() != 9 {
        return false;
    }
    let prefix = bytes[0];
    if !matches!(prefix, b'S' | b'T' | b'F' | b'G' | b'M') {
        return false;
    }
    let check_letter = bytes[8];
    if !check_letter.is_ascii_uppercase() {
        return false;
    }

    let digits: Vec<u32> = bytes[1..8]
        .iter()
        .filter_map(|&b| (b as char).to_digit(10))
        .collect();
    if digits.len() != 7 {
        return false;
    }

    let weights: [u32; 7] = [2, 7, 6, 5, 4, 3, 2];
    let sum: u32 = digits
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();

    let offset: u32 = match prefix {
        b'T' | b'G' => 4,
        b'M' => 3,
        _ => 0, // S, F
    };

    let mut index = ((sum + offset) % 11) as usize;

    // S/T prefix: citizen check letter table
    // F/G prefix: foreigner check letter table
    // M prefix: foreigner table with rotation
    let table: &[u8; 11] = match prefix {
        b'S' | b'T' => b"JZIHGFEDCBA",
        b'M' => {
            index = 10 - index;
            b"KLJNPQRTUWX"
        }
        _ => b"XWUTRQPNMLK", // F, G
    };

    check_letter == table[index]
}

/// PL PESEL checksum validation.
/// 11 digits, weights `[1,3,7,9,1,3,7,9,1,3]` on first 10 digits,
/// check digit = `(10 - sum % 10) % 10`.
pub fn valid_pl_pesel(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 11 {
        return false;
    }
    let weights: [u32; 10] = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    let sum: u32 = digits[..10]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let check = (10 - (sum % 10)) % 10;
    digits[10] == check
}

/// SI EMŠO (Enotna Matična Številka Občana) checksum validation.
/// 13 digits: DDMMYYYRRBBBC. Weights `[7,6,5,4,3,2,7,6,5,4,3,2]` on first 12,
/// check digit = `11 - sum % 11`. Result of 11 → K=0; result of 10 → invalid.
/// Regional code (digits 8-9) must be 50-59 for Slovenia.
pub fn valid_si_emso(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 13 {
        return false;
    }
    // Regional code (0-indexed positions 7-8) must be 50-59 for Slovenia
    let region = digits[7] * 10 + digits[8];
    if !(50..=59).contains(&region) {
        return false;
    }
    let weights: [u32; 12] = [7, 6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
    let sum: u32 = digits[..12]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let remainder = sum % 11;
    if remainder == 0 {
        digits[12] == 0
    } else {
        let check = 11 - remainder;
        if check == 10 {
            return false; // cannot encode as single digit
        }
        digits[12] == check
    }
}

/// SI Tax Number (Davčna Številka) checksum validation.
/// 8 digits, first digit 1-9. Weights `[8,7,6,5,4,3,2]` on first 7,
/// check digit = `11 - sum % 11`. Result of 10 → K=0; result of 11 → invalid.
pub fn valid_si_tax_number(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 8 {
        return false;
    }
    // First digit must not be 0
    if digits[0] == 0 {
        return false;
    }
    let weights: [u32; 7] = [8, 7, 6, 5, 4, 3, 2];
    let sum: u32 = digits[..7]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let remainder = sum % 11;
    if remainder == 0 {
        return false; // invalid — check digit would be 11
    }
    let check = 11 - remainder;
    if check == 10 {
        digits[7] == 0
    } else {
        digits[7] == check
    }
}

/// Thai National Identification Number (TNIN) checksum validation.
/// 13 digits, weights `[13,12,11,10,9,8,7,6,5,4,3,2]` on first 12 digits,
/// check digit = `(11 - sum % 11) % 10`.
pub fn valid_th_tnin(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 13 {
        return false;
    }
    let weights: [u32; 12] = [13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2];
    let sum: u32 = digits[..12]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let check = (11 - (sum % 11)) % 10;
    digits[12] == check
}

/// Finnish Personal Identity Code (henkilötunnus / HETU) validation.
/// Format: DDMMYYCSSSQ (11 chars). C = century separator (+, -, Y, A).
/// SSS = individual number (002-899). Q = mod-31 control character from
/// lookup table `"0123456789ABCDEFHJKLMNPRSTUVWXY"`.
pub fn valid_fi_identity_code(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 11 {
        return false;
    }

    // First 6 chars must be digits (DDMMYY)
    if !bytes[..6].iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // Chars 7-9 must be digits (SSS)
    if !bytes[7..10].iter().all(|b| b.is_ascii_digit()) {
        return false;
    }

    let dd: u32 = s[0..2].parse().unwrap_or(0);
    let mm: u32 = s[2..4].parse().unwrap_or(0);

    // Century separator
    let sep = bytes[6].to_ascii_uppercase();
    if !matches!(sep, b'+' | b'-' | b'Y' | b'A') {
        return false;
    }

    // Basic date range check
    if !(1..=31).contains(&dd) || !(1..=12).contains(&mm) {
        return false;
    }

    // Individual number 002-899
    let individual: u32 = s[7..10].parse().unwrap_or(0);
    if !(2..=899).contains(&individual) {
        return false;
    }

    // Mod-31 control character: concatenate DDMMYY + SSS → 9-digit number
    let nine_digits: u64 = match format!("{}{}", &s[0..6], &s[7..10]).parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    const CONTROL_CHARS: &[u8; 31] = b"0123456789ABCDEFHJKLMNPRSTUVWXY";
    let remainder = (nine_digits % 31) as usize;
    let expected = CONTROL_CHARS[remainder];

    bytes[10].to_ascii_uppercase() == expected
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

    // ── verhoeff_check tests ──

    #[test]
    fn test_verhoeff_known_good() {
        // Wikipedia example: "2363" has Verhoeff checksum 0
        assert!(verhoeff_check("2363"));
        // Single-digit zero is valid (trivial)
        assert!(verhoeff_check("0"));
    }

    #[test]
    fn test_verhoeff_known_bad() {
        assert!(!verhoeff_check("2364")); // off by one from valid
        assert!(!verhoeff_check("1234")); // random
    }

    #[test]
    fn test_verhoeff_detects_transpositions() {
        // 2363 is valid; 2633 (swapped 3 and 6) should be invalid
        assert!(verhoeff_check("2363"));
        assert!(!verhoeff_check("2633"));
    }

    #[test]
    fn test_verhoeff_empty() {
        assert!(!verhoeff_check(""));
    }

    // ── valid_in_aadhaar tests ──

    #[test]
    fn test_valid_in_aadhaar_verhoeff() {
        // 12-digit number where Verhoeff passes
        // Build from Verhoeff: "23456789012" → need to compute valid check digit
        // Let's use a known valid Aadhaar: 234567890120 fails, try computing manually
        // For test purposes, use the Verhoeff "generate" logic to find valid numbers
        // 499118665246 — known Aadhaar-format number that passes Verhoeff
        assert!(valid_in_aadhaar("499118665246"));
    }

    #[test]
    fn test_valid_in_aadhaar_rejects_starts_with_0_or_1() {
        assert!(!valid_in_aadhaar("099118665246")); // starts with 0
        assert!(!valid_in_aadhaar("199118665246")); // starts with 1
    }

    #[test]
    fn test_valid_in_aadhaar_rejects_palindrome() {
        // 234565654321 — palindrome should be rejected regardless of checksum
        assert!(!valid_in_aadhaar("234565654321"));
        // 210000000012 — palindrome
        assert!(!valid_in_aadhaar("210000000012"));
    }

    #[test]
    fn test_valid_in_aadhaar_rejects_repeated_digits() {
        assert!(!valid_in_aadhaar("222222222222"));
        assert!(!valid_in_aadhaar("999999999999"));
    }

    #[test]
    fn test_valid_in_aadhaar_wrong_length() {
        assert!(!valid_in_aadhaar("23456789012")); // 11 digits
        assert!(!valid_in_aadhaar("2345678901234")); // 13 digits
        assert!(!valid_in_aadhaar(""));
    }

    #[test]
    fn test_valid_in_aadhaar_with_spaces() {
        // Spaced format should also work (digits are filtered)
        assert!(valid_in_aadhaar("4991 1866 5246"));
    }

    // ── valid_in_gstin tests ──

    #[test]
    fn test_valid_in_gstin_known_good() {
        // State code 27 (Maharashtra) + PAN AAPFU0939F + entity 1 + Z + check V
        assert!(valid_in_gstin("27AAPFU0939F1ZV"));
        // State code 01 (Jammu & Kashmir)
        assert!(valid_in_gstin("01AAPFU0939F1ZV"));
        // State code 37 (Andhra Pradesh)
        assert!(valid_in_gstin("37AAPFU0939F1ZV"));
    }

    #[test]
    fn test_valid_in_gstin_rejects_bad_state_code() {
        assert!(!valid_in_gstin("00AAPFU0939F1ZV")); // state 00 invalid
        assert!(!valid_in_gstin("38AAPFU0939F1ZV")); // state 38 invalid
        assert!(!valid_in_gstin("99AAPFU0939F1ZV")); // state 99 invalid
    }

    #[test]
    fn test_valid_in_gstin_state_code_97() {
        // 97 = "Other territory" — valid special code
        assert!(valid_in_gstin("97AAPFU0939F1ZV"));
    }

    #[test]
    fn test_valid_in_gstin_wrong_length() {
        assert!(!valid_in_gstin("27AAPFU0939F1Z")); // 14 chars
        assert!(!valid_in_gstin("27AAPFU0939F1ZVX")); // 16 chars
        assert!(!valid_in_gstin(""));
    }

    // ── valid_au_abn tests ──

    #[test]
    fn test_valid_au_abn_known_good() {
        // ATO: 51 824 753 556
        // Subtract 1 from first digit: [4,1,8,2,4,7,5,3,5,5,6]
        // Weights: [10,1,3,5,7,9,11,13,15,17,19]
        // Sum: 40+1+24+10+28+63+55+39+75+85+114 = 534, 534 % 89 = 0 ✓
        assert!(valid_au_abn("51824753556"));
        // With spaces
        assert!(valid_au_abn("51 824 753 556"));
        // Telstra: 33 051 775 556
        assert!(valid_au_abn("33051775556"));
    }

    #[test]
    fn test_valid_au_abn_rejects_bad_checksum() {
        assert!(!valid_au_abn("51824753557")); // off by one
        assert!(!valid_au_abn("12345678901")); // random
    }

    #[test]
    fn test_valid_au_abn_wrong_length() {
        assert!(!valid_au_abn("5182475355")); // 10 digits
        assert!(!valid_au_abn("518247535560")); // 12 digits
        assert!(!valid_au_abn(""));
    }

    // ── valid_au_acn tests ──

    #[test]
    fn test_valid_au_acn_known_good() {
        // 000 000 019: weights [8,7,6,5,4,3,2,1] on first 8 → 0+0+0+0+0+0+0+1=1
        // check = (10 - 1%10) % 10 = 9 ✓
        assert!(valid_au_acn("000000019"));
        // Telstra ACN: 004 085 616
        // First 8: 0,0,4,0,8,5,6,1 → 0+0+24+0+32+15+12+1=84
        // check = (10 - 84%10) % 10 = (10-4)%10 = 6 ✓
        assert!(valid_au_acn("004085616"));
        // With spaces
        assert!(valid_au_acn("004 085 616"));
    }

    #[test]
    fn test_valid_au_acn_rejects_bad_checksum() {
        assert!(!valid_au_acn("000000010")); // expected 9
        assert!(!valid_au_acn("004085617")); // off by one
    }

    #[test]
    fn test_valid_au_acn_check_digit_zero() {
        // First 8 digits sum to multiple of 10 → check digit 0
        // 0,0,0,0,0,0,0,0 → sum=0 → (10-0)%10=0
        assert!(valid_au_acn("000000000"));
    }

    #[test]
    fn test_valid_au_acn_wrong_length() {
        assert!(!valid_au_acn("00000001")); // 8 digits
        assert!(!valid_au_acn("0000000190")); // 10 digits
        assert!(!valid_au_acn(""));
    }

    // ── valid_au_tfn tests ──

    #[test]
    fn test_valid_au_tfn_known_good() {
        // 123 456 782: weights [1,4,3,7,5,8,6,9,10]
        // 1+8+9+28+25+48+42+72+20 = 253, 253 % 11 = 0 ✓
        assert!(valid_au_tfn("123456782"));
        // With spaces
        assert!(valid_au_tfn("123 456 782"));
    }

    #[test]
    fn test_valid_au_tfn_rejects_bad_checksum() {
        assert!(!valid_au_tfn("123456789")); // sum=323, 323%11=4 ≠ 0
        assert!(!valid_au_tfn("123456783")); // off by one
    }

    #[test]
    fn test_valid_au_tfn_wrong_length() {
        assert!(!valid_au_tfn("12345678")); // 8 digits
        assert!(!valid_au_tfn("1234567820")); // 10 digits
        assert!(!valid_au_tfn(""));
    }

    // ── valid_au_medicare tests ──

    #[test]
    fn test_valid_au_medicare_known_good() {
        // 2123 45670 1: weights [1,3,7,9,1,3,7,9] on first 8 digits
        // 2*1+1*3+2*7+3*9+4*1+5*3+6*7+7*9 = 2+3+14+27+4+15+42+63 = 170
        // check digit (9th) = 170 % 10 = 0 → digit 9 is 0 ✓
        assert!(valid_au_medicare("2123456701"));
        // With spaces
        assert!(valid_au_medicare("2123 45670 1"));
    }

    #[test]
    fn test_valid_au_medicare_rejects_bad_checksum() {
        assert!(!valid_au_medicare("2123456711")); // check should be 0, not 1
        assert!(!valid_au_medicare("2123456791")); // check should be 0, not 9
    }

    #[test]
    fn test_valid_au_medicare_wrong_length() {
        assert!(!valid_au_medicare("212345670")); // 9 digits
        assert!(!valid_au_medicare(""));
    }

    // ── valid_kr_rrn tests ──

    #[test]
    fn test_valid_kr_rrn_known_good() {
        // 850101-1234561: compute checksum
        // Digits: [8,5,0,1,0,1,1,2,3,4,5,6,1]
        // Weights: [2,3,4,5,6,7,8,9,2,3,4,5]
        // Sum: 16+15+0+5+0+7+8+18+6+12+20+30 = 137
        // (11 - 137%11) % 10 = (11 - 5) % 10 = 6 % 10 = 6
        // But last digit is 1, so this doesn't pass. Let me compute a valid one.
        // 850101-1234566: check = 6 ✓
        assert!(valid_kr_rrn("850101-1234566"));
    }

    #[test]
    fn test_valid_kr_rrn_gender_digits() {
        // Gender digit must be 1-4
        // Use same base with gender=2: 850101-2234560
        // Digits: [8,5,0,1,0,1,2,2,3,4,5,6,0]
        // Sum: 16+15+0+5+0+7+16+18+6+12+20+30 = 145
        // (11 - 145%11) % 10 = (11 - 2) % 10 = 9 % 10 = 9
        // So 850101-2234569 should be valid
        assert!(valid_kr_rrn("850101-2234569"));
    }

    #[test]
    fn test_valid_kr_rrn_rejects_foreign_gender_digit() {
        // Gender digit 5-8 should be rejected (those are for KR_FRN)
        assert!(!valid_kr_rrn("850101-5234566"));
        assert!(!valid_kr_rrn("850101-6234566"));
        assert!(!valid_kr_rrn("850101-7234566"));
        assert!(!valid_kr_rrn("850101-8234566"));
    }

    #[test]
    fn test_valid_kr_rrn_rejects_bad_checksum() {
        assert!(!valid_kr_rrn("850101-1234567")); // expected 6
        assert!(!valid_kr_rrn("850101-1234560")); // expected 6
    }

    #[test]
    fn test_valid_kr_rrn_wrong_length() {
        assert!(!valid_kr_rrn("850101-123456")); // 12 digits
        assert!(!valid_kr_rrn("850101-12345678")); // 14 digits
        assert!(!valid_kr_rrn(""));
    }

    // ── valid_kr_frn tests ──

    #[test]
    fn test_valid_kr_frn_known_good() {
        // 850101-5234560: gender digit 5 (foreign male, 1900s)
        // Digits: [8,5,0,1,0,1,5,2,3,4,5,6,0]
        // Sum: 16+15+0+5+0+7+40+18+6+12+20+30 = 169
        // (11 - 169%11) % 10 = (11 - 4) % 10 = 7 % 10 = 7
        // So 850101-5234567 should be valid
        assert!(valid_kr_frn("850101-5234567"));
    }

    #[test]
    fn test_valid_kr_frn_rejects_citizen_gender_digit() {
        assert!(!valid_kr_frn("850101-1234566")); // gender 1 = citizen
        assert!(!valid_kr_frn("850101-2234569")); // gender 2 = citizen
    }

    #[test]
    fn test_valid_kr_frn_rejects_bad_checksum() {
        assert!(!valid_kr_frn("850101-5234560")); // expected 7
    }

    #[test]
    fn test_valid_kr_frn_wrong_length() {
        assert!(!valid_kr_frn("850101-523456")); // 12 digits
        assert!(!valid_kr_frn(""));
    }

    // ── valid_kr_brn tests ──

    #[test]
    fn test_valid_kr_brn_known_good() {
        // 123-45-67891: compute
        // Digits: [1,2,3,4,5,6,7,8,9,1]
        // Weights: [1,3,7,1,3,7,1,3,5]
        // Products: 1+6+21+4+15+42+7+24+45 = 165
        // Carry: floor(9*5/10) = floor(4.5) = 4
        // Total: 165 + 4 = 169
        // Check: (10 - 169%10) % 10 = (10 - 9) % 10 = 1 ✓
        assert!(valid_kr_brn("123-45-67891"));
        // Compact
        assert!(valid_kr_brn("1234567891"));
    }

    #[test]
    fn test_valid_kr_brn_rejects_bad_checksum() {
        assert!(!valid_kr_brn("123-45-67890")); // expected 1
        assert!(!valid_kr_brn("123-45-67892")); // expected 1
    }

    #[test]
    fn test_valid_kr_brn_wrong_length() {
        assert!(!valid_kr_brn("123-45-6789")); // 9 digits
        assert!(!valid_kr_brn("123-45-678901")); // 11 digits
        assert!(!valid_kr_brn(""));
    }

    #[test]
    fn test_valid_kr_brn_zero_carry() {
        // Test with digit[8] where carry is 0 (digit[8]*5 < 10)
        // digit[8] = 1 → 1*5=5, carry = 0
        // Digits: [1,2,3,4,5,6,7,8,1,?]
        // Products: 1+6+21+4+15+42+7+24+5 = 125
        // Carry: floor(1*5/10) = 0
        // Total: 125
        // Check: (10 - 125%10) % 10 = (10-5)%10 = 5
        assert!(valid_kr_brn("1234567815"));
    }

    // ── valid_sg_nric_fin tests ──

    #[test]
    fn test_valid_sg_nric_fin_s_prefix() {
        // S prefix (citizen, born before 2000), offset=0
        // S1234567: weights [2,7,6,5,4,3,2]
        // sum = 2+14+18+20+20+18+14 = 106
        // index = (106 + 0) % 11 = 7 → table[7] = 'D'
        assert!(valid_sg_nric_fin("S1234567D"));
    }

    #[test]
    fn test_valid_sg_nric_fin_t_prefix() {
        // T prefix (citizen, born 2000+), offset=4
        // T1234567: sum = 106
        // index = (106 + 4) % 11 = 0 → table[0] = 'J'
        assert!(valid_sg_nric_fin("T1234567J"));
    }

    #[test]
    fn test_valid_sg_nric_fin_f_prefix() {
        // F prefix (foreigner, before 2000), offset=0
        // F1234567: sum = 106
        // index = (106 + 0) % 11 = 7 → F/G table[7] = 'N'
        assert!(valid_sg_nric_fin("F1234567N"));
    }

    #[test]
    fn test_valid_sg_nric_fin_g_prefix() {
        // G prefix (foreigner, 2000-2021), offset=4
        // G1234567: sum = 106
        // index = (106 + 4) % 11 = 0 → F/G table[0] = 'X'
        assert!(valid_sg_nric_fin("G1234567X"));
    }

    #[test]
    fn test_valid_sg_nric_fin_m_prefix() {
        // M prefix (foreigner, 2022+), offset=3
        // M1234567: sum = 106
        // index = (106 + 3) % 11 = 10 → rotated: 10 - 10 = 0 → M table[0] = 'K'
        assert!(valid_sg_nric_fin("M1234567K"));
    }

    #[test]
    fn test_valid_sg_nric_fin_rejects_bad_check_letter() {
        assert!(!valid_sg_nric_fin("S1234567A")); // expected D
        assert!(!valid_sg_nric_fin("T1234567A")); // expected J
        assert!(!valid_sg_nric_fin("F1234567A")); // expected N
    }

    #[test]
    fn test_valid_sg_nric_fin_rejects_invalid_prefix() {
        assert!(!valid_sg_nric_fin("A1234567D")); // A is not valid
        assert!(!valid_sg_nric_fin("X1234567D"));
    }

    #[test]
    fn test_valid_sg_nric_fin_wrong_length() {
        assert!(!valid_sg_nric_fin("S123456D")); // 8 chars (6 digits)
        assert!(!valid_sg_nric_fin("S12345678D")); // 10 chars (8 digits)
        assert!(!valid_sg_nric_fin(""));
    }

    #[test]
    fn test_valid_sg_nric_fin_case_insensitive() {
        assert!(valid_sg_nric_fin("s1234567d")); // lowercase
        assert!(valid_sg_nric_fin("s1234567D")); // mixed case
    }

    // ── valid_pl_pesel tests ──

    #[test]
    fn test_valid_pl_pesel_known_good() {
        // 44051401359: weights [1,3,7,9,1,3,7,9,1,3]
        // 4*1+4*3+0*7+5*9+1*1+4*3+0*7+1*9+3*1+5*3 = 4+12+0+45+1+12+0+9+3+15 = 101
        // check = (10 - 101%10) % 10 = (10-1)%10 = 9
        assert!(valid_pl_pesel("44051401359"));
    }

    #[test]
    fn test_valid_pl_pesel_2000s_century() {
        // 02211307589: born 2002-01-13 (month 21 = January 2000s)
        assert!(valid_pl_pesel("02211307589"));
    }

    #[test]
    fn test_valid_pl_pesel_rejects_bad_checksum() {
        assert!(!valid_pl_pesel("44051401358")); // expected 9, got 8
        assert!(!valid_pl_pesel("44051401350")); // expected 9, got 0
    }

    #[test]
    fn test_valid_pl_pesel_wrong_length() {
        assert!(!valid_pl_pesel("4405140135")); // 10 digits
        assert!(!valid_pl_pesel("440514013590")); // 12 digits
        assert!(!valid_pl_pesel(""));
    }

    #[test]
    fn test_valid_pl_pesel_check_digit_zero() {
        // 02122401358: check digit computation
        // 0*1+2*3+1*7+2*9+2*1+4*3+0*7+1*9+3*1+5*3 = 0+6+7+18+2+12+0+9+3+15 = 72
        // check = (10 - 72%10) % 10 = (10-2)%10 = 8
        assert!(valid_pl_pesel("02122401358"));
    }

    // ── valid_si_emso tests ──

    #[test]
    fn test_valid_si_emso_known_good() {
        // 0101006500006: DDMMYYY=0101006, RR=50, BBB=000, K=6
        // Weights: [7,6,5,4,3,2,7,6,5,4,3,2]
        // 0*7+1*6+0*5+1*4+0*3+0*2+6*7+5*6+0*5+0*4+0*3+0*2 = 0+6+0+4+0+0+42+30+0+0+0+0 = 82
        // 82 % 11 = 5, check = 11-5 = 6 ✓
        assert!(valid_si_emso("0101006500006"));
    }

    #[test]
    fn test_valid_si_emso_check_digit_zero() {
        // 0010006500000: sum = 0+0+5+0+0+0+42+30+0+0+0+0 = 77; 77%11=0 → check=0 ✓
        assert!(valid_si_emso("0010006500000"));
    }

    #[test]
    fn test_valid_si_emso_rejects_bad_region() {
        // Region 49 (not Slovenia)
        assert!(!valid_si_emso("0101006490006"));
        // Region 60 (not Slovenia)
        assert!(!valid_si_emso("0101006600006"));
    }

    #[test]
    fn test_valid_si_emso_rejects_bad_checksum() {
        assert!(!valid_si_emso("0101006500007")); // expected 6
        assert!(!valid_si_emso("0101006500005")); // expected 6
    }

    #[test]
    fn test_valid_si_emso_wrong_length() {
        assert!(!valid_si_emso("010100650000")); // 12 digits
        assert!(!valid_si_emso("01010065000060")); // 14 digits
        assert!(!valid_si_emso(""));
    }

    // ── valid_si_tax_number tests ──

    #[test]
    fn test_valid_si_tax_number_known_good() {
        // 15012557: weights [8,7,6,5,4,3,2]
        // 1*8+5*7+0*6+1*5+2*4+5*3+5*2 = 8+35+0+5+8+15+10 = 81
        // 81 % 11 = 4, check = 11-4 = 7 ✓
        assert!(valid_si_tax_number("15012557"));
    }

    #[test]
    fn test_valid_si_tax_number_check_digit_zero() {
        // 10001000: sum = 1*8+0+0+0+1*4+0+0 = 12; 12%11=1 → check=10 → K=0 ✓
        assert!(valid_si_tax_number("10001000"));
    }

    #[test]
    fn test_valid_si_tax_number_rejects_leading_zero() {
        assert!(!valid_si_tax_number("05012557"));
    }

    #[test]
    fn test_valid_si_tax_number_rejects_bad_checksum() {
        assert!(!valid_si_tax_number("15012558")); // expected 7
        assert!(!valid_si_tax_number("15012550")); // expected 7
    }

    #[test]
    fn test_valid_si_tax_number_rejects_remainder_zero() {
        // Need sum % 11 = 0 → invalid (check digit would be 11)
        // d0*8 = 11 → not possible. Need combo: 11k.
        // 10000100 → 1*8+0+0+0+0+1*3+0 = 11; 11%11=0 → INVALID ✓
        assert!(!valid_si_tax_number("10000100"));
    }

    #[test]
    fn test_valid_si_tax_number_wrong_length() {
        assert!(!valid_si_tax_number("1501255")); // 7 digits
        assert!(!valid_si_tax_number("150125570")); // 9 digits
        assert!(!valid_si_tax_number(""));
    }

    // ── valid_fi_identity_code tests ──

    #[test]
    fn test_valid_fi_identity_code_known_good() {
        // 131052-308T: 131052308 % 31 = 131052308 / 31 = 4227493 rem 25
        // CONTROL_CHARS[25] = 'T' ✓
        assert!(valid_fi_identity_code("131052-308T"));
    }

    #[test]
    fn test_valid_fi_identity_code_century_plus() {
        // Born 1800s: 010199+0022
        // 010199002 % 31 = 2 → CONTROL_CHARS[2] = '2'
        assert!(valid_fi_identity_code("010199+0022"));
    }

    #[test]
    fn test_valid_fi_identity_code_century_a() {
        // Born 2000s: 010100A002B
        // 010100002 % 31 = 325806 rem 16 → CONTROL_CHARS[16] = 'H'
        assert!(valid_fi_identity_code("010100A002H"));
    }

    #[test]
    fn test_valid_fi_identity_code_century_y() {
        // Y is alternative 1900s separator
        // 010199002 % 31 = 2 → CONTROL_CHARS[2] = '2'
        assert!(valid_fi_identity_code("010199Y0022"));
    }

    #[test]
    fn test_valid_fi_identity_code_rejects_bad_control() {
        assert!(!valid_fi_identity_code("131052-308A")); // expected T
        assert!(!valid_fi_identity_code("131052-3080")); // expected T
    }

    #[test]
    fn test_valid_fi_identity_code_rejects_bad_date() {
        assert!(!valid_fi_identity_code("320152-308T")); // day 32
        assert!(!valid_fi_identity_code("011352-308T")); // month 13
        assert!(!valid_fi_identity_code("000152-308T")); // day 00
        assert!(!valid_fi_identity_code("010052-308T")); // month 00
    }

    #[test]
    fn test_valid_fi_identity_code_rejects_bad_individual() {
        // Individual number 000 (< 2)
        assert!(!valid_fi_identity_code("131052-000T"));
        // Individual number 001 (< 2)
        assert!(!valid_fi_identity_code("131052-001T"));
        // Individual number 900 (> 899)
        assert!(!valid_fi_identity_code("131052-900T"));
        // Individual number 999 (> 899)
        assert!(!valid_fi_identity_code("131052-999T"));
    }

    #[test]
    fn test_valid_fi_identity_code_rejects_bad_separator() {
        assert!(!valid_fi_identity_code("131052X308T")); // X not valid separator
        assert!(!valid_fi_identity_code("131052B308T")); // B not valid separator
    }

    #[test]
    fn test_valid_fi_identity_code_wrong_length() {
        assert!(!valid_fi_identity_code("131052-308")); // 10 chars
        assert!(!valid_fi_identity_code("131052-308TT")); // 12 chars
        assert!(!valid_fi_identity_code(""));
    }

    #[test]
    fn test_valid_fi_identity_code_case_insensitive() {
        // Lowercase control character
        assert!(valid_fi_identity_code("131052-308t"));
        // Lowercase century separator
        assert!(valid_fi_identity_code("010100a002H"));
    }

    #[test]
    fn test_valid_fi_identity_code_control_char_digit() {
        // 010101-0020: 010101002 % 31 = 325842 rem 6 → CONTROL_CHARS[6] = '6'
        // 010101002 / 31 = 325842.0, 325842 * 31 = 10101102, but 010101002 = 10101002
        // Let me compute: 10101002 % 31 = 10101002 / 31 = 325839 rem 23
        // CONTROL_CHARS[23] = 'S'
        assert!(valid_fi_identity_code("010101-002S"));
    }

    // ── valid_th_tnin tests ──

    #[test]
    fn test_valid_th_tnin_known_good() {
        // 1123456789014: weights [13..2], sum=315, 315%11=7, (11-7)%10=4 ✓
        assert!(valid_th_tnin("1123456789014"));
    }

    #[test]
    fn test_valid_th_tnin_another_valid() {
        // 3100912345997: sum=257, 257%11=4, (11-4)%10=7 ✓
        assert!(valid_th_tnin("3100912345997"));
    }

    #[test]
    fn test_valid_th_tnin_check_digit_zero() {
        // 1100100001014: sum=40, 40%11=7, (11-7)%10=4 ✓
        assert!(valid_th_tnin("1100100001014"));
    }

    #[test]
    fn test_valid_th_tnin_rejects_bad_checksum() {
        assert!(!valid_th_tnin("1123456789015")); // expected 4, got 5
        assert!(!valid_th_tnin("1123456789010")); // expected 4, got 0
    }

    #[test]
    fn test_valid_th_tnin_wrong_length() {
        assert!(!valid_th_tnin("112345678901")); // 12 digits
        assert!(!valid_th_tnin("11234567890140")); // 14 digits
        assert!(!valid_th_tnin(""));
    }
}
