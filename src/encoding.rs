pub(crate) fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::encode_lower_hex;

    #[test]
    fn encodes_empty_bytes_as_empty_string() {
        assert_eq!(encode_lower_hex(&[]), "");
    }

    #[test]
    fn encodes_leading_zero_bytes() {
        assert_eq!(encode_lower_hex(&[0x00, 0x0f, 0x10, 0xff]), "000f10ff");
    }

    #[test]
    fn encodes_normal_bytes() {
        assert_eq!(encode_lower_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }
}
