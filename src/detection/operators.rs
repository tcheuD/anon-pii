use aes::Aes128;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use regex::Regex;

use crate::encoding::encode_lower_hex;

use super::types::{HashAlgo, MaskConfig};

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes192CbcEnc = cbc::Encryptor<aes::Aes192>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub fn apply_mask(value: &str, config: &MaskConfig) -> String {
    let char_count = value.chars().count();
    let mask_len = config.fixed_count.unwrap_or(char_count);
    if config.from_end {
        let visible = char_count.saturating_sub(mask_len);
        let prefix: String = value.chars().take(visible).collect();
        format!(
            "{}{}",
            prefix,
            config.mask_char.to_string().repeat(char_count - visible)
        )
    } else {
        let visible = char_count.saturating_sub(mask_len);
        let suffix: String = value.chars().skip(char_count - visible).collect();
        format!(
            "{}{}",
            config.mask_char.to_string().repeat(char_count - visible),
            suffix
        )
    }
}

pub fn apply_hash(value: &str, algo: HashAlgo) -> String {
    use sha2::Digest;

    match algo {
        HashAlgo::Sha256 => {
            let hash = sha2::Sha256::digest(value.as_bytes());
            encode_lower_hex(hash.as_ref())
        }
        HashAlgo::Sha512 => {
            let hash = sha2::Sha512::digest(value.as_bytes());
            encode_lower_hex(hash.as_ref())
        }
        HashAlgo::Md5 => {
            let hash = md5::compute(value.as_bytes());
            format!("{:x}", hash)
        }
    }
}

pub fn apply_encrypt(value: &str, key: &[u8]) -> String {
    let mut iv_bytes = [0u8; 16];
    getrandom::fill(&mut iv_bytes).expect("getrandom failed");

    let ciphertext = match key.len() {
        16 => Aes128CbcEnc::new(key.into(), &iv_bytes.into())
            .encrypt_padded_vec_mut::<Pkcs7>(value.as_bytes()),
        24 => Aes192CbcEnc::new(key.into(), &iv_bytes.into())
            .encrypt_padded_vec_mut::<Pkcs7>(value.as_bytes()),
        32 => Aes256CbcEnc::new(key.into(), &iv_bytes.into())
            .encrypt_padded_vec_mut::<Pkcs7>(value.as_bytes()),
        _ => unreachable!("key length validated at CLI parse time"),
    };

    let mut hex = String::with_capacity((16 + ciphertext.len()) * 2);
    for b in &iv_bytes {
        hex.push_str(&format!("{:02x}", b));
    }
    for b in &ciphertext {
        hex.push_str(&format!("{:02x}", b));
    }
    format!("ENC[{hex}]")
}

pub fn apply_custom_replacement(entity_type: &str, format_str: &str) -> String {
    format_str.replace("{entity_type}", entity_type)
}

fn decrypt_single(hex: &str, key: &[u8]) -> Option<String> {
    if hex.len() < 64 || !hex.len().is_multiple_of(2) {
        return None;
    }
    let raw: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .ok()?;
    if raw.len() < 32 {
        return None;
    }
    let (iv, ct) = raw.split_at(16);

    let plaintext = match key.len() {
        16 => Aes128CbcDec::new(key.into(), iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .ok()?,
        24 => Aes192CbcDec::new(key.into(), iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .ok()?,
        32 => Aes256CbcDec::new(key.into(), iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .ok()?,
        _ => return None,
    };
    String::from_utf8(plaintext).ok()
}

pub fn decrypt_encrypted(text: &str, key: &[u8]) -> String {
    let enc_re = Regex::new(r"ENC\[([0-9a-f]{64,})\]").unwrap();
    let mut result = String::with_capacity(text.len());
    let mut last = 0;
    for cap in enc_re.captures_iter(text) {
        let m = cap.get(0).unwrap();
        result.push_str(&text[last..m.start()]);
        if let Some(plaintext) = decrypt_single(&cap[1], key) {
            result.push_str(&plaintext);
        } else {
            result.push_str(m.as_str());
        }
        last = m.end();
    }
    result.push_str(&text[last..]);
    result
}

/// Parse a hex-encoded AES key, returning the raw bytes.
/// Accepts 32 (128-bit), 48 (192-bit), or 64 (256-bit) hex characters.
pub fn parse_encrypt_key(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() != 32 && hex.len() != 48 && hex.len() != 64 {
        return Err(format!(
            "encrypt key must be 32, 48, or 64 hex characters (128/192/256-bit), got {}",
            hex.len()
        ));
    }
    let bytes: Result<Vec<u8>, _> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect();
    bytes.map_err(|e| format!("invalid hex in encrypt key: {e}"))
}
