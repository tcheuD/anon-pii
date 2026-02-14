use std::fs;
use std::io::Write;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::ner::NerConfig;

const HF_BASE: &str =
    "https://huggingface.co/Xenova/distilbert-base-multilingual-cased-ner-hrl/resolve/main";

/// (remote_path, local_name, expected_sha256)
const FILES: &[(&str, &str, &str)] = &[
    (
        "onnx/model_quantized.onnx",
        "model.onnx",
        "24a0b98f4dd4cd92842f5a541272f86f760225a64a29928eddef14bdb2edb986",
    ),
    (
        "tokenizer.json",
        "tokenizer.json",
        "bf1b59b7b11c95f194f51708d918eea378e09d05f84c0e1656dc5180e8117088",
    ),
    (
        "config.json",
        "config.json",
        "38847be4dc6699b1218a749ed69f888c2ccc7b4deba98e3c4a1cac8cb34d54c8",
    ),
];

pub fn download_model(config: &NerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let dir = &config.model_dir;
    fs::create_dir_all(dir)?;

    for (remote, local, expected_hash) in FILES {
        let dest = dir.join(local);
        if dest.exists() {
            eprintln!("  {} already exists, skipping", local);
            continue;
        }

        let url = format!("{}/{}", HF_BASE, remote);
        eprintln!("  Downloading {} ...", local);

        download_file(&url, &dest, expected_hash)?;

        let size = fs::metadata(&dest)?.len();
        eprintln!("  {} ({:.1} MB)", local, size as f64 / 1_048_576.0);
    }

    eprintln!("Model downloaded to {:?}", dir);
    Ok(())
}

fn download_file(
    url: &str,
    dest: &Path,
    expected_sha256: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = ureq::get(url).call()?;

    let status = resp.status();
    if status != 200 {
        return Err(format!("HTTP {status} downloading {url}").into());
    }

    // Write to a temp file then rename — prevents corrupt files from partial downloads
    let tmp = dest.with_extension("tmp");
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut file = fs::File::create(&tmp)?;
        let mut hasher = Sha256::new();
        let mut reader = resp.into_body().into_reader();
        let mut buf = [0u8; 65536];
        loop {
            let n = std::io::Read::read(&mut reader, &mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n])?;
        }
        file.flush()?;

        let actual_hash = format!("{:x}", hasher.finalize());
        if actual_hash != expected_sha256 {
            return Err(format!(
                "SHA-256 mismatch for {url}: expected {expected_sha256}, got {actual_hash}"
            )
            .into());
        }
        Ok(())
    })();

    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    fs::rename(&tmp, dest)?;
    Ok(())
}

pub fn model_exists(config: &NerConfig) -> bool {
    let dir = &config.model_dir;
    FILES.iter().all(|(_, local, _)| dir.join(local).exists())
}
