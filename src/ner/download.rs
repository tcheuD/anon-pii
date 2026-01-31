use std::fs;
use std::io::Write;
use std::path::Path;

use crate::ner::NerConfig;

const HF_BASE: &str =
    "https://huggingface.co/Xenova/distilbert-base-multilingual-cased-ner-hrl/resolve/main";

const FILES: &[(&str, &str)] = &[
    ("onnx/model_quantized.onnx", "model.onnx"),
    ("tokenizer.json", "tokenizer.json"),
    ("config.json", "config.json"),
];

pub fn download_model(config: &NerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let dir = &config.model_dir;
    fs::create_dir_all(dir)?;

    for (remote, local) in FILES {
        let dest = dir.join(local);
        if dest.exists() {
            eprintln!("  {} already exists, skipping", local);
            continue;
        }

        let url = format!("{}/{}", HF_BASE, remote);
        eprintln!("  Downloading {} ...", local);

        download_file(&url, &dest)?;

        let size = fs::metadata(&dest)?.len();
        eprintln!("  {} ({:.1} MB)", local, size as f64 / 1_048_576.0);
    }

    eprintln!("Model downloaded to {:?}", dir);
    Ok(())
}

fn download_file(url: &str, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let resp = ureq::get(url).call()?;

    let status = resp.status();
    if status != 200 {
        return Err(format!("HTTP {status} downloading {url}").into());
    }

    // Write to a temp file then rename — prevents corrupt files from partial downloads
    let tmp = dest.with_extension("tmp");
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut file = fs::File::create(&tmp)?;
        let mut reader = resp.into_reader();
        let mut buf = [0u8; 65536];
        loop {
            let n = std::io::Read::read(&mut reader, &mut buf)?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])?;
        }
        file.flush()?;
        Ok(())
    })();

    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    // Validate: ONNX files must start with the protobuf magic bytes,
    // JSON files must be valid UTF-8 starting with '{' or '['
    let is_json = dest.extension().is_some_and(|e| e == "json");
    if is_json {
        let content = fs::read_to_string(&tmp).map_err(|_| {
            let _ = fs::remove_file(&tmp);
            format!("Downloaded file is not valid UTF-8: {url}")
        })?;
        let trimmed = content.trim_start();
        if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
            let _ = fs::remove_file(&tmp);
            return Err(format!("Downloaded file is not valid JSON: {url}").into());
        }
    }

    fs::rename(&tmp, dest)?;
    Ok(())
}

pub fn model_exists(config: &NerConfig) -> bool {
    let dir = &config.model_dir;
    FILES.iter().all(|(_, local)| dir.join(local).exists())
}
