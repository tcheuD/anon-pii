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

    let mut file = fs::File::create(dest)?;
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
}

pub fn model_exists(config: &NerConfig) -> bool {
    let dir = &config.model_dir;
    FILES.iter().all(|(_, local)| dir.join(local).exists())
}
