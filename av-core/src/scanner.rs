use anyhow::Result;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Вычисляет SHA256 хэш файла
pub fn hash_file(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Проверяет хэш через VirusTotal API (блокирующий вызов)
pub fn check_virustotal(hash: &str, api_key: &str) -> Result<Verdict> {
    let client = reqwest::blocking::Client::new();
    let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);

    let response = client
        .get(&url)
        .header("x-apikey", api_key)
        .send()?;

    if response.status().as_u16() == 404 {
        return Ok(Verdict::Unknown);
    }

    let vt_response: VTResponse = response.json()?;
    let stats = vt_response.data.attributes.last_analysis_stats;

    Ok(if stats.malicious > 0 || stats.suspicious > 0 {
        Verdict::Malicious
    } else {
        Verdict::Clean
    })
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Verdict {
    Clean,
    Malicious,
    Suspicious,
    Unknown,
    Error(String),
}

#[derive(serde::Deserialize)]
struct VTResponse {
    data: VTData,
}

#[derive(serde::Deserialize)]
struct VTData {
    attributes: VTAttributes,
}

#[derive(serde::Deserialize)]
struct VTAttributes {
    last_analysis_stats: VTStats,
}

#[derive(serde::Deserialize)]
struct VTStats {
    malicious: u32,
    suspicious: u32,
    undetected: u32,
    harmless: u32,
}