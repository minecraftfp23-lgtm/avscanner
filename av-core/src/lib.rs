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
    let agent = ureq::AgentBuilder::new().build();
    let url = format!("http://www.virustotal.com/api/v3/files/{}", hash);

    let response = agent
        .get(&url)
        .set("x-apikey", api_key)
        .call()?;

    if response.status() == 404 {
        return Ok(Verdict::Unknown);
    }

    let vt_response: VTResponse = response.into_json()?;
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanResult {
    pub path: String,
    pub hash: String,
    pub verdict: Verdict,
}

/// Сканирует один файл: хэш + VT проверка
pub fn scan_file(path: &Path, vt_api_key: Option<&str>) -> Result<ScanResult> {
    let hash = hash_file(path)?;
    let verdict = if let Some(key) = vt_api_key {
        check_virustotal(&hash, key).unwrap_or(Verdict::Error("VT request failed".into()))
    } else {
        Verdict::Unknown
    };

    Ok(ScanResult {
        path: path.display().to_string(),
        hash,
        verdict,
    })
}

/// Рекурсивно сканирует папку (без rayon)
pub fn scan_directory(dir: &Path, vt_api_key: Option<&str>) -> Result<Vec<ScanResult>> {
    fn collect_files(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                files.push(path);
            } else if path.is_dir() {
                collect_files(&path, files)?;
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    collect_files(dir, &mut files)?;

    let results: Vec<ScanResult> = files
        .iter()
        .filter_map(|path| scan_file(path, vt_api_key).ok())
        .collect();

    Ok(results)
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