//! Tauri command: scan file or directory via Rust av-core library

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tauri::State;
use av_core::{scan_directory, scan_file, Verdict, ScanResult};
use std::path::PathBuf;

// --- State для API ключа VirusTotal ---
struct VtKey(String);

#[tauri::command]
async fn scan_file(path: String, vt_key: Option<String>) -> Result<ScanResult> {
  let api_key = vt_key.unwrap_or_default();
  let p = PathBuf::from(path);
  let result = scan_file(&p, api_key.as_deref())?;
  Ok(result)
}

#[tauri::command]
async fn scan_directory(dir: String, vt_key: Option<String>) -> Result<Vec<ScanResult>> {
  let api_key = vt_key.unwrap_or_default();
  let p = PathBuf::from(dir);
  let result = scan_directory(&p, api_key.as_deref())?;
  Ok(result)
}

/// Get available drives on Windows (for the "Scan Computer" button)
#[tauri::command]
fn get_windows_drives() -> Result<Vec<String>> {
  let mut drives = Vec::new();
  // enumerate logical drives on Windows
  for letter in b'A'..=b'Z' {
    let path = format!("{}:\\", char::from_u32(letter as u32).unwrap());
    if std::fs::metadata(&path).is_ok() {
      drives.push(path);
    }
  }
  Ok(drives)
}

#[tauri::command]
fn get_virustotal_key() -> Option<String> {
  // In production, store securely or prompt user
  None
}

#[tauri::command]
fn set_virustotal_key(key: String) {
  // Store securely (e.g., encrypted config) — for demo only
  println!("VT key set: {}", key);
}

#[cfg(windows)]
mod window {
  use crate::get_windows_drives;
}

#[cfg(not(windows))]
mod window {
  // Non-Windows variants would list mounted volumes differently
}

/// Tauri startup — prompt for VT key if not configured
fn main() {
  tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![
      scan_file,
      scan_directory,
      get_windows_drives,
      get_virustotal_key,
      set_virustotal_key
    ])
    .run(tauri::generate_context!())
    .expect("error running tauri app");
}