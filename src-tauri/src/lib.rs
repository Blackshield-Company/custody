//! Custody desktop. Same hash-chained log as the CLI. Nothing leaves the machine.

use custody::Entry;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Serialize)]
struct OpenedCase {
    case_id: String,
    entries: Vec<Entry>,
}

fn required(value: &str, what: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        Err(format!("{what} is required"))
    } else {
        Ok(value.to_string())
    }
}

fn case_root(root: &str) -> Result<PathBuf, String> {
    Ok(PathBuf::from(required(root, "case folder path")?))
}

fn notes_of(notes: Option<String>) -> Option<String> {
    notes
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[tauri::command]
fn open_case(root: String) -> Result<OpenedCase, String> {
    let root = case_root(&root)?;
    let case_id = custody::case_id(&root).map_err(|e| e.to_string())?;
    let entries = custody::read_log(&root).map_err(|e| e.to_string())?;
    Ok(OpenedCase { case_id, entries })
}

#[tauri::command]
fn init_case(root: String, case_id: String) -> Result<(), String> {
    let root = case_root(&root)?;
    let case_id = required(&case_id, "case id")?;
    custody::init_case(&root, &case_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn intake(
    root: String,
    file: String,
    custodian: String,
    notes: Option<String>,
) -> Result<Entry, String> {
    let root = case_root(&root)?;
    let file = required(&file, "file")?;
    let custodian = required(&custodian, "custodian")?;
    custody::intake(&root, &file, &custodian, notes_of(notes).as_deref()).map_err(|e| e.to_string())
}

#[tauri::command]
fn transfer(
    root: String,
    file: String,
    from: String,
    to: String,
    notes: Option<String>,
) -> Result<Entry, String> {
    let root = case_root(&root)?;
    let file = required(&file, "file")?;
    let from = required(&from, "from")?;
    let to = required(&to, "to")?;
    custody::transfer(&root, &file, &from, &to, notes_of(notes).as_deref())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn verify_case(root: String) -> Result<custody::Verification, String> {
    let root = case_root(&root)?;
    custody::verify(&root).map_err(|e| e.to_string())
}

#[tauri::command]
fn report_text(root: String) -> Result<String, String> {
    let root = case_root(&root)?;
    custody::report(&root).map_err(|e| e.to_string())
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            open_case,
            init_case,
            intake,
            transfer,
            verify_case,
            report_text
        ])
        .run(tauri::generate_context!())
        .expect("error while running custody");
}
