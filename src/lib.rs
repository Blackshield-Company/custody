//! custody — tamper-evident chain-of-custody log for digital evidence.
//!
//! Core library: append-only JSONL log with a SHA-256 hash chain.
//! Each entry's `entry_hash` is the SHA-256 of the canonical JSON
//! serialization of the entry (including `prev_hash`), so editing any
//! field of any entry — or reordering/deleting entries — is detectable.

use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const CUSTODY_DIR: &str = ".custody";
pub const LOG_FILE: &str = "custody.jsonl";
pub const CASE_FILE: &str = "case";
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A single chain-of-custody log entry.
///
/// Field order matters: serde_json serializes struct fields in declaration
/// order, which gives us a deterministic canonical serialization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub seq: u64,
    pub timestamp: String,
    pub action: String,
    pub file: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custodian: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// Canonical form of an entry for hashing — identical to `Entry` minus
/// `entry_hash`, with identical field order.
#[derive(Serialize)]
struct CanonicalEntry<'a> {
    seq: u64,
    timestamp: &'a str,
    action: &'a str,
    file: &'a str,
    sha256: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    custodian: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'a str>,
    prev_hash: &'a str,
}

impl Entry {
    /// Canonical JSON bytes used as the input to `entry_hash`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let c = CanonicalEntry {
            seq: self.seq,
            timestamp: &self.timestamp,
            action: &self.action,
            file: &self.file,
            sha256: &self.sha256,
            custodian: self.custodian.as_deref(),
            from: self.from.as_deref(),
            to: self.to.as_deref(),
            notes: self.notes.as_deref(),
            prev_hash: &self.prev_hash,
        };
        // serde_json serialization of a struct is deterministic (field
        // declaration order), so this is a stable canonical form.
        serde_json::to_vec(&c).expect("canonical entry serialization cannot fail")
    }

    /// Compute this entry's hash from its canonical serialization.
    pub fn compute_hash(&self) -> String {
        hex_sha256_bytes(&self.canonical_bytes())
    }
}

fn hex_sha256_bytes(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

/// SHA-256 (hex) of a file's contents, streamed.
pub fn hash_file(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path)
        .with_context(|| format!("cannot open {} for hashing", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

pub fn custody_dir(root: &Path) -> PathBuf {
    root.join(CUSTODY_DIR)
}

pub fn log_path(root: &Path) -> PathBuf {
    custody_dir(root).join(LOG_FILE)
}

/// Initialize a new custody log for `case_id` under `root`.
pub fn init_case(root: &Path, case_id: &str) -> Result<()> {
    let dir = custody_dir(root);
    if dir.exists() {
        bail!(
            "{} already exists — this directory is already a custody case",
            dir.display()
        );
    }
    fs::create_dir_all(&dir).context("creating .custody directory")?;
    fs::write(dir.join(CASE_FILE), format!("{case_id}\n")).context("writing case file")?;
    fs::write(dir.join(LOG_FILE), "").context("creating empty log")?;
    Ok(())
}

/// Read the case ID, if present.
pub fn case_id(root: &Path) -> Result<String> {
    let p = custody_dir(root).join(CASE_FILE);
    let s = fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
    Ok(s.trim().to_string())
}

/// Read every entry from the log, in order.
pub fn read_log(root: &Path) -> Result<Vec<Entry>> {
    let p = log_path(root);
    if !p.exists() {
        bail!(
            "no custody log found at {} — run `custody init CASEID` first",
            p.display()
        );
    }
    let text = fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
    let mut entries = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let e: Entry =
            serde_json::from_str(line).with_context(|| format!("parsing log line {}", i + 1))?;
        entries.push(e);
    }
    Ok(entries)
}

fn prev_hash_of(entries: &[Entry]) -> String {
    entries
        .last()
        .map(|e| e.entry_hash.clone())
        .unwrap_or_else(|| GENESIS_HASH.to_string())
}

/// Append an intake entry for `file`.
pub fn intake(root: &Path, file: &str, custodian: &str, notes: Option<&str>) -> Result<Entry> {
    let file_path = root.join(file);
    if !file_path.is_file() {
        bail!("file not found: {}", file_path.display());
    }
    let digest = hash_file(&file_path)?;
    let entries = read_log(root)?;
    let entry = Entry {
        seq: entries.len() as u64 + 1,
        timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        action: "intake".to_string(),
        file: file.to_string(),
        sha256: digest,
        custodian: Some(custodian.to_string()),
        from: None,
        to: None,
        notes: notes.map(|s| s.to_string()),
        prev_hash: prev_hash_of(&entries),
        entry_hash: String::new(),
    };
    let entry = Entry {
        entry_hash: entry.compute_hash(),
        ..entry
    };
    append_entry(root, &entry)?;
    Ok(entry)
}

/// Append a transfer entry for `file` (custodian -> custodian handoff).
pub fn transfer(
    root: &Path,
    file: &str,
    from: &str,
    to: &str,
    notes: Option<&str>,
) -> Result<Entry> {
    let file_path = root.join(file);
    if !file_path.is_file() {
        bail!("file not found: {}", file_path.display());
    }
    let entries = read_log(root)?;
    if !entries.iter().any(|e| e.file == file) {
        bail!("{file} has never been logged — run `custody intake {file} ...` first");
    }
    let digest = hash_file(&file_path)?;
    let entry = Entry {
        seq: entries.len() as u64 + 1,
        timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        action: "transfer".to_string(),
        file: file.to_string(),
        sha256: digest,
        custodian: None,
        from: Some(from.to_string()),
        to: Some(to.to_string()),
        notes: notes.map(|s| s.to_string()),
        prev_hash: prev_hash_of(&entries),
        entry_hash: String::new(),
    };
    let entry = Entry {
        entry_hash: entry.compute_hash(),
        ..entry
    };
    append_entry(root, &entry)?;
    Ok(entry)
}

fn append_entry(root: &Path, entry: &Entry) -> Result<()> {
    use std::io::Write;
    let p = log_path(root);
    let mut f = fs::OpenOptions::new()
        .append(true)
        .open(&p)
        .with_context(|| format!("opening {} for append", p.display()))?;
    let mut line = serde_json::to_string(entry).context("serializing entry")?;
    line.push('\n');
    f.write_all(line.as_bytes())
        .context("appending log entry")?;
    Ok(())
}

/// Result of verifying one file against the log.
#[derive(Debug)]
pub struct FileVerification {
    pub file: String,
    pub logged_sha256: String,
    pub current_sha256: Option<String>,
    pub ok: bool,
    pub detail: String,
}

/// Result of verifying the whole chain + all files.
#[derive(Debug)]
pub struct Verification {
    pub chain_ok: bool,
    pub chain_errors: Vec<String>,
    pub files: Vec<FileVerification>,
}

impl Verification {
    pub fn ok(&self) -> bool {
        self.chain_ok && self.files.iter().all(|f| f.ok)
    }
}

/// Verify hash-chain integrity of the entries and re-hash every file
/// referenced in the log, comparing against the file's most recent entry.
pub fn verify(root: &Path) -> Result<Verification> {
    let entries = read_log(root)?;

    // 1. Chain integrity.
    let mut chain_errors = Vec::new();
    let mut expected_prev = GENESIS_HASH.to_string();
    for (i, e) in entries.iter().enumerate() {
        let expect_seq = i as u64 + 1;
        if e.seq != expect_seq {
            chain_errors.push(format!(
                "seq mismatch at position {}: expected {expect_seq}, found {}",
                i + 1,
                e.seq
            ));
        }
        if e.prev_hash != expected_prev {
            chain_errors.push(format!(
                "prev_hash mismatch at seq {}: chain link broken",
                e.seq
            ));
        }
        let recomputed = e.compute_hash();
        if recomputed != e.entry_hash {
            chain_errors.push(format!(
                "entry_hash mismatch at seq {}: entry contents were altered",
                e.seq
            ));
        }
        expected_prev = e.entry_hash.clone();
    }
    let chain_ok = chain_errors.is_empty();

    // 2. Re-hash every referenced file; compare to its most recent logged hash.
    let mut seen: Vec<String> = Vec::new();
    for e in &entries {
        if !seen.contains(&e.file) {
            seen.push(e.file.clone());
        }
    }
    let mut files = Vec::new();
    for file in seen {
        let logged = entries
            .iter()
            .rev()
            .find(|e| e.file == file)
            .map(|e| e.sha256.clone())
            .unwrap_or_default();
        let file_path = root.join(&file);
        let (current, ok, detail) = if !file_path.is_file() {
            (None, false, "file missing".to_string())
        } else {
            match hash_file(&file_path) {
                Ok(h) if h == logged => (Some(h), true, "hash matches log".to_string()),
                Ok(h) => (
                    Some(h),
                    false,
                    "hash mismatch — file altered since logging".to_string(),
                ),
                Err(err) => (None, false, format!("unreadable: {err}")),
            }
        };
        files.push(FileVerification {
            file,
            logged_sha256: logged,
            current_sha256: current,
            ok,
            detail,
        });
    }

    Ok(Verification {
        chain_ok,
        chain_errors,
        files,
    })
}

/// Render a human-readable markdown custody report.
pub fn report(root: &Path) -> Result<String> {
    let case = case_id(root).unwrap_or_else(|_| "(unknown case)".to_string());
    let entries = read_log(root)?;
    let v = verify(root)?;

    let mut out = String::new();
    out.push_str(&format!("# Chain-of-Custody Report\n\n"));
    out.push_str(&format!("**Case:** {case}\n\n"));
    out.push_str(&format!(
        "**Report generated (UTC):** {}\n\n",
        Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
    ));
    out.push_str(&format!("**Total log entries:** {}\n\n", entries.len()));

    out.push_str("## Custody Log\n\n");
    out.push_str(
        "| Seq | Timestamp (UTC) | Action | File | SHA-256 | Custodian / From → To | Notes |\n",
    );
    out.push_str(
        "|-----|-----------------|--------|------|---------|------------------------|-------|\n",
    );
    for e in &entries {
        let who = match e.action.as_str() {
            "transfer" => format!(
                "{} → {}",
                e.from.as_deref().unwrap_or("-"),
                e.to.as_deref().unwrap_or("-")
            ),
            _ => e.custodian.as_deref().unwrap_or("-").to_string(),
        };
        out.push_str(&format!(
            "| {} | {} | {} | `{}` | `{}` | {} | {} |\n",
            e.seq,
            e.timestamp,
            e.action,
            e.file,
            e.sha256,
            who,
            e.notes.as_deref().unwrap_or("")
        ));
    }
    out.push('\n');

    out.push_str("## Hash Chain\n\n");
    out.push_str(&format!("- Genesis prev_hash: `{}`\n", GENESIS_HASH));
    if let Some(last) = entries.last() {
        out.push_str(&format!("- Head entry_hash: `{}`\n", last.entry_hash));
    }
    out.push_str(&format!(
        "- Chain integrity: **{}**\n\n",
        if v.chain_ok { "PASS" } else { "FAIL" }
    ));
    for err in &v.chain_errors {
        out.push_str(&format!("  - {err}\n"));
    }
    if !v.chain_errors.is_empty() {
        out.push('\n');
    }

    out.push_str("## File Verification\n\n");
    out.push_str("| File | Logged SHA-256 | Current SHA-256 | Result |\n");
    out.push_str("|------|----------------|-----------------|--------|\n");
    for f in &v.files {
        out.push_str(&format!(
            "| `{}` | `{}` | `{}` | {} ({}) |\n",
            f.file,
            f.logged_sha256,
            f.current_sha256.as_deref().unwrap_or("(missing)"),
            if f.ok { "PASS" } else { "FAIL" },
            f.detail
        ));
    }
    out.push('\n');

    out.push_str("## Summary\n\n");
    out.push_str(&format!(
        "**Overall result: {}**\n",
        if v.ok() { "PASS" } else { "FAIL" }
    ));

    Ok(out)
}
