//! Integration tests for custody: chain integrity, tamper detection,
//! and transfer chaining. Uses only std (no tempfile dependency).

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempCase {
    root: PathBuf,
}

impl TempCase {
    fn new(case_id: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("custody-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        custody::init_case(&root, case_id).unwrap();
        Self { root }
    }

    fn write_file(&self, name: &str, contents: &[u8]) {
        fs::write(self.root.join(name), contents).unwrap();
    }
}

impl Drop for TempCase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn good_log_passes_verification() {
    let case = TempCase::new("CASE-001");
    case.write_file("photo.jpg", b"fake image bytes 12345");

    custody::intake(
        &case.root,
        "photo.jpg",
        "Officer Example",
        Some("seized at scene"),
    )
    .unwrap();
    custody::transfer(&case.root, "photo.jpg", "Officer Example", "J. Doe", None).unwrap();

    let v = custody::verify(&case.root).unwrap();
    assert!(v.chain_ok, "chain should be intact: {:?}", v.chain_errors);
    assert!(v.ok(), "verification should pass");
    assert_eq!(v.files.len(), 1);
    assert!(v.files[0].ok);

    // Log structure sanity: 2 entries, seq 1..2, genesis prev_hash on first.
    let entries = custody::read_log(&case.root).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].seq, 1);
    assert_eq!(entries[0].prev_hash, custody::GENESIS_HASH);
    assert_eq!(entries[1].seq, 2);
    assert_eq!(entries[1].prev_hash, entries[0].entry_hash);
    // Each stored entry_hash matches its canonical recomputation.
    for e in &entries {
        assert_eq!(e.entry_hash, e.compute_hash());
    }
}

#[test]
fn tampering_with_logged_file_fails_verify() {
    let case = TempCase::new("CASE-002");
    case.write_file("evidence.bin", b"original evidence contents");

    custody::intake(&case.root, "evidence.bin", "Officer Example", None).unwrap();

    // Good state passes.
    assert!(custody::verify(&case.root).unwrap().ok());

    // Tamper with the evidence file.
    case.write_file("evidence.bin", b"ALTERED evidence contents");

    let v = custody::verify(&case.root).unwrap();
    assert!(!v.ok(), "tampered file must fail verification");
    assert!(v.chain_ok, "chain itself is still intact");
    assert!(!v.files[0].ok);
    assert!(v.files[0].detail.contains("mismatch"));
    assert_ne!(
        v.files[0].current_sha256.as_deref(),
        Some(v.files[0].logged_sha256.as_str())
    );
}

#[test]
fn editing_log_entry_breaks_chain_and_is_detected() {
    let case = TempCase::new("CASE-003");
    case.write_file("disk.img", b"disk image bytes");

    custody::intake(&case.root, "disk.img", "J. Doe", Some("forensic image")).unwrap();
    custody::transfer(&case.root, "disk.img", "J. Doe", "Officer Example", None).unwrap();

    // Attacker edits the custodian name in the first log line.
    let log = custody::log_path(&case.root);
    let text = fs::read_to_string(&log).unwrap();
    let tampered = text.replacen("J. Doe", "Mallory Intruder", 1);
    assert_ne!(text, tampered);
    fs::write(&log, tampered).unwrap();

    let v = custody::verify(&case.root).unwrap();
    assert!(!v.ok(), "edited log must fail verification");
    assert!(!v.chain_ok, "chain must be reported broken");
    assert!(
        v.chain_errors
            .iter()
            .any(|e| e.contains("entry_hash mismatch at seq 1")),
        "expected entry_hash mismatch at seq 1, got: {:?}",
        v.chain_errors
    );
    // Note: entry 2's prev_hash still matches entry 1's *stored* entry_hash, so
    // detection comes from the recomputed entry_hash mismatch. If an attacker
    // also recomputed entry 1's entry_hash, the prev_hash link into seq 2 would
    // break instead (covered by deleting_a_log_line_breaks_chain).
    // Files themselves are untouched, so file verification still passes.
    assert!(v.files.iter().all(|f| f.ok));
}

#[test]
fn deleting_a_log_line_breaks_chain() {
    let case = TempCase::new("CASE-004");
    case.write_file("a.dat", b"aaa");
    case.write_file("b.dat", b"bbb");

    custody::intake(&case.root, "a.dat", "Officer Example", None).unwrap();
    custody::intake(&case.root, "b.dat", "Officer Example", None).unwrap();

    // Remove the first line entirely.
    let log = custody::log_path(&case.root);
    let text = fs::read_to_string(&log).unwrap();
    let rest: String = text.lines().skip(1).map(|l| format!("{l}\n")).collect();
    fs::write(&log, rest).unwrap();

    let v = custody::verify(&case.root).unwrap();
    assert!(!v.chain_ok);
    assert!(!v.ok());
}

#[test]
fn transfer_entries_chain_correctly() {
    let case = TempCase::new("CASE-005");
    case.write_file("phone.tar", b"phone dump archive");

    custody::intake(&case.root, "phone.tar", "Officer Example", None).unwrap();
    custody::transfer(
        &case.root,
        "phone.tar",
        "Officer Example",
        "J. Doe",
        Some("lab handoff"),
    )
    .unwrap();
    custody::transfer(&case.root, "phone.tar", "J. Doe", "Analyst Example", None).unwrap();

    let entries = custody::read_log(&case.root).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].action, "intake");
    assert_eq!(entries[1].action, "transfer");
    assert_eq!(entries[2].action, "transfer");
    assert_eq!(entries[1].from.as_deref(), Some("Officer Example"));
    assert_eq!(entries[1].to.as_deref(), Some("J. Doe"));
    assert_eq!(entries[2].from.as_deref(), Some("J. Doe"));
    assert_eq!(entries[2].to.as_deref(), Some("Analyst Example"));

    // Chain links.
    assert_eq!(entries[0].prev_hash, custody::GENESIS_HASH);
    assert_eq!(entries[1].prev_hash, entries[0].entry_hash);
    assert_eq!(entries[2].prev_hash, entries[1].entry_hash);

    // Same file, unchanged: sha256 identical across all entries.
    assert_eq!(entries[0].sha256, entries[1].sha256);
    assert_eq!(entries[1].sha256, entries[2].sha256);

    let v = custody::verify(&case.root).unwrap();
    assert!(v.ok(), "transfer chain should verify cleanly");
}

#[test]
fn transfer_requires_prior_intake() {
    let case = TempCase::new("CASE-006");
    case.write_file("newfile.dat", b"never intaken");
    let err = custody::transfer(&case.root, "newfile.dat", "J. Doe", "Officer Example", None);
    assert!(err.is_err(), "transfer without intake must fail");
}

#[test]
fn report_renders_markdown_with_chain_status() {
    let case = TempCase::new("CASE-007");
    case.write_file("video.mp4", b"video bytes");
    custody::intake(&case.root, "video.mp4", "Officer Example", None).unwrap();

    let md = custody::report(&case.root).unwrap();
    assert!(md.contains("# Chain-of-Custody Report"));
    assert!(md.contains("CASE-007"));
    assert!(md.contains("video.mp4"));
    assert!(md.contains("**Overall result: PASS**"));
}
