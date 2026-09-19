# custody

`custody` is a tamper-evident chain-of-custody log for digital evidence. It keeps an
append-only, hash-chained JSONL log of every evidence intake and custodian transfer,
so any later alteration — to the evidence files or to the log itself — is detectable.

## Who it's for

- **Small police departments** that need evidence logging without a six-figure RMS.
- **Defense attorneys** who want to independently verify the integrity of evidence
  produced against their clients.

## How it works

Every `intake` and `transfer` appends one JSON line to `.custody/custody.jsonl`:

```json
{"seq":1,"timestamp":"2026-09-18T22:00:00Z","action":"intake","file":"photo.jpg","sha256":"…","custodian":"Officer Example","notes":"…","prev_hash":"0000…","entry_hash":"…"}
```

- `sha256` — SHA-256 of the file at the moment of logging.
- `prev_hash` — `entry_hash` of the previous entry (genesis is 64 zero chars).
- `entry_hash` — SHA-256 of the canonical serialization of the entry, *including*
  `prev_hash`. This forms a hash chain: editing any field of any entry, reordering
  entries, or deleting entries breaks the chain and is caught by `custody verify`.

**Local-first:** zero network calls, zero telemetry. Your evidence never leaves the machine.

## Install

Requires a Rust toolchain (1.70+).

```sh
git clone https://github.com/synthalorian/custody
cd custody
cargo install --path .
```

## Usage

```sh
# Start a new case in the current directory
custody init CASE-2026-0142

# Log evidence intake (hashes the file, appends to the log)
custody intake photo.jpg --custodian "Officer Example" --notes "Seized at scene"

# Log a custodian-to-custodian transfer
custody transfer photo.jpg --from "Officer Example" --to "J. Doe" --notes "Lab handoff"

# Verify: re-hash every logged file AND re-verify the hash chain
custody verify
# PASS  photo.jpg  (hash matches log)
# Hash chain: PASS
# Overall: PASS

# Print a markdown custody report suitable for court submission
custody report > custody-report.md
```

`custody verify` exits non-zero if any file hash mismatches, a file is missing, or the
hash chain is broken.

## A note on admissibility

`custody` **aids but does not guarantee legal admissibility.** It can prove that a file
matches what was logged and that the log was not altered after the fact — it cannot prove
who created an entry, that timestamps are trustworthy, or that proper procedure was
followed. Courts weigh chain of custody on testimony, policy, and practice, not on any
single tool. Consult counsel and your jurisdiction's rules of evidence; treat this tool
as one layer of documentation, not a substitute for procedure.

## License

Apache-2.0. See [LICENSE](LICENSE).

Made by synth with blackclaw
