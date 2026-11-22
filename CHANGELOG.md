# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.0] — 2026-11-22

### Added

- Full port of `php2shell_fpm_versions`: branch matrix, `ports_for`,
  `chain_applies`, `source_is_fixed`, `has_session_cancel_decode`,
  `build_status` and full affected-version enumeration.
- Safe precondition diagnostics (`preconditions`) covering version
  classification, small reflection and reference checks; the disruptive OOM
  step remains intentionally unimplemented.
- Pad-spec and `stage3_profile_json` compatibility helpers.
- Markdown offset-inventory generation from local JSON offset files.
- New CLI commands: `preconditions`, `offsets`, `calibrate source|binary|pads`.

## [1.0.0] — 2026-11-22

### Added

- Full Rust workspace with 13 crates and no Python runtime.
- Passive fingerprinting with explicit confidence levels and uncertainty.
- JSON profile registry compatible with all 56 upstream profiles; SHA-256
  manifest for 106 original files.
- Bounds-checked ELF64 parser and two libFuzzer targets.
- Async HTTP client with TLS verification, timeouts, response-size limit and
  explicit host allow-list.
- Diagnostics with compatible/incompatible profiles and hardening advice.
- Calibration metadata records (no exploit stages).
- Inventory (table/JSON), local Docker Compose lab manager and loopback axum
  mock service.
- Clap CLI with `version`, `profile`, `inventory`, `fingerprint`,
  `diagnostics`, `lab`, `report`, `calibrate`, `elf` and `tui`.
- Ratatui TUI with eight functional sections.
- GitHub Actions: CI, four-target release build with SHA256SUMS, and security
  workflow.

### Changed

- The original Python implementation is archived under `legacy/python/`
  and is no longer part of build, test or runtime.
- Release artifacts are built exclusively by GitHub Actions.

### Removed

- All exploitation, OOM, worker-pinning, `/proc` oracle, upstream patching and
  remote command-execution functionality. See `docs/MIGRATION.md`.
