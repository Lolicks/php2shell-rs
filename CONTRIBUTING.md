# Contributing

## Scope of contributions

PHP2Shell-RS accepts contributions that improve diagnostics, profile
compatibility, laboratory ergonomics, documentation, tests and CI.

Contributions that add exploitation, remote command execution, OOM/DoS
primitives, mass scanning, `/proc` memory oracles or Python dependencies will
not be accepted. See `docs/MIGRATION.md`.

## Development

Permitted locally:

```
cargo fmt --all
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
cargo run -- profile validate
```

Release binaries are **never** built locally (`cargo build --release` is
reserved for GitHub Actions).

## Profiles

Do not edit existing files in `profiles/`. To add a profile, use
`cargo run -- profile import --file new.json` and document its provenance.
If an existing checksum must change, update `profiles/manifest.json` in the
same commit and explain why in the PR description.

## Pull requests

- one logical change per PR;
- tests for every behavioural change;
- no credentials, real target data or logs from systems you do not own;
- update `CHANGELOG.md` for user-visible changes;
- CI must be green (fmt, check, clippy, tests, JSON compatibility, audit).
