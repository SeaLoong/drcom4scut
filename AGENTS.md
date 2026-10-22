# Working agreements

- Use the existing isolated checkout; do not create a worktree unless requested.
- The user explicitly requires each completed iteration to be committed and pushed to `master`. Run relevant checks first, use normal non-forced pushes, preserve remote changes, and report a concrete access blocker if pushing fails.
- Do not commit credentials, local config, private logs, build caches or generated release archives.
- Use stable Rust and the lockfile. Required checks for Rust changes: formatting, strict Clippy (all features and minimal), and meaningful affected tests; CI covers platform-specific execution. See README.md and docs/development.md.
- Keep password inputs out of process arguments, logs and diagnostics. Do not replace meaningful protocol tests with trivial passing checks or claim simulation is a campus-network test.
