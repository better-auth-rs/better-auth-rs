# sql-escaper source reference

This directory retains the unmodified formatter source and MIT license from sql-escaper 1.5.2. The pinned mysql2 3.24.5 package uses this formatter for COM_QUERY values. The Rust scanner and formatter in `crates/seaorm/src/store/mysql_text` follow this source. This directory is a source reference, not a runtime dependency.

Run the pinned-source capture in GitHub Actions before accepting formatter behavior. Keep logical UTF-16 SQL separate from its wire encoding.

Pinned source SHA-256:

- `LICENSE`: `93277a18ec90d5b72d3bfaaaccc73cec7e735a8a1b154b74e9fec3e529603cbf`
- `lib/index.js`: `ac9bfa502b26eea8f8503036a4944046701c37f755bd4da8710482980fe61eed`
- `package.json`: `ea2757620053be93e93337220b1c517caded5c9e46b55482bf6ab494009aa9de`
