# mysql2 error-code data

`errors.js` is the complete error-constant source from mysql2 3.24.5. `LICENSE` retains the package license. `ORIGIN.json` records the package URL, pinned integrity value, source hash, license hash, and count of numeric reverse-map entries.

The Better Auth adapter uses the 1,963 numeric reverse-map entries to expose mysql2 symbolic error names. SQLx retains its original numeric codes and error classification. Unknown numeric codes produce an own `undefined` property in the adapter error object.

Run `python3 scripts/check-mysql-error-codes.py` after installing the pinned reference-server dependencies. The check verifies the installed source and every generated Rust entry. Use `--write` to regenerate the complete Rust table. Formatting may change whitespace; entry names, numbers, order, and count must match the source exactly.
