#!/usr/bin/env python3
"""Verify the complete mysql2 error-code table against the installed pinned package."""
import argparse
import hashlib
import json
import re
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source", type=Path, help="Read this mysql2 package directory instead of node_modules")
parser.add_argument("--write", action="store_true", help="Regenerate the Rust table after validating the source")
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
source = args.source or root / "compat-tests/reference-server/node_modules/mysql2"
vendor = root / "vendor/mysql2-errors"
origin = json.loads((vendor / "ORIGIN.json").read_text())
package = json.loads((source / "package.json").read_text())
assert (package["name"], package["version"]) == (origin["package"], origin["version"])
raw = (source / origin["source"]).read_bytes()
assert hashlib.sha256(raw).hexdigest() == origin["source_sha256"], "The installed source hash differs"
assert raw == (vendor / "errors.js").read_bytes(), "The vendored source differs from installed mysql2"
assert hashlib.sha256((vendor / "LICENSE").read_bytes()).hexdigest() == origin["license_sha256"]
entries = [(int(number), name) for number, name in re.findall(
    r"^exports\[(\d+)\] = '([A-Z0-9_]+)';$", raw.decode(), re.M
)]
assert len(entries) == len(set(number for number, _ in entries)) == origin["entries"]
assert entries == sorted(entries), "The source numeric table must be ordered"
assert all(0 <= number <= 65535 for number, _ in entries)
rendered = '\n'.join([
    '// Generated from mysql2 3.24.5 by scripts/check-mysql-error-codes.py --write.',
    '// Source and license: vendor/mysql2-errors. Do not edit individual entries.',
    '',
    'pub(super) fn name(number: u16) -> Option<&\'static str> {',
    '    CODES',
    '        .binary_search_by_key(&number, |(code, _)| *code)',
    '        .ok()',
    '        .and_then(|index| CODES.get(index).map(|entry| entry.1))',
    '}',
    '',
    f'static CODES: [(u16, &str); {len(entries)}] = [',
    *(f'    ({number}, "{name}"),' for number, name in entries),
    '];',
    '',
])
output = root / "crates/seaorm/src/store/db_error/mysql_codes.rs"
if args.write:
    output.write_text(rendered)
else:
    actual = output.read_text()
    prefix, body = actual.split(f'static CODES: [(u16, &str); {len(entries)}] = [\n', 1)
    assert prefix == rendered.split('static CODES:', 1)[0], "The generated table header differs"
    assert body.endswith("];\n"), "The Rust table must end at its declared boundary"
    body = body.removesuffix("];\n")
    pattern = r'\(\s*(\d+),\s*"([A-Z0-9_]+)",?\s*\)'
    observed = [(int(number), name) for number, name in re.findall(pattern, body)]
    assert observed == entries, "Regenerate the complete Rust error-code table"
    assert not re.sub(pattern, "", body).replace(",", "").strip(), "Unexpected Rust table content"
print(f"Verified {len(entries)} mysql2 {origin['version']} symbolic error codes")
