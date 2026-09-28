"""Fail if an accepted risk in .trivyignore.yaml has no reason or no expiry, or has expired.

An allow-list entry without a reason is a vulnerability nobody remembers
accepting, and one without an expiry is permanent by accident.

Parses the file's small, fixed shape by hand so CI needs no YAML library.
"""

import datetime
import re
import sys
from pathlib import Path


def entries(text: str):
    """Yield each `- id:` block under `vulnerabilities:` as a dict of its keys."""
    current = None
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].rstrip()
        if not stripped:
            continue
        match = re.match(r"^\s*-\s*id:\s*(\S+)", stripped)
        if match:
            if current:
                yield current
            current = {"id": match.group(1)}
            continue
        match = re.match(r"^\s+(\w+):\s*(.+)$", stripped)
        if current is not None and match:
            current[match.group(1)] = match.group(2).strip().strip("'\"")
    if current:
        yield current


def main() -> int:
    path = Path(sys.argv[1])
    if not path.exists():
        return 0

    today = datetime.date.today()
    problems = []
    for entry in entries(path.read_text(encoding="utf-8")):
        name = entry["id"]
        if not entry.get("statement"):
            problems.append(f"{name}: no statement saying why it is accepted")
        expiry = entry.get("expired_at")
        if not expiry:
            problems.append(f"{name}: no expired_at")
            continue
        try:
            when = datetime.date.fromisoformat(expiry[:10])
        except ValueError:
            problems.append(f"{name}: expired_at {expiry!r} is not a date")
            continue
        if when < today:
            problems.append(f"{name}: accepted until {when}, which has passed")

    for problem in problems:
        print(f"::error file={path}::{problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
