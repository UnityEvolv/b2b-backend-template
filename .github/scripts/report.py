"""Turn a gitleaks or trivy JSON report into a short markdown section.

Usage: report.py <title> <report.json>

Never prints a secret: gitleaks runs with --redact, and only the rule, file,
line and commit are shown here anyway.
"""

import json
import sys
from pathlib import Path


def rows_gitleaks(data):
    for leak in data or []:
        yield (
            leak.get("RuleID", ""),
            f"`{leak.get('File', '')}:{leak.get('StartLine', '')}`",
            f"`{leak.get('Commit', '')[:8]}`",
        )


def rows_trivy(data):
    for result in (data or {}).get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            yield (
                vuln.get("Severity", ""),
                f"`{vuln.get('VulnerabilityID', '')}`",
                f"`{vuln.get('PkgName', '')}` {vuln.get('InstalledVersion', '')}"
                f" → {vuln.get('FixedVersion') or 'no fix yet'}",
                f"`{result.get('Target', '')}`",
            )


def main() -> None:
    title, path = sys.argv[1], Path(sys.argv[2])
    print(f"#### {title}\n")

    if not path.exists() or path.stat().st_size == 0:
        print("_No report was produced; see the job log._\n")
        return

    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        header = ("Rule", "Where", "Commit")
        rows = list(rows_gitleaks(data))
    else:
        header = ("Severity", "ID", "Package", "Target")
        rows = list(rows_trivy(data))

    if not rows:
        print("Nothing found.\n")
        return

    print("| " + " | ".join(header) + " |")
    print("|" + "---|" * len(header))
    for row in rows:
        print("| " + " | ".join(row) + " |")
    print()


if __name__ == "__main__":
    main()
