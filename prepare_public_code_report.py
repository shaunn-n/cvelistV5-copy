"""Create workbook-ready JSON for the year-balanced public-code CVE review."""

import csv
import json
from pathlib import Path

SOURCE = Path("analysis_results/public_code_review_candidates.csv")
OUT = Path("analysis_results/public_code_review_candidates.json")


def main():
    rows = []
    with SOURCE.open(newline="", encoding="utf-8") as source:
        for row in csv.DictReader(source):
            rows.append({
                "Category": row["semantic_category"],
                "Year": int(row["cve_year"]),
                "CVE": row["cve_id"],
                "CWE": row["matched_cwes"] or "Not specified in record",
                "Title": row["title"] or "(No CNA title)",
                "Description": row["description"],
                "Public vulnerable code": "Yes",
                "Public fix": "Yes",
                "Evidence": "The CVE record links this public commit/PR. Its publicly visible parent/pre-change revision provides the vulnerable code; the commit/PR diff provides the remediation.",
                "Public commit or PR": row["public_code_reference"],
                "CVE record": f"https://www.cve.org/CVERecord?id={row['cve_id']}",
                "Verified date": "2026-07-23",
            })
    OUT.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    print(f"Prepared {len(rows)} rows")


if __name__ == "__main__":
    main()
