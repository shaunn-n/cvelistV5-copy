"""Create a reviewable inventory of CVE records matching selected control flaws."""

import csv
import json
import os
import re
from collections import Counter
from pathlib import Path

ROOT = Path("cves")
OUT = Path("analysis_results")
TARGET_CWES = {
    "CWE-285", "CWE-863", "CWE-639", "CWE-287", "CWE-306", "CWE-266",
    "CWE-269", "CWE-345", "CWE-346", "CWE-20", "CWE-22", "CWE-436",
    "CWE-444", "CWE-610", "CWE-841", "CWE-642",
}

# These are deliberately specific enough to make the non-CWE results useful as
# review candidates rather than treating every occurrence of "access" as a hit.
SIGNALS = {
    "authorization_error": re.compile(r"\b(authori[sz]ation|access[ -]control|permission(?:s)?|privileg(?:e|es|ed)|insecure direct object reference|\bidor\b)\b", re.I),
    "authentication_logic": re.compile(r"\b(authentication|unauthenticated|auth(?:entication)? bypass|login bypass|credential validation|session fixation)\b", re.I),
    "business_logic": re.compile(r"\b(business logic|logic (?:flaw|error|vulnerabilit(?:y|ies))|workflow bypass)\b", re.I),
    "state_machine_error": re.compile(r"\b(state machine|state transition|invalid state|state-management)\b", re.I),
    "trust_boundary_error": re.compile(r"\b(trust boundary|confused deputy|trust(?:ed)? (?:input|data|source))\b", re.I),
    "certificate_validation_error": re.compile(r"\b(certificate validation|improper certificate|certificate (?:chain|hostname|host name) validation|tls certificate|ssl certificate)\b", re.I),
}
CWE_RE = re.compile(r"\bCWE-\d+\b", re.I)


def texts(value):
    """Yield every human-readable string, retaining nested CNA/ADP content."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key not in {"url", "references", "tags"}:
                yield from texts(item)
    elif isinstance(value, list):
        for item in value:
            yield from texts(item)
    elif isinstance(value, str):
        yield value


def cwe_ids(record):
    return sorted({m.upper() for m in CWE_RE.findall(json.dumps(record, ensure_ascii=False)) if m.upper() in TARGET_CWES})


def main():
    OUT.mkdir(exist_ok=True)
    output = OUT / "cve_control_flaw_candidates.csv"
    counts = Counter()
    scanned = malformed = matched = 0

    with output.open("w", newline="", encoding="utf-8") as f:
        fields = ["cve_id", "path", "match_basis", "matched_cwes", "matched_categories", "title", "description"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for directory, _, files in os.walk(ROOT):
            for name in files:
                if not name.endswith(".json") or not name.startswith("CVE-"):
                    continue
                scanned += 1
                path = Path(directory) / name
                try:
                    with path.open(encoding="utf-8") as source:
                        record = json.load(source)
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    malformed += 1
                    continue

                cwes = cwe_ids(record)
                all_text = "\n".join(texts(record))
                categories = [category for category, pattern in SIGNALS.items() if pattern.search(all_text)]
                if not cwes and not categories:
                    continue

                cna = record.get("containers", {}).get("cna", {})
                descriptions = cna.get("descriptions", [])
                description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
                title = cna.get("title", "")
                basis = ";".join(filter(None, ["specified_cwe" if cwes else "", "description_signal" if categories else ""]))
                writer.writerow({
                    "cve_id": record.get("cveMetadata", {}).get("cveId", name[:-5]),
                    "path": path.as_posix(),
                    "match_basis": basis,
                    "matched_cwes": ";".join(cwes),
                    "matched_categories": ";".join(categories),
                    "title": title,
                    "description": description,
                })
                matched += 1
                counts["specified_cwe_records" if cwes else "signal_only_records"] += 1
                for cwe in cwes:
                    counts[cwe] += 1
                for category in categories:
                    counts[category] += 1

    summary = {"records_scanned": scanned, "records_matched": matched, "malformed_or_unreadable": malformed, "counts": dict(sorted(counts.items()))}
    (OUT / "cve_control_flaw_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
