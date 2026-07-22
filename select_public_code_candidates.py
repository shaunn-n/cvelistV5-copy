"""Select distinct high-confidence 2023–2026 CVEs with public code references."""

import csv
import json
import re
from pathlib import Path

SOURCE = Path("analysis_results/semantic_issue_cves.csv")
OUT = Path("analysis_results/public_code_review_candidates.csv")

CATEGORIES = {
    "Authorization errors": {"cwes": {"CWE-285", "CWE-863", "CWE-639", "CWE-266", "CWE-269"}, "signals": {"authorization_error"}},
    "Authentication logic": {"cwes": {"CWE-287", "CWE-306"}, "signals": {"authentication_logic"}},
    "Business logic flaws": {"cwes": set(), "signals": {"business_logic"}},
    "State machine errors": {"cwes": {"CWE-841"}, "signals": {"state_machine_error"}},
    "Trust boundary errors": {"cwes": {"CWE-345", "CWE-346", "CWE-610"}, "signals": {"trust_boundary_error"}},
    "Certificate validation errors": {"cwes": set(), "signals": {"certificate_validation_error"}},
}
PUBLIC_CODE = re.compile(r"(github\.com/.+/(?:commit|pull)/|gitlab\..+/(?:commit|-/commit|merge_requests)/|\.patch(?:$|\?)|\.diff(?:$|\?))", re.I)


def split(value):
    return set(filter(None, value.split(";")))


def refs_for(path):
    try:
        record = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    refs = []
    for container in record.get("containers", {}).values():
        if not isinstance(container, dict):
            continue
        for reference in container.get("references", []):
            url = reference.get("url", "")
            if PUBLIC_CODE.search(url):
                refs.append(url)
    return sorted(set(refs))


def main():
    pools = {name: [] for name in CATEGORIES}
    with SOURCE.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["semantic_confidence"] != "high" or not re.match(r"CVE-202[3-6]-", row["cve_id"]):
                continue
            cwes = split(row["matched_cwes"])
            signals = split(row["matched_categories"])
            for name, rule in CATEGORIES.items():
                if cwes & rule["cwes"] or signals & rule["signals"]:
                    pools[name].append(row)

    selected, used = [], set()
    for name, candidates in pools.items():
        count = 0
        for row in candidates:
            if row["cve_id"] in used:
                continue
            refs = refs_for(row["path"])
            if not refs:
                continue
            row["semantic_category"] = name
            row["public_code_reference"] = refs[0]
            selected.append(row)
            used.add(row["cve_id"])
            count += 1
            if count == 5:
                break
        print(f"{name}: {count}")

    fields = ["semantic_category", "cve_id", "matched_cwes", "matched_categories", "title", "description", "public_code_reference", "path"]
    with OUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(selected)
    print(f"total: {len(selected)}")


if __name__ == "__main__":
    main()
