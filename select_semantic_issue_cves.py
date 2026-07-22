"""Derive an explainable semantic-issue subset from the candidate CVE CSV."""

import csv
import json
import re
from collections import Counter
from pathlib import Path

INPUT = Path("analysis_results/cve_control_flaw_candidates.csv")
OUTPUT = Path("analysis_results/semantic_issue_cves.csv")
SUMMARY = Path("analysis_results/semantic_issue_cves_summary.json")

# These CWEs directly concern an application's interpretation of authority,
# identity, state, origin, trust, or protocol meaning. CWE-20 and CWE-22 are
# intentionally not automatic: they are semantic only when the description
# supplies semantic-control context.
SEMANTIC_CWES = {
    "CWE-285", "CWE-863", "CWE-639", "CWE-287", "CWE-306", "CWE-266",
    "CWE-269", "CWE-345", "CWE-346", "CWE-436", "CWE-444", "CWE-610",
    "CWE-841", "CWE-642",
}
DIRECT_CATEGORIES = {
    "business_logic", "state_machine_error", "trust_boundary_error",
    "certificate_validation_error",
}
STRONG_SEMANTIC_LANGUAGE = re.compile(
    r"\b(access[ -]control|authori[sz]ation|authori[sz]e|permission(?:s)?|"
    r"privileg(?:e|es|ed)|insecure direct object reference|\bidor\b|"
    r"authentication|unauthenticated|auth(?:entication)? bypass|login bypass|"
    r"credential validation|session fixation|business logic|workflow bypass|"
    r"state machine|state transition|trust boundary|confused deputy|"
    r"certificate validation|certificate (?:chain|hostname|host name) validation)\b",
    re.I,
)


def split(value):
    return [item for item in value.split(";") if item]


def main():
    if not INPUT.exists():
        raise SystemExit(f"Missing input report: {INPUT}")

    counts = Counter()
    selected = 0
    with INPUT.open(newline="", encoding="utf-8") as source, OUTPUT.open("w", newline="", encoding="utf-8") as destination:
        reader = csv.DictReader(source)
        fields = list(reader.fieldnames) + ["semantic_confidence", "semantic_basis"]
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()

        for row in reader:
            cwes = set(split(row["matched_cwes"]))
            categories = set(split(row["matched_categories"]))
            direct_cwes = sorted(cwes & SEMANTIC_CWES)
            direct_categories = sorted(categories & DIRECT_CATEGORIES)
            text = " ".join((row.get("title", ""), row.get("description", "")))
            contextual = bool(STRONG_SEMANTIC_LANGUAGE.search(text))

            basis = []
            if direct_cwes:
                basis.append("semantic_CWE=" + ",".join(direct_cwes))
            if direct_categories:
                basis.append("semantic_category=" + ",".join(direct_categories))
            # Authn/authz matches and CWE-20/CWE-22 are retained only when the
            # record itself contains explicit semantic-control language.
            if not basis and contextual:
                basis.append("explicit_semantic_control_language")

            if not basis:
                continue

            row["semantic_confidence"] = "high" if direct_cwes or direct_categories else "medium"
            row["semantic_basis"] = ";".join(basis)
            writer.writerow(row)
            selected += 1
            counts[row["semantic_confidence"]] += 1
            for cwe in direct_cwes:
                counts[cwe] += 1
            for category in direct_categories:
                counts[category] += 1

    SUMMARY.write_text(json.dumps({
        "definition": "CVEs involving incorrect interpretation or enforcement of identity, authority, state, trust, origin, protocol meaning, or certificate validity.",
        "input_candidates": 107278,
        "semantic_issue_cves": selected,
        "counts": dict(sorted(counts.items())),
    }, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"semantic_issue_cves": selected, "counts": dict(sorted(counts.items()))}, indent=2))


if __name__ == "__main__":
    main()
