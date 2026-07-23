import fs from "node:fs/promises";
import { SpreadsheetFile, Workbook } from "@oai/artifact-tool";

const rows = JSON.parse(await fs.readFile("analysis_results/public_code_review_candidates.json", "utf8"));
const outputDir = "outputs/semantic_cve_public_code_report_2023_2026";
await fs.mkdir(outputDir, { recursive: true });

const workbook = Workbook.create();
const summary = workbook.worksheets.add("Summary");
const detail = workbook.worksheets.add("Verified CVEs");

const navy = "#17365D";
const blue = "#DCEAF7";
const green = "#D9EAD3";
const lightBorder = "#D0D7DE";

summary.showGridLines = false;
summary.getRange("A1:F1").merge();
summary.getRange("A1").values = [["High-Confidence Semantic CVEs with Public Code & Fix Evidence"]];
summary.getRange("A1:F1").format = { fill: navy, font: { bold: true, color: "#FFFFFF", size: 16 }, horizontalAlignment: "center", verticalAlignment: "center" };
summary.getRange("A1:F1").format.rowHeight = 30;
summary.getRange("A3:F3").merge();
summary.getRange("A3").values = [["Scope: five CVEs for each semantic category, with at least one selected CVE from every year 2023–2026."]];
summary.getRange("A4:F4").merge();
summary.getRange("A4").values = [["Evidence standard: each selected CVE record contains a direct public GitHub/GitLab commit or pull-request reference. The public pre-change parent/revision is the vulnerable-code evidence; the linked diff/PR is the remediation evidence."]];
summary.getRange("A3:F4").format = { wrapText: true, verticalAlignment: "top" };
summary.getRange("A4:F4").format.rowHeight = 40;

summary.getRange("A6:F6").values = [["Semantic category", "Selected CVEs", "2023", "2024", "2025", "2026"]];
summary.getRange("A6:F6").format = { fill: navy, font: { bold: true, color: "#FFFFFF" }, horizontalAlignment: "center" };
const categories = ["Authorization errors", "Authentication logic", "Business logic flaws", "State machine errors", "Trust boundary errors", "Certificate validation errors"];
summary.getRange("A7:A12").values = categories.map((category) => [category]);
summary.getRange("B7").formulas = [["=COUNTIF('Verified CVEs'!$A$7:$A$36,A7)"]];
summary.getRange("B7:B12").fillDown();
for (let col = 2; col <= 5; col++) {
  const letter = String.fromCharCode(65 + col);
  const year = 2021 + col;
  summary.getCell(6, col).formulas = [[`=COUNTIFS('Verified CVEs'!$A$7:$A$36,$A7,'Verified CVEs'!$B$7:$B$36,${year})`]];
  summary.getRangeByIndexes(6, col, 6, 1).fillDown();
}
summary.getRange("A6:F12").format.borders = { preset: "all", style: "thin", color: lightBorder };
summary.getRange("B7:F12").format.horizontalAlignment = "center";
summary.getRange("A14:F14").merge();
summary.getRange("A14").values = [["All 30 selections are marked high confidence in the prior semantic triage. Source URLs are included in the detailed sheet for direct review."]];
summary.getRange("A14:F14").format = { fill: blue, wrapText: true, font: { italic: true } };
summary.getRange("A14:F14").format.rowHeight = 28;
summary.getRange("A:A").format.columnWidth = 30;
summary.getRange("B:F").format.columnWidth = 13;
summary.freezePanes.freezeRows(6);

detail.showGridLines = false;
detail.getRange("A1:L1").merge();
detail.getRange("A1").values = [["Verified Public Vulnerable-Code and Fix References"]];
detail.getRange("A1:L1").format = { fill: navy, font: { bold: true, color: "#FFFFFF", size: 15 }, horizontalAlignment: "center" };
detail.getRange("A1:L1").format.rowHeight = 28;
detail.getRange("A3:L3").merge();
detail.getRange("A3").values = [["Each row includes the public commit/PR cited in its CVE record. Review the parent/pre-fix revision and the linked diff to compare vulnerable and remediated code."]];
detail.getRange("A3:L3").format = { fill: blue, wrapText: true, verticalAlignment: "center" };
detail.getRange("A3:L3").format.rowHeight = 30;

const headers = ["Category", "Year", "CVE", "CWE", "Title", "Description", "Public vulnerable code", "Public fix", "Evidence", "Public commit or PR", "CVE record", "Verified date"];
detail.getRange("A6:L6").values = [headers];
detail.getRange("A6:L6").format = { fill: navy, font: { bold: true, color: "#FFFFFF" }, wrapText: true, horizontalAlignment: "center", verticalAlignment: "center" };
detail.getRange("A6:L6").format.rowHeight = 36;
const values = rows.map((row) => headers.map((header) => row[header]));
detail.getRange(`A7:L${6 + values.length}`).values = values;
detail.getRange(`A7:L${6 + values.length}`).format = { wrapText: true, verticalAlignment: "top" };
detail.getRange(`G7:H${6 + values.length}`).format = { fill: green, horizontalAlignment: "center", font: { bold: true } };
detail.getRange(`A6:L${6 + values.length}`).format.borders = { preset: "all", style: "thin", color: lightBorder };
for (let r = 6; r < 6 + values.length; r++) detail.getRangeByIndexes(r, 0, 1, headers.length).format.rowHeight = 72;
detail.getRange("A:A").format.columnWidth = 24;
detail.getRange("B:B").format.columnWidth = 9;
detail.getRange("C:C").format.columnWidth = 16;
detail.getRange("D:D").format.columnWidth = 17;
detail.getRange("E:E").format.columnWidth = 33;
detail.getRange("F:F").format.columnWidth = 55;
detail.getRange("G:H").format.columnWidth = 16;
detail.getRange("I:I").format.columnWidth = 42;
detail.getRange("J:K").format.columnWidth = 52;
detail.getRange("L:L").format.columnWidth = 14;
detail.tables.add(`A6:L${6 + values.length}`, true, "VerifiedCVEsTable");
detail.freezePanes.freezeRows(6);
detail.freezePanes.freezeColumns(3);

const check = await workbook.inspect({ kind: "table", range: "Summary!A1:F14", include: "values,formulas", tableMaxRows: 20, tableMaxCols: 8 });
console.log(check.ndjson);
const errors = await workbook.inspect({ kind: "match", searchTerm: "#REF!|#DIV/0!|#VALUE!|#NAME\\?|#N/A", options: { useRegex: true, maxResults: 100 }, summary: "formula error scan" });
console.log(errors.ndjson);
const preview = await workbook.render({ sheetName: "Summary", range: "A1:F14", scale: 1.5, format: "png" });
await fs.writeFile(`${outputDir}/summary_preview.png`, new Uint8Array(await preview.arrayBuffer()));
const detailedPreview = await workbook.render({ sheetName: "Verified CVEs", range: "A1:L14", scale: 1, format: "png" });
await fs.writeFile(`${outputDir}/detail_preview.png`, new Uint8Array(await detailedPreview.arrayBuffer()));

const output = await SpreadsheetFile.exportXlsx(workbook);
await output.save(`${outputDir}/semantic_cves_public_code_2023_2026.xlsx`);
