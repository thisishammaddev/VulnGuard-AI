import { Router, type IRouter } from "express";
import PDFDocument from "pdfkit";
import { and, eq } from "drizzle-orm";
import { GetReportParams } from "@workspace/api-zod";
import { db, scansTable } from "@workspace/db";
import { reportLimiter } from "../../middlewares/rateLimitMiddleware.js";
import { getScan } from "./store.js";

const router: IRouter = Router();

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
};

const COLORS = {
  ink: "#102A43",
  muted: "#52616B",
  teal: "#007C7A",
  paleTeal: "#E6F5F4",
  line: "#C9D6DF",
  paper: "#F7FAFC",
  critical: "#B42318",
  high: "#D97706",
  medium: "#A16207",
  low: "#2563EB",
};

type ReportVulnerability = {
  id?: number;
  severity?: string;
  type?: string;
  swc_id?: string | null;
  line_number?: number | null;
  title?: string;
  description?: string;
  technical_risk?: string | null;
  recommendation?: string | null;
  vulnerable_code?: string | null;
};

type ReportScan = {
  scanId: string;
  userId?: string;
  contract_name: string;
  code_hash: string;
  total_vulnerabilities: number;
  risk_score: number;
  vulnerabilities: unknown[];
  summary: string;
  analysis_time_ms: number;
  timestamp: string;
};

type SeverityCounts = Record<keyof typeof SEVERITY_RANK, number>;

function getSeverityCounts(vulnerabilities: ReportVulnerability[]): SeverityCounts {
  return vulnerabilities.reduce<SeverityCounts>((counts, finding) => {
    const severity = finding.severity as keyof SeverityCounts;
    if (severity in counts) counts[severity] += 1;
    return counts;
  }, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 });
}

function automatedSeverityIndex(counts: SeverityCounts): number {
  return Math.min(100, counts.CRITICAL * 25 + counts.HIGH * 15 + counts.MEDIUM * 7 + counts.LOW * 2);
}

function releasePosture(counts: SeverityCounts): string {
  if (counts.CRITICAL > 0 || counts.HIGH > 0) return "MANUAL REVIEW REQUIRED BEFORE RELEASE";
  if (counts.MEDIUM > 0) return "MANUAL REVIEW RECOMMENDED";
  if (counts.LOW > 0) return "LOW-SEVERITY ITEMS TO REVIEW";
  return "NO AUTOMATED BLOCKERS IDENTIFIED";
}

function severityColor(severity: string): string {
  if (severity === "CRITICAL") return COLORS.critical;
  if (severity === "HIGH") return COLORS.high;
  if (severity === "MEDIUM") return COLORS.medium;
  return COLORS.low;
}

function writeSectionTitle(doc: PDFKit.PDFDocument, title: string, subtitle?: string): void {
  doc.fillColor(COLORS.ink).font("Helvetica-Bold").fontSize(20).text(title);
  if (subtitle) doc.moveDown(0.25).fillColor(COLORS.muted).font("Helvetica").fontSize(9).text(subtitle);
  doc.moveDown(0.75);
}

function writeLabel(doc: PDFKit.PDFDocument, label: string, value: string): void {
  doc.font("Helvetica-Bold").fillColor(COLORS.ink).fontSize(9).text(`${label}  `, { continued: true });
  doc.font("Helvetica").fillColor(COLORS.muted).text(value);
}

function writeCard(doc: PDFKit.PDFDocument, x: number, y: number, width: number, height: number, label: string, value: string, color = COLORS.teal): void {
  doc.roundedRect(x, y, width, height, 6).fillAndStroke(COLORS.paper, COLORS.line);
  doc.fillColor(color).font("Helvetica-Bold").fontSize(8).text(label.toUpperCase(), x + 12, y + 12, { width: width - 24 });
  doc.fillColor(COLORS.ink).font("Helvetica-Bold").fontSize(18).text(value, x + 12, y + 29, { width: width - 24 });
}

function drawPageChrome(doc: PDFKit.PDFDocument, pageNumber: number, pageCount: number): void {
  const width = doc.page.width;
  const height = doc.page.height;
  doc.save();
  doc.lineWidth(0.7).strokeColor(COLORS.line).rect(20, 20, width - 40, height - 40).stroke();
  doc.fillColor(COLORS.teal).rect(20, 20, width - 40, 5).fill();
  doc.fillColor(COLORS.muted).font("Helvetica").fontSize(7).text("VULNGUARD AI | AUTOMATED SECURITY ANALYSIS", 36, 36, { width: 300 });
  doc.text(`PAGE ${pageNumber} OF ${pageCount}`, width - 150, height - 42, { width: 114, align: "right" });
  doc.restore();
}

function writeFinding(doc: PDFKit.PDFDocument, finding: ReportVulnerability, index: number): void {
  if (doc.y > 590) doc.addPage();
  const severity = finding.severity ?? "UNKNOWN";
  const title = finding.title ?? finding.type ?? "Unnamed finding";
  const color = severityColor(severity);
  const x = 50;
  const y = doc.y;

  doc.roundedRect(x, y, 495, 24, 4).fillAndStroke("#FFFFFF", COLORS.line);
  doc.fillColor(color).font("Helvetica-Bold").fontSize(9).text(severity, x + 10, y + 8, { width: 78 });
  doc.fillColor(COLORS.ink).font("Helvetica-Bold").fontSize(11).text(`${index}. ${title}`, x + 94, y + 6, { width: 386 });
  doc.y = y + 34;

  writeLabel(doc, "Location", finding.line_number ? `Line ${finding.line_number}` : "Not available");
  if (finding.swc_id) writeLabel(doc, "Reference", finding.swc_id);
  if (finding.description) writeLabel(doc, "What was detected", finding.description);
  if (finding.technical_risk) writeLabel(doc, "Why it matters", finding.technical_risk);
  if (finding.recommendation) writeLabel(doc, "Recommended action", finding.recommendation);
  if (finding.vulnerable_code) {
    doc.moveDown(0.2);
    doc.roundedRect(50, doc.y, 495, 28, 3).fillAndStroke("#F1F5F9", COLORS.line);
    doc.fillColor("#334155").font("Courier").fontSize(7.5).text(finding.vulnerable_code, 60, doc.y + 8, { width: 475, ellipsis: true });
    doc.y += 36;
  }
  doc.moveDown(0.55);
}

router.get("/report/:scanId", reportLimiter, async (req, res) => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  const parseResult = GetReportParams.safeParse(req.params);
  if (!parseResult.success) {
    res.status(400).json({ error: "Invalid scan ID" });
    return;
  }

  const { scanId } = parseResult.data;
  let scan: ReportScan | undefined = getScan(scanId);
  if (scan && scan.userId !== req.user.id) scan = undefined;

  if (!scan) {
    try {
      const [row] = await db
        .select()
        .from(scansTable)
        .where(and(eq(scansTable.id, scanId), eq(scansTable.userId, req.user.id)))
        .limit(1);
      if (row) {
        scan = {
          scanId: row.id,
          userId: row.userId,
          contract_name: row.contractName,
          code_hash: row.contractHash,
          total_vulnerabilities: Array.isArray(row.vulnerabilities) ? row.vulnerabilities.length : 0,
          risk_score: row.riskScore,
          vulnerabilities: Array.isArray(row.vulnerabilities) ? row.vulnerabilities : [],
          summary: row.summary ?? "",
          analysis_time_ms: row.executionTime ?? 0,
          timestamp: row.createdAt.toISOString(),
        };
      }
    } catch (err) {
      req.log.warn({ err }, "Failed to load scan for report");
    }
  }

  if (!scan) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }

  const generatedAt = new Date().toISOString();
  const vulnerabilities = (scan.vulnerabilities as ReportVulnerability[])
    .slice()
    .sort((left, right) => (SEVERITY_RANK[left.severity ?? ""] ?? 9) - (SEVERITY_RANK[right.severity ?? ""] ?? 9));
  const counts = getSeverityCounts(vulnerabilities);
  const score = automatedSeverityIndex(counts);
  const filename = scan.contract_name.replace(/[^a-z0-9_-]+/gi, "-").replace(/^-+|-+$/g, "") || "contract";

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename="${filename}-automated-analysis.pdf"`);
  res.setHeader("Cache-Control", "no-store");

  const doc = new PDFDocument({ margin: 50, size: "A4", bufferPages: true });
  doc.pipe(res);

  // Cover page
  doc.rect(20, 20, doc.page.width - 40, 176).fill(COLORS.ink);
  doc.fillColor("#FFFFFF").font("Helvetica-Bold").fontSize(11).text("VULNGUARD AI", 50, 56);
  doc.fillColor("#9FE7E5").font("Helvetica-Bold").fontSize(8).text("AUTOMATED SECURITY ANALYSIS", 50, 78);
  doc.fillColor("#FFFFFF").font("Helvetica-Bold").fontSize(28).text("Smart Contract\nSecurity Report", 50, 104, { width: 390 });
  doc.fillColor("#D9E2EC").font("Helvetica").fontSize(9).text("Evidence-based scanner output for developer review.", 50, 166);
  writeCard(doc, 50, 228, 150, 78, "Automated severity index", `${score} / 100`, score >= 40 ? COLORS.critical : COLORS.teal);
  writeCard(doc, 215, 228, 150, 78, "Findings", String(vulnerabilities.length), COLORS.teal);
  writeCard(doc, 380, 228, 150, 78, "Critical / High", `${counts.CRITICAL} / ${counts.HIGH}`, counts.CRITICAL || counts.HIGH ? COLORS.critical : COLORS.teal);
  doc.fillColor(COLORS.ink).font("Helvetica-Bold").fontSize(16).text(scan.contract_name, 50, 350, { width: 495 });
  doc.fillColor(COLORS.muted).font("Helvetica").fontSize(9).text(`Report ID: ${scan.scanId}`, 50, 380);
  doc.text(`Generated: ${generatedAt}`, 50, 396);
  doc.text(`Code hash: ${scan.code_hash}`, 50, 412, { width: 495, ellipsis: true });
  doc.roundedRect(50, 467, 495, 92, 6).fillAndStroke(COLORS.paleTeal, COLORS.line);
  doc.fillColor(COLORS.teal).font("Helvetica-Bold").fontSize(9).text("RELEASE POSTURE", 64, 483);
  doc.fillColor(COLORS.ink).font("Helvetica-Bold").fontSize(13).text(releasePosture(counts), 64, 502, { width: 460 });
  doc.fillColor(COLORS.muted).font("Helvetica").fontSize(8.5).text("This posture is based only on automated finding severity. It is not a deployment approval, professional audit, or certification.", 64, 528, { width: 455 });
  doc.fillColor(COLORS.muted).font("Helvetica").fontSize(8).text("Confidential developer artifact. Validate every finding against source code and compiler output.", 50, 700, { width: 495, align: "center" });

  // Contents
  doc.addPage();
  writeSectionTitle(doc, "Contents", "A concise map of this automated analysis report.");
  [
    ["01", "Report cover", "1"],
    ["02", "Contents", "2"],
    ["03", "Executive snapshot", "3"],
    ["04", "Finding detail", "4+"],
    ["05", "Method and limitations", "Final page"],
  ].forEach(([number, title, page]) => {
    const y = doc.y;
    doc.fillColor(COLORS.teal).font("Helvetica-Bold").fontSize(11).text(number, 50, y);
    doc.fillColor(COLORS.ink).font("Helvetica-Bold").fontSize(11).text(title, 95, y, { width: 330 });
    doc.fillColor(COLORS.muted).font("Helvetica").fontSize(10).text(page, 460, y, { width: 70, align: "right" });
    doc.moveTo(50, y + 23).lineTo(530, y + 23).strokeColor(COLORS.line).lineWidth(0.5).stroke();
    doc.y = y + 38;
  });
  doc.moveDown(1.5);
  doc.roundedRect(50, doc.y, 480, 74, 6).fillAndStroke(COLORS.paper, COLORS.line);
  doc.fillColor(COLORS.ink).font("Helvetica-Bold").fontSize(10).text("How to use this report", 64, doc.y + 14);
  doc.fillColor(COLORS.muted).font("Helvetica").fontSize(9).text("Start with the executive snapshot, reproduce each reported condition, and use the final page to plan manual validation. A clean report does not prove a contract is secure.", 64, doc.y + 31, { width: 450 });

  // Executive snapshot
  doc.addPage();
  writeSectionTitle(doc, "Executive Snapshot", "Measured from the recorded automated findings, not estimated financial impact.");
  writeCard(doc, 50, doc.y, 112, 72, "Critical", String(counts.CRITICAL), COLORS.critical);
  writeCard(doc, 174, doc.y, 112, 72, "High", String(counts.HIGH), COLORS.high);
  writeCard(doc, 298, doc.y, 112, 72, "Medium", String(counts.MEDIUM), COLORS.medium);
  writeCard(doc, 422, doc.y, 112, 72, "Low", String(counts.LOW), COLORS.low);
  doc.y += 94;
  writeSectionTitle(doc, "Score interpretation");
  doc.fillColor(COLORS.ink).font("Helvetica-Bold").fontSize(24).text(`${score} / 100`);
  doc.fillColor(COLORS.muted).font("Helvetica").fontSize(9).text("Automated Severity Index. It is calculated as critical x 25, high x 15, medium x 7, and low x 2, capped at 100. It is not CVSS, exploit probability, funds-at-risk, or an audit grade.", { width: 480 });
  doc.moveDown(1);
  writeSectionTitle(doc, "Scan record");
  writeLabel(doc, "Contract", scan.contract_name);
  writeLabel(doc, "Scan timestamp", scan.timestamp);
  writeLabel(doc, "Analysis duration", `${(scan.analysis_time_ms / 1000).toFixed(2)} seconds`);
  writeLabel(doc, "Findings recorded", String(vulnerabilities.length));
  doc.moveDown(0.8);
  doc.fillColor(COLORS.ink).font("Helvetica-Bold").fontSize(11).text("Scanner summary");
  doc.moveDown(0.3).fillColor(COLORS.muted).font("Helvetica").fontSize(9).text(scan.summary || "No summary was generated.", { width: 480 });

  // Findings
  doc.addPage();
  writeSectionTitle(doc, "Finding Detail", "Each item is an automated signal that requires source-level validation.");
  if (vulnerabilities.length === 0) {
    doc.roundedRect(50, doc.y, 480, 64, 6).fillAndStroke(COLORS.paleTeal, COLORS.line);
    doc.fillColor(COLORS.ink).font("Helvetica-Bold").fontSize(11).text("No automated findings were produced.", 64, doc.y + 14);
    doc.fillColor(COLORS.muted).font("Helvetica").fontSize(9).text("This is not proof that the contract is secure. Continue with compiler checks, tests, and manual review.", 64, doc.y + 33, { width: 450 });
  } else {
    vulnerabilities.forEach((finding, index) => writeFinding(doc, finding, index + 1));
  }

  // Limitations
  doc.addPage();
  writeSectionTitle(doc, "Method and Limitations", "Important context before using this report for any release decision.");
  doc.roundedRect(50, doc.y, 480, 88, 6).fillAndStroke("#FFF7ED", COLORS.line);
  doc.fillColor(COLORS.critical).font("Helvetica-Bold").fontSize(10).text("AUTOMATED ANALYSIS IS NOT A SECURITY AUDIT", 64, doc.y + 14);
  doc.fillColor(COLORS.muted).font("Helvetica").fontSize(9).text("The scanner can miss vulnerabilities and can produce false positives. It does not establish compliance, audit completion, production readiness, exploitability, financial loss, or remediation cost.", 64, doc.y + 34, { width: 450 });
  doc.y += 110;
  writeSectionTitle(doc, "Recommended next steps");
  [
    "Compile the contract with its exact Solidity version and dependencies.",
    "Reproduce each finding and confirm the affected execution path manually.",
    "Run parser-aware tools such as Slither alongside unit, fuzz, and invariant tests.",
    "Use an independent professional audit before mainnet deployment or significant asset custody.",
  ].forEach((item, index) => {
    const y = doc.y;
    doc.circle(60, y + 7, 9).fill(COLORS.teal);
    doc.fillColor("#FFFFFF").font("Helvetica-Bold").fontSize(8).text(String(index + 1), 56, y + 3, { width: 8, align: "center" });
    doc.fillColor(COLORS.ink).font("Helvetica").fontSize(10).text(item, 80, y, { width: 430 });
    doc.y = y + 31;
  });

  const pageRange = doc.bufferedPageRange();
  for (let pageIndex = 0; pageIndex < pageRange.count; pageIndex += 1) {
    doc.switchToPage(pageIndex);
    drawPageChrome(doc, pageIndex + 1, pageRange.count);
  }
  doc.end();
});

export default router;