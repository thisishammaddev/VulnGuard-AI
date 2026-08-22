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

function severityLabel(vulnerabilities: ReportVulnerability[]): string {
  if (vulnerabilities.some((v) => v.severity === "CRITICAL")) return "CRITICAL FINDINGS";
  if (vulnerabilities.some((v) => v.severity === "HIGH")) return "HIGH FINDINGS";
  if (vulnerabilities.some((v) => v.severity === "MEDIUM")) return "MEDIUM FINDINGS";
  if (vulnerabilities.length > 0) return "LOW FINDINGS";
  return "NO FINDINGS";
}

function writeTitle(doc: PDFKit.PDFDocument, title: string): void {
  doc.fillColor("#0f172a").fontSize(22).font("Helvetica-Bold").text(title);
  doc.moveDown(0.5);
}

function writeLabel(doc: PDFKit.PDFDocument, label: string, value: string): void {
  doc.font("Helvetica-Bold").fillColor("#0f172a").fontSize(10).text(`${label}: `, { continued: true });
  doc.font("Helvetica").fillColor("#334155").text(value);
}

function writeFinding(doc: PDFKit.PDFDocument, finding: ReportVulnerability, index: number): void {
  const severity = finding.severity ?? "UNKNOWN";
  const title = finding.title ?? finding.type ?? "Unnamed finding";
  doc.moveDown(0.6);
  doc.font("Helvetica-Bold").fillColor("#0f172a").fontSize(13).text(`${index}. [${severity}] ${title}`);
  writeLabel(doc, "Location", finding.line_number ? `line ${finding.line_number}` : "not available");
  if (finding.swc_id) writeLabel(doc, "Reference", finding.swc_id);
  if (finding.description) writeLabel(doc, "Description", finding.description);
  if (finding.technical_risk) writeLabel(doc, "Risk", finding.technical_risk);
  if (finding.recommendation) writeLabel(doc, "Recommendation", finding.recommendation);
  if (finding.vulnerable_code) {
    doc.moveDown(0.2);
    doc.font("Courier").fontSize(8).fillColor("#334155").text(finding.vulnerable_code, {
      indent: 12,
      width: 500,
    });
  }
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

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename="${scan.contract_name}-audit-report.pdf"`);
  res.setHeader("Cache-Control", "no-store");

  const doc = new PDFDocument({ margin: 50, size: "A4" });
  doc.pipe(res);

  writeTitle(doc, "VulnGuard AI Automated Scan Report");
  doc.font("Helvetica").fontSize(10).fillColor("#475569").text(
    "Automated findings only. This document is not a professional security audit, release approval, compliance certification, or financial assessment.",
  );
  doc.moveDown(1);
  writeLabel(doc, "Contract", scan.contract_name);
  writeLabel(doc, "Report ID", scan.scanId);
  writeLabel(doc, "Scan timestamp", scan.timestamp);
  writeLabel(doc, "Report generated", generatedAt);
  writeLabel(doc, "Code hash", scan.code_hash);
  writeLabel(doc, "Scan duration", `${(scan.analysis_time_ms / 1000).toFixed(2)} seconds`);
  writeLabel(doc, "Finding status", severityLabel(vulnerabilities));
  writeLabel(doc, "Finding count", String(vulnerabilities.length));
  doc.moveDown(1);
  doc.font("Helvetica-Bold").fontSize(12).fillColor("#0f172a").text("Scanner summary");
  doc.font("Helvetica").fontSize(10).fillColor("#334155").text(scan.summary || "No summary was generated.");

  doc.addPage();
  writeTitle(doc, "Findings");
  if (vulnerabilities.length === 0) {
    doc.font("Helvetica").fontSize(10).fillColor("#334155").text(
      "No automated findings were produced. This is not proof that the contract is secure.",
    );
  } else {
    vulnerabilities.forEach((finding, index) => writeFinding(doc, finding, index + 1));
  }

  doc.addPage();
  writeTitle(doc, "Limitations and Next Steps");
  doc.font("Helvetica").fontSize(10).fillColor("#334155").text(
    "The scanner uses automated analysis and can miss issues or produce false positives. Confirm findings against the source code and compiler output before acting on them.",
  );
  doc.moveDown(0.7);
  [
    "Compile the contract with its exact Solidity and dependency versions.",
    "Run parser-aware static analysis such as Slither and review the results manually.",
    "Add unit, integration, fuzz, and invariant tests for the intended protocol behavior.",
    "Use an independent professional audit before a mainnet deployment or significant asset custody.",
  ].forEach((item) => doc.text(`- ${item}`));

  doc.end();
});

export default router;