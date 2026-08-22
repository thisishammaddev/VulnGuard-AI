import { Router, type IRouter } from "express";
import { createHash } from "crypto";
import { anthropic } from "@workspace/integrations-anthropic-ai";
import { OPENROUTER_MODEL } from "@workspace/integrations-anthropic-ai";
import { ScanContractBody } from "@workspace/api-zod";
import { SYSTEM_PROMPT, buildUserPrompt } from "./prompts.js";
import { storeScan } from "./store.js";
import { db, scansTable } from "@workspace/db";
import { analyzeContractFallback, type FallbackVulnerability } from "./fallback-analyzer.js";
import { compileSolidity } from "../../services/solidity/compiler.js";
import * as zod from "zod";

const router: IRouter = Router();

function resolveAiError(err: unknown): string {
  const status = (err as { status?: number })?.status;
  const message = (err as { message?: string })?.message ?? "";

  if (status === 429) return "AI rate limit reached. Auto-fallback scan returned results.";
  if (status === 401 || status === 403) return "AI provider authentication failed. Auto-fallback scan returned results.";
  if (status === 402) return "AI provider quota/billing issue. Auto-fallback scan returned results.";
  if (status === 400) return "AI request rejected by provider. Auto-fallback scan returned results.";
  if (status && status >= 500) return "AI provider temporarily unavailable. Auto-fallback scan returned results.";
  if (/timeout|timed out|abort/i.test(message)) return "AI request timed out. Auto-fallback scan returned results.";
  return "AI unavailable. Auto-fallback scan returned results.";
}

const VulnerabilityAI = zod.object({
  id: zod.number().optional(),
  type: zod.string(),
  severity: zod.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
  swc_id: zod.string().nullable().optional(),
  line_number: zod.number().nullable().optional(),
  affected_lines: zod.string().nullable().optional(),
  affected_functions: zod.string().nullable().optional(),
  title: zod.string(),
  description: zod.string(),
  technical_risk: zod.string().optional(),
  attack_scenario: zod.string().nullable().optional(),
  impact: zod.string().nullable().optional(),
  gas_impact: zod.string().nullable().optional(),
  vulnerable_code: zod.string().nullable().optional(),
  fixed_code: zod.string().nullable().optional(),
  recommendation: zod.string().optional(),
});

type VulnerabilityAIType = zod.infer<typeof VulnerabilityAI>;

const AIResponseSchema = zod.object({
  contract_name: zod.string().optional(),
  total_vulnerabilities: zod.number().optional(),
  risk_score: zod.number().optional(),
  vulnerabilities: zod.array(VulnerabilityAI).optional(),
  summary: zod.string().optional(),
});

function sseWrite(res: import("express").Response, event: string, data: unknown) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

const STAGES = [
  { ms: 0, msg: "Parsing Solidity abstract syntax tree..." },
  { ms: 3000, msg: "Checking access control patterns..." },
  { ms: 6000, msg: "Analyzing reentrancy attack vectors..." },
  { ms: 9000, msg: "Scanning arithmetic for overflows..." },
  { ms: 12000, msg: "Evaluating external call safety..." },
  { ms: 16000, msg: "Inspecting oracle and flash loan risks..." },
  { ms: 22000, msg: "Running final comprehensive audit..." },
];

function vulnKey(v: { type: string; line_number: number | null | undefined; title: string }): string {
  return `${v.type}|${v.line_number ?? -1}|${v.title}`;
}

function normalizeFallbackVulns(vulns: FallbackVulnerability[]): Array<Record<string, unknown>> {
  return vulns.map((v) => ({
    id: v.id,
    type: v.type,
    severity: v.severity,
    swc_id: v.swc_id,
    line_number: v.line_number,
    affected_lines: v.affected_lines,
    affected_functions: v.affected_functions,
    title: v.title,
    description: v.description,
    technical_risk: v.technical_risk,
    attack_scenario: v.attack_scenario,
    impact: v.impact,
    gas_impact: null,
    vulnerable_code: v.vulnerable_code,
    fixed_code: v.fixed_code,
    recommendation: v.recommendation,
  }));
}

function mergeVulnerabilities(
  aiVulns: Array<Record<string, unknown>>,
  fallbackVulns: FallbackVulnerability[],
): Array<Record<string, unknown>> {
  const merged = [...aiVulns];
  const seen = new Set(
    aiVulns.map((v) =>
      vulnKey({
        type: String(v.type ?? ""),
        line_number: typeof v.line_number === "number" ? v.line_number : null,
        title: String(v.title ?? ""),
      }),
    ),
  );

  for (const f of fallbackVulns) {
    const key = vulnKey(f);
    if (seen.has(key)) continue;
    merged.push(...normalizeFallbackVulns([f]));
    seen.add(key);
  }

  return merged;
}

function tryParseAiJson(text: string): unknown {
  const trimmed = text.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    // continue
  }

  const codeBlockMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (codeBlockMatch) return JSON.parse(codeBlockMatch[1].trim());

  let braceCount = 0;
  let start = -1;
  let end = -1;
  for (let i = 0; i < trimmed.length; i++) {
    if (trimmed[i] === "{") {
      if (braceCount === 0) start = i;
      braceCount++;
    } else if (trimmed[i] === "}") {
      braceCount--;
      if (braceCount === 0 && start !== -1) {
        end = i;
        break;
      }
    }
  }
  if (start !== -1 && end !== -1) return JSON.parse(trimmed.slice(start, end + 1));

  const lastOpen = trimmed.lastIndexOf("{");
  const lastClose = trimmed.lastIndexOf("}");
  if (lastOpen !== -1 && lastClose > lastOpen) return JSON.parse(trimmed.slice(lastOpen, lastClose + 1));

  throw new Error("Could not find JSON structure in AI response");
}

router.post("/scan-stream", async (req, res) => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  const startTime = Date.now();

  const parseResult = ScanContractBody.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: "Invalid request body" });
    return;
  }

  const { code, contractName } = parseResult.data;

  if (!code || code.trim().length === 0) {
    res.status(400).json({ error: "Solidity code is required" });
    return;
  }

  if (code.length > 50000) {
    res.status(400).json({ error: "Contract code too large (max 50KB)" });
    return;
  }

  const compilation = compileSolidity(code);
  if (!compilation.success) {
    res.status(400).json({
      error: "Solidity compilation failed",
      diagnostics: compilation.diagnostics.filter((diagnostic) => diagnostic.severity === "error").slice(0, 10),
    });
    return;
  }

  const fallback = analyzeContractFallback(code, contractName ?? undefined);

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  const stageTimers: ReturnType<typeof setTimeout>[] = [];
  let completed = false;
  let streamClosed = false;

  // Handle client disconnect
  const onClientClose = () => {
    streamClosed = true;
    clearTimers();
    req.log.info("Client disconnected from scan stream");
  };
  res.on("close", onClientClose);
  res.on("finish", onClientClose);

  // Request timeout (60 seconds max)
  const timeoutTimer = setTimeout(() => {
    if (!completed && !streamClosed) {
      streamClosed = true;
      clearTimers();
      req.log.warn("Scan request timeout after 60 seconds");
      if (!res.headersSent) res.status(504).json({ error: "Scan timeout" });
      else if (!res.writableEnded) res.end();
    }
  }, 60000);

  for (const stage of STAGES) {
    const timer = setTimeout(() => {
      if (!completed && !streamClosed) sseWrite(res, "stage", { message: stage.msg });
    }, stage.ms);
    stageTimers.push(timer);
  }

  const clearTimers = () => {
    stageTimers.forEach(clearTimeout);
    clearTimeout(timeoutTimer);
  };

  try {
    const claudeStream = anthropic.messages.stream({
      model: OPENROUTER_MODEL,
      max_tokens: 8192,
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: buildUserPrompt(code, contractName ?? undefined) }],
    });

    const fullText = await claudeStream.finalText();
    clearTimers();
    completed = true;

    let rawParsed: unknown;
    try {
      rawParsed = tryParseAiJson(fullText);
    } catch (err) {
      req.log.warn({ err: String(err) }, "AI JSON parse failed, using fallback analysis");
      if (streamClosed) return;
      const analysis_time_ms = Date.now() - startTime;
      const code_hash = createHash("sha256").update(code).digest("hex");
      const vulnerabilities = normalizeFallbackVulns(fallback.vulnerabilities);
      const scanData = {
        success: true,
        contract_name: contractName ?? "Unknown Contract",
        code_hash,
        total_vulnerabilities: vulnerabilities.length,
        risk_score: fallback.risk_score,
        vulnerabilities,
        summary: `${fallback.summary} (AI response was unstructured.)`,
        analysis_time_ms,
        timestamp: new Date().toISOString(),
      };

      const scanId = await storeScan(scanData, req.user.id, code);

      sseWrite(res, "meta", {
        contract_name: scanData.contract_name,
        total_vulnerabilities: scanData.total_vulnerabilities,
        risk_score: scanData.risk_score,
        summary: scanData.summary,
        analysis_time_ms,
        scanId,
      });
      for (const vuln of vulnerabilities) sseWrite(res, "vulnerability", vuln);
      sseWrite(res, "complete", { ...scanData, scanId });
      res.end();
      return;
    }

    const parsedResult = AIResponseSchema.safeParse(rawParsed);
    const analysis_time_ms = Date.now() - startTime;
    const code_hash = createHash("sha256").update(code).digest("hex");
    
    if (streamClosed) return;

    let contract_name = contractName ?? "Unknown Contract";
    let vulnerabilities: Array<Record<string, unknown>> = [];
    let risk_score = fallback.risk_score;
    let summary = fallback.summary;

    if (!parsedResult.success) {
      req.log.warn({ issues: parsedResult.error.issues }, "AI schema validation failed, merging fallback");
      const partial = rawParsed as Record<string, unknown>;
      const aiVulns = Array.isArray(partial.vulnerabilities)
        ? (partial.vulnerabilities as VulnerabilityAIType[]).map((v, idx) => ({
            id: v?.id ?? idx + 1,
            type: v?.type ?? "unknown",
            severity: v?.severity ?? "LOW",
            swc_id: v?.swc_id ?? null,
            line_number: v?.line_number ?? null,
            affected_lines: v?.affected_lines ?? null,
            affected_functions: v?.affected_functions ?? null,
            title: v?.title ?? "Vulnerability",
            description: v?.description ?? "Potential issue detected.",
            technical_risk: v?.technical_risk ?? "",
            attack_scenario: v?.attack_scenario ?? null,
            impact: v?.impact ?? null,
            gas_impact: v?.gas_impact ?? null,
            vulnerable_code: v?.vulnerable_code ?? null,
            fixed_code: v?.fixed_code ?? null,
            recommendation: v?.recommendation ?? "Review and patch this issue.",
          }))
        : [];

      vulnerabilities = mergeVulnerabilities(aiVulns as Array<Record<string, unknown>>, fallback.vulnerabilities);
      contract_name = (partial.contract_name as string) || contract_name;
      risk_score = Math.max((partial.risk_score as number) || 0, fallback.risk_score);
      summary = (partial.summary as string) || `${fallback.summary} (AI response partial.)`;
    } else {
      const parsed = parsedResult.data;
      const aiVulns = (parsed.vulnerabilities ?? []).map((v, idx) => ({
        id: v.id ?? idx + 1,
        type: v.type,
        severity: v.severity,
        swc_id: v.swc_id ?? null,
        line_number: v.line_number ?? null,
        affected_lines: v.affected_lines ?? null,
        affected_functions: v.affected_functions ?? null,
        title: v.title,
        description: v.description,
        technical_risk: v.technical_risk ?? "",
        attack_scenario: v.attack_scenario ?? null,
        impact: v.impact ?? null,
        gas_impact: v.gas_impact ?? null,
        vulnerable_code: v.vulnerable_code ?? null,
        fixed_code: v.fixed_code ?? null,
        recommendation: v.recommendation ?? "Review and patch this issue.",
      }));

      vulnerabilities = mergeVulnerabilities(aiVulns as Array<Record<string, unknown>>, fallback.vulnerabilities);
      contract_name = parsed.contract_name ?? contract_name;
      risk_score = Math.max(parsed.risk_score ?? 0, fallback.risk_score);
      summary = parsed.summary ?? fallback.summary;
    }

    const scanData = {
      success: true,
      contract_name,
      code_hash,
      total_vulnerabilities: vulnerabilities.length,
      risk_score,
      vulnerabilities,
      summary,
      analysis_time_ms,
      timestamp: new Date().toISOString(),
    };

    const scanId = await storeScan(scanData, req.user.id, code);

    if (streamClosed) return;

    sseWrite(res, "meta", {
      contract_name: scanData.contract_name,
      total_vulnerabilities: scanData.total_vulnerabilities,
      risk_score: scanData.risk_score,
      summary: scanData.summary,
      analysis_time_ms,
      scanId,
    });

    for (const vuln of vulnerabilities) {
      if (streamClosed) return;
      await new Promise<void>((resolve) => setTimeout(resolve, 120));
      sseWrite(res, "vulnerability", vuln);
    }

    if (!streamClosed) {
      sseWrite(res, "complete", { ...scanData, scanId });
      res.end();
    }
  } catch (err: unknown) {
    clearTimers();
    completed = true;
    if (streamClosed) return;
    
    req.log.error({ err }, "Error calling OpenRouter API, using fallback analysis");

    const analysis_time_ms = Date.now() - startTime;
    const code_hash = createHash("sha256").update(code).digest("hex");
    const vulnerabilities = normalizeFallbackVulns(fallback.vulnerabilities);
    const summary = `${fallback.summary} (${resolveAiError(err)})`;

    const scanData = {
      success: true,
      contract_name: contractName ?? "Unknown Contract",
      code_hash,
      total_vulnerabilities: vulnerabilities.length,
      risk_score: fallback.risk_score,
      vulnerabilities,
      summary,
      analysis_time_ms,
      timestamp: new Date().toISOString(),
    };

    const scanId = await storeScan(scanData, req.user.id, code);

    sseWrite(res, "meta", {
      contract_name: scanData.contract_name,
      total_vulnerabilities: scanData.total_vulnerabilities,
      risk_score: scanData.risk_score,
      summary: scanData.summary,
      analysis_time_ms,
      scanId,
    });
    for (const vuln of vulnerabilities) sseWrite(res, "vulnerability", vuln);
    sseWrite(res, "complete", { ...scanData, scanId });
    res.end();
  }
});

export default router;
