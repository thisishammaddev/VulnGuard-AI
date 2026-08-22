import { Router, type IRouter } from "express";
import { createHash } from "crypto";
import { anthropic } from "@workspace/integrations-anthropic-ai";
import { OPENROUTER_MODEL } from "@workspace/integrations-anthropic-ai";
import { ScanContractBody } from "@workspace/api-zod";
import { SYSTEM_PROMPT, buildUserPrompt } from "./prompts.js";
import { storeScan } from "./store.js";
import { analyzeContractFallback } from "./fallback-analyzer.js";
import { compileSolidity } from "../../services/solidity/compiler.js";
import { AIResponseSchema, mergeVulnerabilities, normalizeFallbackVulns, resolveAiError, tryParseAiJson, type VulnerabilityAIType } from "../../services/scanning/scan-response.js";

const router: IRouter = Router();

router.post("/scan", async (req, res) => {
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

  try {
    const message = await anthropic.messages.create({
      model: OPENROUTER_MODEL,
      max_tokens: 8192,
      system: SYSTEM_PROMPT,
      messages: [
        {
          role: "user",
          content: buildUserPrompt(code, contractName ?? undefined),
        },
      ],
    });

    const content = message.content[0];
    if (content.type !== "text") {
      const analysis_time_ms = Date.now() - startTime;
      const scanData = {
        success: true,
        contract_name: contractName ?? "Unknown Contract",
        code_hash: createHash("sha256").update(code).digest("hex"),
        total_vulnerabilities: fallback.vulnerabilities.length,
        risk_score: fallback.risk_score,
        vulnerabilities: normalizeFallbackVulns(fallback.vulnerabilities),
        summary: `${fallback.summary} (AI returned unexpected content type.)`,
        analysis_time_ms,
        timestamp: new Date().toISOString(),
      };
      const scanId = await storeScan(scanData, req.user.id, code);
      res.json({ ...scanData, scanId });
      return;
    }

    let rawParsed: unknown;
    try {
      rawParsed = tryParseAiJson(content.text);
    } catch (jsonError) {
      req.log.warn({ err: String(jsonError) }, "AI JSON parse failed, using fallback analysis");
      const analysis_time_ms = Date.now() - startTime;
      const scanData = {
        success: true,
        contract_name: contractName ?? "Unknown Contract",
        code_hash: createHash("sha256").update(code).digest("hex"),
        total_vulnerabilities: fallback.vulnerabilities.length,
        risk_score: fallback.risk_score,
        vulnerabilities: normalizeFallbackVulns(fallback.vulnerabilities),
        summary: `${fallback.summary} (AI response was unstructured.)`,
        analysis_time_ms,
        timestamp: new Date().toISOString(),
      };

      const scanId = await storeScan(scanData, req.user.id, code);
      res.json({ ...scanData, scanId });
      return;
    }

    const aiResult = AIResponseSchema.safeParse(rawParsed);
    const analysis_time_ms = Date.now() - startTime;
    const timestamp = new Date().toISOString();

    if (!aiResult.success) {
      req.log.warn({ issues: aiResult.error.issues }, "AI schema validation failed, merging with fallback");
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
            vulnerable_code: v?.vulnerable_code ?? null,
            fixed_code: v?.fixed_code ?? null,
            recommendation: v?.recommendation ?? "Review and patch this issue.",
          }))
        : [];

      const merged = mergeVulnerabilities(aiVulns as Array<Record<string, unknown>>, fallback.vulnerabilities);

      const scanData = {
        success: true,
        contract_name: (partial.contract_name as string) || contractName || "Unknown Contract",
        code_hash: createHash("sha256").update(code).digest("hex"),
        total_vulnerabilities: merged.length,
        risk_score: Math.max((partial.risk_score as number) || 0, fallback.risk_score),
        vulnerabilities: merged,
        summary: (partial.summary as string) || `${fallback.summary} (AI response partial.)`,
        analysis_time_ms,
        timestamp,
      };

      const scanId = await storeScan(scanData, req.user.id, code);
      res.json({ ...scanData, scanId });
      return;
    }

    const parsed = aiResult.data;
    const aiVulns = (parsed.vulnerabilities ?? []).map((v: VulnerabilityAIType, idx: number) => ({
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
      vulnerable_code: v.vulnerable_code ?? null,
      fixed_code: v.fixed_code ?? null,
      recommendation: v.recommendation ?? "Review and patch this issue.",
    }));

    const merged = mergeVulnerabilities(aiVulns as Array<Record<string, unknown>>, fallback.vulnerabilities);

    const scanData = {
      success: true,
      contract_name: parsed.contract_name ?? contractName ?? "Unknown Contract",
      code_hash: createHash("sha256").update(code).digest("hex"),
      total_vulnerabilities: merged.length,
      risk_score: Math.max(parsed.risk_score ?? 0, fallback.risk_score),
      vulnerabilities: merged,
      summary: parsed.summary ?? fallback.summary,
      analysis_time_ms,
      timestamp,
    };

    const scanId = await storeScan(scanData, req.user.id, code);
    res.json({ ...scanData, scanId });
  } catch (err: unknown) {
    req.log.error({ err }, "Error calling OpenRouter API, using fallback analyzer");
    const resolved = resolveAiError(err);
    const analysis_time_ms = Date.now() - startTime;
    const scanData = {
      success: true,
      contract_name: contractName ?? "Unknown Contract",
      code_hash: createHash("sha256").update(code).digest("hex"),
      total_vulnerabilities: fallback.vulnerabilities.length,
      risk_score: fallback.risk_score,
      vulnerabilities: normalizeFallbackVulns(fallback.vulnerabilities),
      summary: `${fallback.summary} (AI unavailable: ${resolved.message})`,
      analysis_time_ms,
      timestamp: new Date().toISOString(),
    };

    const scanId = await storeScan(scanData, req.user.id, code);
    res.json({ ...scanData, scanId });
  }
});

export default router;
