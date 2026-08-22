import * as zod from "zod";
import type { FallbackVulnerability } from "../../routes/vulnguard/fallback-analyzer.js";

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
  vulnerable_code: zod.string().nullable().optional(),
  fixed_code: zod.string().nullable().optional(),
  recommendation: zod.string().optional(),
});

export type VulnerabilityAIType = zod.infer<typeof VulnerabilityAI>;

export const AIResponseSchema = zod.object({
  contract_name: zod.string().optional(),
  total_vulnerabilities: zod.number().optional(),
  risk_score: zod.number().optional(),
  vulnerabilities: zod.array(VulnerabilityAI).optional(),
  summary: zod.string().optional(),
});

export function resolveAiError(err: unknown): { status: number; message: string } {
  const status = (err as { status?: number })?.status;
  const message = (err as { message?: string })?.message ?? "";
  if (status === 429) return { status: 429, message: "AI rate limit reached. Please wait 30-60 seconds and retry." };
  if (status === 401 || status === 403) return { status: 502, message: "AI provider authentication failed. Verify OPENROUTER_API_KEY in backend environment." };
  if (status === 402) return { status: 502, message: "AI provider quota/billing issue. Check OpenRouter credits and model access." };
  if (status === 400) return { status: 502, message: "AI request rejected. Check OPENROUTER_MODEL and provider compatibility." };
  if (status && status >= 500) return { status: 502, message: "AI provider is temporarily unavailable. Please retry shortly." };
  if (/timeout|timed out|abort/i.test(message)) return { status: 504, message: "AI request timed out. Please retry with a smaller contract or try again shortly." };
  return { status: 500, message: "Failed to analyze contract. Please try again." };
}

function vulnKey(v: { type: string; line_number: number | null | undefined; title: string }): string {
  return `${v.type}|${v.line_number ?? -1}|${v.title}`;
}

export function normalizeFallbackVulns(vulns: FallbackVulnerability[]): Array<Record<string, unknown>> {
  return vulns.map((v) => ({ ...v }));
}

export function mergeVulnerabilities(aiVulns: Array<Record<string, unknown>>, fallbackVulns: FallbackVulnerability[]): Array<Record<string, unknown>> {
  const merged = [...aiVulns];
  const seen = new Set(aiVulns.map((v) => vulnKey({ type: String(v.type ?? ""), line_number: typeof v.line_number === "number" ? v.line_number : null, title: String(v.title ?? "") })));
  for (const fallback of fallbackVulns) {
    const key = vulnKey(fallback);
    if (seen.has(key)) continue;
    merged.push(...normalizeFallbackVulns([fallback]));
    seen.add(key);
  }
  return merged;
}

export function tryParseAiJson(text: string): unknown {
  const trimmed = text.trim();
  try { return JSON.parse(trimmed); } catch { /* Continue with extraction strategies. */ }
  const codeBlockMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (codeBlockMatch) return JSON.parse(codeBlockMatch[1].trim());
  let braceCount = 0;
  let jsonStart = -1;
  for (let index = 0; index < trimmed.length; index++) {
    if (trimmed[index] === "{") { if (braceCount === 0) jsonStart = index; braceCount++; }
    else if (trimmed[index] === "}") { braceCount--; if (braceCount === 0 && jsonStart !== -1) return JSON.parse(trimmed.slice(jsonStart, index + 1)); }
  }
  const lastOpen = trimmed.lastIndexOf("{");
  const lastClose = trimmed.lastIndexOf("}");
  if (lastOpen !== -1 && lastClose > lastOpen) return JSON.parse(trimmed.slice(lastOpen, lastClose + 1));
  throw new Error("Could not find JSON structure in AI response");
}