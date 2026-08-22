import { randomUUID } from "crypto";
import { db, scansTable } from "@workspace/db";

export interface StoredScan {
  scanId: string;
  userId: string;
  success: boolean;
  contract_name: string;
  code_hash: string;
  total_vulnerabilities: number;
  risk_score: number;
  vulnerabilities: unknown[];
  summary: string;
  analysis_time_ms: number;
  timestamp: string;
}

type ScanResult = Omit<StoredScan, "scanId" | "userId">;

const scanStore = new Map<string, StoredScan>();

export async function storeScan(data: ScanResult, userId: string, contractCode: string): Promise<string> {
  const scanId = randomUUID();
  await db.insert(scansTable).values({
    id: scanId,
    userId,
    contractName: data.contract_name,
    contractCode,
    contractHash: data.code_hash,
    riskScore: data.risk_score,
    vulnerabilities: data.vulnerabilities,
    summary: data.summary,
    executionTime: data.analysis_time_ms,
  });
  scanStore.set(scanId, { ...data, scanId, userId });
  return scanId;
}

export function getScan(scanId: string): StoredScan | undefined {
  return scanStore.get(scanId);
}