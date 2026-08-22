import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "./schema";

const { Pool } = pg;

function getDatabaseUrl(): string {
  const dbUrl = process.env.DATABASE_URL ?? process.env.SUPABASE_DB_URL;
  if (!dbUrl) {
    throw new Error(
      "DATABASE_URL (or SUPABASE_DB_URL) must be set. Add your Supabase Postgres connection string.",
    );
  }
  return dbUrl;
}

function shouldUseSsl(connectionString: string): boolean {
  return /supabase\.(co|com)/i.test(connectionString);
}

function normalizeConnectionString(connectionString: string): string {
  try {
    const url = new URL(connectionString);

    // We control SSL behavior explicitly in Pool config below.
    url.searchParams.delete("sslmode");
    url.searchParams.delete("sslcert");
    url.searchParams.delete("sslkey");
    url.searchParams.delete("sslrootcert");

    return url.toString();
  } catch {
    return connectionString;
  }
}

const rejectUnauthorized = process.env.DATABASE_SSL_REJECT_UNAUTHORIZED !== "false";

const rawConnectionString = getDatabaseUrl();
const connectionString = normalizeConnectionString(rawConnectionString);

export const pool = new Pool({
  connectionString,
  ssl: shouldUseSsl(rawConnectionString)
    ? {
        rejectUnauthorized,
      }
    : false,
});
export const db = drizzle(pool, { schema });

export * from "./schema";
