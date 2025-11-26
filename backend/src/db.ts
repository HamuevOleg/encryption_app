import { Pool } from "pg";
import { config } from "./config";

export const pool = new Pool({
  host: config.db.host,
  port: config.db.port,
  user: config.db.user,
  password: config.db.password,
  database: config.db.database
});

export async function logOperation(params: {
  method: string;
  operationType: "encrypt" | "decrypt";
  textHash: string;
  executionTimeMs: number;
}) {
  const client = await pool.connect();
  try {
    await client.query(
      `
      INSERT INTO operation_logs
        (method, operation_type, text_hash, execution_time_ms)
      VALUES ($1, $2, $3, $4)
      `,
      [params.method, params.operationType, params.textHash, params.executionTimeMs]
    );
  } catch (err) {
    console.error("Failed to log operation:", err);
  } finally {
    client.release();
  }
}

export async function getRecentOperations(limit = 10) {
  const client = await pool.connect();
  try {
    const result = await client.query(
      `SELECT id, method, operation_type, text_hash, execution_time_ms, created_at
       FROM operation_logs
       ORDER BY created_at DESC
       LIMIT $1`,
      [limit]
    );
    return result.rows;
  } finally {
    client.release();
  }
}
