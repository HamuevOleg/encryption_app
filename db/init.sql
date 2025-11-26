CREATE TABLE IF NOT EXISTS operation_logs (
  id SERIAL PRIMARY KEY,
  method TEXT NOT NULL,
  operation_type TEXT NOT NULL,
  text_hash TEXT NOT NULL,
  execution_time_ms INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
