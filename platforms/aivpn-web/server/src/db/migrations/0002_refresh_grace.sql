-- Refresh-rotation grace columns: the previous refresh-token hash is honoured
-- for a short window after rotation (cross-tab refresh race, routes/auth.ts).
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS prev_token_hash VARCHAR(128);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS prev_expires_at TIMESTAMPTZ;
