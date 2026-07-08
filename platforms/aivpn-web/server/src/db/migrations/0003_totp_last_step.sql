-- TOTP replay protection: last accepted RFC 6238 time step. A code is valid
-- only if its step is greater than this value (one-time use, RFC 6238 §5.2).
-- See server/src/auth/totp.ts and routes/auth.ts.
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step INTEGER;
