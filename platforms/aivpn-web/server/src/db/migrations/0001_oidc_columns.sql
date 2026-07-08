-- Add OIDC identity columns to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_iss VARCHAR(512);
ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_sub VARCHAR(256);
CREATE UNIQUE INDEX IF NOT EXISTS users_oidc_idx ON users (oidc_iss, oidc_sub) WHERE oidc_iss IS NOT NULL;
