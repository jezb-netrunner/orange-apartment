-- =====================================================
-- Orange Apartment — Supabase Security Migration
-- =====================================================
-- Run this SQL in the Supabase SQL Editor (Dashboard > SQL Editor)
-- BEFORE deploying the updated index.html.
--
-- This migration:
--   1. Enables Row Level Security (RLS) on tenants and settings tables
--   2. Creates RLS policies (admin = full access, anon = denied)
--   3. Creates a login_tenant() RPC function for secure tenant login
--   4. Creates a login_attempts table for server-side rate limiting
--   5. Creates a read_setting() RPC function for anon settings access
-- =====================================================

-- ─────────────────────────────────────────────────────
-- 0. Drop old permissive policies that allowed public SELECT
-- ─────────────────────────────────────────────────────

DROP POLICY IF EXISTS tenant_select ON tenants;
DROP POLICY IF EXISTS admin_all ON tenants;
DROP POLICY IF EXISTS settings_select ON settings;
DROP POLICY IF EXISTS settings_admin_all ON settings;

-- ─────────────────────────────────────────────────────
-- 1. Enable RLS on all tables
-- ─────────────────────────────────────────────────────

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE settings ENABLE ROW LEVEL SECURITY;

-- ─────────────────────────────────────────────────────
-- 2. RLS Policies — tenants table
-- ─────────────────────────────────────────────────────

-- Authenticated (admin) gets full CRUD access
CREATE POLICY "Admin full access on tenants"
  ON tenants
  FOR ALL
  USING (auth.role() = 'authenticated')
  WITH CHECK (auth.role() = 'authenticated');

-- Anon gets NO direct access (login goes through RPC function)
-- No policy for anon = denied by default when RLS is enabled

-- ─────────────────────────────────────────────────────
-- 3. RLS Policies — settings table
-- ─────────────────────────────────────────────────────

-- Authenticated (admin) gets full CRUD access
CREATE POLICY "Admin full access on settings"
  ON settings
  FOR ALL
  USING (auth.role() = 'authenticated')
  WITH CHECK (auth.role() = 'authenticated');

-- Anon gets NO direct access (reads go through RPC function)

-- ─────────────────────────────────────────────────────
-- 4. Login attempts table for server-side rate limiting
-- ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS login_attempts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  code text NOT NULL,
  attempted_at timestamptz NOT NULL DEFAULT now()
);

-- Index for fast lookups by code + time window
CREATE INDEX IF NOT EXISTS idx_login_attempts_code_time
  ON login_attempts (code, attempted_at DESC);

-- Auto-cleanup: delete attempts older than 1 hour (optional, run periodically or via cron)
-- You can set up a Supabase cron job or pg_cron extension:
-- SELECT cron.schedule('cleanup-login-attempts', '*/15 * * * *',
--   $$DELETE FROM login_attempts WHERE attempted_at < now() - interval '1 hour'$$
-- );

-- RLS on login_attempts: only the RPC function (SECURITY DEFINER) accesses this
ALTER TABLE login_attempts ENABLE ROW LEVEL SECURITY;
-- No policies = no direct access from anon or authenticated roles

-- ─────────────────────────────────────────────────────
-- 5. Secure tenant login RPC function
-- ─────────────────────────────────────────────────────
-- SECURITY DEFINER runs as the function owner (bypasses RLS),
-- so this is the ONLY way anon can read tenant data.

CREATE OR REPLACE FUNCTION login_tenant(access_code text)
RETURNS SETOF tenants
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  recent_attempts int;
BEGIN
  -- Rate limiting: count attempts for this code in the last 15 minutes
  SELECT count(*) INTO recent_attempts
  FROM login_attempts
  WHERE code = access_code
    AND attempted_at > now() - interval '15 minutes';

  -- Record this attempt
  INSERT INTO login_attempts (code) VALUES (access_code);

  -- Block if too many attempts (5 per 15-minute window)
  IF recent_attempts >= 5 THEN
    RAISE EXCEPTION 'Too many login attempts. Please wait and try again.'
      USING ERRCODE = 'P0001';
  END IF;

  -- Return matching tenant (only active, non-archived)
  RETURN QUERY
    SELECT *
    FROM tenants
    WHERE tenants.code = access_code
      AND tenants.archived_at IS NULL
    LIMIT 1;
END;
$$;

-- Grant anon role permission to call the RPC function
GRANT EXECUTE ON FUNCTION login_tenant(text) TO anon;

-- ─────────────────────────────────────────────────────
-- 6. Secure settings read RPC function
-- ─────────────────────────────────────────────────────
-- Allows anon (tenant portal) to read specific settings
-- without direct table access.

CREATE OR REPLACE FUNCTION read_setting(setting_key text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  result text;
BEGIN
  SELECT value INTO result
  FROM settings
  WHERE key = setting_key
  LIMIT 1;

  RETURN COALESCE(result, '');
END;
$$;

-- Grant anon role permission to call the RPC function
GRANT EXECUTE ON FUNCTION read_setting(text) TO anon;
