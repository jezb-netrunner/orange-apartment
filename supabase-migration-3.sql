-- =====================================================
-- Orange Apartment — Schema v3 Migration
-- =====================================================
-- Run this SQL in the Supabase SQL Editor (Dashboard > SQL Editor)
-- AFTER supabase-migration-2.sql. Safe to re-run: every statement is
-- idempotent. The portal works without it — expenses just can't be
-- tagged by floor until it runs.
--
-- This migration:
--   1. Adds an optional floor tag to expenses so the per-floor income
--      statement can charge a floor its direct costs. Untagged expenses
--      ('' = the default, so every existing row) stay building-wide and
--      are split across floors by headcount or revenue in the report.
--
-- Nothing else needs a schema change:
--   * Recurring-billing state (template.auto / postedThrough / skip and
--     bill.tmplId / period) lives inside the existing tenants.bills and
--     tenants.templates jsonb columns — additive keys, old rows unchanged.
--   * The automatic-billing settings (auto_billing, auto_billing_lead_days)
--     are ordinary rows in the settings table. They are admin-only:
--     read_setting / read_portal_settings keep their allowlists, so the
--     anon role can never read them.
-- =====================================================

ALTER TABLE expenses ADD COLUMN IF NOT EXISTS floor text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_expenses_floor ON expenses (floor) WHERE floor <> '';
