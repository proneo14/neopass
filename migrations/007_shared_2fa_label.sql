-- Migration 007: Add label to shared_2fa for service identification.
ALTER TABLE shared_2fa ADD COLUMN IF NOT EXISTS label TEXT NOT NULL DEFAULT '';
