-- Add hardware key enforcement column to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS require_hw_key BOOLEAN NOT NULL DEFAULT false;
