-- Migration 002: Add metadata column for certificate/key metadata
-- Stores parsed certificate/key metadata as JSON text for queryability.
-- Metadata is plaintext by design (not encrypted) for search and expiry queries.

ALTER TABLE secrets ADD COLUMN metadata TEXT NOT NULL DEFAULT '';
