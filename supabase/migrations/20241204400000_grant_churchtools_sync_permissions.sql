-- ============================================================================
-- Migration: Grant table permissions on churchtools_sync schema
-- ============================================================================
-- Ensures service_role has full access to tables in the churchtools_sync schema

-- Grant all privileges on all tables in the schema to service_role
GRANT ALL ON ALL TABLES IN SCHEMA churchtools_sync TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA churchtools_sync TO service_role;

-- Grant select on tables to authenticated users (RLS will filter)
GRANT SELECT ON ALL TABLES IN SCHEMA churchtools_sync TO authenticated;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA churchtools_sync 
    GRANT ALL ON TABLES TO service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA churchtools_sync 
    GRANT ALL ON SEQUENCES TO service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA churchtools_sync 
    GRANT SELECT ON TABLES TO authenticated;
