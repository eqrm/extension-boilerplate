-- ============================================================================
-- Migration: Create ChurchTools Sync Schema
-- ============================================================================
-- This migration creates the churchtools_sync schema and users table
-- for syncing data between ChurchTools and Supabase

-- Create the churchtools_sync schema
CREATE SCHEMA IF NOT EXISTS churchtools_sync;

-- Grant usage on schema to authenticated users and service role
GRANT USAGE ON SCHEMA churchtools_sync TO authenticated;
GRANT USAGE ON SCHEMA churchtools_sync TO service_role;

-- ============================================================================
-- Users Table
-- ============================================================================
-- Stores the link between Supabase auth users and ChurchTools users
-- Primary key for lookups is churchtools_id (unique per ChurchTools instance)

CREATE TABLE IF NOT EXISTS churchtools_sync.users (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    
    -- Supabase auth user reference
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    
    -- ChurchTools unique identifier (from OAuth 'sub' claim)
    -- This is the primary lookup key since emails can be duplicated in ChurchTools
    churchtools_id TEXT NOT NULL,
    
    -- User profile data (synced from ChurchTools)
    email TEXT,
    name TEXT,
    
    -- Additional ChurchTools user data (non-sensitive only)
    churchtools_data JSONB DEFAULT '{}'::jsonb,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT unique_user_id UNIQUE (user_id),
    CONSTRAINT unique_churchtools_id UNIQUE (churchtools_id)
);

-- Create indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_sync_users_churchtools_id ON churchtools_sync.users(churchtools_id);
CREATE INDEX IF NOT EXISTS idx_sync_users_user_id ON churchtools_sync.users(user_id);
CREATE INDEX IF NOT EXISTS idx_sync_users_email ON churchtools_sync.users(email);

-- Enable RLS
ALTER TABLE churchtools_sync.users ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only read their own ChurchTools data
CREATE POLICY "Users can view own data" ON churchtools_sync.users
    FOR SELECT 
    TO authenticated
    USING (auth.uid() = user_id);

-- Policy: Service role can do everything (for edge functions)
CREATE POLICY "Service role full access" ON churchtools_sync.users
    FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- Comments
COMMENT ON SCHEMA churchtools_sync IS 'Schema for ChurchTools synchronization data';
COMMENT ON TABLE churchtools_sync.users IS 'Mapping between Supabase auth users and ChurchTools users';
COMMENT ON COLUMN churchtools_sync.users.churchtools_id IS 'Unique identifier from ChurchTools OAuth (sub claim). Primary lookup key.';
COMMENT ON COLUMN churchtools_sync.users.user_id IS 'Reference to Supabase auth.users. One-to-one with churchtools_id.';
COMMENT ON COLUMN churchtools_sync.users.churchtools_data IS 'Non-sensitive user profile data from ChurchTools (name, etc.)';

-- ============================================================================
-- Trigger: Auto-update updated_at timestamp
-- ============================================================================

CREATE OR REPLACE FUNCTION churchtools_sync.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON churchtools_sync.users
    FOR EACH ROW
    EXECUTE FUNCTION churchtools_sync.update_updated_at_column();

-- ============================================================================
-- Security Trigger: Prevent user_id changes
-- ============================================================================
-- Once a churchtools_id is linked to a user, the user_id cannot be changed
-- This prevents account hijacking attacks

CREATE OR REPLACE FUNCTION churchtools_sync.prevent_user_id_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.user_id IS DISTINCT FROM NEW.user_id THEN
        RAISE EXCEPTION 'Cannot change user_id for an existing ChurchTools mapping. Delete and recreate instead.';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER prevent_user_id_change_trigger
    BEFORE UPDATE ON churchtools_sync.users
    FOR EACH ROW
    EXECUTE FUNCTION churchtools_sync.prevent_user_id_change();
