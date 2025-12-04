-- ============================================================================
-- Migration: Move churchtools_sync.users to public.churchtools_users
-- ============================================================================
-- PostgREST only exposes public and graphql_public schemas by default.
-- Moving the table to public schema with a prefixed name.

-- Drop the old schema and recreate in public
DROP SCHEMA IF EXISTS churchtools_sync CASCADE;

-- ============================================================================
-- ChurchTools Users Table (in public schema)
-- ============================================================================
-- Stores the link between Supabase auth users and ChurchTools users
-- Primary key for lookups is churchtools_id (unique per ChurchTools instance)

CREATE TABLE IF NOT EXISTS public.churchtools_users (
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
    CONSTRAINT churchtools_users_unique_user_id UNIQUE (user_id),
    CONSTRAINT churchtools_users_unique_churchtools_id UNIQUE (churchtools_id)
);

-- Create indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_churchtools_users_churchtools_id ON public.churchtools_users(churchtools_id);
CREATE INDEX IF NOT EXISTS idx_churchtools_users_user_id ON public.churchtools_users(user_id);
CREATE INDEX IF NOT EXISTS idx_churchtools_users_email ON public.churchtools_users(email);

-- Enable RLS
ALTER TABLE public.churchtools_users ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only read their own ChurchTools data
CREATE POLICY "Users can view own churchtools data" ON public.churchtools_users
    FOR SELECT 
    TO authenticated
    USING (auth.uid() = user_id);

-- Policy: Service role can do everything (for edge functions)
CREATE POLICY "Service role full access on churchtools_users" ON public.churchtools_users
    FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- Comments
COMMENT ON TABLE public.churchtools_users IS 'Mapping between Supabase auth users and ChurchTools users';
COMMENT ON COLUMN public.churchtools_users.churchtools_id IS 'Unique identifier from ChurchTools OAuth (sub claim). Primary lookup key.';
COMMENT ON COLUMN public.churchtools_users.user_id IS 'Reference to Supabase auth.users. One-to-one with churchtools_id.';
COMMENT ON COLUMN public.churchtools_users.churchtools_data IS 'Non-sensitive user profile data from ChurchTools (name, etc.)';

-- ============================================================================
-- Trigger: Auto-update updated_at timestamp
-- ============================================================================

CREATE OR REPLACE FUNCTION public.churchtools_users_update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_churchtools_users_updated_at
    BEFORE UPDATE ON public.churchtools_users
    FOR EACH ROW
    EXECUTE FUNCTION public.churchtools_users_update_updated_at();

-- ============================================================================
-- Security Trigger: Prevent user_id changes
-- ============================================================================
-- Once a churchtools_id is linked to a user, the user_id cannot be changed
-- This prevents account hijacking attacks

CREATE OR REPLACE FUNCTION public.churchtools_users_prevent_user_id_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.user_id IS DISTINCT FROM NEW.user_id THEN
        RAISE EXCEPTION 'Cannot change user_id for an existing ChurchTools mapping. Delete and recreate instead.';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER prevent_churchtools_users_user_id_change
    BEFORE UPDATE ON public.churchtools_users
    FOR EACH ROW
    EXECUTE FUNCTION public.churchtools_users_prevent_user_id_change();
