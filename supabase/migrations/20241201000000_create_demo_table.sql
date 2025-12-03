-- ChurchTools Users mapping table
-- Stores the link between Supabase users and ChurchTools users
CREATE TABLE IF NOT EXISTS public.churchtools_users (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE UNIQUE,
    churchtools_id TEXT NOT NULL,
    email TEXT,
    name TEXT,
    churchtools_data JSONB,
    churchtools_access_token TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_churchtools_users_ct_id ON public.churchtools_users(churchtools_id);
CREATE INDEX IF NOT EXISTS idx_churchtools_users_user_id ON public.churchtools_users(user_id);

-- Enable RLS
ALTER TABLE public.churchtools_users ENABLE ROW LEVEL SECURITY;

-- Users can only read their own ChurchTools data
CREATE POLICY "Users can view own churchtools data" ON public.churchtools_users
    FOR SELECT USING (auth.uid() = user_id);

COMMENT ON TABLE public.churchtools_users IS 'Mapping between Supabase users and ChurchTools users';

-- Demo table to verify Supabase connection
-- This migration creates a simple demo table that the extension will query

CREATE TABLE IF NOT EXISTS public.demo (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert some sample data
INSERT INTO public.demo (title, description) VALUES
    ('Hello Supabase', 'This is a test entry to verify the connection'),
    ('ChurchTools Integration', 'OAuth authentication is working!'),
    ('Extension Ready', 'Your ChurchTools extension is connected to Supabase');

-- Enable Row Level Security
ALTER TABLE public.demo ENABLE ROW LEVEL SECURITY;

-- Policy: Allow authenticated users to read demo data
CREATE POLICY "Allow authenticated read access" ON public.demo
    FOR SELECT 
    TO authenticated 
    USING (true);

-- Policy: Allow authenticated users to insert demo data
CREATE POLICY "Allow authenticated insert access" ON public.demo
    FOR INSERT 
    TO authenticated 
    WITH CHECK (true);

COMMENT ON TABLE public.demo IS 'Demo table to verify Supabase connection from ChurchTools extension';
