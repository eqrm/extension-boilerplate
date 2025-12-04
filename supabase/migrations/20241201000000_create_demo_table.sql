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
