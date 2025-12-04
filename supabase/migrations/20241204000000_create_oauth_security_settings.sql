-- Create OAuth security settings table for storing allowed origins and redirect URIs
-- This allows managing security settings without needing to redeploy or update secrets

-- Create schema if it doesn't exist
CREATE SCHEMA IF NOT EXISTS "oauth-extension";

CREATE TABLE IF NOT EXISTS "oauth-extension".oauth_security_settings (
    id TEXT PRIMARY KEY DEFAULT 'default',
    allowed_origins TEXT[] NOT NULL DEFAULT '{}',
    allowed_redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Add comment explaining the table
COMMENT ON TABLE "oauth-extension".oauth_security_settings IS 'Stores OAuth security configuration like allowed origins and redirect URIs';
COMMENT ON COLUMN "oauth-extension".oauth_security_settings.allowed_origins IS 'Array of allowed CORS origins (e.g., https://yourapp.com)';
COMMENT ON COLUMN "oauth-extension".oauth_security_settings.allowed_redirect_uris IS 'Array of allowed OAuth redirect URIs';

-- Insert default row (can be updated via Supabase dashboard or SQL)
INSERT INTO "oauth-extension".oauth_security_settings (id, allowed_origins, allowed_redirect_uris)
VALUES (
    'default',
    ARRAY[]::TEXT[],  -- Add your allowed origins here
    ARRAY[]::TEXT[]   -- Add your allowed redirect URIs here
)
ON CONFLICT (id) DO NOTHING;

-- Create trigger to auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION "oauth-extension".update_oauth_security_settings_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER oauth_security_settings_updated_at
    BEFORE UPDATE ON "oauth-extension".oauth_security_settings
    FOR EACH ROW
    EXECUTE FUNCTION "oauth-extension".update_oauth_security_settings_updated_at();

-- Security: Only allow service role to read/write this table (edge functions use service role)
-- Revoke all access from public/anon
ALTER TABLE "oauth-extension".oauth_security_settings ENABLE ROW LEVEL SECURITY;

-- No RLS policies = only service_role can access (which is what edge functions use)
-- If you want to allow authenticated admins to manage settings, add a policy like:
-- CREATE POLICY "Allow admins to manage oauth settings" ON "oauth-extension".oauth_security_settings
--     FOR ALL
--     TO authenticated
--     USING (auth.jwt() ->> 'role' = 'admin')
--     WITH CHECK (auth.jwt() ->> 'role' = 'admin');
