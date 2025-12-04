-- Create an RPC function to fetch OAuth security settings
-- This is needed because the Supabase JS client has issues with schema names containing hyphens

CREATE OR REPLACE FUNCTION public.get_oauth_security_settings()
RETURNS TABLE (
    allowed_origins TEXT[],
    allowed_redirect_uris TEXT[]
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT 
        allowed_origins,
        allowed_redirect_uris
    FROM "oauth-extension".oauth_security_settings
    WHERE id = 'default'
    LIMIT 1;
$$;

-- Grant execute permission to service_role (used by edge functions)
GRANT EXECUTE ON FUNCTION public.get_oauth_security_settings() TO service_role;

-- Revoke from public/anon for security
REVOKE EXECUTE ON FUNCTION public.get_oauth_security_settings() FROM anon, authenticated;

COMMENT ON FUNCTION public.get_oauth_security_settings() IS 'Fetches OAuth security settings from oauth-extension schema. Used by edge functions.';
