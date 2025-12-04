// deno-lint-ignore-file
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient, SupabaseClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { encode as base64Encode } from 'https://deno.land/std@0.168.0/encoding/base64.ts';

// Deno global declaration for TypeScript (Edge Functions run in Deno runtime)
declare const Deno: {
    env: {
        get(key: string): string | undefined;
    };
};

// Security: Rate limiting configuration
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_WINDOW_MS = 60000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 10; // Max 10 requests per minute per IP
const RATE_LIMIT_CLEANUP_INTERVAL_MS = 300000; // Cleanup every 5 minutes
let lastRateLimitCleanup = Date.now();

// State token configuration
const STATE_TOKEN_MAX_AGE_MS = 600000; // 10 minutes

// Security: Timeout for external API calls (in milliseconds)
const EXTERNAL_API_TIMEOUT_MS = 10000;

// Cache for security settings (refresh every 5 minutes)
let securitySettingsCache: { origins: string[]; redirectUris: string[]; lastFetch: number } | null = null;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

interface SecuritySettings {
    allowed_origins: string[];
    allowed_redirect_uris: string[];
}

/**
 * Fetch security settings from database with caching
 * Uses RPC function to avoid issues with hyphenated schema names
 */
async function getSecuritySettings(supabase: SupabaseClient): Promise<{ origins: string[]; redirectUris: string[] }> {
    const now = Date.now();
    
    // Return cached values if still valid
    if (securitySettingsCache && (now - securitySettingsCache.lastFetch) < CACHE_TTL_MS) {
        return { origins: securitySettingsCache.origins, redirectUris: securitySettingsCache.redirectUris };
    }
    
    // Fetch from database using RPC function (avoids schema name issues)
    const { data, error } = await supabase.rpc('get_oauth_security_settings');
    
    console.log('Security settings fetch result:', { data, error: error?.message });
    
    if (error || !data || (Array.isArray(data) && data.length === 0)) {
        console.warn('Failed to fetch security settings from database, using fallback:', error?.message);
        // Fallback to environment variables if database fetch fails
        const origins = (Deno.env.get('ALLOWED_ORIGINS') || '').split(',').filter(Boolean);
        const redirectUris = (Deno.env.get('ALLOWED_REDIRECT_URIS') || '').split(',').filter(Boolean);
        return { origins, redirectUris };
    }
    
    // RPC returns an array, get first row
    const settings = (Array.isArray(data) ? data[0] : data) as SecuritySettings;
    
    console.log('Loaded security settings:', settings);
    
    // Update cache
    securitySettingsCache = {
        origins: settings.allowed_origins || [],
        redirectUris: settings.allowed_redirect_uris || [],
        lastFetch: now,
    };
    
    return { origins: securitySettingsCache.origins, redirectUris: securitySettingsCache.redirectUris };
}

function getCorsHeaders(origin: string | null, allowedOrigins: string[]): Record<string, string> {
    const headers: Record<string, string> = {
        'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Cache-Control': 'no-store',
    };
    
    // Only allow specific origins
    if (origin && allowedOrigins.includes(origin)) {
        headers['Access-Control-Allow-Origin'] = origin;
    } else if (allowedOrigins.length === 0) {
        // Fallback for development - log warning
        console.warn('SECURITY WARNING: No allowed origins configured, allowing all origins');
        headers['Access-Control-Allow-Origin'] = origin || '*';
    }
    
    return headers;
}

function checkRateLimit(clientIp: string): boolean {
    const now = Date.now();
    
    // Periodic cleanup of expired rate limit entries to prevent memory leak
    if (now - lastRateLimitCleanup > RATE_LIMIT_CLEANUP_INTERVAL_MS) {
        for (const [ip, record] of rateLimitMap.entries()) {
            if (now > record.resetTime) {
                rateLimitMap.delete(ip);
            }
        }
        lastRateLimitCleanup = now;
    }
    
    const record = rateLimitMap.get(clientIp);
    
    if (!record || now > record.resetTime) {
        rateLimitMap.set(clientIp, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
        return true;
    }
    
    if (record.count >= RATE_LIMIT_MAX_REQUESTS) {
        return false;
    }
    
    record.count++;
    return true;
}

function createErrorResponse(
    message: string, 
    status: number, 
    headers: Record<string, string>,
    internalDetails?: string
): Response {
    // Log detailed error internally, return generic message to client
    if (internalDetails) {
        console.error(`[${status}] ${message}:`, internalDetails);
    }
    return new Response(
        JSON.stringify({ error: message }),
        { status, headers: { ...headers, 'Content-Type': 'application/json' } }
    );
}

function validateInput(value: unknown, name: string, maxLength = 2048): string | null {
    if (typeof value !== 'string') return null;
    if (value.length === 0 || value.length > maxLength) return null;
    // Allow alphanumeric, hyphens, underscores, and for URIs: colons, slashes, dots, query params
    if (name === 'redirect_uri') {
        if (!/^https?:\/\/[a-zA-Z0-9._\-:\/\?&=]+$/.test(value)) return null;
    } else if (name === 'state') {
        // State tokens are base64url encoded and may contain dots for structured tokens
        if (!/^[a-zA-Z0-9_\-\.]+$/.test(value)) return null;
    } else {
        if (!/^[a-zA-Z0-9_\-]+$/.test(value)) return null;
    }
    return value;
}

/**
 * Validates email address with stricter RFC 5322 compliant pattern
 */
function validateEmail(email: unknown): string | null {
    if (typeof email !== 'string') return null;
    // More comprehensive email validation
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    if (!emailRegex.test(email) || email.length > 254) return null;
    return email.toLowerCase();
}

/**
 * Generate a unique request ID for log correlation
 */
function generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
}

/**
 * Verify HMAC-signed state token for CSRF protection
 * State format: base64url(timestamp.nonce.signature)
 * 
 * The client should generate state tokens using the same secret:
 * 1. Generate a random nonce
 * 2. Create payload: timestamp.nonce
 * 3. Sign with HMAC-SHA256 using STATE_SECRET
 * 4. Encode: base64url(timestamp.nonce.signature)
 */
async function verifyStateToken(state: string, secret: string): Promise<{ valid: boolean; error?: string }> {
    try {
        const parts = state.split('.');
        if (parts.length !== 3) {
            return { valid: false, error: 'Invalid state format' };
        }
        
        const [timestampStr, nonce, providedSignature] = parts;
        const timestamp = parseInt(timestampStr, 10);
        
        // Check timestamp validity
        if (isNaN(timestamp)) {
            return { valid: false, error: 'Invalid timestamp' };
        }
        
        const now = Date.now();
        if (now - timestamp > STATE_TOKEN_MAX_AGE_MS) {
            return { valid: false, error: 'State token expired' };
        }
        
        // Prevent future-dated tokens (clock skew tolerance: 30 seconds)
        if (timestamp > now + 30000) {
            return { valid: false, error: 'State token timestamp in future' };
        }
        
        // Verify HMAC signature
        const encoder = new TextEncoder();
        const key = await crypto.subtle.importKey(
            'raw',
            encoder.encode(secret),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        
        const payload = `${timestampStr}.${nonce}`;
        const signatureBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
        const expectedSignature = base64Encode(new Uint8Array(signatureBuffer))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        
        // Constant-time comparison to prevent timing attacks
        if (providedSignature.length !== expectedSignature.length) {
            return { valid: false, error: 'Invalid signature' };
        }
        
        let result = 0;
        for (let i = 0; i < providedSignature.length; i++) {
            result |= providedSignature.charCodeAt(i) ^ expectedSignature.charCodeAt(i);
        }
        
        if (result !== 0) {
            return { valid: false, error: 'Invalid signature' };
        }
        
        return { valid: true };
    } catch (error) {
        return { valid: false, error: 'State verification failed' };
    }
}

/**
 * Fetch with timeout wrapper for external API calls
 */
async function fetchWithTimeout(url: string, options: RequestInit, timeoutMs: number): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    
    try {
        const response = await fetch(url, {
            ...options,
            signal: controller.signal,
        });
        return response;
    } finally {
        clearTimeout(timeoutId);
    }
}

/**
 * Edge Function: ChurchTools OAuth Callback Handler
 * 
 * This function handles the OAuth token exchange:
 * 1. Receives the authorization code from the frontend
 * 2. Exchanges it for an access token with ChurchTools
 * 3. Fetches user info from ChurchTools
 * 4. Creates/updates user in Supabase and returns a session
 * 
 * Security measures implemented:
 * - CSRF protection via state parameter validation
 * - Redirect URI allowlist validation
 * - Rate limiting
 * - Input validation and sanitization
 * - Restricted CORS policy
 * - No sensitive token storage
 * - Generic error messages to clients
 */
serve(async (req: Request) => {
    const requestId = generateRequestId();
    const origin = req.headers.get('origin');
    
    // Get environment variables early for Supabase client
    const supabaseUrl = Deno.env.get('SUPABASE_URL');
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
    const stateSecret = Deno.env.get('STATE_SECRET');
    
    // Create Supabase admin client early to fetch security settings
    let supabase: SupabaseClient | null = null;
    let securitySettings = { origins: [] as string[], redirectUris: [] as string[] };
    
    if (supabaseUrl && supabaseServiceKey) {
        // Client for public schema (default) - used for auth and data operations
        supabase = createClient(supabaseUrl, supabaseServiceKey, {
            auth: {
                autoRefreshToken: false,
                persistSession: false,
            },
        });
        
        // Fetch security settings from database
        securitySettings = await getSecuritySettings(supabase);
    }
    
    const corsHeaders = getCorsHeaders(origin, securitySettings.origins);
    
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
        return new Response('ok', { headers: corsHeaders });
    }

    // Security: Only allow POST requests
    if (req.method !== 'POST') {
        return createErrorResponse('Method not allowed', 405, corsHeaders);
    }

    // Security: Rate limiting
    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 
                     req.headers.get('cf-connecting-ip') || 
                     'unknown';
    if (!checkRateLimit(clientIp)) {
        return createErrorResponse('Too many requests', 429, corsHeaders);
    }

    try {
        // Parse request body
        let body: Record<string, unknown>;
        try {
            body = await req.json();
        } catch {
            return createErrorResponse('Invalid request body', 400, corsHeaders);
        }

        const { code, code_verifier, redirect_uri, state } = body;

        console.log('Received OAuth callback request:', { 
            hasCode: !!code, 
            hasCodeVerifier: !!code_verifier, 
            redirect_uri,
            hasState: !!state 
        });

        // Security: Validate state parameter (CSRF protection)
        // State tokens are HMAC-signed: timestamp.nonce.signature
        const validatedState = validateInput(state, 'state', 512);
        if (!validatedState) {
            console.error(`[${requestId}] State validation failed:`, { stateLength: typeof state === 'string' ? state.length : 'not-string' });
            return createErrorResponse('Missing or invalid state parameter', 400, corsHeaders);
        }
        
        // Verify HMAC signature and expiry of state token
        if (!stateSecret) {
            console.error(`[${requestId}] STATE_SECRET not configured`);
            return createErrorResponse('Server configuration error', 500, corsHeaders, 'STATE_SECRET not configured');
        }
        
        const stateVerification = await verifyStateToken(validatedState, stateSecret);
        if (!stateVerification.valid) {
            console.error(`[${requestId}] State token verification failed:`, stateVerification.error);
            return createErrorResponse('Invalid or expired state parameter', 400, corsHeaders);
        }

        // Security: Validate and sanitize inputs
        const validatedCode = validateInput(code, 'code');
        if (!validatedCode) {
            console.error(`[${requestId}] Code validation failed`);
            return createErrorResponse('Missing or invalid authorization code', 400, corsHeaders);
        }

        const validatedRedirectUri = validateInput(redirect_uri, 'redirect_uri');
        if (!validatedRedirectUri) {
            console.error(`[${requestId}] Redirect URI validation failed`);
            return createErrorResponse('Missing or invalid redirect URI', 400, corsHeaders);
        }

        // Security: Validate redirect_uri against allowlist from database
        console.log(`[${requestId}] Checking redirect URI against allowlist:`, { 
            redirectUriHost: new URL(validatedRedirectUri).host,
            allowlistCount: securitySettings.redirectUris.length 
        });
        if (securitySettings.redirectUris.length > 0 && !securitySettings.redirectUris.includes(validatedRedirectUri)) {
            console.error(`[${requestId}] Redirect URI not in allowlist`);
            return createErrorResponse('Invalid redirect URI', 400, corsHeaders);
        }

        const validatedCodeVerifier = code_verifier ? validateInput(code_verifier, 'code_verifier') : null;

        // Get remaining environment variables
        const churchToolsUrl = Deno.env.get('CHURCHTOOLS_URL');
        const churchToolsClientId = Deno.env.get('CHURCHTOOLS_CLIENT_ID');

        if (!churchToolsUrl || !churchToolsClientId || !supabaseUrl || !supabaseServiceKey || !supabase) {
            return createErrorResponse('Server configuration error', 500, corsHeaders, 'Missing environment variables');
        }

        // Security: Validate ChurchTools URL format (must be HTTPS)
        if (!/^https:\/\/[a-zA-Z0-9][a-zA-Z0-9._\-]*[a-zA-Z0-9]\/?$/.test(churchToolsUrl)) {
            return createErrorResponse('Server configuration error', 500, corsHeaders, 'Invalid ChurchTools URL format');
        }

        // Exchange authorization code for access token
        // ChurchTools uses public client (no secret), with PKCE
        const tokenParams = new URLSearchParams({
            grant_type: 'authorization_code',
            code: validatedCode,
            client_id: churchToolsClientId,
            redirect_uri: validatedRedirectUri,
        });

        // Add code_verifier for PKCE
        if (validatedCodeVerifier) {
            tokenParams.append('code_verifier', validatedCodeVerifier);
        }

        const tokenResponse = await fetchWithTimeout(`${churchToolsUrl}/oauth/access_token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: tokenParams.toString(),
        }, EXTERNAL_API_TIMEOUT_MS);

        if (!tokenResponse.ok) {
            const errorText = await tokenResponse.text();
            return createErrorResponse('Authentication failed', 400, corsHeaders, `Token exchange failed: ${errorText}`);
        }

        const tokenData = await tokenResponse.json();
        const accessToken = tokenData.access_token;

        if (!accessToken || typeof accessToken !== 'string') {
            return createErrorResponse('Authentication failed', 400, corsHeaders, 'No access token in response');
        }

        // Fetch user info from ChurchTools with timeout
        const userInfoResponse = await fetchWithTimeout(`${churchToolsUrl}/oauth/userinfo`, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
            },
        }, EXTERNAL_API_TIMEOUT_MS);

        if (!userInfoResponse.ok) {
            const errorText = await userInfoResponse.text();
            return createErrorResponse('Failed to retrieve user information', 400, corsHeaders, `User info fetch failed: ${errorText}`);
        }

        const userInfo = await userInfoResponse.json();

        // Extract user details from ChurchTools response
        // ChurchTools uses 'sub' (subject) as the unique user identifier per OAuth/OIDC spec
        const churchToolsUserId = String(userInfo.sub || userInfo.id || userInfo.personId);
        if (!churchToolsUserId || churchToolsUserId === 'undefined' || churchToolsUserId === 'null') {
            console.error(`[${requestId}] No valid ChurchTools user ID in response`);
            return createErrorResponse('Invalid user data from identity provider', 400, corsHeaders, 'No ChurchTools user ID');
        }
        
        const email = validateEmail(userInfo.email);
        const name = userInfo.name || `${userInfo.given_name || ''} ${userInfo.family_name || ''}`.trim() || 'Unknown User';

        // Security: Validate email format with stricter validation
        if (!email) {
            console.error(`[${requestId}] ChurchTools user has no valid email`);
            return createErrorResponse('Invalid user data from identity provider', 400, corsHeaders, 'ChurchTools user has no valid email');
        }

        // Security: Look up user by ChurchTools ID (not email) since emails can be duplicated
        // First check if we have an existing mapping in churchtools_users table
        let user = null;
        let existingMapping = null;
        
        const { data: mappingData, error: mappingError } = await supabase
            .from('churchtools_users')
            .select('user_id')
            .eq('churchtools_id', churchToolsUserId)
            .maybeSingle();
        
        if (mappingData?.user_id) {
            // User exists, get their Supabase auth record
            existingMapping = mappingData;
            const { data: existingUserData, error: getUserError } = await supabase.auth.admin.getUserById(mappingData.user_id);
            if (!getUserError && existingUserData?.user) {
                user = existingUserData.user;
                console.log(`[${requestId}] Found existing user by ChurchTools ID mapping`);
            }
        }
        
        // If no mapping exists, check if there's a user with matching email AND churchtools_id in metadata
        // This handles legacy users or manual migrations
        if (!user) {
            const { data: allUsersData, error: listError } = await supabase.auth.admin.listUsers();
            if (!listError && allUsersData?.users) {
                // First try to find by churchtools_id in metadata
                user = allUsersData.users.find(
                    (u: { user_metadata?: { churchtools_id?: string } }) => 
                        u.user_metadata?.churchtools_id === churchToolsUserId
                ) || null;
                
                // If not found by churchtools_id, DON'T fall back to email
                // This prevents account hijacking if someone in ChurchTools has another user's email
                if (user) {
                    console.log(`[${requestId}] Found existing user by churchtools_id in metadata`);
                }
            }
        }

        if (!user) {
            // Check if email is already in use by another account (without churchtools_id)
            // This prevents creating duplicate accounts with the same email
            const { data: emailCheckData } = await supabase.auth.admin.listUsers();
            const emailConflict = emailCheckData?.users?.find(
                (u: { email?: string; user_metadata?: { churchtools_id?: string } }) => 
                    u.email === email && u.user_metadata?.churchtools_id && u.user_metadata.churchtools_id !== churchToolsUserId
            );
            
            if (emailConflict) {
                console.error(`[${requestId}] Email already associated with different ChurchTools account`);
                return createErrorResponse(
                    'This email is already associated with a different ChurchTools account. Please contact support.',
                    409, 
                    corsHeaders
                );
            }
            
            // Create new Supabase user
            console.log(`[${requestId}] Creating new user for ChurchTools ID: ${churchToolsUserId}`);
            const { data: newUser, error: createError } = await supabase.auth.admin.createUser({
                email: email,
                email_confirm: true,
                user_metadata: {
                    churchtools_id: churchToolsUserId,
                    name: name,
                    full_name: name,
                    provider: 'churchtools',
                },
            });

            if (createError) {
                // Handle race condition: user might have been created by concurrent request
                if (createError.message?.includes('already been registered') || createError.message?.includes('duplicate')) {
                    console.warn(`[${requestId}] Race condition detected, retrying lookup`);
                    // Retry lookup
                    const { data: retryData } = await supabase.auth.admin.listUsers();
                    user = retryData?.users?.find(
                        (u: { user_metadata?: { churchtools_id?: string } }) => 
                            u.user_metadata?.churchtools_id === churchToolsUserId
                    ) || null;
                    
                    if (!user) {
                        return createErrorResponse('Failed to create user account', 500, corsHeaders, createError.message);
                    }
                } else {
                    return createErrorResponse('Failed to create user account', 500, corsHeaders, createError.message);
                }
            } else {
                user = newUser.user;
            }
        } else {
            // Update existing user metadata
            console.log(`[${requestId}] Updating existing user: ${user.id}`);
            const { error: updateError } = await supabase.auth.admin.updateUserById(user.id, {
                user_metadata: {
                    ...user.user_metadata,
                    churchtools_id: churchToolsUserId,
                    name: name,
                    full_name: name,
                    provider: 'churchtools',
                },
            });
            
            if (updateError) {
                // Non-fatal, continue
                console.error(`[${requestId}] Failed to update user metadata:`, updateError.message);
            }
        }

        if (!user || !user.id) {
            return createErrorResponse('Failed to process user account', 500, corsHeaders, 'User object is null after create/update');
        }

        // Security: Store ChurchTools data WITHOUT the access token
        // If you need to store the token, encrypt it first
        const { error: upsertError } = await supabase
            .from('churchtools_users')
            .upsert({
                user_id: user.id,
                churchtools_id: churchToolsUserId,
                email: email,
                name: name,
                churchtools_data: {
                    sub: userInfo.sub,
                    // Only store non-sensitive user info
                    name: userInfo.name,
                    given_name: userInfo.given_name,
                    family_name: userInfo.family_name,
                    // Explicitly exclude: access tokens, refresh tokens, etc.
                },
                // Security: Do NOT store access token in plain text
                // churchtools_access_token: accessToken, // REMOVED
                updated_at: new Date().toISOString(),
            }, {
                // Use churchtools_id as the conflict target since it's the primary lookup key
                onConflict: 'churchtools_id',
                ignoreDuplicates: false,
            });
        
        if (upsertError) {
            // Log the actual error for debugging, but don't fail the auth flow
            console.error(`[${requestId}] ChurchTools user data storage failed:`, upsertError.message, upsertError.code);
        }

        // Generate a magic link to create a session for the user
        // Note: createSession is not available in all Supabase versions, so we use generateLink
        const { data: linkData, error: linkError } = await supabase.auth.admin.generateLink({
            type: 'magiclink',
            email: email,
        });

        if (linkError || !linkData) {
            return createErrorResponse('Failed to generate session', 500, corsHeaders, linkError?.message);
        }

        // Security: Return minimal user info, don't expose internal IDs unnecessarily
        return new Response(
            JSON.stringify({
                type: 'magiclink',
                token_hash: linkData.properties?.hashed_token,
                email: email,
                user: {
                    id: user.id,
                    email: email,
                    name: name,
                },
            }),
            { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );

    } catch (error: unknown) {
        // Security: Log error internally but don't expose details to client
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        console.error(`[${requestId}] OAuth callback error:`, errorMessage);
        return createErrorResponse('Internal server error', 500, corsHeaders);
    }
});
