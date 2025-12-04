// deno-lint-ignore-file
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { encode as base64Encode } from 'https://deno.land/std@0.168.0/encoding/base64.ts';

// Deno global declaration for TypeScript
declare const Deno: {
    env: {
        get(key: string): string | undefined;
    };
};

// CORS headers - allow all origins for this endpoint since it's just generating tokens
function getCorsHeaders(origin: string | null): Record<string, string> {
    const allowedOrigins = (Deno.env.get('ALLOWED_ORIGINS') || '').split(',').filter(Boolean);
    
    const headers: Record<string, string> = {
        'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'no-store',
    };
    
    if (origin && (allowedOrigins.length === 0 || allowedOrigins.includes(origin))) {
        headers['Access-Control-Allow-Origin'] = origin;
    }
    
    return headers;
}

/**
 * Generate a cryptographically random nonce
 */
function generateNonce(length = 16): string {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Edge Function: Generate OAuth State Token
 * 
 * This function generates HMAC-signed state tokens for OAuth CSRF protection.
 * The token format is: timestamp.nonce.signature
 * 
 * Clients should call this before initiating OAuth flow to get a secure state token.
 */
serve(async (req: Request) => {
    const origin = req.headers.get('origin');
    const corsHeaders = getCorsHeaders(origin);
    
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
        return new Response('ok', { headers: corsHeaders });
    }
    
    // Allow both GET and POST
    if (req.method !== 'GET' && req.method !== 'POST') {
        return new Response(
            JSON.stringify({ error: 'Method not allowed' }),
            { status: 405, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
    }
    
    try {
        const stateSecret = Deno.env.get('STATE_SECRET');
        if (!stateSecret) {
            console.error('STATE_SECRET not configured');
            return new Response(
                JSON.stringify({ error: 'Server configuration error' }),
                { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
            );
        }
        
        // Generate token components
        const timestamp = Date.now().toString();
        const nonce = generateNonce();
        const payload = `${timestamp}.${nonce}`;
        
        // Create HMAC-SHA256 signature
        const encoder = new TextEncoder();
        const key = await crypto.subtle.importKey(
            'raw',
            encoder.encode(stateSecret),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        
        const signatureBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
        const signature = base64Encode(new Uint8Array(signatureBuffer))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        
        const stateToken = `${timestamp}.${nonce}.${signature}`;
        
        return new Response(
            JSON.stringify({ 
                state: stateToken,
                expiresIn: 600, // 10 minutes in seconds
            }),
            { 
                status: 200, 
                headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
            }
        );
        
    } catch (error: unknown) {
        console.error('Error generating state token:', error instanceof Error ? error.message : 'Unknown error');
        return new Response(
            JSON.stringify({ error: 'Failed to generate state token' }),
            { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
    }
});
