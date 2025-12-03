import { createClient, type SupabaseClient, type Session, type User } from '@supabase/supabase-js';

// ChurchTools OAuth Configuration
const CHURCHTOOLS_URL = import.meta.env.VITE_CHURCHTOOLS_URL || 'https://eqrm.church.tools';
const CHURCHTOOLS_CLIENT_ID = import.meta.env.VITE_CHURCHTOOLS_CLIENT_ID || 'a0e5bb7b6241e873104f8dda7fab9d80c4cc5bd433b052226b22971156c4176b';

// Supabase Configuration
const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL || 'https://efebxhsfaouwgibydisz.supabase.co';
const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY || '';

// Callback URLs
const OAUTH_CALLBACK_URL = import.meta.env.VITE_OAUTH_CALLBACK_URL || 'http://localhost:5173';
const SUPABASE_FUNCTION_URL = `${SUPABASE_URL}/functions/v1/churchtools-callback`;

// Create Supabase client
export const supabase: SupabaseClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// PKCE Helper Functions
function generateRandomString(length: number): string {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(plain: string): Promise<ArrayBuffer> {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return crypto.subtle.digest('SHA-256', data);
}

function base64UrlEncode(arrayBuffer: ArrayBuffer): string {
    const bytes = new Uint8Array(arrayBuffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

async function generateCodeChallenge(codeVerifier: string): Promise<string> {
    const hash = await sha256(codeVerifier);
    return base64UrlEncode(hash);
}

// Storage keys
const CODE_VERIFIER_KEY = 'churchtools_oauth_code_verifier';
const STATE_KEY = 'churchtools_oauth_state';

/**
 * Initiates the OAuth flow by redirecting to ChurchTools authorization endpoint
 */
export async function startOAuthFlow(): Promise<void> {
    // Generate PKCE values
    const codeVerifier = generateRandomString(64);
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    const state = generateRandomString(32);

    // Store values for callback verification
    sessionStorage.setItem(CODE_VERIFIER_KEY, codeVerifier);
    sessionStorage.setItem(STATE_KEY, state);

    // Build authorization URL
    const authUrl = new URL(`${CHURCHTOOLS_URL}/oauth/authorize`);
    authUrl.searchParams.set('client_id', CHURCHTOOLS_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', OAUTH_CALLBACK_URL);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid profile email');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    // Redirect to ChurchTools
    window.location.href = authUrl.toString();
}

/**
 * Handles the OAuth callback - exchanges code for Supabase session
 */
export async function handleOAuthCallback(): Promise<{ session: Session | null; user: User | null; error: string | null }> {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    const error = urlParams.get('error');
    const errorDescription = urlParams.get('error_description');

    // Check for OAuth error
    if (error) {
        return { session: null, user: null, error: errorDescription || error };
    }

    // Check if this is a callback
    if (!code) {
        return { session: null, user: null, error: null };
    }

    // Verify state
    const storedState = sessionStorage.getItem(STATE_KEY);
    if (state !== storedState) {
        return { session: null, user: null, error: 'Invalid state parameter - possible CSRF attack' };
    }

    // Get code verifier
    const codeVerifier = sessionStorage.getItem(CODE_VERIFIER_KEY);
    if (!codeVerifier) {
        return { session: null, user: null, error: 'Missing code verifier - please try logging in again' };
    }

    // Clean up storage
    sessionStorage.removeItem(CODE_VERIFIER_KEY);
    sessionStorage.removeItem(STATE_KEY);

    // Clear URL parameters
    window.history.replaceState({}, document.title, window.location.pathname);

    try {
        // Call Supabase Edge Function to exchange code for session
        const response = await fetch(SUPABASE_FUNCTION_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'apikey': SUPABASE_ANON_KEY,
                'Authorization': `Bearer ${SUPABASE_ANON_KEY}`,
            },
            body: JSON.stringify({
                code,
                code_verifier: codeVerifier,
                redirect_uri: OAUTH_CALLBACK_URL,
            }),
        });

        const data = await response.json();

        if (!response.ok) {
            return { session: null, user: null, error: data.error || 'Failed to exchange code for session' };
        }

        // Handle different response types
        if (data.type === 'magiclink') {
            // Use magic link token to complete sign in
            const { data: sessionData, error: verifyError } = await supabase.auth.verifyOtp({
                token_hash: data.token_hash,
                type: 'magiclink',
            });

            if (verifyError) {
                return { session: null, user: null, error: verifyError.message };
            }

            return { session: sessionData.session, user: sessionData.user, error: null };
        }

        // Direct session response - set the session in Supabase client
        const { data: sessionData, error: setSessionError } = await supabase.auth.setSession({
            access_token: data.access_token,
            refresh_token: data.refresh_token,
        });

        if (setSessionError) {
            return { session: null, user: null, error: setSessionError.message };
        }

        return { session: sessionData.session, user: sessionData.user, error: null };
    } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error during authentication';
        return { session: null, user: null, error: message };
    }
}

/**
 * Gets the current Supabase session
 */
export async function getSession(): Promise<Session | null> {
    const { data: { session } } = await supabase.auth.getSession();
    return session;
}

/**
 * Gets the current Supabase user
 */
export async function getUser(): Promise<User | null> {
    const { data: { user } } = await supabase.auth.getUser();
    return user;
}

/**
 * Signs out the current user
 */
export async function signOut(): Promise<void> {
    await supabase.auth.signOut();
}

/**
 * Subscribes to auth state changes
 */
export function onAuthStateChange(callback: (session: Session | null, user: User | null) => void): () => void {
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
        callback(session, session?.user ?? null);
    });

    return () => subscription.unsubscribe();
}

export type { Session, User };
