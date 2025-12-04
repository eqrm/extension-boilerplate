/**
 * OAuth State Token Utilities
 * 
 * This module provides client-side utilities for working with HMAC-signed
 * state tokens for CSRF protection in OAuth flows.
 * 
 * State tokens are generated server-side via the generate-state-token Edge Function.
 * This ensures the STATE_SECRET never leaves the server.
 */

/**
 * Storage key for persisting state token in sessionStorage
 */
const STATE_STORAGE_KEY = 'oauth_state_token';

/**
 * Store state token in sessionStorage for verification after OAuth redirect
 */
export function storeStateToken(state: string): void {
    if (typeof sessionStorage !== 'undefined') {
        sessionStorage.setItem(STATE_STORAGE_KEY, state);
    }
}

/**
 * Retrieve stored state token from sessionStorage (does not remove it)
 */
export function getStoredStateToken(): string | null {
    if (typeof sessionStorage === 'undefined') {
        return null;
    }
    return sessionStorage.getItem(STATE_STORAGE_KEY);
}

/**
 * Retrieve and clear stored state token from sessionStorage
 */
export function retrieveStateToken(): string | null {
    if (typeof sessionStorage === 'undefined') {
        return null;
    }
    const state = sessionStorage.getItem(STATE_STORAGE_KEY);
    sessionStorage.removeItem(STATE_STORAGE_KEY);
    return state;
}

/**
 * Clear the stored state token without retrieving it
 */
export function clearStateToken(): void {
    if (typeof sessionStorage !== 'undefined') {
        sessionStorage.removeItem(STATE_STORAGE_KEY);
    }
}

/**
 * Verify that the returned state matches the stored state
 * This is a client-side check before sending to the server
 * The server will also verify the HMAC signature
 * 
 * @param returnedState - State parameter from OAuth callback URL
 * @returns true if states match, false otherwise
 */
export function verifyStateMatch(returnedState: string | null): boolean {
    const storedState = getStoredStateToken();
    return storedState !== null && returnedState === storedState;
}

/**
 * Check if a state token appears to be expired based on its timestamp
 * State tokens have format: timestamp.nonce.signature
 * 
 * @param state - The state token to check
 * @param maxAgeMs - Maximum age in milliseconds (default: 10 minutes)
 * @returns true if token appears expired, false otherwise
 */
export function isStateTokenExpired(state: string, maxAgeMs = 600000): boolean {
    try {
        const parts = state.split('.');
        if (parts.length !== 3) {
            return true; // Invalid format, treat as expired
        }
        
        const timestamp = parseInt(parts[0], 10);
        if (isNaN(timestamp)) {
            return true;
        }
        
        return Date.now() - timestamp > maxAgeMs;
    } catch {
        return true;
    }
}
