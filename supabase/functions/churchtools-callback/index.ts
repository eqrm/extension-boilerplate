import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

/**
 * Edge Function: ChurchTools OAuth Callback Handler
 * 
 * This function handles the OAuth token exchange:
 * 1. Receives the authorization code from the frontend
 * 2. Exchanges it for an access token with ChurchTools
 * 3. Fetches user info from ChurchTools
 * 4. Creates/updates user in Supabase and returns a session
 */
serve(async (req: Request) => {
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
        return new Response('ok', { headers: corsHeaders });
    }

    try {
        // Parse request body
        const { code, code_verifier, redirect_uri } = await req.json();

        if (!code) {
            return new Response(
                JSON.stringify({ error: 'Missing authorization code' }),
                { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
            );
        }

        // Get environment variables
        const churchToolsUrl = Deno.env.get('CHURCHTOOLS_URL');
        const churchToolsClientId = Deno.env.get('CHURCHTOOLS_CLIENT_ID');
        const supabaseUrl = Deno.env.get('SUPABASE_URL');
        const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');

        if (!churchToolsUrl || !churchToolsClientId || !supabaseUrl || !supabaseServiceKey) {
            console.error('Missing environment variables');
            return new Response(
                JSON.stringify({ error: 'Server configuration error' }),
                { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
            );
        }

        // Exchange authorization code for access token
        // ChurchTools uses public client (no secret), with PKCE
        const tokenParams = new URLSearchParams({
            grant_type: 'authorization_code',
            code: code,
            client_id: churchToolsClientId,
            redirect_uri: redirect_uri,
        });

        // Add code_verifier for PKCE
        if (code_verifier) {
            tokenParams.append('code_verifier', code_verifier);
        }

        console.log('Exchanging code for token...');
        const tokenResponse = await fetch(`${churchToolsUrl}/oauth/access_token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: tokenParams.toString(),
        });

        if (!tokenResponse.ok) {
            const errorText = await tokenResponse.text();
            console.error('Token exchange failed:', errorText);
            return new Response(
                JSON.stringify({ error: 'Failed to exchange code for token', details: errorText }),
                { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
            );
        }

        const tokenData = await tokenResponse.json();
        const accessToken = tokenData.access_token;
        console.log('Token received successfully');

        // Fetch user info from ChurchTools
        const userInfoResponse = await fetch(`${churchToolsUrl}/oauth/userinfo`, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
            },
        });

        if (!userInfoResponse.ok) {
            const errorText = await userInfoResponse.text();
            console.error('User info fetch failed:', errorText);
            return new Response(
                JSON.stringify({ error: 'Failed to fetch user info', details: errorText }),
                { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
            );
        }

        const userInfo = await userInfoResponse.json();
        console.log('ChurchTools user info received:', userInfo.email || userInfo.sub);

        // Create Supabase admin client
        const supabase = createClient(supabaseUrl, supabaseServiceKey, {
            auth: {
                autoRefreshToken: false,
                persistSession: false,
            },
        });

        // Extract user details from ChurchTools response
        const churchToolsUserId = String(userInfo.sub || userInfo.id || userInfo.personId);
        const email = userInfo.email;
        const name = userInfo.name || `${userInfo.given_name || ''} ${userInfo.family_name || ''}`.trim();

        if (!email) {
            return new Response(
                JSON.stringify({ error: 'ChurchTools user has no email address' }),
                { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
            );
        }

        // Try to find existing user by email
        const { data: existingUsers } = await supabase.auth.admin.listUsers();
        let user = existingUsers?.users?.find((u: { email?: string }) => u.email === email);

        if (!user) {
            // Create new Supabase user
            console.log('Creating new user:', email);
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
                console.error('Failed to create user:', createError);
                return new Response(
                    JSON.stringify({ error: 'Failed to create user', details: createError.message }),
                    { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
                );
            }
            user = newUser.user;
        } else {
            // Update existing user metadata
            console.log('Updating existing user:', email);
            await supabase.auth.admin.updateUserById(user.id, {
                user_metadata: {
                    ...user.user_metadata,
                    churchtools_id: churchToolsUserId,
                    name: name,
                    full_name: name,
                    provider: 'churchtools',
                },
            });
        }

        // Store ChurchTools data in a separate table (optional)
        await supabase
            .from('churchtools_users')
            .upsert({
                user_id: user!.id,
                churchtools_id: churchToolsUserId,
                email: email,
                name: name,
                churchtools_data: userInfo,
                churchtools_access_token: accessToken,
                updated_at: new Date().toISOString(),
            }, {
                onConflict: 'user_id',
            })
            .then(({ error }) => {
                if (error) {
                    // Table might not exist, that's okay
                    console.log('Note: churchtools_users table not found or insert failed:', error.message);
                }
            });

        // Generate a magic link to create a session for the user
        // Note: createSession is not available in all Supabase versions, so we use generateLink
        const { data: linkData, error: linkError } = await supabase.auth.admin.generateLink({
            type: 'magiclink',
            email: email,
        });

        if (linkError) {
            console.error('Failed to generate magic link:', linkError);
            return new Response(
                JSON.stringify({ error: 'Failed to generate session', details: linkError.message }),
                { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
            );
        }

        // Return the magic link token for the client to use
        return new Response(
            JSON.stringify({
                type: 'magiclink',
                token_hash: linkData.properties?.hashed_token,
                email: email,
                user: {
                    id: user!.id,
                    email: email,
                    name: name,
                    churchtools_id: churchToolsUserId,
                },
            }),
            { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );

    } catch (error: unknown) {
        console.error('OAuth callback error:', error);
        const message = error instanceof Error ? error.message : 'Unknown error';
        return new Response(
            JSON.stringify({ error: 'Internal server error', details: message }),
            { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
    }
});
