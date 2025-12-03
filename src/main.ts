import type { Person } from './utils/ct-types';
import { churchtoolsClient } from '@churchtools/churchtools-client';
import {
    startOAuthFlow,
    handleOAuthCallback,
    getSession,
    signOut,
    onAuthStateChange,
    type Session,
    type User,
} from './utils/supabase-auth';

// only import reset.css in development mode to keep the production bundle small and to simulate CT environment
if (import.meta.env.MODE === 'development') {
    import('./utils/reset.css');
}

declare const window: Window &
    typeof globalThis & {
        settings: {
            base_url?: string;
        };
    };

const baseUrl = window.settings?.base_url ?? import.meta.env.VITE_BASE_URL;
churchtoolsClient.setBaseUrl(baseUrl);

const username = import.meta.env.VITE_USERNAME;
const password = import.meta.env.VITE_PASSWORD;
if (import.meta.env.MODE === 'development' && username && password) {
    await churchtoolsClient.post('/login', { username, password });
}

const KEY = import.meta.env.VITE_KEY;
export { KEY };

// DOM Elements
const appElement = document.querySelector<HTMLDivElement>('#app')!;

// Render functions
function renderLoading(): void {
    appElement.innerHTML = `
        <div style="display: flex; place-content: center; place-items: center; height: 100vh; flex-direction: column; gap: 1rem;">
            <p>Loading...</p>
        </div>
    `;
}

function renderLoginPage(): void {
    appElement.innerHTML = `
        <div style="display: flex; place-content: center; place-items: center; height: 100vh; flex-direction: column; gap: 1rem;">
            <h1>ChurchTools Extension</h1>
            <p>Sign in with your ChurchTools account to continue</p>
            <button id="login-btn" style="padding: 12px 24px; font-size: 16px; cursor: pointer; background: #4F46E5; color: white; border: none; border-radius: 8px;">
                Sign in with ChurchTools
            </button>
        </div>
    `;

    document.getElementById('login-btn')?.addEventListener('click', () => {
        startOAuthFlow();
    });
}

function renderError(message: string): void {
    appElement.innerHTML = `
        <div style="display: flex; place-content: center; place-items: center; height: 100vh; flex-direction: column; gap: 1rem;">
            <h1 style="color: #DC2626;">Authentication Error</h1>
            <p>${message}</p>
            <button id="retry-btn" style="padding: 12px 24px; font-size: 16px; cursor: pointer; background: #4F46E5; color: white; border: none; border-radius: 8px;">
                Try Again
            </button>
        </div>
    `;

    document.getElementById('retry-btn')?.addEventListener('click', () => {
        startOAuthFlow();
    });
}

async function renderDashboard(session: Session, user: User, ctUser: Person | null): Promise<void> {
    const userMetadata = user.user_metadata || {};
    
    appElement.innerHTML = `
        <div style="display: flex; flex-direction: column; min-height: 100vh; padding: 2rem;">
            <header style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem;">
                <h1>ChurchTools Extension</h1>
                <button id="logout-btn" style="padding: 8px 16px; cursor: pointer; background: #EF4444; color: white; border: none; border-radius: 6px;">
                    Sign Out
                </button>
            </header>
            
            <main style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem;">
                <!-- Supabase User Info -->
                <div style="background: #F3F4F6; padding: 1.5rem; border-radius: 12px;">
                    <h2 style="margin-bottom: 1rem; color: #4F46E5;">✅ Supabase Authentication</h2>
                    <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                        <p><strong>User ID:</strong> ${user.id}</p>
                        <p><strong>Email:</strong> ${user.email || 'N/A'}</p>
                        <p><strong>Name:</strong> ${userMetadata.name || userMetadata.full_name || 'N/A'}</p>
                        <p><strong>ChurchTools ID:</strong> ${userMetadata.churchtools_id || 'N/A'}</p>
                        <p><strong>Provider:</strong> ${userMetadata.provider || 'churchtools'}</p>
                        <p><strong>Session Expires:</strong> ${session.expires_at ? new Date(session.expires_at * 1000).toLocaleString() : 'N/A'}</p>
                    </div>
                </div>

                <!-- ChurchTools User Info -->
                <div style="background: #F3F4F6; padding: 1.5rem; border-radius: 12px;">
                    <h2 style="margin-bottom: 1rem; color: #059669;">🏛️ ChurchTools Profile</h2>
                    ${ctUser ? `
                        <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                            <p><strong>Name:</strong> ${[ctUser.firstName, ctUser.lastName].filter(Boolean).join(' ') || 'N/A'}</p>
                            <p><strong>Person ID:</strong> ${ctUser.id || 'N/A'}</p>
                            <p><strong>Email:</strong> ${ctUser.email || 'N/A'}</p>
                        </div>
                    ` : `
                        <p style="color: #6B7280;">ChurchTools profile not available (sign in via ChurchTools in extension context)</p>
                    `}
                </div>

                <!-- Session Token Info -->
                <div style="background: #F3F4F6; padding: 1.5rem; border-radius: 12px;">
                    <h2 style="margin-bottom: 1rem; color: #7C3AED;">🔐 Session Token</h2>
                    <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                        <p><strong>Access Token:</strong></p>
                        <code style="background: #E5E7EB; padding: 0.5rem; border-radius: 4px; font-size: 12px; word-break: break-all; max-height: 100px; overflow: auto;">
                            ${session.access_token.substring(0, 50)}...
                        </code>
                        <p style="color: #6B7280; font-size: 12px; margin-top: 0.5rem;">
                            This token can be used to make authenticated requests to Supabase APIs.
                        </p>
                    </div>
                </div>
            </main>

            <footer style="margin-top: auto; padding-top: 2rem; text-align: center; color: #6B7280;">
                <p>Successfully authenticated via ChurchTools OAuth → Supabase</p>
            </footer>
        </div>
    `;

    document.getElementById('logout-btn')?.addEventListener('click', async () => {
        await signOut();
        renderLoginPage();
    });
}

// Main initialization
async function init(): Promise<void> {
    renderLoading();

    // Check if this is an OAuth callback
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('code')) {
        const { session, user, error } = await handleOAuthCallback();
        
        if (error) {
            renderError(error);
            return;
        }

        if (session && user) {
            // Try to get ChurchTools user info
            let ctUser: Person | null = null;
            try {
                ctUser = await churchtoolsClient.get<Person>('/whoami');
            } catch {
                // ChurchTools user info not available (might not be in CT context)
            }
            await renderDashboard(session, user, ctUser);
            return;
        }
    }

    // Check for existing session
    const session = await getSession();
    if (session?.user) {
        // Try to get ChurchTools user info
        let ctUser: Person | null = null;
        try {
            ctUser = await churchtoolsClient.get<Person>('/whoami');
        } catch {
            // ChurchTools user info not available
        }
        await renderDashboard(session, session.user, ctUser);
        return;
    }

    // No session, show login page
    renderLoginPage();
}

// Listen for auth state changes
onAuthStateChange(async (session, user) => {
    if (session && user) {
        let ctUser: Person | null = null;
        try {
            ctUser = await churchtoolsClient.get<Person>('/whoami');
        } catch {
            // ChurchTools user info not available
        }
        await renderDashboard(session, user, ctUser);
    } else {
        renderLoginPage();
    }
});

// Start the app
init();
