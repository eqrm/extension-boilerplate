/// <reference types="vite/client" />

interface ImportMetaEnv {
    readonly VITE_KEY: string;
    readonly VITE_BASE_URL: string;
    readonly VITE_USERNAME?: string;
    readonly VITE_PASSWORD?: string;
    readonly VITE_SUPABASE_URL: string;
    readonly VITE_SUPABASE_ANON_KEY: string;
    readonly VITE_CHURCHTOOLS_URL: string;
    readonly VITE_CHURCHTOOLS_CLIENT_ID: string;
    readonly VITE_OAUTH_CALLBACK_URL: string;
}

interface ImportMeta {
    readonly env: ImportMetaEnv;
}
