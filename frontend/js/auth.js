// Cognito hosted login, authorization code + PKCE. Tokens live in sessionStorage only.

const cfg = () => window.SIEM_CONFIG;
const redirectUri = () => window.location.origin + "/";

function b64url(bytes) {
    return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomString(len) {
    return b64url(crypto.getRandomValues(new Uint8Array(len))).slice(0, len);
}

export const configured = () => Boolean(cfg() && cfg().apiUrl && cfg().clientId && cfg().loginUrl);

export async function login() {
    const verifier = randomString(64);
    const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
    const state = randomString(16);
    sessionStorage.setItem("pkce_verifier", verifier);
    sessionStorage.setItem("pkce_state", state);

    const params = new URLSearchParams({
        response_type: "code",
        client_id: cfg().clientId,
        redirect_uri: redirectUri(),
        scope: "openid email",
        code_challenge: challenge,
        code_challenge_method: "S256",
        state
    });
    window.location.href = cfg().loginUrl + "/oauth2/authorize?" + params.toString();
}

async function tokenRequest(body) {
    const res = await fetch(cfg().loginUrl + "/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(body).toString()
    });
    if (!res.ok) throw new Error("Login failed (" + res.status + ")");
    return res.json();
}

function saveTokens(tokens) {
    sessionStorage.setItem("access_token", tokens.access_token);
    sessionStorage.setItem("expires_at", String(Date.now() + (tokens.expires_in - 60) * 1000));
    if (tokens.refresh_token) sessionStorage.setItem("refresh_token", tokens.refresh_token);
}

export async function handleRedirect() {
    const params = new URLSearchParams(window.location.search);
    if (!params.has("code")) return;

    const expected = sessionStorage.getItem("pkce_state");
    const verifier = sessionStorage.getItem("pkce_verifier");
    window.history.replaceState({}, "", window.location.pathname);
    if (!verifier || params.get("state") !== expected) throw new Error("Unexpected login response, try again");

    saveTokens(await tokenRequest({
        grant_type: "authorization_code",
        client_id: cfg().clientId,
        code: params.get("code"),
        redirect_uri: redirectUri(),
        code_verifier: verifier
    }));
    sessionStorage.removeItem("pkce_verifier");
    sessionStorage.removeItem("pkce_state");
}

export async function getToken() {
    const token = sessionStorage.getItem("access_token");
    if (token && Date.now() < Number(sessionStorage.getItem("expires_at"))) return token;

    const refresh = sessionStorage.getItem("refresh_token");
    if (!refresh) return null;
    try {
        saveTokens(await tokenRequest({ grant_type: "refresh_token", client_id: cfg().clientId, refresh_token: refresh }));
        return sessionStorage.getItem("access_token");
    } catch (e) {
        sessionStorage.clear();
        return null;
    }
}

export function clearSession() {
    sessionStorage.clear();
}

export function logout() {
    sessionStorage.clear();
    const params = new URLSearchParams({ client_id: cfg().clientId, logout_uri: redirectUri() });
    window.location.href = cfg().loginUrl + "/logout?" + params.toString();
}

// Display only: the API Gateway authorizer is what actually enforces access
export function claims() {
    try {
        const payload = sessionStorage.getItem("access_token").split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
        const data = JSON.parse(atob(payload));
        return { name: data.username || data.email || "user", groups: data["cognito:groups"] || [] };
    } catch (e) {
        return { name: "user", groups: [] };
    }
}
