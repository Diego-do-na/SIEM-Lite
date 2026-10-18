import { getToken, clearSession } from "./auth.js";

export class ApiError extends Error {
    constructor(message, status) {
        super(message);
        this.status = status;
    }
}

let mock = null;
let onSignedOut = () => {};

export const setSignedOutHandler = (fn) => { onSignedOut = fn; };
export const isMock = () => mock !== null;

// Demo mode: the same calls are answered from generated data, no AWS needed
export async function enableMock(mode) {
    mock = await import("./mock.js");
    mock.configure(mode);
}

export async function api(path, { auth = true } = {}) {
    if (mock) return mock.handle(path);

    const headers = {};
    if (auth) {
        const token = await getToken();
        if (!token) {
            onSignedOut();
            throw new ApiError("Not signed in", 401);
        }
        headers.Authorization = "Bearer " + token;
    }
    const res = await fetch(window.SIEM_CONFIG.apiUrl + path, { headers });
    if (res.status === 401) {
        clearSession();
        onSignedOut();
        throw new ApiError("Session expired", 401);
    }
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new ApiError(body.error || "Request failed (" + res.status + ")", res.status);
    return body;
}
