const API_BASE_URL = (import.meta.env.VITE_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
const SESSION_KEY = "cybershield.session";

export function getSession() {
  try { return JSON.parse(localStorage.getItem(SESSION_KEY) || "null"); }
  catch { return null; }
}

export function setSession(session) { localStorage.setItem(SESSION_KEY, JSON.stringify(session)); }
export function clearSession() { localStorage.removeItem(SESSION_KEY); }

async function request(method, path, body, options = {}) {
  const session = getSession();
  const target = new URL(API_BASE_URL);
  if (import.meta.env.PROD && target.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(target.hostname)) {
    throw new Error("Secure API connection required. Set VITE_API_URL to your HTTPS backend URL.");
  }
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method,
      headers: {
        ...(body === undefined || body instanceof FormData ? {} : { "Content-Type": "application/json" }),
        ...((options.token || session?.access_token) ? { Authorization: `Bearer ${options.token || session.access_token}` } : {}),
        ...(options.headers || {}),
      },
      ...(body === undefined ? {} : { body: body instanceof FormData ? body : JSON.stringify(body) }),
    });
  } catch {
    const error = new Error(`Cannot reach CyberShield API at ${API_BASE_URL}. Start the backend or set VITE_API_URL in frontend/.env.`);
    error.network = true;
    throw error;
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = payload.detail;
    const message = Array.isArray(detail) ? detail.map((issue) => issue.msg).join(" · ") : detail;
    const error = new Error(message || `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return payload;
}

export const api = {
  get: (path, options) => request("GET", path, undefined, options),
  post: (path, body, options) => request("POST", path, body, options),
  upload: (path, formData, options) => request("POST", path, formData, options),
  delete: (path, options) => request("DELETE", path, undefined, options),
  put: (path, body, options) => request("PUT", path, body, options),
};

export const apiBaseUrl = API_BASE_URL;
