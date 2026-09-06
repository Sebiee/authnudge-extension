export function originHost(tabUrl) {
  const origin = normalizeOrigin(tabUrl);
  if (!origin) return null;
  const url = new URL(origin);
  return `${url.protocol}//${url.host.toLowerCase()}`;
}

export function sameLoginHost(tabUrl, requestedOrigin) {
  const left = originHost(tabUrl);
  const right = originHost(requestedOrigin);
  return Boolean(left && right && left === right);
}

export function normalizeOrigin(tabUrl) {
  let url;
  try {
    url = new URL(tabUrl);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  if (!url.hostname) return null;
  const path = url.pathname === "/" ? "" : url.pathname.replace(/\/+$/, "");
  return `${url.protocol}//${url.host.toLowerCase()}${path}`;
}

export function normalizeTo(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/^@+/, "");
}

export function normalizeBaseUrl(value) {
  const url = new URL(String(value ?? "").trim());
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Authnudge URL must be http or https");
  }
  if (!url.hostname) throw new Error("Authnudge URL is missing a host");
  return `${url.protocol}//${url.host}`;
}

export const DEFAULT_BASE = "https://authnudge.com";
export const LOCAL_BASE = "http://127.0.0.1:5173";

export function resolveBaseUrl(raw) {
  if (raw == null || raw === "") return DEFAULT_BASE;
  try {
    const url = normalizeBaseUrl(raw);
    const host = new URL(url).hostname;
    if (host === "127.0.0.1" || host === "localhost" || host === "[::1]") return url;
  } catch {
    /* fall through */
  }
  return DEFAULT_BASE;
}
