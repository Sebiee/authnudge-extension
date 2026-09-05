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
