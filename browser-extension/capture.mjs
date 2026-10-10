export const GATEWAY = "http://127.0.0.1:8765";
export const BODY_LIMIT = 128 * 1024;
const sensitive = /authorization|cookie|api[-_]?key|token|secret|session/i;

export function cleanHeaders(headers = []) {
  return headers.slice(0, 200).map(h => ({name: String(h.name).slice(0, 1024),
    value: sensitive.test(h.name) ? "<redacted>" : String(h.value).slice(0, 8192)}));
}

function asBase64(bytes) {
  let text = "";
  for (let offset = 0; offset < bytes.length; offset += 8192) {
    text += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  }
  return btoa(text);
}

export function captureBody(value, encoding = "", limit = BODY_LIMIT) {
  if (typeof value !== "string") return {base64: null, truncated: false};
  if (encoding === "base64") {
    const count = Math.floor(value.length * 3 / 4) - (value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0);
    const prefix = value.slice(0, Math.ceil(limit / 3) * 4);
    const binary = atob(prefix);
    const bytes = Uint8Array.from(binary.slice(0, limit), c => c.charCodeAt(0));
    return {base64: asBase64(bytes), truncated: count > limit};
  }
  // Encode a bounded character prefix; never upload an unbounded browser body.
  const prefix = new TextEncoder().encode(value.slice(0, limit + 2));
  return {base64: asBase64(prefix.subarray(0, limit)), truncated: prefix.length > limit || value.length > limit};
}

function size(value) { return Number.isSafeInteger(value) && value >= 0 ? value : null; }

export function makeObservation(entry, responseContent, responseEncoding, tabId, limit = BODY_LIMIT) {
  const url = new URL(entry.request.url);
  if (!["http:", "https:"].includes(url.protocol) || url.origin === GATEWAY) return null;
  if (url.username || url.password) return null;
  const requestBody = captureBody(entry.request.postData?.text, "", limit);
  const responseBody = captureBody(responseContent, responseEncoding, limit);
  return {
    id: crypto.randomUUID(), url: url.href, method: entry.request.method,
    seen_at: entry.startedDateTime || new Date().toISOString(),
    status: entry.response.status || 0, duration_ms: typeof entry.time === "number" && entry.time >= 0 ? entry.time : null,
    tab_id: tabId, request_headers: cleanHeaders(entry.request.headers), response_headers: cleanHeaders(entry.response.headers),
    request_body_base64: requestBody.base64, response_body_base64: responseBody.base64,
    request_reported_size: size(entry.request.bodySize), response_reported_size: size(entry.response.content?.size),
    request_truncated: requestBody.truncated, response_truncated: responseBody.truncated,
    note: responseBody.base64 === null ? "Browser response body was unavailable." : "",
    error: entry._error ? String(entry._error).slice(0, 4000) : null,
  };
}

export function readResponseContent(request, timeout = 5000) {
  return new Promise(resolve => {
    let timer;
    let finished = false;
    function done(content, encoding = "") {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      resolve({content, encoding});
    }
    timer = setTimeout(() => done(null), timeout);
    try {
      // Supports legacy callbacks and the Promise form in newer Chromium.
      const result = request.getContent(done);
      if (result && typeof result.then === "function") {
        result.then(value => done(value?.content, value?.encoding), () => done(null));
      }
    } catch { done(null); }
  });
}
