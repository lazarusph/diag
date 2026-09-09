const MAX_BODY_BYTES = 8192;
const MAX_REPORTS = 120;
const MAX_DEVICE_SAMPLES = 12;
const MAX_ANDROID_SAMPLES = 10;
const MAX_APP_VERSIONS = 8;
const GITHUB_API_VERSION = "2026-03-10";
const ALLOWED_CODES = new Set([
  "HEX-ARCHIVE-EMPTY-001",
  "HEX-ARCHIVE-MISSING-001",
  "HEX-ARCHIVE-READ-001",
  "HEX-CYBER-INPUT-001",
  "HEX-CYBER-IO-001",
  "HEX-CYBER-MODE-001",
  "HEX-CYBER-UNKNOWN-001",
  "HEX-LEGACY-DIR-001",
  "HEX-LEGACY-DIR-002",
  "HEX-LEGACY-PERM-001",
  "HEX-LEGACY-WRITE-001",
  "HEX-PERM-SAF-001",
  "HEX-PERM-SAF-002",
  "HEX-PERM-SAF-003",
  "HEX-PERM-SAF-004",
  "HEX-PERM-SHIZUKU-001",
  "HEX-PERM-SHIZUKU-002",
  "HEX-SAF-DIR-001",
  "HEX-SAF-FILE-001",
  "HEX-SAF-GRANT-001",
  "HEX-SAF-PERM-001",
  "HEX-SAF-STREAM-001",
  "HEX-SAF-TARGET-001",
  "HEX-SAF-TREE-001",
  "HEX-SAF-WRITE-001",
  "HEX-SAF-WRITE-002",
  "HEX-SHIZUKU-DIR-001",
  "HEX-SHIZUKU-DIR-002",
  "HEX-SHIZUKU-PERM-001",
  "HEX-SHIZUKU-STATE-001",
  "HEX-SHIZUKU-WRITE-001",
  "HEX-UNKNOWN-001"
]);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return jsonResponse({
        ok: true,
        service: "hex-diagnostics-collector",
        version: 1
      }, 200);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: responseHeaders()
      });
    }

    if (url.pathname !== "/report") {
      return jsonResponse({ ok: false, error: "not_found" }, 404);
    }
    if (request.method !== "POST") {
      return jsonResponse({ ok: false, error: "method_not_allowed" }, 405);
    }

    try {
      assertEnvironment(env);

      const rateKey = request.headers.get("X-HEX-Rate-Key") || "";
      const userAgent = request.headers.get("User-Agent") || "";
      if (!/^[a-f0-9]{24,64}$/.test(rateKey)) {
        return jsonResponse({ ok: false, error: "invalid_client" }, 400);
      }
      if (!/^HEX-GFX\/[ -~]{1,64}$/.test(userAgent)) {
        return jsonResponse({ ok: false, error: "invalid_client" }, 400);
      }

      const limitResponse = await enforceRateLimits(env, rateKey);
      if (limitResponse) return limitResponse;

      const declaredLength = Number(request.headers.get("content-length") || 0);
      if (declaredLength > MAX_BODY_BYTES) {
        return jsonResponse({ ok: false, error: "payload_too_large" }, 413);
      }

      const bytes = await request.arrayBuffer();
      if (bytes.byteLength === 0 || bytes.byteLength > MAX_BODY_BYTES) {
        return jsonResponse({ ok: false, error: "invalid_payload_size" }, 413);
      }

      let raw;
      try {
        raw = JSON.parse(new TextDecoder().decode(bytes));
      } catch {
        return jsonResponse({ ok: false, error: "invalid_json" }, 400);
      }

      const report = validateReport(raw);
      if (!report) {
        return jsonResponse({ ok: false, error: "invalid_report" }, 422);
      }

      const result = await aggregateIntoGithub(env, report);
      return jsonResponse({
        ok: true,
        id: result.id,
        occurrences: result.occurrences,
        deduplicated: true
      }, 202);
    } catch (error) {
      console.error("diagnostics collector failure", safeErrorName(error));
      return jsonResponse({ ok: false, error: "collector_unavailable" }, 503);
    }
  }
};

async function enforceRateLimits(env, rateKey) {
  if (env.CLIENT_RATE_LIMITER && typeof env.CLIENT_RATE_LIMITER.limit === "function") {
    const client = await env.CLIENT_RATE_LIMITER.limit({ key: rateKey });
    if (!client.success) {
      return jsonResponse({ ok: false, error: "client_rate_limited" }, 429);
    }
  }

  if (env.GLOBAL_RATE_LIMITER && typeof env.GLOBAL_RATE_LIMITER.limit === "function") {
    const global = await env.GLOBAL_RATE_LIMITER.limit({ key: "hex-report" });
    if (!global.success) {
      return jsonResponse({ ok: false, error: "collector_rate_limited" }, 429);
    }
  }
  return null;
}

function assertEnvironment(env) {
  const owner = String(env.GITHUB_OWNER || "");
  const repo = String(env.GITHUB_REPO || "");
  const branch = String(env.GITHUB_BRANCH || "");
  const path = String(env.GITHUB_LOG_PATH || "");

  if (!env.GITHUB_TOKEN) throw new Error("missing_github_token");
  if (!/^[A-Za-z0-9_.-]{1,100}$/.test(owner)) throw new Error("invalid_owner");
  if (!/^[A-Za-z0-9_.-]{1,100}$/.test(repo)) throw new Error("invalid_repo");
  if (!/^[A-Za-z0-9_./-]{1,200}$/.test(branch)) throw new Error("invalid_branch");
  if (!/^[A-Za-z0-9_./-]{1,200}$/.test(path) || path.includes("..")) {
    throw new Error("invalid_log_path");
  }
}

function validateReport(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  if (Number(raw.schema_version) !== 1 || raw.event_type !== "failure") return null;

  const category = enumValue(raw.category, ["UNZIP", "PERMISSION"]);
  const backend = enumValue(raw.backend, ["SAF", "SHIZUKU", "LEGACY", "UNKNOWN"]);
  const accessMode = enumValue(
    raw.access_mode,
    ["PRIMARY", "SECONDARY", "SHIZUKU", "UNKNOWN"]
  );
  const source = enumValue(
    raw.source,
    ["CyberTaskManager", "PermissionHubManager"]
  );
  const code = cleanText(raw.code, 48);
  const stage = cleanText(raw.stage, 72);

  if (!category || !backend || !accessMode || !source) return null;
  if (!/^HEX-[A-Z0-9-]{5,44}$/.test(code)) return null;
  if (!ALLOWED_CODES.has(code)) return null;
  if (code.includes("CANCEL") || code.includes("ABORT")) return null;
  if (!/^[A-Z0-9_]{3,72}$/.test(stage)) return null;

  const sdk = boundedInteger(raw.sdk_int, 21, 60);
  const progress = boundedInteger(raw.progress, 0, 100);
  if (sdk === null || progress === null) return null;

  const title = cleanText(raw.title, 90);
  const message = cleanText(raw.message, 220);
  const manufacturer = cleanText(raw.manufacturer, 36) || "Unknown";
  const model = cleanText(raw.model, 56) || "Unknown";
  const androidRelease = cleanText(raw.android_release, 20) || "Unknown";
  const appVersion = cleanText(raw.app_version, 32) || "unknown";
  const exceptionType = cleanText(raw.exception_type, 64);
  if (!title || !message) return null;

  return {
    category,
    code,
    title,
    stage,
    backend,
    access_mode: accessMode,
    progress,
    message,
    exception_type: exceptionType,
    source,
    manufacturer,
    model,
    android_release: androidRelease,
    sdk_int: sdk,
    app_version: appVersion
  };
}

async function aggregateIntoGithub(env, report) {
  const id = (await sha256Hex(report.code)).slice(0, 20);
  let lastConflict = null;

  for (let attempt = 0; attempt < 4; attempt += 1) {
    const current = await readLogFile(env);
    const now = new Date().toISOString();
    const store = normalizeStore(current.data);
    const aggregated = aggregateReport(store, report, id, now);
    const content = JSON.stringify(store, null, 2) + "\n";

    const response = await writeLogFile(env, current.sha, content, report.code);
    if (response.ok) return aggregated;

    if (response.status !== 409) {
      throw new Error("github_write_" + response.status);
    }
    lastConflict = response.status;
    await wait(80 + Math.floor(Math.random() * 160));
  }

  throw new Error("github_conflict_" + String(lastConflict || "unknown"));
}

function normalizeStore(value) {
  const store = value && typeof value === "object" && !Array.isArray(value)
    ? value
    : {};
  if (!Array.isArray(store.reports)) store.reports = [];
  store.schema_version = 1;
  return store;
}

function aggregateReport(store, incoming, id, now) {
  let target = store.reports.find((item) => item && item.id === id);
  if (!target) {
    target = {
      id,
      code: incoming.code,
      title: incoming.title,
      category: incoming.category,
      source: incoming.source,
      stage: incoming.stage,
      backend: incoming.backend,
      message: incoming.message,
      occurrences: 0,
      first_seen: now,
      last_seen: now,
      latest: {},
      access_modes: {},
      devices: [],
      android_versions: [],
      app_versions: []
    };
    store.reports.push(target);
  }

  target.code = incoming.code;
  target.title = incoming.title;
  target.category = incoming.category;
  target.source = incoming.source;
  target.stage = incoming.stage;
  target.backend = incoming.backend;
  target.message = incoming.message;
  target.occurrences = safeCount(target.occurrences) + 1;
  target.first_seen = validDate(target.first_seen) ? target.first_seen : now;
  target.last_seen = now;
  target.latest = {
    access_mode: incoming.access_mode,
    progress: incoming.progress,
    manufacturer: incoming.manufacturer,
    model: incoming.model,
    android_release: incoming.android_release,
    sdk_int: incoming.sdk_int,
    app_version: incoming.app_version,
    exception_type: incoming.exception_type,
    received_at: now
  };

  if (!target.access_modes || typeof target.access_modes !== "object"
      || Array.isArray(target.access_modes)) {
    target.access_modes = {};
  }
  target.access_modes[incoming.access_mode] =
    safeCount(target.access_modes[incoming.access_mode]) + 1;

  target.devices = bumpDimension(
    target.devices,
    { manufacturer: incoming.manufacturer, model: incoming.model },
    ["manufacturer", "model"],
    now,
    MAX_DEVICE_SAMPLES
  );
  target.android_versions = bumpDimension(
    target.android_versions,
    { android_release: incoming.android_release, sdk_int: incoming.sdk_int },
    ["android_release", "sdk_int"],
    now,
    MAX_ANDROID_SAMPLES
  );
  target.app_versions = bumpDimension(
    target.app_versions,
    { app_version: incoming.app_version },
    ["app_version"],
    now,
    MAX_APP_VERSIONS
  );

  store.updated_at = now;
  store.reports.sort((a, b) => dateNumber(b && b.last_seen) - dateNumber(a && a.last_seen));
  if (store.reports.length > MAX_REPORTS) {
    store.reports.length = MAX_REPORTS;
  }
  return target;
}

function bumpDimension(items, values, keyFields, now, max) {
  const list = Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  const key = dimensionKey(values, keyFields);
  let item = list.find((candidate) => dimensionKey(candidate, keyFields) === key);
  if (!item) {
    item = { ...values, count: 0, last_seen: now };
    list.push(item);
  }
  Object.assign(item, values);
  item.count = safeCount(item.count) + 1;
  item.last_seen = now;
  list.sort((a, b) => {
    const countDifference = safeCount(b.count) - safeCount(a.count);
    return countDifference || dateNumber(b.last_seen) - dateNumber(a.last_seen);
  });
  return list.slice(0, max);
}

function dimensionKey(value, fields) {
  return fields.map((field) => String(value && value[field] == null ? "" : value[field]))
    .join("|")
    .toLowerCase();
}

async function readLogFile(env) {
  const endpoint = githubContentEndpoint(env);
  const response = await fetch(endpoint + "?ref=" + encodeURIComponent(env.GITHUB_BRANCH), {
    headers: githubHeaders(env)
  });

  if (response.status === 404) {
    return {
      sha: null,
      data: { schema_version: 1, updated_at: null, reports: [] }
    };
  }
  if (!response.ok) throw new Error("github_read_" + response.status);

  const body = await response.json();
  if (!body || body.type !== "file" || typeof body.content !== "string") {
    throw new Error("github_invalid_content");
  }

  let data;
  try {
    data = JSON.parse(decodeBase64(body.content));
  } catch {
    throw new Error("github_invalid_json");
  }
  return { sha: body.sha || null, data };
}

async function writeLogFile(env, sha, content, code) {
  const body = {
    message: "diagnostics: aggregate " + code,
    content: encodeBase64(content),
    branch: env.GITHUB_BRANCH
  };
  if (sha) body.sha = sha;

  return fetch(githubContentEndpoint(env), {
    method: "PUT",
    headers: {
      ...githubHeaders(env),
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });
}

function githubContentEndpoint(env) {
  const owner = encodeURIComponent(env.GITHUB_OWNER);
  const repo = encodeURIComponent(env.GITHUB_REPO);
  const path = String(env.GITHUB_LOG_PATH)
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
  return "https://api.github.com/repos/" + owner + "/" + repo + "/contents/" + path;
}

function githubHeaders(env) {
  return {
    Accept: "application/vnd.github+json",
    Authorization: "Bearer " + env.GITHUB_TOKEN,
    "User-Agent": "hex-diagnostics-collector",
    "X-GitHub-Api-Version": GITHUB_API_VERSION
  };
}

function encodeBase64(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function decodeBase64(value) {
  const binary = atob(String(value).replace(/\s/g, ""));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function cleanText(value, max) {
  return String(value == null ? "" : value)
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}

function enumValue(value, allowed) {
  const normalized = cleanText(value, 72);
  return allowed.includes(normalized) ? normalized : "";
}

function boundedInteger(value, min, max) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) return null;
  return number;
}

function safeCount(value) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0) return 0;
  return Math.min(Math.floor(number), Number.MAX_SAFE_INTEGER - 1);
}

function validDate(value) {
  return Number.isFinite(Date.parse(String(value || "")));
}

function dateNumber(value) {
  const number = Date.parse(String(value || ""));
  return Number.isFinite(number) ? number : 0;
}

function safeErrorName(error) {
  if (!error) return "unknown";
  return cleanText(error.message || error.name || "unknown", 80);
}

function responseHeaders() {
  return {
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer"
  };
}

function jsonResponse(value, status) {
  return new Response(JSON.stringify(value), {
    status,
    headers: responseHeaders()
  });
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
