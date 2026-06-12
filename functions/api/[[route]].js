/**
 * Overture Portfolio Support Tracker — API layer
 * Cloudflare Pages Function (drop this file into functions/api/ in the repo)
 *
 * Routes (all same-origin, automatically behind the Cloudflare Access policy):
 *   GET  /api/tasks            -> all rows from the tasks tab (first row treated as headers)
 *   POST /api/tasks            -> append a row.  Body: { "values": ["col A", "col B", ...] }
 *   PUT  /api/tasks/:rowNumber -> overwrite a row (1-indexed, as shown in Sheets).
 *                                 Body: { "values": ["col A", "col B", ...] }
 *
 * Required environment variables (Pages project > Settings > Variables and Secrets):
 *   SHEET_ID             - the Google Sheet ID
 *   SHEET_TAB            - tab name holding tasks (e.g. "Tasks")
 *   GOOGLE_CLIENT_EMAIL  - service account email (xxx@xxx.iam.gserviceaccount.com)
 *   GOOGLE_PRIVATE_KEY   - service account private key (paste the full PEM; \n escapes are handled)
 *
 * The service account email must be shared on the Sheet as an Editor.
 * No credentials ever reach the browser.
 */

// ---- Google auth: exchange a signed JWT for a short-lived access token ----

let cachedToken = null; // { token, expiresAt } cached per isolate

async function getAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && cachedToken.expiresAt - 60 > now) return cachedToken.token;

  const header = { alg: "RS256", typ: "JWT" };
  const claims = {
    iss: env.GOOGLE_CLIENT_EMAIL,
    scope: "https://www.googleapis.com/auth/spreadsheets",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };

  const enc = (obj) => b64url(new TextEncoder().encode(JSON.stringify(obj)));
  const unsigned = `${enc(header)}.${enc(claims)}`;

  const key = await importPrivateKey(env.GOOGLE_PRIVATE_KEY);
  const sig = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    key,
    new TextEncoder().encode(unsigned)
  );
  const jwt = `${unsigned}.${b64url(new Uint8Array(sig))}`;

  const resp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });
  if (!resp.ok) throw new Error(`Token exchange failed: ${await resp.text()}`);
  const data = await resp.json();
  cachedToken = { token: data.access_token, expiresAt: now + data.expires_in };
  return cachedToken.token;
}

async function importPrivateKey(pem) {
  const cleaned = pem
    .replace(/\\n/g, "\n")
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s/g, "");
  const binary = Uint8Array.from(atob(cleaned), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "pkcs8",
    binary.buffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

function b64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---- Sheets helpers ----

const SHEETS_BASE = "https://sheets.googleapis.com/v4/spreadsheets";

async function sheetsFetch(env, path, options = {}) {
  const token = await getAccessToken(env);
  const resp = await fetch(`${SHEETS_BASE}/${env.SHEET_ID}/${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  if (!resp.ok) throw new Error(`Sheets API ${resp.status}: ${await resp.text()}`);
  return resp.json();
}

function columnLetter(n) {
  let s = "";
  while (n > 0) {
    const m = (n - 1) % 26;
    s = String.fromCharCode(65 + m) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

// ---- Request handling ----

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });

export async function onRequest(context) {
  const { request, env, params } = context;
  const route = params.route || []; // e.g. ["tasks"] or ["tasks", "7"]

  try {
    if (route[0] !== "tasks") return json({ error: "Not found" }, 404);

    const tab = env.SHEET_TAB || "Tasks";

    // GET /api/tasks
    if (request.method === "GET" && route.length === 1) {
      const data = await sheetsFetch(
        env,
        `values/${encodeURIComponent(tab)}!A:Z`
      );
      const rows = data.values || [];
      const headers = rows[0] || [];
      const tasks = rows.slice(1).map((r, i) => ({
        row: i + 2, // 1-indexed sheet row number
        values: r,
      }));
      return json({ headers, tasks });
    }

    // POST /api/tasks  { values: [...] }
    if (request.method === "POST" && route.length === 1) {
      const body = await request.json();
      if (!Array.isArray(body.values))
        return json({ error: "Body must include a 'values' array" }, 400);
      const result = await sheetsFetch(
        env,
        `values/${encodeURIComponent(tab)}!A:Z:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS`,
        { method: "POST", body: JSON.stringify({ values: [body.values] }) }
      );
      return json({ ok: true, updatedRange: result.updates?.updatedRange });
    }

    // PUT /api/tasks/:row  { values: [...] }
    if (request.method === "PUT" && route.length === 2) {
      const rowNum = parseInt(route[1], 10);
      if (!Number.isInteger(rowNum) || rowNum < 2)
        return json({ error: "Row must be an integer >= 2" }, 400);
      const body = await request.json();
      if (!Array.isArray(body.values))
        return json({ error: "Body must include a 'values' array" }, 400);
      const lastCol = columnLetter(Math.max(body.values.length, 1));
      await sheetsFetch(
        env,
        `values/${encodeURIComponent(tab)}!A${rowNum}:${lastCol}${rowNum}?valueInputOption=USER_ENTERED`,
        {
          method: "PUT",
          body: JSON.stringify({ values: [body.values] }),
        }
      );
      return json({ ok: true, row: rowNum });
    }

    return json({ error: "Method not allowed" }, 405);
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}
