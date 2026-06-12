/**
 * Overture Portfolio Support Tracker — API layer (v2)
 * Cloudflare Pages Function: functions/api/[[route]].js
 *
 * Routes (same-origin, behind Cloudflare Access):
 *   GET    /api/tasks?tab=Tasks        -> { headers, rows } (rows exclude header row)
 *   POST   /api/tasks?tab=Tasks        -> append rows. Body: { "values": [[...], ...] }
 *   PUT    /api/tasks/:row?tab=Tasks   -> overwrite a row (1-indexed sheet row >= 2).
 *                                         Body: { "values": [...] }
 *   DELETE /api/tasks/:row?tab=Tasks   -> delete a row entirely (shifts rows up)
 *   POST   /api/ensure                 -> create tab if missing + fix header row.
 *                                         Body: { "tab": "...", "headers": [...] }
 *
 * Allowed tabs: "Tasks" and "Archive" only.
 *
 * Required environment variables (Pages > Settings > Variables and Secrets):
 *   SHEET_ID, GOOGLE_CLIENT_EMAIL, GOOGLE_PRIVATE_KEY
 *   (SHEET_TAB optional; default tab when ?tab= omitted is "Tasks")
 */

const ALLOWED_TABS = ["Tasks", "Archive"];

// ---- Google auth: signed JWT -> short-lived access token ----

let cachedToken = null;

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

async function getSheetIdByTitle(env, title) {
  const meta = await sheetsFetch(env, "?fields=sheets.properties");
  const match = (meta.sheets || []).find((s) => s.properties.title === title);
  return match ? match.properties.sheetId : null;
}

// ---- Request handling ----

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });

function resolveTab(request, env) {
  const url = new URL(request.url);
  const tab = url.searchParams.get("tab") || env.SHEET_TAB || "Tasks";
  if (!ALLOWED_TABS.includes(tab)) return null;
  return tab;
}

export async function onRequest(context) {
  const { request, env, params } = context;
  const route = params.route || []; // ["tasks"], ["tasks","7"], or ["ensure"]

  try {
    // POST /api/ensure  { tab, headers }
    if (route[0] === "ensure" && request.method === "POST") {
      const body = await request.json();
      const tab = body.tab;
      if (!ALLOWED_TABS.includes(tab)) return json({ error: "Invalid tab" }, 400);
      const headers = Array.isArray(body.headers) ? body.headers : [];

      let sheetId = await getSheetIdByTitle(env, tab);
      if (sheetId === null) {
        await sheetsFetch(env, ":batchUpdate", {
          method: "POST",
          body: JSON.stringify({
            requests: [{ addSheet: { properties: { title: tab } } }],
          }),
        });
      }
      if (headers.length) {
        const data = await sheetsFetch(
          env,
          `values/${encodeURIComponent(tab)}!A1:${columnLetter(headers.length)}1`
        ).catch(() => ({}));
        const existing = (data.values && data.values[0]) || [];
        const needsRewrite =
          !existing[0] ||
          existing[0] !== headers[0] ||
          existing.length < headers.length;
        if (needsRewrite) {
          await sheetsFetch(
            env,
            `values/${encodeURIComponent(tab)}!A1:${columnLetter(headers.length)}1?valueInputOption=RAW`,
            { method: "PUT", body: JSON.stringify({ values: [headers] }) }
          );
        }
      }
      return json({ ok: true, tab });
    }

    if (route[0] !== "tasks") return json({ error: "Not found" }, 404);

    const tab = resolveTab(request, env);
    if (!tab) return json({ error: "Invalid tab" }, 400);

    // GET /api/tasks?tab=
    if (request.method === "GET" && route.length === 1) {
      const data = await sheetsFetch(
        env,
        `values/${encodeURIComponent(tab)}!A:Z`
      );
      const all = data.values || [];
      const headers = all[0] || [];
      const rows = all.slice(1);
      return json({ headers, rows });
    }

    // POST /api/tasks?tab=  { values: [[...], ...] }  (append one or many rows)
    if (request.method === "POST" && route.length === 1) {
      const body = await request.json();
      if (!Array.isArray(body.values) || !body.values.length)
        return json({ error: "Body must include a non-empty 'values' array" }, 400);
      // Accept either a single row (flat array) or an array of rows.
      const rows = Array.isArray(body.values[0]) ? body.values : [body.values];
      const result = await sheetsFetch(
        env,
        `values/${encodeURIComponent(tab)}!A:Z:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`,
        { method: "POST", body: JSON.stringify({ values: rows }) }
      );
      return json({ ok: true, updatedRange: result.updates?.updatedRange });
    }

    // PUT /api/tasks/:row?tab=  { values: [...] }
    if (request.method === "PUT" && route.length === 2) {
      const rowNum = parseInt(route[1], 10);
      if (!Number.isInteger(rowNum) || rowNum < 2)
        return json({ error: "Row must be an integer >= 2" }, 400);
      const body = await request.json();
      if (!Array.isArray(body.values))
        return json({ error: "Body must include a 'values' array" }, 400);
      const values = Array.isArray(body.values[0]) ? body.values[0] : body.values;
      const lastCol = columnLetter(Math.max(values.length, 1));
      await sheetsFetch(
        env,
        `values/${encodeURIComponent(tab)}!A${rowNum}:${lastCol}${rowNum}?valueInputOption=RAW`,
        { method: "PUT", body: JSON.stringify({ values: [values] }) }
      );
      return json({ ok: true, row: rowNum });
    }

    // DELETE /api/tasks/:row?tab=
    if (request.method === "DELETE" && route.length === 2) {
      const rowNum = parseInt(route[1], 10);
      if (!Number.isInteger(rowNum) || rowNum < 2)
        return json({ error: "Row must be an integer >= 2" }, 400);
      const sheetId = await getSheetIdByTitle(env, tab);
      if (sheetId === null) return json({ error: "Tab not found" }, 404);
      await sheetsFetch(env, ":batchUpdate", {
        method: "POST",
        body: JSON.stringify({
          requests: [
            {
              deleteDimension: {
                range: {
                  sheetId,
                  dimension: "ROWS",
                  startIndex: rowNum - 1,
                  endIndex: rowNum,
                },
              },
            },
          ],
        }),
      });
      return json({ ok: true, deleted: rowNum });
    }

    return json({ error: "Method not allowed" }, 405);
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}
