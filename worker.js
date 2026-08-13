/**
 * MEDI 045 — Cloudflare Worker backend
 * ---------------------------------------------------------------------------
 * Replaces the original Worker, which inherited the Apps Script design where
 * every endpoint was open. Three things changed:
 *
 *   1. Credentials are never stored. Records of type 'app_credentials' are
 *      rejected on write and filtered on read, so the admin password can no
 *      longer be served to anyone who opens this URL.
 *   2. Reads are scoped. A student may read only their own records plus the
 *      public config (announcements, batch window, grading rules). Reading
 *      everything requires the staff token.
 *   3. Destructive and administrative actions require the staff token:
 *      delete, backup_now, file upload, and writes of admin record types.
 *
 * Bindings required (Settings -> Bindings):
 *   MEDI045_DB     D1 database    medi045-db
 *   MEDI045_FILES  R2 bucket      medi045-files
 *
 * Variables and Secrets required (Settings -> Variables and Secrets):
 *   STAFF_TOKEN      Secret  long random string; given to supervisors once
 *   RESEND_API_KEY   Secret  email service key
 *   BACKUP_EMAIL     Text    address the backup CSV is sent to
 *   ALLOWED_ORIGIN   Text    e.g. https://waledbadawy-beep.github.io
 *
 * Table (unchanged):
 *   records(id TEXT PRIMARY KEY, type TEXT, student TEXT, status TEXT,
 *           updated TEXT, json TEXT)
 */

// Record types a student may create or update without the staff token.
const STUDENT_WRITABLE = new Set([
  'clinic', 'intraop', 'pacu', 'ward', 'case', 'airway',
  'survey', 'skill_log', 'student_profile'
]);

// Record types every student needs to read.
const PUBLIC_CONFIG = new Set([
  'announcement', 'batch_config', 'grading_config', 'supervisor_list'
]);

// Types a student must never receive, even for their own records. Marks are
// released by the programme, not read out of the app before moderation.
const STAFF_ONLY_TYPES = ['evaluation', 'audit_log'];

// Never stored, never returned, under any circumstances.
const FORBIDDEN_TYPES = new Set(['app_credentials']);

// Field names stripped from every incoming record as a second line of defence.
const FORBIDDEN_FIELDS = ['evalPwd', 'adminPwd', 'password', 'pin', 'recoveryCode'];

const MAX_BODY_BYTES = 512 * 1024;   // 512 KB per record
const MAX_FILE_BYTES = 8 * 1024 * 1024; // 8 MB per attachment

// ---------------------------------------------------------------- helpers

function corsHeaders(env) {
  return {
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Staff-Token',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}

function json(env, obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...corsHeaders(env) }
  });
}

/**
 * Constant-time string comparison. A plain === leaks the token a character at
 * a time through timing, which matters for a value an attacker can guess at.
 */
function safeEqual(a, b) {
  const x = String(a || '');
  const y = String(b || '');
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}

function isStaff(request, env) {
  if (!env.STAFF_TOKEN) return false; // fail closed if the secret is missing
  const header = request.headers.get('X-Staff-Token');
  return safeEqual(header, env.STAFF_TOKEN);
}

function stripForbidden(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  for (const f of FORBIDDEN_FIELDS) {
    if (f in obj) delete obj[f];
  }
  return obj;
}

async function ensureTable(env) {
  await env.MEDI045_DB.prepare(
    `CREATE TABLE IF NOT EXISTS records (
       id TEXT PRIMARY KEY, type TEXT, student TEXT,
       status TEXT, updated TEXT, json TEXT
     )`
  ).run();
}

// ---------------------------------------------------------------- read

async function handleGet(request, env) {
  const url = new URL(request.url);
  const staff = isStaff(request, env);
  const sid = (url.searchParams.get('sid') || '').trim();

  await ensureTable(env);

  let rows;
  if (staff) {
    // Full read — supervisors and the director.
    rows = await env.MEDI045_DB
      .prepare(`SELECT json FROM records WHERE type NOT IN ('app_credentials')`)
      .all();
  } else if (sid) {
    // Scoped read — this student's own records, plus shared config.
    const placeholders = [...PUBLIC_CONFIG].map(() => '?').join(',');
    const staffOnly = STAFF_ONLY_TYPES.map(() => '?').join(',');
    rows = await env.MEDI045_DB
      .prepare(
        `SELECT json FROM records
          WHERE type NOT IN ('app_credentials')
            AND type NOT IN (${staffOnly})
            AND (student = ? OR type IN (${placeholders}))`
      )
      .bind(...STAFF_ONLY_TYPES, sid, ...PUBLIC_CONFIG)
      .all();
  } else {
    // No token and no student id — return only what is public to everyone.
    const placeholders = [...PUBLIC_CONFIG].map(() => '?').join(',');
    rows = await env.MEDI045_DB
      .prepare(`SELECT json FROM records WHERE type IN (${placeholders})`)
      .bind(...PUBLIC_CONFIG)
      .all();
  }

  const out = [];
  for (const r of (rows.results || [])) {
    try {
      const parsed = JSON.parse(r.json);
      if (parsed && !FORBIDDEN_TYPES.has(parsed.type) && parsed.status !== 'deleted') {
        out.push(stripForbidden(parsed));
      }
    } catch (e) { /* skip unparseable row rather than failing the whole read */ }
  }
  return json(env, out);
}

// ---------------------------------------------------------------- write

async function handlePost(request, env) {
  const staff = isStaff(request, env);

  const raw = await request.text();
  if (raw.length > MAX_BODY_BYTES) {
    return json(env, { success: false, error: 'Payload too large' }, 413);
  }

  let data;
  try {
    data = JSON.parse(raw);
  } catch (e) {
    return json(env, { success: false, error: 'Malformed JSON' }, 400);
  }
  if (!data || typeof data !== 'object') {
    return json(env, { success: false, error: 'Malformed record' }, 400);
  }

  await ensureTable(env);

  // ---- administrative actions: staff only
  if (data._action === 'delete') {
    if (!staff) return json(env, { success: false, error: 'Not authorised' }, 403);
    const type = data.type || 'all';
    const res = type === 'all'
      ? await env.MEDI045_DB.prepare(`DELETE FROM records`).run()
      : await env.MEDI045_DB.prepare(`DELETE FROM records WHERE type = ?`).bind(type).run();
    return json(env, { success: true, deleted: (res.meta && res.meta.changes) || 0 });
  }

  if (data._action === 'upload_file') {
    if (!staff) return json(env, { success: false, error: 'Not authorised' }, 403);
    if (!env.MEDI045_FILES) {
      return json(env, { success: false, error: 'File storage is not bound to this Worker' }, 500);
    }
    let bytes;
    try {
      const bin = atob(data.base64 || '');
      bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    } catch (e) {
      return json(env, { success: false, error: 'Attachment is not valid base64' }, 400);
    }
    if (bytes.length > MAX_FILE_BYTES) {
      return json(env, { success: false, error: 'Attachment exceeds 8 MB' }, 413);
    }
    const safeName = String(data.fileName || 'attachment')
      .replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120);
    const key = `${Date.now()}_${safeName}`;
    await env.MEDI045_FILES.put(key, bytes, {
      httpMetadata: { contentType: data.mimeType || 'application/octet-stream' }
    });
    const url = new URL(request.url);
    return json(env, {
      success: true,
      url: `${url.origin}/file/${encodeURIComponent(key)}`,
      fileName: safeName
    });
  }

  if (data._action === 'backup_now') {
    if (!staff) return json(env, { success: false, error: 'Not authorised' }, 403);
    return await runBackup(env);
  }

  // ---- ordinary record upsert
  const type = String(data.type || '');

  if (FORBIDDEN_TYPES.has(type)) {
    return json(env, {
      success: false,
      error: 'Credentials are not stored on the server. Passwords are held on the device only.'
    }, 403);
  }

  if (!staff && !STUDENT_WRITABLE.has(type)) {
    return json(env, { success: false, error: 'Not authorised to write this record type' }, 403);
  }

  stripForbidden(data);

  const id = String(data.id || '');
  if (!id) return json(env, { success: false, error: 'Record id is required' }, 400);

  const updated = new Date().toISOString();
  data.updated = updated;

  await env.MEDI045_DB.prepare(
    `INSERT INTO records (id, type, student, status, updated, json)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       type = excluded.type, student = excluded.student,
       status = excluded.status, updated = excluded.updated, json = excluded.json`
  ).bind(
    id,
    type,
    String(data.studentId || data.sid || data.studentName || data.student || ''),
    String(data.status || ''),
    updated,
    JSON.stringify(data)
  ).run();

  return json(env, { success: true, updated });
}

// ---------------------------------------------------------------- files

async function handleFile(request, env, key) {
  if (!env.MEDI045_FILES) return new Response('File storage not bound', { status: 500 });
  const obj = await env.MEDI045_FILES.get(key);
  if (!obj) return new Response('Not found', { status: 404 });
  const headers = new Headers(corsHeaders(env));
  obj.writeHttpMetadata(headers);
  headers.set('Cache-Control', 'private, max-age=3600');
  return new Response(obj.body, { headers });
}

// ---------------------------------------------------------------- backup

function csvCell(v) {
  let s = String(v == null ? '' : v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // neutralise spreadsheet formulas
  return '"' + s.replace(/"/g, '""') + '"';
}

async function buildBackupCsv(env) {
  await ensureTable(env);
  const rows = await env.MEDI045_DB
    .prepare(`SELECT id, type, student, status, updated, json FROM records
               WHERE type NOT IN ('app_credentials') ORDER BY type, updated`)
    .all();

  let csv = 'id,type,student,status,updated,json\n';
  for (const r of (rows.results || [])) {
    csv += [r.id, r.type, r.student, r.status, r.updated, r.json].map(csvCell).join(',') + '\n';
  }
  return { csv, count: (rows.results || []).length };
}

async function runBackup(env) {
  if (!env.RESEND_API_KEY) {
    return json(env, { success: false, error: 'Email key is not configured on the Worker' }, 500);
  }
  if (!env.BACKUP_EMAIL) {
    return json(env, { success: false, error: 'Backup address is not configured on the Worker' }, 500);
  }

  const { csv, count } = await buildBackupCsv(env);
  const stamp = new Date().toISOString().slice(0, 10);

  // base64-encode the CSV as UTF-8 for the attachment
  const utf8 = new TextEncoder().encode('\ufeff' + csv);
  let binary = '';
  for (let i = 0; i < utf8.length; i++) binary += String.fromCharCode(utf8[i]);
  const b64 = btoa(binary);

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: 'onboarding@resend.dev',
      to: [env.BACKUP_EMAIL],
      subject: `MEDI 045 backup — ${stamp} (${count} records)`,
      text: `Automatic backup of the MEDI 045 log book.\n\nRecords: ${count}\nGenerated: ${new Date().toISOString()}\n\nThe CSV is attached.`,
      attachments: [{ filename: `MEDI045_Backup_${stamp}.csv`, content: b64 }]
    })
  });

  if (!res.ok) {
    const detail = await res.text();
    return json(env, {
      success: false,
      error: `Email service rejected the backup (HTTP ${res.status}). ${detail.slice(0, 300)}`
    }, 502);
  }
  return json(env, { success: true, records: count, sentTo: env.BACKUP_EMAIL });
}

// ---------------------------------------------------------------- entry

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    if (url.pathname.startsWith('/file/')) {
      return handleFile(request, env, decodeURIComponent(url.pathname.slice(6)));
    }

    if (url.pathname === '/health') {
      return json(env, { ok: true, time: new Date().toISOString() });
    }

    try {
      if (request.method === 'GET') return await handleGet(request, env);
      if (request.method === 'POST') return await handlePost(request, env);
      return json(env, { success: false, error: 'Method not allowed' }, 405);
    } catch (err) {
      // Log the detail, return a generic message — internal errors should not
      // describe the database to whoever triggered them.
      console.error('Worker error:', err && err.stack ? err.stack : err);
      return json(env, { success: false, error: 'Server error' }, 500);
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(runBackup(env));
  }
};
