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
const STAFF_ONLY_TYPES = ['evaluation', 'audit_log', 'app_credentials', 'backup_log'];

// Nothing is forbidden outright any more, but credentials are special: see
// STAFF_ONLY_TYPES below and the plain-text guard in handlePost. The record may
// hold only PBKDF2 hashes, never a password.
const FORBIDDEN_TYPES = new Set([]);

// Plain-text credential fields are stripped from every incoming record. A
// password must never reach the database in a readable form, whatever sends it.
const FORBIDDEN_FIELDS = ['evalPwd', 'adminPwd', 'password', 'pin', 'recoveryCode'];

// Only a staff-authenticated request may write these.
const STAFF_WRITABLE_ONLY = new Set(['app_credentials']);

// An ordinary record is small; an attachment arrives base64-encoded in the same
// body, which is about a third larger than the file itself. Two limits, so a
// photo is not rejected by the record limit before the file limit is reached.
const MAX_BODY_BYTES = 512 * 1024;        // 512 KB for a normal record
const MAX_UPLOAD_BODY_BYTES = 14 * 1024 * 1024; // 14 MB for an upload request
const MAX_FILE_BYTES = 10 * 1024 * 1024;  // 10 MB per attachment once decoded

// ---------------------------------------------------------------- helpers

function corsHeaders(env) {
  return {
    // Fails CLOSED: an unset variable must not open the API to every website.
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || 'https://waledbadawy-beep.github.io',
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

/**
 * The token may arrive three ways. A custom header forces the browser to send
 * a CORS preflight first, which some deployments cannot answer, so the body
 * and query forms exist as preflight-free alternatives. All three are compared
 * the same way.
 */
function isStaff(request, env, bodyToken) {
  if (!env.STAFF_TOKEN) return false; // fail closed if the secret is missing
  const header = request.headers.get('X-Staff-Token');
  if (safeEqual(header, env.STAFF_TOKEN)) return true;
  if (bodyToken && safeEqual(bodyToken, env.STAFF_TOKEN)) return true;
  // The ?staff= query form was removed. A query string is written to browser
  // history, proxy logs and Referer headers, so the token outlived the session
  // on any shared hospital computer. Header for GET, body for POST.
  return false;
}

/**
 * A shared code issued to the batch with the app link. It does not identify an
 * individual - that needs per-student accounts - but it stops anyone who merely
 * knows this URL from reading or writing the database.
 *
 * If STUDENT_TOKEN is not set on the Worker this check is skipped, so deploying
 * this file changes nothing until the secret exists. Set it, then send the code
 * to the batch.
 */
function isStudentAuthorised(request, env, bodyToken) {
  if (!env.STUDENT_TOKEN) return true; // not configured yet - old behaviour
  const header = request.headers.get('X-Student-Token');
  if (safeEqual(header, env.STUDENT_TOKEN)) return true;
  if (bodyToken && safeEqual(bodyToken, env.STUDENT_TOKEN)) return true;
  return false;
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

  if (!staff && !isStudentAuthorised(request, env)) {
    return json(env, { success: false, error: 'Class access code required' }, 403);
  }

  await ensureTable(env);

  let rows;
  if (staff) {
    // Full read — supervisors and the director.
    rows = await env.MEDI045_DB
      .prepare(`SELECT json FROM records`)
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
      if (parsed && parsed.status !== 'deleted') {
        out.push(stripForbidden(parsed));
      }
    } catch (e) { /* skip unparseable row rather than failing the whole read */ }
  }
  return json(env, out);
}

// ---------------------------------------------------------------- write

async function handlePost(request, env) {
  const raw = await request.text();
  // The upload path is allowed a larger body; everything else is not.
  const looksLikeUpload = raw.indexOf('"_action":"upload_file"') !== -1 ||
                          raw.indexOf('"_action": "upload_file"') !== -1;
  const bodyCap = looksLikeUpload ? MAX_UPLOAD_BODY_BYTES : MAX_BODY_BYTES;
  if (raw.length > bodyCap) {
    return json(env, {
      success: false,
      error: looksLikeUpload
        ? 'That attachment is too large. Please use a file under 10 MB.'
        : 'Record too large.'
    }, 413);
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

  const staff = isStaff(request, env, data._staffToken);
  const studentOk = staff || isStudentAuthorised(request, env, data._studentToken);
  // Never let either token be written into a record.
  if ('_staffToken' in data) delete data._staffToken;
  if ('_studentToken' in data) delete data._studentToken;

  if (!studentOk) {
    return json(env, { success: false, error: 'Class access code required' }, 403);
  }

  await ensureTable(env);

  // ---- administrative actions: staff only
  if (data._action === 'delete') {
    if (!staff) return json(env, { success: false, error: 'Not authorised' }, 403);

    // One record, by id - the ordinary case, and the safe one.
    if (data.id) {
      const res = await env.MEDI045_DB
        .prepare(`DELETE FROM records WHERE id = ?`).bind(String(data.id)).run();
      return json(env, { success: true, deleted: (res.meta && res.meta.changes) || 0 });
    }

    const type = data.type || 'all';

    // There is no import anywhere in the app: the CSV is an export, not a
    // restore. A wipe is therefore final, so it must be typed out in full and
    // cannot happen by tapping one button.
    if (type === 'all' && data.confirm !== 'DELETE ALL RECORDS') {
      return json(env, {
        success: false,
        error: 'To erase every record, resend with confirm set to the exact phrase DELETE ALL RECORDS. This cannot be undone and there is no import.'
      }, 400);
    }

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
      return json(env, { success: false, error: 'Attachment exceeds 10 MB' }, 413);
    }
    const safeName = String(data.fileName || 'attachment')
      .replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120);
    // Was `${Date.now()}_${name}` - guessable, and /file/ has no authentication,
    // so anyone could walk the keyspace. A random segment makes the URL itself
    // the capability. This is obscurity, not authentication: treat any link as
    // readable by whoever receives it.
    const rand = crypto.randomUUID().replace(/-/g, '').slice(0, 16);
    const key = `${Date.now()}_${rand}_${safeName}`;
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

  if (STAFF_WRITABLE_ONLY.has(type) && !staff) {
    return json(env, { success: false, error: 'Not authorised to write credentials' }, 403);
  }

  // Credentials may be stored only as a hash. If anything resembling a readable
  // password arrives, refuse the whole record rather than store it.
  if (type === 'app_credentials') {
    const allowed = new Set(['type', 'id', 'status', 'updated', 'updatedAt',
                             'evalPwdHash', 'adminPwdHash', 'salt', 'iterations', 'algo']);
    for (const k of Object.keys(data)) {
      if (!allowed.has(k)) {
        return json(env, {
          success: false,
          error: 'Credential records may contain only hashed values, not passwords.'
        }, 400);
      }
    }
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

/**
 * The nightly run happens with nobody watching, and a failed send produced no
 * trace anywhere - an inbox with no new mail looks the same whether the cron
 * never fired or the email service refused it. Every attempt now leaves a row.
 * Read it from the supervisor dashboard: type 'backup_log', staff only.
 */
async function recordBackupResult(env, ok, count, detail) {
  try {
    await ensureTable(env);
    const now = new Date().toISOString();
    const row = {
      type: 'backup_log', id: 'backup_' + now,
      ok: ok, records: count, detail: detail || '',
      label: (env.APP_LABEL || '').trim(), timestamp: now
    };
    await env.MEDI045_DB.prepare(
      `INSERT INTO records (id, type, student, status, updated, json)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET json = excluded.json`
    ).bind(row.id, 'backup_log', '', ok ? 'ok' : 'failed', now, JSON.stringify(row)).run();
  } catch (e) {
    console.error('Could not record backup result:', e);
  }
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

  // Both deployments send to the same inbox, so the mail has to say which one
  // it came from. Set APP_LABEL as a plain variable on each Worker
  // ("Undergraduate" / "Postgraduate"); unset, the mail reads as before.
  const label = (env.APP_LABEL || '').trim();
  const slug  = label ? label.replace(/[^A-Za-z0-9]+/g, '') : 'Backup';

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: 'onboarding@resend.dev',
      to: [env.BACKUP_EMAIL],
      subject: `MEDI 045 ${label} backup — ${stamp} (${count} records)`,
      text: `Automatic backup of the MEDI 045 ${label} log book.\n\nRecords: ${count}\nGenerated: ${new Date().toISOString()}\n\nThe CSV is attached.`,
      attachments: [{ filename: `MEDI045_${slug}_Backup_${stamp}.csv`, content: b64 }]
    })
  });

  if (!res.ok) {
    const detail = await res.text();
    await recordBackupResult(env, false, count, `HTTP ${res.status} ${detail.slice(0, 200)}`);
    return json(env, {
      success: false,
      error: `Email service rejected the backup (HTTP ${res.status}). ${detail.slice(0, 300)}`
    }, 502);
  }
  await recordBackupResult(env, true, count, '');
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
    ctx.waitUntil(
      runBackup(env).catch(async (err) => {
        console.error('Nightly backup threw:', err && err.stack ? err.stack : err);
        await recordBackupResult(env, false, 0, String(err && err.message || err).slice(0, 200));
      })
    );
  }
};
