// Loopback HTTP console and API (contract sections 2 and 8 to 12). Every route
// answers from stored state; none waits for a Peerspan subprocess.
import { createServer } from 'node:http';
import { readdir, readFile } from 'node:fs/promises';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { stamp } from './clock.mjs';
import { buildSnapshot } from './snapshot.mjs';
import { emptyBody, invalid, newWorkflow, pageQuery, reviewVerdict, workflowPatch } from './validate.mjs';

const MAX_BODY_BYTES = 65_536;
const SESSION_MS = 12 * 60 * 60 * 1000;
const MAX_STREAMS = 16;
const STREAM_MIN_INTERVAL_MS = 250;
const STREAM_HEARTBEAT_MS = 15_000;
const COOKIE = 'managed_session';

const SECURITY_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Robots-Tag': 'noindex, nofollow',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    + "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
};

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
};

// New IDs are UUIDs; the store decides whether an ID exists, so migrated IDs of any shape work too.
const ID = '[A-Za-z0-9_-]{1,64}';
const WORKFLOW_ACTION = new RegExp(`^/api/workflows/(${ID})/(pause|resume|run|archive|restore|approve|skip)$`);
const WORKFLOW = new RegExp(`^/api/workflows/(${ID})$`);
const RUN = new RegExp(`^/api/runs/(${ID})$`);
const RUN_ACTION = new RegExp(`^/api/runs/(${ID})/(cancel|abandon|review)$`);
const REVIEW_ACTION = new RegExp(`^/api/runs/(${ID})/review/(cancel|abandon)$`);

/** `{"confirm": TASK_ID}` and nothing else (contract sections 10 and 15.1). */
function confirmation(body) {
  if (Object.keys(body).some(key => key !== 'confirm') || typeof body.confirm !== 'string') {
    throw invalid('Confirm with the exact task ID');
  }
  return body.confirm;
}

function sameText(a, b) {
  return typeof a === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b)
    && timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function refuse(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

/** Static console files, read once at start. They contain no customer state. */
async function loadAssets() {
  const root = fileURLToPath(new URL('../public/', import.meta.url));
  const assets = new Map();
  for (const entry of await readdir(root, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const type = CONTENT_TYPES[entry.name.slice(entry.name.lastIndexOf('.'))];
    if (!type) continue;
    const file = join(entry.parentPath, entry.name);
    const route = '/' + file.slice(root.length).split('\\').join('/');
    assets.set(route, { type, body: await readFile(file) });
  }
  assets.set('/', assets.get('/index.html'));
  return assets;
}

async function readBody(req) {
  if (Number(req.headers['content-length']) > MAX_BODY_BYTES) throw refuse(413, 'Request is too large');
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw refuse(413, 'Request is too large');
    chunks.push(chunk);
  }
  let data;
  try {
    data = JSON.parse(Buffer.concat(chunks).toString() || '{}');
  } catch {
    throw invalid('Invalid JSON');
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw invalid('Expected a JSON object');
  return data;
}

export async function startServer({ engine, store, token, port, version }) {
  const assets = await loadAssets();
  const sessions = new Map();
  const streams = new Set();
  const origins = [`http://127.0.0.1:${port}`, `http://localhost:${port}`];
  const now = stamp;

  function openStream(req, res, session) {
    if (streams.size >= MAX_STREAMS) throw refuse(503, 'Too many live update streams');
    res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'X-Accel-Buffering': 'no' });
    res.write('retry: 3000\n\n');
    const stream = { res, session, timer: null, sentAt: 0 };
    const send = () => {
      stream.timer = null;
      stream.sentAt = performance.now();
      res.write(`event: change\ndata: ${JSON.stringify({ revision: engine.revision })}\n\n`);
    };
    const unsubscribe = engine.onChange(() => {
      if (stream.timer) return;
      const wait = STREAM_MIN_INTERVAL_MS - (performance.now() - stream.sentAt);
      if (wait <= 0) send();
      else stream.timer = setTimeout(send, wait);
    });
    const heartbeat = setInterval(() => res.write(': keep-alive\n\n'), STREAM_HEARTBEAT_MS);
    stream.close = () => {
      clearInterval(heartbeat);
      clearTimeout(stream.timer);
      unsubscribe();
      streams.delete(stream);
      res.end();
    };
    streams.add(stream);
    req.on('close', stream.close);
    send();
  }

  async function route(req, res, { path, query, session }) {
    const { method } = req;
    const json = (status, data) => {
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(data));
    };

    if (path === '/api/login' && method === 'POST') {
      const data = await readBody(req);
      if (Object.keys(data).some(key => key !== 'token')) throw invalid('Unexpected login fields');
      if (!sameText(data.token, token)) throw refuse(401, 'Invalid access token');
      for (const [key, expiry] of sessions) if (expiry < Date.now()) sessions.delete(key);
      const created = randomBytes(32).toString('hex');
      sessions.set(created, Date.now() + SESSION_MS);
      res.setHeader('Set-Cookie', `${COOKIE}=${created}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}`);
      return json(200, { ok: true });
    }
    if (path === '/api/logout' && method === 'POST') {
      emptyBody(await readBody(req));
      if (session) {
        sessions.delete(session);
        for (const stream of [...streams]) if (stream.session === session) stream.close();
      }
      res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
      return json(200, { ok: true });
    }

    if (path === '/api/snapshot' && method === 'GET') return json(200, await buildSnapshot({ store, engine, version }));
    if (path === '/api/events' && method === 'GET') return openStream(req, res, session);
    if (path === '/api/activity' && method === 'GET') return json(200, await store.listActivity(pageQuery(query)));
    if (path === '/api/runs' && method === 'GET') {
      return json(200, await store.listRuns(pageQuery(query, { allowWorkflow: true })));
    }

    if (path === '/api/workflows' && method === 'POST') {
      const workflow = await store.createWorkflow(newWorkflow(await readBody(req)), now());
      engine.poke();
      return json(201, workflow);
    }
    let match = path.match(WORKFLOW_ACTION);
    if (match && method === 'POST') {
      emptyBody(await readBody(req));
      const workflow = await store.workflowAction(match[1], match[2], now());
      engine.poke();
      return json(200, workflow);
    }
    match = path.match(WORKFLOW);
    if (match && method === 'PATCH') {
      const workflow = await store.editWorkflow(match[1], workflowPatch(await readBody(req)), now());
      engine.poke();
      return json(200, workflow);
    }

    match = path.match(RUN);
    if (match && method === 'GET') return json(200, await store.runDetail(match[1]));
    match = path.match(RUN_ACTION);
    if (match && method === 'POST') {
      const body = await readBody(req);
      let run;
      if (match[2] === 'cancel') {
        emptyBody(body);
        run = await store.requestCancel(match[1], now());
      } else if (match[2] === 'review') {
        const { verdict, note } = reviewVerdict(body);
        run = await store.reviewRun(match[1], verdict, note, now());
      } else {
        run = await store.abandonRun(match[1], confirmation(body), now());
      }
      engine.poke();
      return json(200, run);
    }
    match = path.match(REVIEW_ACTION);
    if (match && method === 'POST') {
      const body = await readBody(req);
      let run;
      if (match[2] === 'cancel') {
        emptyBody(body);
        run = await store.requestReviewCancel(match[1], now());
      } else {
        run = await store.abandonReview(match[1], confirmation(body), now());
      }
      engine.poke();
      return json(200, run);
    }

    const asset = method === 'GET' ? assets.get(path) : undefined;
    if (asset) {
      res.writeHead(200, { 'Content-Type': asset.type });
      return res.end(asset.body);
    }
    throw refuse(404, 'Not found');
  }

  const server = createServer(async (req, res) => {
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) res.setHeader(name, value);
    const fail = (status, message) => {
      if (res.headersSent) return res.end();
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: message }));
    };
    try {
      const { headers, method } = req;
      // DNS rebinding and cross-site requests are refused before any state is read.
      if (![`127.0.0.1:${port}`, `localhost:${port}`].includes(headers.host)) throw refuse(403, 'Host is not allowed');
      const origin = 'http://' + headers.host;
      if (!URL.canParse(req.url, origin)) throw refuse(400, 'Invalid request target');
      const url = new URL(req.url, origin);
      const path = url.pathname;
      const isApi = path.startsWith('/api/');
      if (headers.origin && !(origins.includes(headers.origin) && headers.origin === origin)) {
        throw refuse(403, 'Origin is not allowed');
      }
      if (isApi && ['cross-site', 'same-site'].includes(headers['sec-fetch-site'])) {
        throw refuse(403, 'Cross-site request is not allowed');
      }
      if (path === '/health' && method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        return res.end('{"ok":true}');
      }

      const bearer = headers.authorization?.startsWith('Bearer ') && sameText(headers.authorization.slice(7), token);
      const cookie = headers.cookie?.split(';').map(part => part.trim())
        .find(part => part.startsWith(COOKIE + '='))?.slice(COOKIE.length + 1);
      const session = cookie && (sessions.get(cookie) || 0) > Date.now() ? cookie : null;
      const mutation = !['GET', 'HEAD'].includes(method);
      if (mutation && !bearer && headers.origin !== origin) throw refuse(403, 'Same-origin request required');
      if (isApi && path !== '/api/login' && !bearer && !session) throw refuse(401, 'Sign in to your local console');
      await route(req, res, { path, query: url.searchParams, session });
    } catch (error) {
      if (error.status) return fail(error.status, error.message);
      console.error('Request failed: ' + error.message);
      fail(500, 'Internal error');
    }
  });
  server.requestTimeout = 20_000;
  server.headersTimeout = 15_000;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });

  return {
    /** Stops accepting requests and ends every open connection and stream. */
    close() {
      for (const stream of [...streams]) stream.close();
      return new Promise(resolve => {
        server.close(() => resolve());
        server.closeAllConnections();
      });
    }
  };
}
