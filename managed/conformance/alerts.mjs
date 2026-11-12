#!/usr/bin/env node
// Contract-only black-box suite for docs/managed-contract.md revision 10, section 16, cases 29 to 31: alerts to a
// webhook (sections 1, 8, 8.1 and 11). No imports or reads of the managed implementation or its database: the
// documented CLI, HTTP, the explicitly fake Peerspan executable, throwaway state and a SCRIPTED local webhook receiver
// (node:http on 127.0.0.1) only. Attention items are made to appear and disappear through the fake: an unready worker
// (worker_unready, action while an enabled workflow uses it, otherwise warning: a FAKE daemon that does not answer, a
// missing worker state file, or a sender that answers as the worker host), a result awaiting the operator
// (review_pending, action) and a used-up daily cap (daily_limit_reached, info). Retries and the 24-hour give-up are
// moved with MANAGED_CLOCK_FILE (§1). Section numbers (§) refer to that contract.
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {isDeepStrictEqual} from 'node:util';
import {alertsSubject, checkActivityEntry, clock, delay, expect, expectEqual, expectStatus, fixture, pick, runCases,
  snippet, until, writeJson} from './harness.mjs';

const second = 1000, minute = 60 * second, hour = 60 * minute, day = 24 * hour;
// The secret parts of every webhook URL here. §8.1: no HTTP response, activity entry, log line, CLI output or alert
// contains more of the URL than its host name. They begin with PRIVATE-, so the harness also refuses them in every
// HTTP response of the controller (§8).
const secrets = ['PRIVATE-SECRET-PATH', 'PRIVATE-TOKEN', 'PRIVATE-PASSWORD'];
const secretPart = '/PRIVATE-SECRET-PATH?token=PRIVATE-TOKEN';
// §8.1: attention is evaluated within 10 seconds of every change of meta.revision. A window in which nothing may be sent
// lasts that long and 1.5 seconds more; an alert that is due may take up to `soon`, for a loaded machine.
const quiet = 11500, soon = 15000;
const off = {configured: false, host: null};
const local = {configured: true, host: '127.0.0.1'};
const startAt = '2026-05-04T10:00:00.000Z';   // the controller clock of the cases that move it (§1)
const receivers = [];

function noSecrets(text, where) {
  for (const secret of secrets) {
    const at = text.indexOf(secret);
    expect(at < 0, `§8.1 no HTTP response, activity entry, log line, CLI output or alert contains more of the webhook ` +
      `URL than its host name: ${where} contains ${secret}`, text.slice(Math.max(0, at - 100), at + 100));
  }
}
const scanLogs = (f, when) => noSecrets(f.logs, `the controller log (${when})`);
const brief = entry => ({path: entry.path, event: entry.data?.event, kind: entry.data?.item?.kind,
  id: entry.data?.item?.subject?.id, status: entry.status, abandoned: entry.abandoned,
  at: new Date(entry.at).toISOString()});

// §8.1: TEXT is "Needs your action: NAME: MESSAGE" for an action item, "Warning: NAME: MESSAGE" for a warning item
// and "Resolved: NAME: MESSAGE" for a cleared alert, NAME and MESSAGE as raised.
function textOf(event, item) {
  const lead = event === 'attention.cleared' ? 'Resolved' : item?.severity === 'action' ? 'Needs your action' : 'Warning';
  return `${lead}: ${item?.subject?.name}: ${item?.message}`;
}
// What every request to the receiver must be (§8.1 Delivery), whichever alert it carries.
function checkDelivery(entry, r) {
  expect(entry.method === 'POST' && r.allowed.has(entry.path), '§8.1 each alert is one POST to the configured URL, ' +
    'with its path and query (the controller follows no redirect)', brief(entry));
  expect(/^application\/json(\s*;\s*charset=utf-8)?$/i.test(entry.headers['content-type'] ?? ''),
    '§8.1 an alert has Content-Type: application/json', entry.headers['content-type']);
  noSecrets(entry.body + JSON.stringify(entry.headers), 'an alert body or its headers');
  const {data} = entry;
  expect(data !== null && typeof data === 'object' && isDeepStrictEqual(Object.keys(data).sort(),
    ['content', 'event', 'item', 'text']) && ['attention.raised', 'attention.cleared'].includes(data.event) &&
    data.item !== null && typeof data.item === 'object' && isDeepStrictEqual(Object.keys(data.item).sort(),
    ['kind', 'message', 'severity', 'since', 'subject']), '§8.1 the body is JSON {text,content,event,item}, event ' +
    'attention.raised or attention.cleared, item an attention item of §8', entry.body);
  expect(['action', 'warning'].includes(data.item.severity) && data.item.kind !== 'alerts_failing', '§8.1 only action ' +
    'and warning items are announced, never info items, and the alerts_failing item never', data.item);
  expectEqual([data.text, data.content], Array(2).fill(textOf(data.event, data.item)), '§8.1 text and content repeat ' +
    'TEXT: "Needs your action: NAME: MESSAGE", "Warning: NAME: MESSAGE" or, cleared, "Resolved: NAME: MESSAGE"');
}
function expectAlert(entry, event, item, rule) {
  expect(entry !== undefined, rule + ': no such alert was received');
  expectEqual(entry.data, {text: textOf(event, item), content: textOf(event, item), event, item}, rule +
    ' (§8.1 the body {text,content,event,item}, ITEM the attention item as §8 shows it when it was raised)');
}

// A SCRIPTED webhook receiver on 127.0.0.1. Each request is recorded with its method, target, headers and body, when it
// arrived and when it ended (answered, or abandoned by the controller): `at` and `endedAt` on the controller's clock
// (f.now(), §1), `t` and `tEnd` on the monotonic clock. `plan(entry)` answers it: {status, wait (ms), location}.
async function receiver(f) {
  const r = {requests: [], allowed: new Set(), plan: () => ({status: 200})};
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      let data = null;
      try { data = JSON.parse(body); } catch { data = null; }
      const entry = {method: req.method, path: req.url, headers: req.headers, body, data, at: f.now(), t: clock(),
        endedAt: null, tEnd: null, status: null, abandoned: false};
      r.requests.push(entry);
      const {status = 200, wait = 0, location} = r.plan(entry);
      res.on('close', () => {
        if (!res.writableEnded) entry.abandoned = true;
        entry.endedAt ??= f.now();
        entry.tEnd ??= clock();
      });
      setTimeout(() => {
        if (entry.abandoned || res.destroyed) return;
        Object.assign(entry, {status, endedAt: f.now(), tEnd: clock()});
        res.writeHead(status, {'Content-Type': 'text/plain', ...(location ? {Location: location} : {})});
        res.end('FAKE webhook receiver');
      }, wait);
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  r.port = server.address().port;
  r.target = (tag = '') => `/PRIVATE-SECRET-PATH${tag}?token=PRIVATE-TOKEN${tag}`;
  r.url = (tag = '') => { r.allowed.add(r.target(tag)); return `http://127.0.0.1:${r.port}${r.target(tag)}`; };
  r.close = () => { server.closeAllConnections(); server.close(); };
  // Waits until `count` requests have arrived and ended, checks every request so far, and returns the first `count`.
  r.wait = async (count, why, timeout = soon) => {
    await until(() => `${why}: expected ${count} webhook request(s) in all, received ${r.requests.length}: ` +
      snippet(r.requests.map(brief)), () => r.requests.length >= count &&
      r.requests.slice(0, count).every(entry => entry.endedAt !== null), timeout);
    r.requests.forEach(entry => checkDelivery(entry, r));
    return r.requests.slice(0, count);
  };
  // Nothing more than `count` requests arrives within `ms`.
  r.none = async (count, why, ms = quiet) => {
    await delay(ms);
    expect(r.requests.length === count, `${why} (expected ${count} webhook request(s) in all, ${ms} ms later)`,
      r.requests.slice(count).map(brief));
    r.requests.forEach(entry => checkDelivery(entry, r));
  };
  receivers.push(r);
  return r;
}

// ---- CLI, snapshot and activity helpers ----

// §8.1: alerts --url, --off and alone each print one JSON object and exit 0; no CLI output shows more of the URL.
function printed(result, why) {
  noSecrets(result.stdout + result.stderr, 'the output of alerts ' + why);
  const lines = result.stdout.trim().split('\n');
  let value;
  try { value = JSON.parse(lines[0]); } catch { value = undefined; }
  expect(result.code === 0 && lines.length === 1 && value !== undefined,
    `§8.1 alerts ${why} prints one JSON object and exits 0`, result);
  return value;
}
// `stdin`: the URL is passed as --url - and written to standard input (§8.1, read there and trimmed).
async function alerts(f, args, expected, why, stdin) {
  const result = stdin === undefined ? await f.cli('alerts', ...args) : await f.cliInput(stdin, 'alerts', ...args);
  expectEqual(printed(result, why), expected, `§8.1 alerts ${why} prints ` +
    '{"configured":BOOLEAN,"host":HOST}, HOST the URL host name, or null when none is configured');
}
async function refused(f, url, what, {stdin = false} = {}) {
  const result = stdin ? await f.cliInput(url, 'alerts', '--url', '-') : await f.cli('alerts', '--url', url);
  noSecrets(result.stdout + result.stderr, `the refusal of ${what}`);
  expect(result.code === 1 && result.stderr.trim() !== '' && result.stderr.trim().split('\n').length === 1,
    `§8.1 alerts --url ${stdin ? '- ' : ''}refuses ${what}: one error line on stderr and exit 1`, result);
}
// The attention item of `kind` and subject `id`, or null, once `test` accepts it.
async function attention(f, kind, id, why, test = item => item !== null) {
  let last = null;
  await until(() => `${why}: §8 attention ${kind} ${id}; last seen: ${snippet(last)}`, async () => {
    last = (await f.snapshot()).attention.find(item => item.kind === kind && item.subject.id === id) ?? null;
    return test(last);
  });
  return last;
}
const gone = item => item === null;
async function metaAlerts(f, expected, why) {
  let last;
  await until(() => `§8.1 meta.alerts ${JSON.stringify(expected)} ${why} (§1: a change takes effect at the next ` +
    `scheduler tick); last: ${snippet(last)}`, async () => isDeepStrictEqual(last = (await f.snapshot()).meta.alerts, expected));
}
// §8.1: while the latest attempt failed, meta.alerts.failing is true and alerts_failing is present: warning, subject
// {type:"alerts",id:"alerts",name:"Alerts"}, a message that names the host and the failure (`failure`).
async function failingItem(f, failure, why) {
  let last = null;
  await until(() => `§8.1 meta.alerts.failing and the alerts_failing item, its message naming 127.0.0.1 and ` +
    `${failure} (${why}); last: ${snippet(last)}`, async () => {
    const s = await f.snapshot();
    last = {alerts: s.meta.alerts, item: s.attention.find(item => item.kind === 'alerts_failing') ?? null};
    return s.meta.alerts.failing && last.item?.message.includes('127.0.0.1') && failure.test(last.item.message);
  });
  expectEqual(pick(last.item, 'kind severity subject'), {kind: 'alerts_failing', severity: 'warning',
    subject: alertsSubject}, '§8.1 alerts_failing is a warning with subject {type:"alerts",id:"alerts",name:"Alerts"}');
  return last.item;
}
async function notFailing(f, why) {
  let last = null;
  await until(() => `§8.1 failing is false and alerts_failing gone once a delivery succeeds (${why}); last: ` +
    snippet(last), async () => {
    const s = await f.snapshot();
    last = {alerts: s.meta.alerts, items: s.attention.filter(item => item.kind === 'alerts_failing')};
    return !s.meta.alerts.failing && last.items.length === 0;
  });
}
const near = (time, at, rule) => expect(Math.abs(Date.parse(time) - at) <= 5000, rule + ` (within 5 s of ` +
  `${new Date(at).toISOString()})`, time);
// §8.1: an alert that fails is tried again `ms` after the failure of the attempt before. The clock is first moved
// shortly before that moment (`early`), when nothing may come, then 1 second past it.
async function retry(f, r, last, ms, why, {early = true} = {}) {
  await until(`${why}: the attempt before has ended`, () => last.endedAt !== null, soon);
  const count = r.requests.length;
  const due = last.endedAt + ms;
  if (early && f.now() < due - 6000) {
    await f.clockAt(due - 6000, `6 seconds before a retry ${why}`);
    await delay(1200);
    expect(r.requests.length === count, `§8.1 an alert is not tried again before ${ms / second} seconds have passed ` +
      `since its failure (${why}); the clock stood at most 4 seconds before that`, r.requests.slice(count).map(brief));
  }
  await f.setClock(Math.max(f.now(), due + 1000));
  const entry = (await r.wait(count + 1, `§8.1 the alert is tried again ${ms / second} seconds after its failure ` +
    `(${why}); the clock was moved 1 second past that moment`, 12000)).at(-1);
  // A retry is tried within 10 seconds of its time; 1 second more for the moment the failure was recorded.
  expect(entry.at <= due + 11000, `§8.1 a retry is tried within 10 seconds of its time (${why})`,
    {due: new Date(due).toISOString(), at: new Date(entry.at).toISOString()});
  return entry;
}
// The alerts.* entries of the whole activity log (§11), oldest first.
async function alertsActivity(f) {
  const entries = [];
  for (let before = null; ;) {
    const query = '/api/activity?limit=200' + (before === null ? '' : '&before=' + encodeURIComponent(before));
    const data = expectStatus(await f.request('GET', query), 200, '§11 GET /api/activity').data;
    entries.push(...data.activity);
    if (data.nextBefore === null) break;
    before = data.nextBefore;
  }
  entries.forEach(checkActivityEntry);
  return entries.reverse().filter(entry => entry.kind.startsWith('alerts.'));
}
async function finish(f, r) {
  await f.stop();
  scanLogs(f, 'at the end');
  r.requests.forEach(entry => checkDelivery(entry, r));
}
// A workflow with one result awaiting the operator (§15), paused so that it uses its worker no more (§8).
async function pendingReview(f) {
  const w = await f.create({review: 'operator', enabled: true});
  const run = await f.newRun(w.id, 'queued');
  await f.action(w.id, 'pause');
  await f.finish(run, 'succeeded', {output: 'FAKE result awaiting review'});
  return {w, run, item: await attention(f, 'review_pending', w.id, 'a result awaits the operator')};
}
const verdict = async (f, run) => expectStatus(await f.request('POST', `/api/runs/${run.id}/review`,
  {verdict: 'accepted'}), 200, '§15 POST /api/runs/:id/review');
// The FAKE worker daemon stops answering (§3 daemon_not_running), and answers again with a ready session. One read
// decides either way, so a check made across the change never reports a third state with another message.
const down = f => f.configure({statusMode: 'daemon-not-running'});
const up = f => f.configure({statusMode: 'normal', ready: true});

// §8.1: values that alerts --url refuses. Each carries the secret markers, so an error line that repeats it is caught.
const pad = (prefix, length) => prefix + 'a'.repeat(length - prefix.length);
const longPrefix = 'https://hooks.example.invalid' + secretPart + '&pad=';
const refusals = port => [
  ['an http URL to another host', 'http://hooks.example.invalid' + secretPart],
  ['an http URL to 127.0.0.2, a loopback address that is not listed', `http://127.0.0.2:${port}${secretPart}`],
  ['an http URL with a user name', `http://FAKE-user@127.0.0.1:${port}${secretPart}`],
  ['an https URL with a user name and password', 'https://FAKE-user:PRIVATE-PASSWORD@hooks.example.invalid' + secretPart],
  ['an https URL with a password only', 'https://:PRIVATE-PASSWORD@hooks.example.invalid' + secretPart],
  ['a URL of 2,049 characters', pad(longPrefix, 2049)],
  ['a URL that is not absolute', secretPart],
  ['a URL without a scheme', 'hooks.example.invalid' + secretPart],
  ['a URL of another scheme', `ftp://127.0.0.1:${port}${secretPart}`],
  ['an empty value', '']];

// Case 29. §8.1 configuration: alerts --url, --off and alone with their JSON output; the refusals; the URL's secret
// path and query in no HTTP response, activity entry, CLI output, log line or alert; the alerts.* activity (§11);
// meta.alerts (§8), following a change while serving and kept across a restart.
async function case29_configuration() {
  const f = await fixture('alerts-configuration');
  const r = await receiver(f);
  await f.start();
  await f.code(f.connectionId, 'ready', 'the worker is ready, so no attention item is present');
  await metaAlerts(f, {...off, failing: false}, 'before any webhook is set (§1 state created directly)');
  await alerts(f, [], off, 'alone, with no webhook');
  await alerts(f, ['--url', r.url()], local, '--url with an http 127.0.0.1 URL');
  await metaAlerts(f, {...local, failing: false}, 'once a webhook is set while serving');

  for (const [what, url] of refusals(r.port)) await refused(f, url, what);
  for (const [what, url] of [['an http URL to another host', 'http://hooks.example.invalid' + secretPart + '\n'],
    ['an http URL with a user name', ` http://FAKE-user@127.0.0.1:${r.port}${secretPart}\n`],
    ['a URL that is not absolute', secretPart + '\n'], ['only whitespace', ' \t\n']]) {
    await refused(f, url, what + ' on standard input', {stdin: true});
  }
  await alerts(f, [], local, 'alone after the refusals, which change nothing');
  await metaAlerts(f, {...local, failing: false}, 'after the refusals, which change nothing');

  await alerts(f, ['--url', '-'], {configured: true, host: 'localhost'}, '--url - with an http localhost URL on ' +
    'standard input, trimmed', `\t http://localhost:${r.port}${secretPart} \r\n`);
  const v6 = printed(await f.cli('alerts', '--url', `http://[::1]:${r.port}${secretPart}`), '--url with an http [::1] URL');
  expectEqual(v6, {configured: true, host: '[::1]'}, '§8.1 an http URL is accepted when its host is [::1]; host is ' +
    'the URL host name as the WHATWG URL standard writes it');
  const longest = pad(longPrefix, 2048);
  await alerts(f, ['--url', longest], {configured: true, host: 'hooks.example.invalid'},
    '--url with an https URL of exactly 2,048 characters');
  await metaAlerts(f, {configured: true, host: 'hooks.example.invalid', failing: false}, 'after another URL');
  await alerts(f, ['--off'], off, '--off');
  await metaAlerts(f, {...off, failing: false}, 'after --off');
  await alerts(f, [], off, 'alone after --off');
  await alerts(f, ['--url', r.url()], local, '--url with the http 127.0.0.1 URL again');
  await f.stop();
  scanLogs(f, 'before a restart');
  await alerts(f, [], local, 'alone while the controller is stopped');
  await f.start();
  await metaAlerts(f, {...local, failing: false}, 'after a restart');

  const entries = await alertsActivity(f);
  expectEqual(entries.map(entry => [entry.kind, entry.data]), [['alerts.configured', {host: '127.0.0.1'}],
    ['alerts.configured', {host: 'localhost'}], ['alerts.configured', {host: v6?.host}],
    ['alerts.configured', {host: 'hooks.example.invalid'}], ['alerts.removed', null],
    ['alerts.configured', {host: '127.0.0.1'}]], '§11 (rev 10) setting a URL records alerts.configured with {host}, ' +
    '--off records alerts.removed with data null, and a refused URL records nothing');
  expect(entries.every(entry => entry.actor === 'operator' && entry.workflowId === null && entry.runId === null &&
    entry.connectionId === null), '§11 alerts.* entries are operator entries without references', entries);
  // Every response is scanned by the harness (§8); the CLI output and the log here.
  for (const route of ['/api/runs', '/health']) await f.request('GET', route);
  for (const name of ['status', 'doctor']) {
    const result = await f.cli(name);
    noSecrets(result.stdout + result.stderr, 'the output of ' + name);
  }
  await r.none(0, '§8.1 with no attention item present, setting a webhook announces nothing');
  await finish(f, r);
}

// Case 29. §8.1: a refused URL changes nothing, not even an older store's version, and creates nothing: no state
// directory where there was none, and a version 1 store (§13, created here as that section documents it; an older
// store than version 7) left byte for byte, with no backup copy or any other file beside it (§1).
async function case29_refusalChangesNothing() {
  const f = await fixture('alerts-refusal', {connect: false});
  const port = f.port;   // any port: nothing is delivered here
  const exists = file => fs.stat(file).then(() => true, () => false);
  for (const [what, url] of refusals(port).slice(0, 3)) {
    await refused(f, url, what + ' with no state directory');
    expect(!(await exists(f.state)), `§8.1 a refused URL creates nothing: no state directory (${what})`);
  }
  await fs.mkdir(f.state, {mode: 0o700});
  const file = path.join(f.state, 'managed.sqlite');
  const db = new DatabaseSync(file);
  db.exec('PRAGMA user_version = 0; CREATE TABLE records(kind TEXT NOT NULL, id TEXT PRIMARY KEY, body TEXT NOT NULL)');
  db.close();
  await fs.chmod(file, 0o600);
  const [bytes, listing] = [await fs.readFile(file), await fs.readdir(f.state)];
  for (const [what, url, stdin] of [...refusals(port).map(([what, url]) => [what, url, false]),
    ['an http URL to another host on standard input', 'http://hooks.example.invalid' + secretPart + '\n', true]]) {
    await refused(f, url, what + ' with a version 1 store', {stdin});
    expect((await fs.readFile(file)).equals(bytes), `§8.1 a refused URL changes nothing, not even an older store's ` +
      `version: the version 1 database is unchanged (${what})`);
    expectEqual(await fs.readdir(f.state), listing, `§8.1 a refused URL neither migrates nor backs up the store, nor ` +
      `creates anything: no managed.v1-backup.sqlite or other new file (${what})`);
  }
}

// Case 30. §8.1: the items present when alerts are set announced, with the exact bodies of an action and a warning
// item; a cleared alert once an item is gone; a new URL announced the items present again, the previous one
// forgotten; an item that comes back raising again; nothing after --off.
async function case30_raiseAndClear() {
  const f = await fixture('alerts-raise');
  const r = await receiver(f);
  await f.start();
  await f.code(f.connectionId, 'ready', 'the worker is ready');
  const review = await pendingReview(f);
  await down(f);
  const unready = await attention(f, 'worker_unready', f.connectionId, 'the worker of no enabled workflow is unready',
    item => item?.severity === 'warning');
  expect(review.item.severity === 'action', '§8 review_pending is an action item', review.item);

  await alerts(f, ['--url', r.url('-first')], local, '--url');
  const first = await r.wait(2, '§8.1 setting alerts announces the action and warning items present then');
  await r.none(2, '§8.1 one raised alert per item', 2000);
  for (const item of [review.item, unready]) {
    expectAlert(first.find(entry => entry.data.item.kind === item.kind), 'attention.raised', item,
      `§8.1 the raised alert of the ${item.severity} item ${item.kind}, present when alerts were set`);
  }
  expect(first.every(entry => entry.path === r.target('-first')), '§8.1 alerts go to the URL set', first.map(brief));

  await verdict(f, review.run);
  await attention(f, 'review_pending', review.w.id, 'the verdict leaves no result waiting', gone);
  const [cleared] = (await r.wait(3, '§8.1 when the item is gone a cleared alert is sent')).slice(2);
  expectAlert(cleared, 'attention.cleared', review.item, '§8.1 the cleared alert of review_pending: "Resolved: NAME: ' +
    'MESSAGE" and the item as raised');

  await alerts(f, ['--url', '-'], local, '--url - with a new URL on standard input', `  ${r.url('-second')}\n`);
  const [again] = (await r.wait(4, '§8.1 a new URL starts over: the items present then are announced to it')).slice(3);
  expectAlert(again, 'attention.raised', unready, '§8.1 the unready worker announced again, to the new URL');
  expectEqual(again.path, r.target('-second'), '§8.1 after a new URL, alerts go to the new URL, read from standard ' +
    'input and trimmed');

  await up(f);
  await attention(f, 'worker_unready', f.connectionId, 'the worker is ready again', gone);
  const [resolved] = (await r.wait(5, '§8.1 the cleared alert of the worker')).slice(4);
  expectAlert(resolved, 'attention.cleared', unready, '§8.1 the cleared alert of worker_unready, to the new URL');
  await down(f);
  const back = await attention(f, 'worker_unready', f.connectionId, 'the worker is unready once more');
  const [returned] = (await r.wait(6, '§8.1 an item that disappears and comes back is a new one')).slice(5);
  expectAlert(returned, 'attention.raised', back, '§8.1 the item that came back raises a new alert');
  expect(r.requests.slice(3).every(entry => entry.path === r.target('-second')), '§8.1 every alert of the previous ' +
    'URL is forgotten: none goes there once a new URL is set', r.requests.map(brief));

  await alerts(f, ['--off'], off, '--off');
  await metaAlerts(f, {...off, failing: false}, 'after --off');
  await up(f);
  await attention(f, 'worker_unready', f.connectionId, 'the worker is ready after --off', gone);
  await r.none(6, '§8.1 --off forgets every alert of the previous URL: nothing is announced, not even a cleared alert');
  expectEqual((await alertsActivity(f)).map(entry => [entry.kind, entry.data]), [['alerts.configured', {host: '127.0.0.1'}],
    ['alerts.configured', {host: '127.0.0.1'}], ['alerts.removed', null]], '§11 (rev 10) the alerts.* entries');
  await finish(f, r);
}

// Case 30. §8.1: no alert for an info item (daily_limit_reached), and no new alert when an item's severity (an action
// worker_unready whose workflow is paused) or message (another reason) changes; its cleared alert carries the item
// and the TEXT as raised.
async function case30_quietChanges() {
  const f = await fixture('alerts-quiet');
  const r = await receiver(f);
  await f.start();
  await f.code(f.connectionId, 'ready', 'the worker is ready');
  await alerts(f, ['--url', r.url()], local, '--url');
  const w = await f.create({enabled: true, maxRunsPerDay: 1});
  await f.finish(await f.newRun(w.id, 'queued'), 'succeeded');
  await f.action(w.id, 'run');
  const capped = await attention(f, 'daily_limit_reached', w.id, 'the daily cap of one is used up');
  expect(capped.severity === 'info', '§8 daily_limit_reached is an info item', capped);
  await r.none(0, '§8.1 info items are never announced (daily_limit_reached)');

  await down(f);
  const raised = await attention(f, 'worker_unready', f.connectionId, 'the worker of an enabled workflow is unready',
    item => item?.severity === 'action');
  const [alert] = await r.wait(1, '§8.1 a raised alert for an action item');
  expectAlert(alert, 'attention.raised', raised, '§8.1 the raised alert of an action item: "Needs your action: NAME: MESSAGE"');
  await f.action(w.id, 'pause');
  await attention(f, 'worker_unready', f.connectionId, 'its workflow is paused, so the item becomes a warning',
    item => item?.severity === 'warning' && item.message === raised.message);
  await r.none(1, '§8.1 a change of the item severity is not a new alert');
  await f.configure({statusMode: 'normal', ready: false});
  await attention(f, 'worker_unready', f.connectionId, 'precondition: the worker is unready for another reason (its ' +
    'daemon answers, without a ready session), so the message changes', item => item !== null && item.message !== raised.message);
  await r.none(1, '§8.1 a change of the item message is not a new alert');
  await up(f);
  await attention(f, 'worker_unready', f.connectionId, 'the worker is ready again', gone);
  const [, cleared] = await r.wait(2, '§8.1 a cleared alert once the item is gone');
  expectAlert(cleared, 'attention.cleared', raised, '§8.1 the cleared alert carries the item as raised (severity action, ' +
    'the first message) and "Resolved: NAME: MESSAGE" with NAME and MESSAGE as raised');
  await r.none(2, '§8.1 one cleared alert', 2000);
  await finish(f, r);
}

// Case 30. §8.1 restarts: none is sent twice after it was delivered; an item that cleared while the controller was
// stopped is announced as cleared at its next start (a connection removed, a worker state file restored); and (rev 10)
// until a connection's first check after a start has ended (checking, §3), its worker_unready alert is neither raised
// nor cleared: the FAKE sender status of one unready worker is made slow (15 seconds), so that its first check lasts
// about as long as the 10 seconds within which attention is evaluated after a change, or longer.
async function case30_restart() {
  const f = await fixture('alerts-restart');
  const r = await receiver(f);
  const staysSender = path.join(f.dir, 'PRIVATE-stays-sender');
  await f.configure({senderStates: [f.senderDir, staysSender]});
  const copy = async name => { const file = path.join(f.dir, `PRIVATE-${name}-worker.json`); await writeJson(file, f.worker); return file; };
  const files = {returns: await copy('returns'), removed: await copy('removed')};
  const connect = async (name, file, sender) => JSON.parse(await f.checkedCli('connect', '--name', 'FAKE-CONFORMANCE ' +
    name, '--worker-state', file, '--sender-state', sender)).id;
  const conn = {stays: await connect('stays', f.workerFile, staysSender), returns: await connect('returns',
    files.returns, f.senderDir), removed: await connect('removed', files.removed, f.senderDir)};
  await f.start();
  for (const id of [f.connectionId, ...Object.values(conn)]) await f.code(id, 'ready', 'every worker is ready at first');
  const review = await pendingReview(f);
  // The sender of `stays` now answers as the worker host (§3 sender_is_worker); the other two lose their state file.
  await f.configure({senderStates: [f.senderDir]});
  await Promise.all(Object.values(files).map(file => fs.rm(file)));
  const items = {review: review.item};
  for (const [name, id] of Object.entries(conn)) items[name] = await attention(f, 'worker_unready', id, name + ' is unready');

  await alerts(f, ['--url', r.url()], local, '--url');
  const raised = await r.wait(4, '§8.1 the four items present when alerts are set are announced');
  await r.none(4, '§8.1 one raised alert per item', 1500);
  const of = (list, item) => list.find(entry => entry.data.item.subject.id === item.subject.id);
  for (const [name, item] of Object.entries(items)) {
    expectAlert(of(raised, item), 'attention.raised', item, `§8.1 the raised alert of ${name}`);
  }

  await f.configure({delayWhen: [{command: 'status', state: staysSender, ms: 15000}]});
  await f.stop();
  scanLogs(f, 'before the restart');
  await writeJson(files.returns, f.worker);   // ready again at its first check
  await f.checkedCli('disconnect', '--id', conn.removed);   // gone while the controller is stopped
  await f.start();
  expectEqual((await f.readiness(conn.stays)).code, 'checking', 'precondition, §3: until its first check after a ' +
    'start has finished (a FAKE sender status slowed to 15 seconds here), a connection readiness is checking');
  await f.code(conn.returns, 'ready', 'its worker state file was restored while the controller was stopped');
  const cleared = (await r.wait(6, '§8.1 the items that cleared while the controller was stopped are announced as ' +
    'cleared at its next start')).slice(4);
  for (const name of ['returns', 'removed']) {
    expectAlert(of(cleared, items[name]), 'attention.cleared', items[name], `§8.1 the cleared alert of ${name}`);
  }
  // The check ends sender_is_worker, or sender_unavailable when the controller abandons the slow call first; either
  // is the same unready item, its message changed at most, which is no new alert.
  let stays = null;
  await until(() => `§3 the slow first check of stays after the start ends; last readiness: ${snippet(stays)}`,
    async () => (stays = await f.readiness(conn.stays))?.code !== 'checking', 30000);
  expect(stays.ready === false, 'precondition: stays is still unready after its first check', stays);
  await r.none(6, '§8.1 a restart sends nothing twice (no raised alert again for review_pending or stays), and (rev 10) ' +
    'the worker_unready alert of stays was neither cleared nor raised while its first check ran (checking)');

  await verdict(f, review.run);
  const [reviewed] = (await r.wait(7, '§8.1 the cleared alert of review_pending, raised before the restart')).slice(6);
  expectAlert(reviewed, 'attention.cleared', items.review, '§8.1 the cleared alert of review_pending after the restart');
  await f.configure({senderStates: [f.senderDir, staysSender], delayWhen: []});
  await f.code(conn.stays, 'ready', 'its sender is another host again', 20000);
  const [last] = (await r.wait(8, '§8.1 the cleared alert of stays, raised before the restart')).slice(7);
  expectAlert(last, 'attention.cleared', items.stays, '§8.1 the cleared alert of stays carries the item as raised ' +
    'before the restart');
  await r.none(8, '§8.1 each alert once', 2000);
  await finish(f, r);
}

// Case 31. §8.1 failed delivery: HTTP 500 and 404, a redirect (never followed) and a receiver slower than 5 seconds
// each counting as a failure; the retry delays of 30, 60, 120 and 240 seconds (MANAGED_CLOCK_FILE); a cleared alert
// waiting for its raised alert, and the item coming back meanwhile raising a new alert that waits for both;
// meta.alerts.failing and the alerts_failing item (never announced) until a 2xx status.
async function case31_failures() {
  const f = await fixture('alerts-failures', {clock: startAt});
  const r = await receiver(f);
  const redirect = `http://127.0.0.1:${r.port}/FAKE-redirect-target`;
  const answers = [{status: 500}, {status: 404}, {status: 302, location: redirect}, {status: 200, wait: 8000},
    {status: 204}, {status: 299}];
  r.plan = entry => answers[r.requests.indexOf(entry)] ?? {status: 200};
  await f.start();
  await f.code(f.connectionId, 'ready', 'the worker is ready');
  await alerts(f, ['--url', r.url()], local, '--url');
  await down(f);
  const item = await attention(f, 'worker_unready', f.connectionId, 'the worker is unready');
  const [a1] = await r.wait(1, '§8.1 a raised alert');
  expectAlert(a1, 'attention.raised', item, '§8.1 the raised alert of a warning item: "Warning: NAME: MESSAGE"');
  const failing = await failingItem(f, /\b500\b/, 'after HTTP 500');
  near(failing.since, a1.endedAt, '§8.1 alerts_failing since is when the first failure since the last delivery happened');

  const a2 = await retry(f, r, a1, 30 * second, 'after HTTP 500');
  expectEqual(Date.parse((await failingItem(f, /\b404\b/, 'after HTTP 404')).since), Date.parse(failing.since),
    '§8.1 alerts_failing since stays the first failure since the last delivery');
  await up(f);
  await attention(f, 'worker_unready', f.connectionId, 'the worker is ready again', gone);
  await r.none(2, '§8.1 a cleared alert waits until its raised alert is delivered');
  // The item comes back while its raised alert is still retried: a new raised alert, which waits for both older ones.
  await down(f);
  const back = await attention(f, 'worker_unready', f.connectionId, 'the worker is unready once more');

  const a3 = await retry(f, r, a2, 60 * second, 'after HTTP 404');
  await failingItem(f, /\b302\b/, 'after a redirect, which is not followed');
  const a4 = await retry(f, r, a3, 120 * second, 'after a redirect');
  expect(a4.abandoned && a4.tEnd - a4.t <= 7000, '§8.1 the controller waits at most 5 seconds for a response: it ' +
    'abandons a FAKE receiver that answers after 8 seconds (allowed here: 7 seconds)', {...brief(a4), ms: a4.tEnd - a4.t});
  await failingItem(f, /time|no response|not respond|5 seconds/i, 'after a receiver that did not answer within 5 seconds');
  const a5 = await retry(f, r, a4, 240 * second, 'after a timeout');
  expectEqual(a5.status, 204, 'precondition: the FAKE receiver accepts the fifth attempt with HTTP 204');
  const [cleared, again] = (await r.wait(7, '§8.1 once its raised alert is delivered, the cleared alert follows, and ' +
    'then the raised alert of the item that came back')).slice(5);
  await notFailing(f, 'HTTP 204, 299 and 200');
  expect(r.requests.slice(0, 5).every(entry => isDeepStrictEqual(entry.data, a1.data)), '§8.1 each retry sends the ' +
    'same raised alert', r.requests.map(brief));
  expectAlert(cleared, 'attention.cleared', item, '§8.1 one item alerts are delivered in order: the cleared alert ' +
    'after its raised alert');
  expectAlert(again, 'attention.raised', back, '§8.1 one item alerts are delivered in order, also when the item came ' +
    'back while its raised alert was still retried: raised, cleared, then the new raised alert');
  await r.none(7, '§8.1 a delivered alert is not sent again', 3000);
  expect(!r.requests.some(entry => entry.path.startsWith('/FAKE-redirect')), '§8.1 the controller follows no redirect');
  await finish(f, r);
}

// Case 31. §8.1: one item's alerts arrive in order also when the item comes back while its cleared alert is still
// retried: the receiver sees raised, cleared, raised, never the new raised alert before the cleared one is delivered.
async function case31_backWhileClearedRetried() {
  const f = await fixture('alerts-back-in-order', {clock: startAt});
  const r = await receiver(f);
  let accept = false;   // the FAKE receiver accepts raised alerts, and cleared ones only once this is set
  r.plan = entry => ({status: accept || entry.data?.event === 'attention.raised' ? 200 : 500});
  await f.start();
  await f.code(f.connectionId, 'ready', 'the worker is ready');
  await alerts(f, ['--url', r.url()], local, '--url');
  await down(f);
  const first = await attention(f, 'worker_unready', f.connectionId, 'the worker is unready');
  const [raised] = await r.wait(1, '§8.1 a raised alert');
  expectAlert(raised, 'attention.raised', first, '§8.1 the raised alert, delivered');
  await up(f);
  await attention(f, 'worker_unready', f.connectionId, 'the worker is ready again', gone);
  const c1 = (await r.wait(2, '§8.1 its cleared alert, which the FAKE receiver fails with HTTP 500')).at(-1);
  expectAlert(c1, 'attention.cleared', first, '§8.1 the cleared alert');
  await down(f);
  const back = await attention(f, 'worker_unready', f.connectionId, 'the worker is unready once more');
  await r.none(2, '§8.1 one item alerts are delivered in order: the raised alert of the item that came back waits ' +
    'while its older cleared alert is retried');
  accept = true;
  const c2 = await retry(f, r, c1, 30 * second, 'after the cleared alert failed');
  expectAlert(c2, 'attention.cleared', first, '§8.1 the older cleared alert is delivered first');
  const again = (await r.wait(4, '§8.1 then the raised alert of the item that came back')).at(-1);
  expectAlert(again, 'attention.raised', back, '§8.1 the new raised alert, after the cleared alert');
  expectEqual(r.requests.map(entry => entry.data?.event), ['attention.raised', 'attention.cleared', 'attention.cleared',
    'attention.raised'], '§8.1 the receiver sees raised, cleared (failed, then delivered), raised');
  await r.none(4, '§8.1 each alert is delivered once', 3000);
  await finish(f, r);
}

// Case 31. §8.1: the delays doubling up to 30 minutes; the alerts_failing since kept; an alert given up 24 hours after
// its item appeared, even with a receiver that would accept it then; its cleared alert never sent; failing until a
// new alert is delivered.
async function case31_backoffAndGiveUp() {
  const f = await fixture('alerts-give-up', {clock: startAt});
  const r = await receiver(f);
  r.plan = () => ({status: 500});
  await f.start();
  await f.code(f.connectionId, 'ready', 'the worker is ready');
  await alerts(f, ['--url', r.url()], local, '--url');
  await down(f);
  const item = await attention(f, 'worker_unready', f.connectionId, 'the worker is unready');
  const appeared = Date.parse(item.since);   // §8: worker_unready since is when its readiness stopped being ready
  let [last] = await r.wait(1, '§8.1 a raised alert');
  const failing = await failingItem(f, /\b500\b/, 'after HTTP 500');
  for (const seconds of [30, 60, 120, 240, 480, 960, 1800, 1800]) {
    last = await retry(f, r, last, seconds * second, `after ${r.requests.length} failure(s)`, {early: seconds >= 480});
  }
  expectEqual(Date.parse((await failingItem(f, /\b500\b/, 'after nine failures')).since), Date.parse(failing.since),
    '§8.1 alerts_failing since stays the first failure since the last delivery');
  await f.setClock(appeared + day - 5 * minute);
  const n = (await r.wait(r.requests.length + 1, '§8.1 the alert is still tried 23 hours 55 minutes after its item ' +
    'appeared')).length;
  r.plan = () => ({status: 200});
  await f.clockAt(appeared + day + 27 * minute, 'a retry is due 30 minutes after the last failure, 24 hours after the item appeared');
  await r.none(n, '§8.1 an alert that is not delivered within 24 hours is given up; a raised alert counts from the ' +
    'moment its item appeared (the FAKE receiver would now accept it)', 4000);
  await f.clockAt(appeared + day + 3 * hour, 'hours later');
  await r.none(n, '§8.1 an alert given up is never sent', 3000);
  await failingItem(f, /\b500\b/, 'after the give-up: the latest attempt failed, and no delivery has succeeded');

  await up(f);
  await attention(f, 'worker_unready', f.connectionId, 'the worker is ready again', gone);
  await r.none(n, '§8.1 when a raised alert is never delivered its cleared alert is not sent');
  await down(f);
  const next = await attention(f, 'worker_unready', f.connectionId, 'the worker is unready once more');
  const [fresh] = (await r.wait(n + 1, '§8.1 a new item raises a new alert')).slice(n);
  expectAlert(fresh, 'attention.raised', next, '§8.1 the raised alert of the new item');
  await notFailing(f, 'the new alert was delivered');
  await finish(f, r);
}

// Case 31. §8.1: a cleared alert is given up 24 hours after the evaluation that found its item gone. (A) Its raised
// alert was delivered, and the first failed attempt of the cleared alert shows that the controller has found the item
// gone: given up 24 hours after that attempt. (B) Its raised alert still fails when the item goes, and is delivered 20
// hours later: the clock moves only after the 10 seconds within which the controller evaluates a change, and the
// cleared alert is given up 24 hours after that evaluation, not after the delivery of its raised alert. Then starting
// over, with a new URL and with --off, sets failing to false.
async function case31_clearedGiveUp() {
  const f = await fixture('alerts-cleared-give-up', {clock: startAt});
  const r = await receiver(f);
  let accept = {'attention.raised': true, 'attention.cleared': false};   // what the FAKE receiver answers with 200
  r.plan = entry => ({status: accept[entry.data?.event] ? 200 : 500});
  await f.start();
  await f.code(f.connectionId, 'ready', 'the worker is ready');
  await alerts(f, ['--url', r.url()], local, '--url');
  const giveUp = async (base, count, what) => {
    await f.setClock(base + day - 5 * minute);
    const late = (await r.wait(count + 1, `§8.1 the cleared alert is still tried 23 hours 55 minutes after ${what}`)).at(-1);
    expect(late.data?.event === 'attention.cleared', '§8.1 the retry sends the cleared alert', brief(late));
    await f.clockAt(base + day + 2 * minute, 'a retry is due, 24 hours after ' + what);
    await r.none(count + 1, `§8.1 an alert not delivered within 24 hours is given up; the 24 hours of a cleared alert ` +
      `count from the evaluation that found its item gone (${what}, ${new Date(base).toISOString()} or earlier)`, 4000);
  };

  // (A) The raised alert is delivered; the cleared alert fails.
  await down(f);
  const first = await attention(f, 'worker_unready', f.connectionId, 'the worker is unready');
  await r.wait(1, '§8.1 a raised alert, delivered');
  await up(f);
  await attention(f, 'worker_unready', f.connectionId, 'the worker is ready again', gone);
  const c1 = (await r.wait(2, '§8.1 its cleared alert, which the FAKE receiver fails')).at(-1);
  expectAlert(c1, 'attention.cleared', first, '§8.1 the cleared alert');
  await giveUp(c1.at, 2, 'its first attempt');

  // (B) The raised alert still fails when the item goes.
  accept = {'attention.raised': false, 'attention.cleared': false};
  await down(f);
  const back = await attention(f, 'worker_unready', f.connectionId, 'the worker is unready once more');
  const [a1] = (await r.wait(4, '§8.1 the raised alert of the item that came back, which the FAKE receiver fails')).slice(3);
  await up(f);
  await attention(f, 'worker_unready', f.connectionId, 'the worker is ready again', gone);
  const goneAt = Date.parse((await f.readiness(f.connectionId)).since);   // §3: since is when ready last changed
  await r.none(4, '§8.1 a cleared alert waits until its raised alert is delivered (meanwhile the controller ' +
    'evaluates the change, within 10 seconds)');
  accept['attention.raised'] = true;
  const before = r.requests.length;
  await f.setClock(goneAt + 20 * hour);
  const [delivered, d1] = (await r.wait(before + 2, '§8.1 20 hours after the item was gone its raised alert is ' +
    'delivered at a retry, and the cleared alert is tried next')).slice(before);
  expect(isDeepStrictEqual(delivered.data, a1.data) && delivered.status === 200, '§8.1 the retry delivers the raised ' +
    'alert first', brief(delivered));
  expectAlert(d1, 'attention.cleared', back, '§8.1 then the cleared alert');
  near((await failingItem(f, /\b500\b/, 'after the cleared alert failed')).since, d1.endedAt,
    '§8.1 alerts_failing since is the first failure since the last delivery, not an earlier one');
  await giveUp(goneAt + 10 * second, before + 2, 'the evaluation that found the item gone, within 10 seconds of the ' +
    'change and 20 hours before the raised alert was delivered');
  await f.clockAt(goneAt + day + 3 * hour, 'hours later');
  await r.none(before + 3, '§8.1 an alert given up is never sent', 3000);

  // Starting over sets failing to false: a new URL, then --off, each while the latest attempt failed.
  accept = {};
  await failingItem(f, /\b500\b/, 'before a new URL is set');
  await alerts(f, ['--url', r.url('-new')], local, '--url with a new URL while failing');
  await metaAlerts(f, {...local, failing: false}, 'after a new URL: starting over sets failing to false');
  await down(f);
  await r.wait(before + 4, '§8.1 a raised alert to the new URL, which the FAKE receiver fails');
  await failingItem(f, /\b500\b/, 'before --off');
  await alerts(f, ['--off'], off, '--off while failing');
  await metaAlerts(f, {...off, failing: false}, 'after --off: starting over sets failing to false');
  await finish(f, r);
}

await runCases('alerts', [case29_configuration, case29_refusalChangesNothing, case30_raiseAndClear, case30_quietChanges,
  case30_restart, case31_failures, case31_backWhileClearedRetried, case31_backoffAndGiveUp, case31_clearedGiveUp]);
for (const r of receivers) r.close();
