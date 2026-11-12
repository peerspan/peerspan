// Shared plumbing for the revision 2 and 3 contract suites (operations.mjs, visibility.mjs, remote.mjs and
// schedules.mjs). Contract-only and black-box: it launches the documented CLI, speaks HTTP and drives the
// explicitly fake Peerspan executable in throwaway private directories. It never imports or reads the
// managed implementation or its database. Section numbers (§) refer to docs/managed-contract.md.
// Shapes are those of revision 3, which keeps every revision 2 behavior and adds fields (§1: schema 3).
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import http from 'node:http';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {isDeepStrictEqual} from 'node:util';
import {setTimeout as delay} from 'node:timers/promises';

assert.ok(Number(process.versions.node.split('.')[0]) >= 24, 'Run this suite with Node 24 or later');
assert.equal(process.platform, 'linux', 'Throwaway state and permissions must be tested on Linux');
const here = path.dirname(fileURLToPath(import.meta.url));
const cli = path.resolve(here, '../cli.mjs');
const fixtures = [];
let stopped = false;

export {delay};
// Durations are measured on the monotonic clock: the wall clock of a virtual machine can step back.
export const clock = () => performance.now();
// §1: while the wall clock is stepped back by less than ten minutes the controller keeps the newest
// time it has recorded. A suite that compares a time it chose itself with a time the controller
// recorded asks here first whether such a step was seen while it ran.
let lastWallTime = Date.now(), steppedBackMs = 0;
function sampleWallClock() {
  const wall = Date.now();
  if (wall < lastWallTime - 2) steppedBackMs += lastWallTime - wall;
  lastWallTime = wall;
}
setInterval(sampleWallClock, 20).unref();
export const wallClockSteppedBack = (atLeastMs = 3) => { sampleWallClock(); return steppedBackMs >= atLeastMs; };

export const hex = (prefix, digit, length = 32) => prefix + '_' + String(digit).repeat(length);
export const ids = {hostId: hex('host', 1, 64), agentId: hex('agent', 2),
  adapterId: hex('adapter', 3), sessionId: hex('session', 4)};
// §6: the fake answers status for a sender state directory as another host than the worker's.
export const senderHostId = hex('host', 'd', 64);
// Present in every fixture's status, so each response of both suites is checked for §8 privacy.
export const privateAttention = {kind: 'fake_private_history', subject: 'PRIVATE-ATTENTION-SUBJECT',
  detail: 'PRIVATE-ATTENTION-DETAIL', command: 'peerspan --state /PRIVATE-ATTENTION-PATH status'};
const defaults = {...ids, active: true, ready: true, verified: true, verifiedAt: '2026-01-01T00:00:00Z',
  statusExit: 1, statusMalformed: false, submitMode: 'normal', inspectMode: 'normal', eventsMode: 'normal',
  remoteState: 'queued', recordShape: 'rev2', attention: [privateAttention], senderHostId, senderStatusExit: 0,
  senderAttention: [{...privateAttention, kind: 'fake_private_sender_history'}]};

// ---- Assertions with a contract rule and the observed evidence in the failure message ----

export const snippet = value => {
  const text = typeof value === 'string' ? value : JSON.stringify(value) ?? String(value);
  return text.length > 600 ? text.slice(0, 600) + '…' : text;
};
export function expect(condition, rule, evidence) {
  if (!condition) assert.fail(evidence === undefined ? rule : rule + ' | observed: ' + snippet(evidence));
}
export function expectEqual(actual, expected, rule) {
  if (!isDeepStrictEqual(actual, expected)) {
    assert.fail(rule + ' | expected: ' + snippet(expected) + ' | observed: ' + snippet(actual));
  }
}
export function expectStatus(response, status, rule) {
  expect(response.status === status, `${rule}: expected HTTP ${status}, got ${response.status}`, response.text);
  return response;
}
export function expectError(response, status, rule) {
  expectStatus(response, status, rule);
  expect(response.data !== null && isDeepStrictEqual(Object.keys(response.data), ['error']) &&
    typeof response.data.error === 'string', rule + ': §2 errors are JSON {error}', response.text);
  return response;
}
export const isTime = value => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d/.test(value) &&
  Number.isFinite(Date.parse(value));
export const pick = (value, names) => Object.fromEntries(names.split(' ').map(name => [name, value[name]]));
export const option = (argv, name) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : undefined);
// §4: the input travels as the single argument --input=TEXT.
export function inputOf(argv) {
  const inputs = argv.filter(arg => arg.startsWith('--input='));
  expect(inputs.length === 1 && !argv.includes('--input'), '§4 task submit carries exactly one --input=TEXT argument', argv);
  return inputs[0].slice('--input='.length);
}
const nullable = (value, test) => value === null || test(value);
const text = value => typeof value === 'string';
function keys(value, names, rule) {
  expect(value !== null && typeof value === 'object' && !Array.isArray(value), rule + ' must be an object', value);
  expectEqual(Object.keys(value).sort(), names.split(' ').sort(), rule + ' has exactly the contract fields');
}

// ---- Exact shapes of sections 3, 8, 10 and 11, checked on every snapshot either suite fetches ----

export const readinessCodes = {worker_state_invalid: false, identity_changed: false, peerspan_unavailable: false,
  peerspan_incompatible: false, daemon_not_running: false, status_invalid: false, sender_unavailable: false,
  sender_is_worker: false, agent_missing: false, session_not_ready: false, channel_unverified: false,
  ready_service_inactive: true, ready: true};
// §7.1 (rev 3): the table of a remote connection.
export const remoteReadinessCodes = {peerspan_unavailable: false, peerspan_incompatible: false,
  sender_unavailable: false, sender_is_worker: false, directory_unavailable: false, agent_missing: false,
  host_unreachable: false, not_authorized: false, session_not_ready: false, ready: true};
const anyReadinessCode = {...readinessCodes, ...remoteReadinessCodes};
const unresolved = ['submitting', 'queued', 'running'];
const runStates = [...unresolved, 'succeeded', 'failed', 'cancelled', 'rejected', 'expired', 'abandoned'];
const severities = ['action', 'warning', 'info'];
// §8 attention table: kind -> [severity (null: action or warning, by use), subject.type].
const attentionRows = {controller_error: ['action', 'controller'], workflow_auto_paused: ['action', 'workflow'],
  worker_unready: [null, 'connection'], run_problem: ['warning', 'run'], observed_unavailable: ['warning', 'observation'],
  observed_problem: ['warning', 'observation'], daily_limit_reached: ['info', 'workflow'],
  review_pending: ['action', 'workflow']};
const activityKinds = {
  operator: ['workflow.created', 'workflow.paused', 'workflow.resumed', 'workflow.run_requested',
    'workflow.archived', 'workflow.restored', 'workflow.edited', 'run.cancel_requested', 'run.abandoned',
    'run.reviewed', 'connection.added', 'connection.removed', 'observation.added', 'observation.removed'],
  system: ['run.dispatched', 'run.finished', 'run.problem', 'run.recovered', 'workflow.auto_paused',
    'worker.ready', 'worker.unready']};
const runFields = 'id workflowId workflowName taskId state output outputTruncated error reason progress ' +
  'cancelRequestedAt createdAt updatedAt startedAt finishedAt';
export const dayNames = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];

// `mode` is the connection's (§8): file and agent mode use the §3 table, remote mode the §7.1 table.
export function checkReadiness(r, {mode} = {}) {
  keys(r, 'ready code reason checkedAt since hints directoryAt', '§3 readiness');
  if (r.checkedAt === null || r.code === 'checking') {
    expect(r.ready === false && r.code === 'checking' && r.checkedAt === null && isDeepStrictEqual(r.hints, []) &&
      nullable(r.since, isTime) && r.directoryAt === null, '§3 before the first check readiness is ' +
      '{ready:false,code:"checking",checkedAt:null,hints:[],directoryAt:null} with the last recorded since', r);
    return;
  }
  const table = mode === 'remote' ? remoteReadinessCodes : mode === undefined ? anyReadinessCode : readinessCodes;
  expect(Object.hasOwn(table, r.code) && r.ready === table[r.code],
    `§3/§7.1 readiness code and ready value come from the table of a ${mode ?? 'connection'}`, r);
  expect(mode === 'remote' || mode === undefined ? nullable(r.directoryAt, isTime) : r.directoryAt === null,
    '§3 directoryAt is null except for remote connections; §7.1 there it is null or a time', r);
  expect(text(r.reason) && r.reason !== '' && isTime(r.checkedAt) && isTime(r.since),
    '§3 reason is a sentence; checkedAt and since are times', r);
  expect(Array.isArray(r.hints) && r.hints.length <= 10, '§3 hints lists at most ten items', r.hints);
  for (const hint of r.hints) {
    keys(hint, 'kind command', '§3 hint');
    expect(/^[a-z_]{1,64}$/.test(hint.kind) && nullable(hint.command, value => text(value) &&
      /^peerspan [ -~]*$/.test(value) && value.length <= 200 && !/[/\\]/.test(value)),
    '§3 hint kind and command rules', hint);
  }
}

// `detail` is the run of GET /api/runs/:id: full retained output and the submitted instructions (§10).
export function checkRun(run, {detail = false} = {}) {
  keys(run, runFields + ' review reviewedAt reviewNote' + (detail ? ' instructions' : ''), detail ? '§10 run detail' : '§8 run');
  // §15: review is null unless the run ended succeeded and needs review; reviewedAt and reviewNote come
  // with a verdict, the note trimmed, nonempty and at most 2,000 characters.
  const verdict = ['accepted', 'rejected'].includes(run.review);
  expect([null, 'pending', 'accepted', 'rejected'].includes(run.review) && (run.review === null || run.state === 'succeeded') &&
    (verdict ? isTime(run.reviewedAt) : run.reviewedAt === null) && (verdict ? nullable(run.reviewNote, note =>
      text(note) && note !== '' && note.length <= 2000 && note === note.trim()) : run.reviewNote === null),
  '§15 review is null, pending, accepted or rejected (null unless succeeded); reviewedAt and reviewNote only with a ' +
    'verdict, the note trimmed, nonempty and at most 2,000 characters', pick(run, 'state review reviewedAt reviewNote'));
  expect(runStates.includes(run.state) && /^task_[0-9a-f]{32}$/.test(run.taskId) && text(run.id) &&
    text(run.workflowId) && text(run.workflowName), '§8 run identity, state and §4 task ID', run);
  expect(nullable(run.output, value => text(value) && value.length <= (detail ? 262144 : 2000)) &&
    typeof run.outputTruncated === 'boolean', detail ? '§10 retained output is at most 262,144 characters'
    : '§8 snapshot output is at most 2,000 characters', {length: run.output?.length, flag: run.outputTruncated});
  expect(nullable(run.error, text) && nullable(run.reason, value => text(value) && value.length <= 2000) &&
    nullable(run.progress, value => text(value) && value.length <= 300),
  '§8 error, reason (at most 2,000 characters) and progress (at most 300)', pick(run, 'error reason progress'));
  expect(isTime(run.createdAt) && isTime(run.updatedAt) && nullable(run.startedAt, isTime) &&
    nullable(run.cancelRequestedAt, isTime), '§8 run times', run);
  expect(unresolved.includes(run.state) ? run.finishedAt === null : isTime(run.finishedAt),
    '§8 finishedAt is null until the run is terminal', pick(run, 'state finishedAt'));
  if (detail) expect(text(run.instructions) && run.instructions !== '', '§10 run detail has instructions', run);
}

export function checkActivityEntry(entry) {
  keys(entry, 'seq at actor kind workflowId runId connectionId data', '§11 activity entry');
  expect(Number.isInteger(entry.seq) && isTime(entry.at) && activityKinds[entry.actor]?.includes(entry.kind),
    '§11 seq, at, and the kind listed for its actor', entry);
  const [area] = entry.kind.split('.');
  const present = {workflow: ['workflowId'], run: ['runId', 'workflowId'], connection: ['connectionId'],
    worker: ['connectionId'], observation: []}[area];
  const absent = {workflow: ['runId'], run: [], connection: ['workflowId', 'runId'],
    worker: ['workflowId', 'runId'], observation: ['workflowId', 'runId', 'connectionId']}[area];
  expect(present.every(name => text(entry[name])) && absent.every(name => entry[name] === null),
    '§11 an entry carries the references of its kind; absent references are null', entry);
  const only = (data, name) => data !== null && isDeepStrictEqual(Object.keys(data), [name]);
  const dataRules = {
    'workflow.edited': data => only(data, 'fields') && Array.isArray(data.fields) && data.fields.length > 0 &&
      isDeepStrictEqual(data.fields, [...data.fields].sort()),
    'run.finished': data => only(data, 'state') && runStates.includes(data.state) && !unresolved.includes(data.state),
    'workflow.auto_paused': data => only(data, 'failureStreak') && Number.isInteger(data.failureStreak),
    'worker.ready': data => only(data, 'code') && anyReadinessCode[data.code] === true,
    'worker.unready': data => only(data, 'code') && anyReadinessCode[data.code] === false,
    'run.reviewed': data => only(data, 'verdict') && ['accepted', 'rejected'].includes(data.verdict)};
  expect((dataRules[entry.kind] ?? (data => data === null))(entry.data), '§11 data of ' + entry.kind, entry);
}

// §14: a schedule as the controller returns it, normalized.
export function checkSchedule(schedule) {
  keys(schedule, 'timeZone days times', '§14 schedule');
  const {timeZone, days, times} = schedule;
  expect(text(timeZone) && timeZone.length >= 1 && timeZone.length <= 64 && Array.isArray(days) && days.length >= 1 &&
    isDeepStrictEqual(days, dayNames.filter(day => days.includes(day))) && Array.isArray(times) && times.length >= 1 &&
    times.length <= 24 && times.every((time, index) => /^([01]\d|2[0-3]):[0-5]\d$/.test(time) && (index === 0 || times[index - 1] < time)),
  '§14 a schedule is {timeZone,days,times}: distinct days in mon..sun order, 1 to 24 distinct HH:MM times ascending', schedule);
}

function checkWorkflow(w) {
  keys(w, 'id name connectionId instructions intervalMinutes maxRunsPerDay acceptanceMinutes enabled ' +
    'nextRunAt failureStreak blockedReason createdAt updatedAt pausedBy recent stats schedule review', '§8 workflow');
  expect(w.enabled ? w.pausedBy === null : ['operator', 'failures'].includes(w.pausedBy),
    '§8 pausedBy is null while enabled, otherwise operator or failures', pick(w, 'enabled pausedBy'));
  expect((w.schedule === null) !== (w.intervalMinutes === null) && ['none', 'operator'].includes(w.review),
    '§8 exactly one of intervalMinutes and schedule is null; §15 review is none or operator',
    pick(w, 'intervalMinutes schedule review'));
  if (w.schedule !== null) checkSchedule(w.schedule);
  expect(Array.isArray(w.recent) && w.recent.length <= 20, '§8 recent is at most 20 runs', w.recent);
  for (const run of w.recent) {
    keys(run, 'id state createdAt finishedAt review', '§8 recent run');
    expect([null, 'pending', 'accepted', 'rejected'].includes(run.review), '§8 a recent run has the run review', run);
  }
  newestFirst(w.recent, 'createdAt', '§8 recent is newest first');
  keys(w.stats, 'windowDays runs succeeded failed successRate averageSeconds interventions unattendedRuns ' +
    'awaitingReview', '§8 stats');
  const {succeeded, failed, successRate, averageSeconds} = w.stats;
  expect(w.stats.windowDays === 7 && ['runs', 'succeeded', 'failed', 'interventions', 'unattendedRuns', 'awaitingReview']
    .every(name => Number.isInteger(w.stats[name]) && w.stats[name] >= 0) &&
    (succeeded + failed === 0 ? successRate === null : Math.abs(successRate - succeeded / (succeeded + failed)) < 1e-9) &&
    (succeeded === 0 ? averageSeconds === null : Number.isInteger(averageSeconds)),
  '§8 stats: seven-day window, counts, successRate and averageSeconds in whole seconds or null', w.stats);
  expect(w.stats.awaitingReview >= w.recent.filter(run => run.review === 'pending').length,
    '§8 awaitingReview counts every run of the workflow whose review is pending', {stats: w.stats, recent: w.recent});
}

function newestFirst(rows, field, rule) {
  for (let index = 1; index < rows.length; index++) {
    expect(Date.parse(rows[index - 1][field]) >= Date.parse(rows[index][field]), rule, rows.map(row => row[field]));
  }
}

// §8 attention: shape, order, and "present while" for every kind that the snapshot itself explains.
function checkAttention(s) {
  let previous = null;
  for (const item of s.attention) {
    keys(item, 'kind severity subject message since', '§8 attention entry');
    keys(item.subject, 'type id name', '§8 attention subject');
    const [severity, type] = attentionRows[item.kind] ?? [];
    const allowed = severity === null ? ['action', 'warning'] : [severity];
    expect(type === item.subject.type && allowed.includes(item.severity) &&
      text(item.message) && item.message !== '' && nullable(item.since, isTime) && text(item.subject.id) &&
      text(item.subject.name), '§8 attention kind with its severity and subject type, a message and since', item);
    const position = [severities.indexOf(item.severity), item.since === null ? Infinity : Date.parse(item.since)];
    if (previous) {
      expect(previous[0] < position[0] || (previous[0] === position[0] && previous[1] <= position[1]),
        '§8 attention is ordered by severity, then since oldest first, null last',
        s.attention.map(entry => pick(entry, 'kind severity since')));
    }
    previous = position;
  }
  const expected = [];
  for (const c of s.connections) {
    if (c.readiness === null || c.readiness.ready || c.readiness.code === 'checking') continue;
    const inUse = s.workflows.some(w => w.enabled && w.connectionId === c.id);
    expected.push({kind: 'worker_unready', severity: inUse ? 'action' : 'warning',
      subject: {type: 'connection', id: c.id, name: c.name}, message: c.readiness.reason, since: c.readiness.since});
  }
  for (const w of s.workflows) {
    if (w.pausedBy === 'failures') expected.push({kind: 'workflow_auto_paused', severity: 'action', subject: {type: 'workflow', id: w.id, name: w.name}});
  }
  for (const run of s.runs) {
    if (unresolved.includes(run.state) && run.error !== null) expected.push({kind: 'run_problem', severity: 'warning', subject: {type: 'run', id: run.id, name: run.workflowName}});
  }
  for (const o of s.observed) {
    const kind = !o.available ? 'observed_unavailable' : o.error !== null ? 'observed_problem' : null;
    if (kind) expected.push({kind, severity: 'warning', subject: {type: 'observation', id: o.id, name: o.name}});
  }
  // review_pending (rev 3): one item per workflow, archived or not, with a pending run. A workflow's
  // awaitingReview says so; for an archived workflow only its runs among the newest 100 can show it, so an
  // item for an archived workflow without such a visible run is allowed but not required.
  const pendingRuns = id => s.runs.filter(run => run.workflowId === id && run.review === 'pending');
  const reviewed = [...s.workflows.filter(w => w.stats.awaitingReview > 0),
    ...s.archived.filter(a => pendingRuns(a.id).length > 0)];
  for (const w of reviewed) expected.push({kind: 'review_pending', severity: 'action', subject: {type: 'workflow', id: w.id, name: w.name}});
  const optional = item => item.kind === 'review_pending' && s.archived.some(a => a.id === item.subject.id);
  const derived = Object.keys(attentionRows).filter(kind => !['controller_error', 'daily_limit_reached'].includes(kind));
  const label = item => item.kind + ' ' + item.subject.id;
  const wanted = expected.map(label);
  expectEqual(s.attention.filter(item => derived.includes(item.kind) && (wanted.includes(label(item)) || !optional(item)))
    .map(label).sort(), wanted.sort(), '§8 an attention entry is present exactly while its table row applies');
  for (const want of expected) {
    const found = s.attention.find(item => label(item) === label(want));
    expectEqual(pick(found, Object.keys(want).join(' ')), want, '§8 attention row for ' + want.kind);
  }
  const words = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten'];
  for (const item of s.attention.filter(entry => entry.kind === 'review_pending')) {
    expect(s.workflows.some(w => w.id === item.subject.id) || optional(item),
      '§8 review_pending names a workflow, archived or not', item);
    const count = s.workflows.find(w => w.id === item.subject.id)?.stats.awaitingReview ?? null;
    if (count !== null) {
      expect(new RegExp(`(^|\\D)${count}(\\D|$)`).test(item.message) ||
        new RegExp(`\\b${words[count] ?? 'NO-WORD'}\\b`, 'i').test(item.message),
      `§8 review_pending message gives the number of pending runs (${count})`, item.message);
    }
    const visible = pendingRuns(item.subject.id);
    if (visible.length > 0 && (count === null || visible.length === count)) {
      expectEqual(Date.parse(item.since), Math.min(...visible.map(run => Date.parse(run.finishedAt))),
        '§8 review_pending since is the earliest finishedAt of the pending runs (as instants)');
    }
  }
}

export function checkSnapshot(s) {
  keys(s, 'connections workflows runs observed attention activity archived meta', '§8 snapshot');
  for (const c of s.connections) {
    keys(c, 'id name hostId agentId mode readiness', '§8 connection');
    expect(['file', 'agent', 'remote'].includes(c.mode), '§8 mode is file, agent or remote', c.mode);
    if (c.readiness !== null) checkReadiness(c.readiness, {mode: c.mode});
  }
  s.workflows.forEach(checkWorkflow);
  for (let index = 1; index < s.workflows.length; index++) {
    expect(Date.parse(s.workflows[index - 1].createdAt) <= Date.parse(s.workflows[index].createdAt),
      '§8 workflows are oldest first', s.workflows.map(w => w.createdAt));
  }
  expect(s.runs.length <= 100, '§8 runs lists at most the newest 100', s.runs.length);
  s.runs.forEach(run => checkRun(run));
  newestFirst(s.runs, 'createdAt', '§8 runs are newest first');
  for (const o of s.observed) {
    keys(o, 'id name available enabled cycle phase lastTickAt error task lastBatch', '§6 observation entry');
  }
  checkAttention(s);
  expect(s.activity.length <= 30, '§8 activity lists the newest 30 entries', s.activity.length);
  s.activity.forEach(checkActivityEntry);
  expect(s.activity.every((entry, index) => index === 0 || s.activity[index - 1].seq > entry.seq),
    '§8 activity is newest first', s.activity.map(entry => entry.seq));
  for (const a of s.archived) keys(a, 'id name archivedAt', '§8 archived entry');
  newestFirst(s.archived, 'archivedAt', '§8 archived is newest first');
  keys(s.meta, 'name version mode revision schemaVersion lastTickAt tickSeconds error modelCostAvailable ' +
    'modelCost cloudProvisioning', '§8 meta');
  expect(s.meta.modelCostAvailable === false && s.meta.cloudProvisioning === false && text(s.meta.revision) &&
    s.meta.revision !== '' && s.meta.schemaVersion === 3, '§8 meta: no model cost, no cloud provisioning, ' +
    'an opaque revision string and §1 schema version 3', s.meta);
}

// ---- Process and file plumbing ----

export async function until(description, check, timeout = 10000) {
  const end = clock() + timeout;
  let last;
  while (clock() < end && !stopped) {
    try { const value = await check(); if (value) return value; }
    catch (error) { last = error; }
    await delay(80);
  }
  const what = typeof description === 'function' ? description() : description;
  throw new Error((stopped ? 'Stopped by the suite watchdog: ' : 'Timed out: ') + what, {cause: last});
}

export async function command(args, env, timeout = 8000) {
  const child = spawn(process.execPath, [cli, ...args], {env, stdio: ['ignore', 'pipe', 'pipe']});
  let stdout = '', stderr = '';
  child.stdout.on('data', data => stdout += data);
  child.stderr.on('data', data => stderr += data);
  const timer = setTimeout(() => child.kill('SIGKILL'), timeout);
  const code = await new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('exit', resolve);
  });
  clearTimeout(timer);
  return {code, stdout, stderr};
}

export async function freePort() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

export async function writeJson(file, value) {
  const temp = file + '.new';
  await fs.writeFile(temp, JSON.stringify(value), {mode: 0o600});
  await fs.rename(temp, file);
}

// The fake appends one JSON line per write; a line still being written is left for the next read.
export async function jsonLines(file) {
  const lines = (await fs.readFile(file, 'utf8').catch(() => '')).split('\n').filter(Boolean);
  return lines.flatMap((line, index) => {
    try { return [JSON.parse(line)]; }
    catch (error) { if (index === lines.length - 1) return []; throw error; }
  });
}

// A private external controller directory for `observe` (§5), with markers that must never be returned.
export async function observedDirectory(f, state = {}) {
  const dir = path.join(f.dir, 'PRIVATE-external-controller');
  await fs.mkdir(dir, {mode: 0o700});
  const files = {
    'config.json': JSON.stringify({enabled: true, token: 'PRIVATE-OBSERVATION-TOKEN', directory: dir}),
    'state.json': JSON.stringify({cycle: 7, phase: 'FAKE watching', lastTickAt: '2026-01-01T00:00:00Z', error: null,
      task: null, lastBatch: null, reportPath: dir, secret: 'PRIVATE-STATE-SECRET', ...state}),
    'events.jsonl': '{"secret":"PRIVATE-EVENT-SECRET"}\n'};
  for (const [name, content] of Object.entries(files)) await fs.writeFile(path.join(dir, name), content, {mode: 0o600});
  return {dir, files};
}

// ---- One throwaway controller: private state, a copy of the fake executable, HTTP and CLI helpers ----

// `clock` (rev 3): an instant (ISO string or milliseconds) the controller's clock starts at, through
// MANAGED_CLOCK_FILE (§1); f.setClock and f.clockAt move it, f.now() is the suite's view of it.
export async function fixture(label, {connect = true, config = {}, env: extraEnv = {}, clock: startAt} = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'FAKE-managed-conformance-' + label + '-'));
  await fs.chmod(dir, 0o700);
  const state = path.join(dir, 'private-managed-state');
  const fake = path.join(dir, 'explicitly-fake-peerspan');
  await fs.copyFile(path.join(here, 'fake-peerspan.mjs'), fake);
  await fs.chmod(fake, 0o700);
  await fs.mkdir(path.join(dir, 'remote'), {mode: 0o700});
  await fs.writeFile(path.join(dir, 'calls.jsonl'), '', {mode: 0o600});
  const workerFile = path.join(dir, 'PRIVATE-worker.json');
  const workerDir = path.join(dir, 'PRIVATE-worker-host');
  const senderDir = path.join(dir, 'PRIVATE-sender');
  const worker = {host_dir: workerDir, host_id: ids.hostId, agent_id: ids.agentId,
    adapter_id: ids.adapterId, session_id: ids.sessionId};
  await writeJson(workerFile, worker);
  const clockFile = startAt === undefined ? null : path.join(dir, 'FAKE-clock-offset-ms');
  const env = {...process.env, PEERSPAN_BIN: fake, FAKE_PEERSPAN_FIXTURE: dir, MANAGED_TICK_MS: '100',
    ...(clockFile ? {MANAGED_CLOCK_FILE: clockFile} : {}), ...extraEnv};
  // senderStates tells the fake which state directories are sender hosts (§6).
  const f = {label, dir, state, fake, workerFile, workerDir, senderDir, worker, env,
    config: {...defaults, senderStates: [senderDir], ...config}, child: null, logs: '', token: '',
    connectionId: null, port: await freePort(), secrets: [dir], streams: [], seen: new Set(), offset: 0};
  fixtures.push(f);

  f.configure = async patch => {
    Object.assign(f.config, patch);
    await writeJson(path.join(dir, 'config.json'), f.config);
  };
  await f.configure({});
  // §1 (rev 3): the file holds the whole milliseconds the controller adds to the system clock.
  const instant = value => (typeof value === 'number' ? value : Date.parse(value));
  f.now = () => Date.now() + f.offset;
  f.setClock = async at => {
    assert.ok(clockFile, label + ': this fixture was created without a clock');
    f.offset = Math.round(instant(at) - Date.now());
    await fs.writeFile(clockFile + '.new', String(f.offset) + '\n', {mode: 0o600});
    await fs.rename(clockFile + '.new', clockFile);
  };
  // Moves the clock and, while serving, waits for a scheduler pass that ran on it (meta.lastTickAt).
  f.clockAt = async (at, why = 'the suite moved the clock') => {
    await f.setClock(at);
    if (!f.child) return;
    let last = null;
    await until(() => `§1 a changed MANAGED_CLOCK_FILE takes effect at the next scheduler pass, which starts within ` +
      `one second (${why}): meta.lastTickAt should reach ${new Date(instant(at)).toISOString()}, last ${last}`, async () => {
      last = (await f.snapshot()).meta.lastTickAt;
      return Date.parse(last) >= instant(at);
    }, 5000);
  };
  if (clockFile) await f.setClock(startAt);
  f.cli = async (...args) => command([...args, '--state', state], env);
  f.checkedCli = async (...args) => {
    const result = await f.cli(...args);
    assert.equal(result.code, 0, snippet({args, ...result}));
    return result.stdout.trim();
  };
  if (connect) {
    f.connectionId = JSON.parse(await f.checkedCli('connect', '--name', 'FAKE-CONFORMANCE ' + label,
      '--worker-state', workerFile, '--sender-state', senderDir)).id;
    assert.ok(f.connectionId, 'connect returns the registered id');
  }

  // §8: no response of any route contains a filesystem path, the access token, a session cookie value,
  // a state directory location, or upstream attention detail or subject text. Every PRIVATE- marker in
  // this fixture is one of those, and so is the fixture directory itself.
  f.assertPrivate = (body, where) => {
    for (const secret of ['PRIVATE-', ...f.secrets]) {
      if (!body.includes(secret)) continue;
      const at = body.indexOf(secret);
      assert.fail(`§8 privacy: ${where} returns ${JSON.stringify(secret)} | observed: ` +
        snippet(body.slice(Math.max(0, at - 100), at + 200)));
    }
    if (f.token && body.includes(f.token)) assert.fail(`§8 privacy: ${where} returns the access token`);
  };
  f.headers = options => ({Host: '127.0.0.1:' + f.port,
    ...(options.auth === false ? {} : {Authorization: 'Bearer ' + f.token}), ...options.headers});
  f.origin = 'http://127.0.0.1:' + f.port;
  f.request = async (method, route, body, options = {}) => {
    const headers = f.headers(options);
    let payload;
    if (body !== undefined) {
      payload = options.raw ? body : JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(payload);
    }
    const response = await new Promise((resolve, reject) => {
      const req = http.request({hostname: '127.0.0.1', port: f.port, method, path: route, headers}, res => {
        let received = '';
        res.setEncoding('utf8');
        res.on('data', chunk => received += chunk);
        res.on('end', () => {
          let data; try { data = JSON.parse(received); } catch { data = null; }
          resolve({status: res.statusCode, headers: res.headers, text: received, data});
        });
      });
      req.on('error', reject);
      req.setTimeout(6000, () => req.destroy(new Error('HTTP request timed out: ' + method + ' ' + route)));
      req.end(payload);
    });
    f.assertPrivate(response.text, method + ' ' + route);
    return response;
  };
  // GET /api/events (§12). Resolves at the response headers; `changes`, `comments` and `retry` fill in
  // as the stream is read, and `done` resolves when the server ends it.
  f.stream = (options = {}) => new Promise((resolve, reject) => {
    const req = http.request({hostname: '127.0.0.1', port: f.port, method: 'GET', path: '/api/events',
      headers: {...f.headers(options), Accept: 'text/event-stream'}}, res => {
      let pending = '', current = {}, finish;
      const stream = {status: res.statusCode, headers: res.headers, text: '', changes: [], comments: [],
        retry: null, openedAt: clock(), closed: false, close: () => req.destroy()};
      stream.done = new Promise(done => { finish = done; });
      res.setEncoding('utf8');
      res.on('data', chunk => {
        stream.text += chunk;
        const lines = (pending + chunk).split('\n');
        pending = lines.pop();
        for (const line of lines.map(raw => raw.replace(/\r$/, ''))) {
          if (line === '') {
            if (current.event === 'change') stream.changes.push({at: clock(), data: current.data});
            current = {};
          } else if (line.startsWith(':')) stream.comments.push(clock());
          else if (line.startsWith('retry:')) stream.retry = Number(line.slice(6));
          else if (line.startsWith('event:')) current.event = line.slice(6).trim();
          else if (line.startsWith('data:')) {
            try { current.data = JSON.parse(line.slice(5)); } catch { current.data = line.slice(5); }
          }
        }
      });
      for (const ending of ['end', 'close', 'error']) res.on(ending, () => { stream.closed = true; finish(); });
      stream.change = (rule, matches = () => true, timeout = 3000) =>
        until(() => rule + ' | stream so far: ' + snippet(stream.text), () => stream.changes.find(matches), timeout);
      f.streams.push(stream);
      resolve(stream);
    });
    req.on('error', reject);
    req.end();
  });

  f.start = async () => {
    assert.equal(f.child, null);
    f.child = spawn(process.execPath, [cli, 'serve', '--state', state, '--port', String(f.port)],
      {env, stdio: ['ignore', 'pipe', 'pipe']});
    const child = f.child;
    child.stdout.on('data', data => f.logs += data);
    child.stderr.on('data', data => f.logs += data);
    await until(() => label + ': serve answers /health; output: ' + snippet(f.logs), async () => {
      if (child.exitCode !== null) throw new Error('serve exited with ' + child.exitCode + ': ' + f.logs);
      return (await f.request('GET', '/health', undefined, {auth: false})).status === 200;
    }, 15000);
    f.token = await f.checkedCli('token');
    assert.ok(f.token.length >= 24, 'private token must be nonempty and unguessable');
  };
  // Signals the controller and reports how it exited (§1: exit 0 within 5 seconds).
  f.terminate = async signal => {
    const child = f.child;
    f.child = null;
    const exited = new Promise(resolve => child.once('exit', (code, killedBy) => resolve({code, signal: killedBy})));
    const at = clock();
    child.kill(signal);
    const killer = setTimeout(() => child.kill('SIGKILL'), 9000);
    const result = await exited;
    clearTimeout(killer);
    return {...result, ms: Math.round(clock() - at)};
  };
  f.stop = async (signal = 'SIGTERM') => {
    for (const stream of f.streams.splice(0)) stream.close();
    const child = f.child;
    f.child = null;
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    const exited = new Promise(resolve => child.once('exit', resolve));
    child.kill(signal);
    const killer = setTimeout(() => child.kill('SIGKILL'), 2000);
    await exited;
    clearTimeout(killer);
  };

  f.snapshot = async () => {
    const response = expectStatus(await f.request('GET', '/api/snapshot'), 200, '§2 GET /api/snapshot');
    checkSnapshot(response.data);
    return response.data;
  };
  f.create = async (patch = {}) => expectStatus(await f.request('POST', '/api/workflows', {
    name: 'FAKE-CONFORMANCE ' + label, connectionId: f.connectionId,
    instructions: 'FAKE fixture only: $(touch NEVER_EXECUTE); `not-a-shell`\nUnicode: λ',
    intervalMinutes: 1, maxRunsPerDay: 50, acceptanceMinutes: 5, ...patch}), 201, '§2 POST /api/workflows').data;
  f.action = async (id, action) => expectStatus(await f.request('POST', `/api/workflows/${id}/${action}`, {}),
    200, '§2 POST /api/workflows/:id/' + action).data;
  f.patch = async (id, body) => expectStatus(await f.request('PATCH', '/api/workflows/' + id, body),
    200, '§9 PATCH /api/workflows/:id ' + JSON.stringify(body).slice(0, 80)).data;
  f.workflow = async id => (await f.snapshot()).workflows.find(item => item.id === id);
  f.readiness = async id => (await f.snapshot()).connections.find(item => item.id === id)?.readiness ?? null;
  // Waits for a readiness code; polls past `checking` (§3).
  f.code = async (id, expected, why, timeout) => {
    let last = null;
    return until(() => `§3 readiness code ${expected} when ${why}; last readiness: ${snippet(last)}`, async () => {
      last = await f.readiness(id);
      return last?.code === expected && last;
    }, timeout);
  };
  f.runById = async id => (await f.snapshot()).runs.find(run => run.id === id);
  f.waitRun = async (id, stateValue, timeout) => {
    let last;
    return until(() => `${label}: run reaches ${stateValue}; last seen: ` +
      snippet(last && pick(last, 'state error reason progress cancelRequestedAt')), async () => {
      last = await f.runById(id);
      return last?.state === stateValue && last;
    }, timeout);
  };
  // The next run of a workflow that this fixture has not handed out yet, optionally in one state.
  f.newRun = async (workflowId, stateValue, timeout) => {
    let last = [];
    const run = await until(() => `${label}: a new run${stateValue ? ' in state ' + stateValue : ''}; runs: ` +
      snippet(last.map(item => pick(item, 'id state error'))), async () => {
      last = (await f.snapshot()).runs.filter(item => item.workflowId === workflowId && !f.seen.has(item.id));
      return last.find(item => !stateValue || item.state === stateValue);
    }, timeout);
    f.seen.add(run.id);
    return run;
  };
  f.detail = async id => {
    const response = expectStatus(await f.request('GET', '/api/runs/' + id), 200, '§10 GET /api/runs/:id');
    keys(response.data, 'run events', '§10 run detail response');
    checkRun(response.data.run, {detail: true});
    for (const item of response.data.events) keys(item, 'sequence kind state message at', '§10 timeline event');
    expect(response.data.events.every((item, index, all) => index === 0 || all[index - 1].sequence < item.sequence),
      '§10 events are ascending', response.data.events.map(item => item.sequence));
    return response.data;
  };

  // What the fake logged in this fixture directory: argument arrays, exit statuses and hanging calls.
  f.calls = () => jsonLines(path.join(dir, 'calls.jsonl'));
  f.outcomes = () => jsonLines(path.join(dir, 'outcomes.jsonl'));
  f.hanging = () => jsonLines(path.join(dir, 'hanging.jsonl'));
  const isTask = (argv, sub, taskId) => argv[argv.indexOf('task') + 1] === sub && argv.includes('task') &&
    (taskId === undefined || argv.includes(taskId));
  f.taskCalls = async (sub, taskId) => (await f.calls()).filter(call => isTask(call.argv, sub, taskId));
  f.taskOutcomes = async (sub, taskId) => (await f.outcomes()).filter(call => isTask(call.argv, sub, taskId));
  f.submissions = () => f.taskCalls('submit');
  f.awaitSubmissions = async (count, why, timeout) => {
    let seen = 0;
    return until(() => `${why}: expected ${count} task submit invocation(s) in all, the fake logged ${seen}`,
      async () => (seen = (await f.submissions()).length) === count, timeout);
  };
  f.cancelSent = taskId => until(label + ': a task cancel invocation exits 0',
    async () => (await f.taskOutcomes('cancel', taskId)).find(call => call.code === 0));

  // The fake sender daemon's record of a task, driven directly as the remote agent would.
  f.remoteFile = taskId => path.join(dir, 'remote', taskId + '.json');
  f.remoteEvent = async (taskId, kind, {message = null, output = null, at = new Date().toISOString()} = {}) => {
    const remote = JSON.parse(await fs.readFile(f.remoteFile(taskId), 'utf8'));
    const sequence = remote.status.last_event + 1;
    const stateValue = ['accepted', 'progress'].includes(kind) ? 'running' : kind;
    const recorded = {sequence, kind, state: stateValue, message, output, created_at: at};
    remote.status = {...remote.status, state: stateValue, last_event: sequence};
    remote.events.push(recorded);
    await writeJson(f.remoteFile(taskId), remote);
    return recorded;
  };
  f.finish = async (run, stateValue, {message = null, output, at, timeout} = {}) => {
    const final = ['succeeded', 'failed'].includes(stateValue) ? output ?? `FAKE ${stateValue} output` : null;
    await f.remoteEvent(run.taskId, stateValue, {message, output: final, at});
    return f.waitRun(run.id, stateValue, timeout);
  };
  return f;
}

// ---- Runner: concurrent cases, a watchdog under the two-minute budget, and cleanup ----

export async function runCases(suite, cases) {
  const started = clock();
  const seconds = since => ((clock() - since) / 1000).toFixed(1);
  let failures = 0;
  const watchdog = setTimeout(() => {
    console.error('FAIL: bounded suite exceeded 115 seconds');
    failures++;
    stopped = true;
    for (const f of fixtures) f.child?.kill('SIGKILL');
  }, 115000);
  try {
    await Promise.all(cases.map(async runCase => {
      const start = clock();
      try {
        await runCase();
        console.log(`PASS ${runCase.name} (${seconds(start)}s)`);
      } catch (error) {
        failures++;
        console.error(`FAIL ${runCase.name} (${seconds(start)}s):`, error.stack);
        for (let cause = error.cause; cause; cause = cause.cause) console.error('  cause:', cause.stack ?? cause);
      }
    }));
  } finally {
    clearTimeout(watchdog);
    for (const f of fixtures) {
      await f.stop('SIGKILL');
      if (process.env.KEEP_FAKE_MANAGED_FIXTURES === '1') console.log('FAKE fixture retained: ' + f.dir);
      else await fs.rm(f.dir, {recursive: true, force: true});
    }
  }
  const passed = Math.max(0, cases.length - failures);
  console.log(`${suite}: ${passed}/${cases.length} cases passed in ${seconds(started)}s; ` +
    'fake adapter only, no model or transport validation.' +
    (wallClockSteppedBack() ? ` The wall clock stepped back by ${steppedBackMs} ms in all during this run (§1).` : ''));
  process.exitCode = failures ? 1 : 0;
  setTimeout(() => process.exit(), 3000).unref();
}
