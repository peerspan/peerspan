#!/usr/bin/env node
// Contract-only black-box suite for docs/managed-contract.md revision 2, section 14, cases 11 and 12:
// timeline, history and activity; live updates and boundaries. Cases 7 to 10 are in operations.mjs.
// No imports or reads of the managed implementation or its database: the documented CLI, HTTP, the
// explicitly fake Peerspan executable and throwaway state only. Two cases CREATE an input database
// with node:sqlite, exactly as the contract documents it, and never read a database afterwards.
// Section numbers (§) in comments and failure messages refer to that contract.
import fs from 'node:fs/promises';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {isDeepStrictEqual} from 'node:util';
import {checkActivityEntry, checkRun, clock, delay, expect, expectEqual, expectError, expectStatus, fixture, hex,
  ids, inputOf, observedDirectory, option, pick, runCases, until, wallClockSteppedBack} from './harness.mjs';

// Case 11. §8: runs, stats, attention, activity and meta in the snapshot; §10: run history and detail;
// §11: the activity log. The shape, order and "present while" rules of §8 are checked on every snapshot.
async function case11_timelineHistoryAndActivity() {
  const f = await fixture('visibility');
  const external = await observedDirectory(f, {error: 'FAKE observed controller reports a problem'});
  const observation = JSON.parse(await f.checkedCli('observe', '--name', 'FAKE observed', '--directory', external.dir)).id;
  await f.start();
  const spare = JSON.parse(await f.checkedCli('connect', '--name', 'FAKE spare worker',
    '--worker-state', f.workerFile, '--sender-state', f.senderDir)).id;
  await f.code(f.connectionId, 'ready', 'the worker is ready');
  await f.code(spare, 'ready', 'a connection registered while serving is checked without a restart');
  const attention = (kind, id, present = true) => until(`§8 attention ${kind} ${present ? 'appears' : 'clears'}`, async () => {
    const found = (await f.snapshot()).attention.find(item => item.kind === kind && item.subject.id === id);
    return present ? found : !found;
  });
  const {meta} = await f.snapshot();
  expect(/unavailable/i.test(String(meta.modelCost)), '§8 meta.modelCost says that model cost is unavailable', meta);
  await attention('observed_problem', observation);
  const idle = await f.create({name: 'FAKE idle'});
  expectEqual((await f.workflow(idle.id)).stats, {windowDays: 7, runs: 0, succeeded: 0, failed: 0, successRate: null,
    averageSeconds: null, interventions: 0, unattendedRuns: 0, awaitingReview: 0}, '§8 stats of a workflow that has not run');
  const workflow = await f.create({enabled: true});
  const stats = async () => (await f.workflow(workflow.id)).stats;
  const first = await f.newRun(workflow.id, 'queued');
  expectEqual(pick(first, 'startedAt progress output outputTruncated reason'),
    {startedAt: null, progress: null, output: null, outputTruncated: false, reason: null},
    '§8 a queued run has not started and has no progress, output or reason');

  // Attention: an unready worker (action when an enabled workflow uses it, otherwise warning), a run problem.
  await f.configure({ready: false});
  expectEqual([(await attention('worker_unready', f.connectionId)).severity, (await attention('worker_unready', spare)).severity],
    ['action', 'warning'], '§8 worker_unready is action when an enabled workflow uses the connection, otherwise warning');
  await f.configure({ready: true});
  await attention('worker_unready', f.connectionId, false);
  await f.configure({inspectMode: 'error'});
  await attention('run_problem', first.id);
  await f.configure({inspectMode: 'normal'});
  await attention('run_problem', first.id, false);

  // Timeline: accepted, progress, then a long output. The accepted event carries the time of this
  // machine, which normally lies between createdAt and the controller's observation, so startedAt is that
  // time. Only when the wall clock was stepped back (§1: the controller's time then stands still) can the
  // event time lie before createdAt, or after the controller's observation, and be kept inside them.
  const accepted = await f.remoteEvent(first.taskId, 'accepted');
  await until('§8 startedAt is the accepted event time once that event is retained', async () => {
    const run = await f.runById(first.id);
    const [createdAt, startedAt, eventAt] = [run.createdAt, run.startedAt, accepted.created_at].map(Date.parse);
    return run.state === 'running' && (startedAt === eventAt || (wallClockSteppedBack() &&
      (startedAt === Math.max(eventAt, createdAt) || (startedAt >= createdAt && startedAt < eventAt))));
  });
  await f.remoteEvent(first.taskId, 'progress', {message: 'FAKE progress one'});
  await until('§8 progress is the latest progress event message',
    async () => (await f.runById(first.id)).progress === 'FAKE progress one');
  const long = await f.remoteEvent(first.taskId, 'progress', {message: 'FAKE progress two ' + 'p'.repeat(2400)});
  const preview = await until('§8 progress follows the latest progress event', async () => {
    const run = await f.runById(first.id);
    return run.progress !== 'FAKE progress one' && run;
  });
  expect(preview.progress.startsWith('FAKE progress two'), '§8 progress is the latest message, at most 300 characters', preview.progress);
  const live = await f.detail(first.id);
  const shown = live.events.find(event => event.sequence === long.sequence);
  expect(shown && shown.kind === 'progress' && shown.state === 'running' && shown.message.length <= 2000 &&
    shown.message.startsWith('FAKE progress two') && Date.parse(shown.at) === Date.parse(long.created_at),
  '§10 the timeline shows a progress event as {sequence,kind,state,message,at}, message at most 2,000 characters',
  shown ?? live.events);
  const output = 'FAKE output ' + 'o'.repeat(4988);
  const done = await f.finish(first, 'succeeded', {output});
  expectEqual([done.output, done.outputTruncated], [output.slice(0, 2000), true],
    '§8 snapshot output is the first 2,000 characters, with outputTruncated set');
  const full = await f.detail(first.id);
  expectEqual([full.run.output, full.run.outputTruncated], [output, false], '§10 the run detail has the retained output in full');
  expect(full.events.at(-1).kind === 'succeeded' && full.events.at(-1).state === 'succeeded' &&
    !JSON.stringify(full.events).includes('ooooo'),
  '§10 the terminal event is retained and output is never repeated in the timeline', full.events.slice(-2));
  const seconds = (Date.parse(done.finishedAt) - Date.parse(done.createdAt)) / 1000;
  const afterOne = await stats();
  expectEqual({...afterOne, averageSeconds: null}, {windowDays: 7, runs: 1, succeeded: 1, failed: 0, successRate: 1,
    averageSeconds: null, interventions: 0, unattendedRuns: 1, awaitingReview: 0}, '§8 stats after one success without intervention');
  expect(Math.abs(afterOne.averageSeconds - seconds) <= 1,
    '§8 averageSeconds is finishedAt minus createdAt of the succeeded runs, in whole seconds', {...afterOne, seconds});

  // Statistics follow interventions; reason; clocks of another host; the retained output limit.
  await f.action(workflow.id, 'run');
  expectEqual(pick(await stats(), 'interventions unattendedRuns'), {interventions: 1, unattendedRuns: 0},
    '§8 an operator request is an intervention, and unattendedRuns counts runs finished after the latest one');
  const second = await f.newRun(workflow.id, 'queued');
  const declined = await f.finish(second, 'rejected', {message: 'FAKE declined\u0007: ' + 'r'.repeat(2100)});
  expect(declined.reason.startsWith('FAKE declined: rrr'),
    '§8 reason is the terminal event message, at most 2,000 characters, with control characters removed',
    declined.reason.slice(0, 40));
  expectEqual(pick(await stats(), 'runs succeeded failed successRate unattendedRuns'),
    {runs: 2, succeeded: 1, failed: 1, successRate: 0.5, unattendedRuns: 1}, '§8 stats after a success and a rejection');
  await f.action(workflow.id, 'run');
  const third = await f.newRun(workflow.id, 'queued');
  await f.remoteEvent(third.taskId, 'accepted', {at: '2020-01-01T00:00:00.000Z'});
  await until('§8 an accepted event time before createdAt is kept at createdAt', async () => {
    const run = await f.runById(third.id);
    return run.state === 'running' && Date.parse(run.startedAt) === Date.parse(run.createdAt);
  });
  const failed = await f.finish(third, 'failed', {output: 'B'.repeat(262144) + 'FAKE-TAIL-BEYOND-THE-LIMIT',
    at: '2020-01-01T00:05:00.000Z', timeout: 20000});
  expect(Date.parse(failed.finishedAt) >= Date.parse(failed.createdAt) && Date.parse(failed.startedAt) === Date.parse(failed.createdAt),
    '§8 finishedAt is when the controller retained the result, whatever the other host clock says',
    pick(failed, 'createdAt startedAt finishedAt'));
  const big = (await f.detail(third.id)).run;
  expect(big.output.length > 2000 && big.outputTruncated === true && !big.output.includes('FAKE-TAIL') &&
    failed.output === big.output.slice(0, 2000) && failed.outputTruncated === true,
  '§10 the retained output is at most 262,144 characters with outputTruncated set; the snapshot has its first 2,000',
  {retained: big.output.length, detailFlag: big.outputTruncated, snapshotFlag: failed.outputTruncated});

  // The failure circuit, then operator results: cancelled on request and abandoned.
  await f.action(workflow.id, 'run');
  await f.finish(await f.newRun(workflow.id, 'queued'), 'expired');
  await attention('workflow_auto_paused', workflow.id);
  const tripped = await f.workflow(workflow.id);
  expect(tripped.pausedBy === 'failures' && tripped.failureStreak === 3 && tripped.blockedReason,
    '§4 three consecutive failures pause the workflow with pausedBy failures and a visible reason',
    pick(tripped, 'enabled pausedBy failureStreak blockedReason'));
  await f.action(workflow.id, 'resume');
  await f.action(workflow.id, 'run');
  const fifth = await f.newRun(workflow.id, 'queued');
  await f.remoteEvent(fifth.taskId, 'accepted', {at: '2099-01-01T00:00:00.000Z'});
  await f.waitRun(fifth.id, 'running');
  for (let request = 0; request < 2; request++) {
    expectStatus(await f.request('POST', `/api/runs/${fifth.id}/cancel`, {}), 200, '§10 cancel');
  }
  await f.cancelSent(fifth.taskId);
  const stopped = await f.finish(fifth, 'cancelled');
  expect(Date.parse(stopped.startedAt) >= Date.parse(stopped.createdAt) && Date.parse(stopped.startedAt) <= Date.parse(stopped.finishedAt),
    '§8 an accepted event time in the future is kept at the time the controller observed it',
    pick(stopped, 'createdAt startedAt finishedAt'));
  await f.action(workflow.id, 'run');
  const sixth = await f.newRun(workflow.id, 'queued');
  expectStatus(await f.request('POST', `/api/runs/${sixth.id}/abandon`, {confirm: sixth.taskId}), 200, '§10 abandon');

  // The daily cap, then the remaining operator kinds of the activity log.
  await f.patch(workflow.id, {maxRunsPerDay: 6});
  await f.action(workflow.id, 'run');
  await attention('daily_limit_reached', workflow.id);
  expect((await f.workflow(workflow.id)).blockedReason && (await f.submissions()).length === 6,
    '§4 six runs were reserved today and the cap of six blocks the seventh', await f.workflow(workflow.id));
  await f.action(workflow.id, 'pause');
  await f.action(workflow.id, 'pause');
  await f.patch(workflow.id, {name: 'FAKE renamed visibility', maxRunsPerDay: 50});
  await f.patch(workflow.id, {name: 'FAKE renamed visibility'});   // changes no value
  for (const action of ['archive', 'restore']) {
    expectStatus(await f.request('POST', `/api/workflows/${workflow.id}/${action}`, {}), 200, '§9 ' + action);
  }
  await fs.writeFile(path.join(external.dir, 'state.json'), 'FAKE malformed JSON');
  await attention('observed_unavailable', observation);
  await f.checkedCli('unobserve', '--id', observation);
  await f.checkedCli('disconnect', '--id', spare);
  await until('§1 removed registrations leave the snapshot without a restart', async () => {
    const now = await f.snapshot();
    return now.observed.length === 0 && now.connections.length === 1;
  });

  // Run history pages.
  const page = async (route, field) => {
    const response = expectStatus(await f.request('GET', route), 200, 'GET ' + route);
    expectEqual(Object.keys(response.data).sort(), [field, 'nextBefore'].sort(), `GET ${route} returns {${field},nextBefore}`);
    return response.data;
  };
  const runIds = (await f.snapshot()).runs.map(run => run.id);
  expectEqual(runIds.length, 6, '§8 six runs so far');
  const pageOne = await page('/api/runs?limit=4', 'runs');
  expect(pageOne.runs.length === 4 && pageOne.nextBefore !== null, '§10 a first page of four of six runs names the next page', pageOne.nextBefore);
  const pageTwo = await page('/api/runs?limit=4&before=' + encodeURIComponent(pageOne.nextBefore), 'runs');
  expectEqual([[...pageOne.runs, ...pageTwo.runs].map(run => run.id), pageTwo.nextBefore], [runIds, null],
    '§10 run history pages newest first; nextBefore is the before value of the next page and null on the last page');
  [...pageOne.runs, ...pageTwo.runs].forEach(run => checkRun(run));
  expectEqual(await page('/api/runs?workflowId=' + idle.id, 'runs'), {runs: [], nextBefore: null}, '§10 workflowId filters run history');
  expectEqual((await page(`/api/runs?limit=200&workflowId=${workflow.id}`, 'runs')).runs.map(run => run.id), runIds,
    '§10 run history of one workflow, limit 200');
  expectEqual((await page('/api/runs', 'runs')).runs.length, 6, '§10 run history without a query');
  for (const query of ['limit=0', 'limit=201', 'limit=abc']) {
    expectError(await f.request('GET', '/api/runs?' + query), 400, '§10 run history with ' + query);
    expectError(await f.request('GET', '/api/activity?' + query), 400, '§11 activity with ' + query);
  }
  expectError(await f.request('GET', '/api/activity?before=abc'), 400, '§2 activity with before=abc');

  // The activity log, walked in pages of seven.
  const log = [];
  for (let before = '', pages = 0; before !== null; pages++) {
    expect(pages < 100, '§11 activity paging ends', before);
    const data = await page('/api/activity?limit=7' + (before === '' ? '' : '&before=' + encodeURIComponent(before)), 'activity');
    expect(data.activity.length <= 7, '§11 a page has at most limit entries', data.activity.length);
    log.push(...data.activity);
    before = data.nextBefore;
  }
  log.forEach(checkActivityEntry);
  expect(log.every((entry, index) => index === 0 || log[index - 1].seq === entry.seq + 1),
    '§11 seq increases by one per entry; pages are newest first, without gaps or repeats', log.map(entry => entry.seq));
  expectEqual((await f.snapshot()).activity, log.slice(0, 30), '§8 snapshot activity is the newest 30 entries, newest first');
  const main = {workflowId: workflow.id}, worker = {connectionId: f.connectionId};
  const ofRun = run => ({runId: run.id, workflowId: workflow.id});
  // [kind, references, data (undefined: any), entries expected]. The actor of each kind is checked above.
  const expected = [
    ['observation.added', {}, null, 1], ['observation.removed', {}, null, 1],
    ['connection.added', worker, null, 1], ['connection.added', {connectionId: spare}, null, 1],
    ['connection.removed', {connectionId: spare}, null, 1],
    ['worker.ready', worker, {code: 'ready'}, 2], ['worker.unready', worker, undefined, 1],
    ['worker.ready', {connectionId: spare}, {code: 'ready'}, 2], ['worker.unready', {connectionId: spare}, undefined, 1],
    ['workflow.created', main, null, 1], ['workflow.created', {workflowId: idle.id}, null, 1],
    ['run.dispatched', main, null, 6], ['run.dispatched', ofRun(first), null, 1],
    ['run.problem', ofRun(first), null, 1], ['run.recovered', ofRun(first), null, 1],
    ['run.finished', ofRun(first), {state: 'succeeded'}, 1], ['run.finished', ofRun(second), {state: 'rejected'}, 1],
    ['run.finished', ofRun(third), {state: 'failed'}, 1], ['run.finished', ofRun(fifth), {state: 'cancelled'}, 1],
    ['run.finished', main, {state: 'expired'}, 1], ['workflow.auto_paused', main, {failureStreak: 3}, 1],
    ['workflow.run_requested', main, null, 6], ['workflow.resumed', main, null, 1], ['workflow.paused', main, null, 2],
    ['workflow.edited', main, {fields: ['maxRunsPerDay']}, 1], ['workflow.edited', main, {fields: ['maxRunsPerDay', 'name']}, 1],
    ['workflow.edited', main, undefined, 2], ['workflow.archived', main, null, 1], ['workflow.restored', main, null, 1],
    ['run.cancel_requested', ofRun(fifth), null, 1], ['run.abandoned', ofRun(sixth), null, 1]];
  for (const [kind, references, data, wanted] of expected) {
    const found = log.filter(entry => entry.kind === kind && (data === undefined || isDeepStrictEqual(entry.data, data)) &&
      Object.entries(references).every(([name, value]) => entry[name] === value));
    expect(found.length === wanted, `§11 activity: expected ${wanted} × ${kind} ${JSON.stringify(references)} ` +
      `${data === undefined ? '' : JSON.stringify(data)}, found ${found.length}`, log.filter(entry => entry.kind === kind));
  }
  const interventions = log.filter(entry => entry.actor === 'operator' && entry.workflowId === workflow.id &&
    entry.kind !== 'workflow.created').length;
  expectEqual(pick(await stats(), 'runs succeeded failed successRate interventions unattendedRuns'),
    {runs: 6, succeeded: 1, failed: 3, successRate: 0.25, interventions, unattendedRuns: 0},
    '§8 stats: failed excludes the cancelled-on-request and abandoned runs; interventions counts the operator ' +
    'entries of the workflow other than workflow.created; no run finished after the latest intervention');

  // A restart alone records nothing for workers and does not move since.
  const {since} = await f.readiness(f.connectionId);
  await f.stop();
  await f.start();
  expectEqual((await f.code(f.connectionId, 'ready', 'the first check after a restart')).since, since,
    '§3 the first check after a start is a change only when the value differs from the one last recorded');
  await delay(300);
  const later = (await page('/api/activity?limit=200', 'activity')).activity.filter(entry => entry.seq > log[0].seq);
  expectEqual(later.filter(entry => entry.kind.startsWith('worker.')), [], '§11 a restart alone records no worker entry');
  await f.stop();
}

// Case 12, live updates. §12: the event stream; §2: the fetch-site rule and the error statuses; §1: SIGINT.
async function case12_liveUpdatesAndFetchSite() {
  const f = await fixture('live');
  await f.start();
  await f.code(f.connectionId, 'ready', 'the worker is ready before a stream opens');
  const parsed = body => { try { return JSON.parse(body); } catch { return null; } };
  const refused = await f.stream({auth: false});
  await Promise.race([refused.done, delay(2000)]);
  expect(refused.status === 401 && typeof parsed(refused.text)?.error === 'string',
    '§12 an unauthenticated stream is refused: 401 with JSON {error}', {status: refused.status, body: refused.text});

  const revisionBefore = (await f.snapshot()).meta.revision;
  const stream = await f.stream();
  expect(stream.status === 200 && /^text\/event-stream/.test(stream.headers['content-type'] ?? ''),
    '§12 GET /api/events is an authenticated text/event-stream', {status: stream.status, type: stream.headers['content-type']});
  const first = await stream.change('§12 one change event is sent immediately', () => true, 2000);
  const revisionAfter = (await f.snapshot()).meta.revision;
  expectEqual(stream.retry, 3000, '§12 the stream sends retry: 3000');
  expect(first.data !== null && isDeepStrictEqual(Object.keys(first.data), ['revision']) &&
    [revisionBefore, revisionAfter].includes(first.data.revision),
  '§12 change data is {"revision":VALUE}, the snapshot meta.revision, and carries no other state',
  {event: first.data, revisionBefore, revisionAfter});
  const workflow = await f.create();
  await stream.change('§12 a change event follows a mutation', event => event.data?.revision !== first.data.revision);
  const settled = () => until('§12 the latest change event carries the current snapshot meta.revision',
    async () => stream.changes.at(-1).data.revision === (await f.snapshot()).meta.revision);
  await settled();
  const burstFrom = stream.changes.length;
  for (let round = 0; round < 2; round++) {
    await Promise.all(Array.from({length: 10}, (unused, index) => f.patch(workflow.id, {name: `FAKE burst ${round}-${index}`})));
  }
  await delay(1500);
  const times = stream.changes.slice(burstFrom).map(event => event.at);
  expect(times.length >= 1 && times.every((at, index) => index < 8 || at - times[index - 8] >= 1000),
    '§12 change events follow a burst of twenty edits, at most four per second (milliseconds since the first)',
    times.map(at => at - times[0]));
  await settled();

  // At most 16 streams are open at once.
  const extra = [];
  for (let index = 0; index < 15; index++) extra.push(await f.stream());
  expectEqual(extra.map(item => item.status), Array(15).fill(200), '§12 sixteen streams may be open at once');
  const overflow = await f.stream();
  expectEqual(overflow.status, 503, '§12 a seventeenth stream is 503');
  extra[0].close();
  const replacement = await until('§12 a stream can open again after one of the sixteen closes', async () => {
    const opened = await f.stream();
    if (opened.status === 200) return opened;
    opened.close();
    return null;
  });
  for (const item of [...extra, overflow, replacement]) item.close();

  // The fetch-site rule, with and without credentials.
  const login = expectStatus(await f.request('POST', '/api/login', {token: f.token},
    {auth: false, headers: {Origin: f.origin}}), 200, '§2 login');
  const cookie = (login.headers['set-cookie'] ?? []).join(';').split(';')[0];
  expect(cookie.includes('='), '§2 login sets a session cookie', login.headers['set-cookie']);
  const cookieValue = cookie.slice(cookie.indexOf('=') + 1);
  if (cookieValue.length >= 16) f.secrets.push(cookieValue);   // §8: no response contains a session cookie value
  const body = {name: 'FAKE refused by fetch site', connectionId: f.connectionId, instructions: 'FAKE only',
    intervalMinutes: 5, maxRunsPerDay: 1, acceptanceMinutes: 5};
  const credentials = {'a bearer token': {}, 'a session cookie': {auth: false, headers: {Cookie: cookie}},
    'no credentials': {auth: false}};
  const workflowsBefore = (await f.snapshot()).workflows.length;
  for (const site of ['cross-site', 'same-site']) {
    for (const [how, options] of Object.entries(credentials)) {
      const headers = {...options.headers, 'Sec-Fetch-Site': site, Origin: f.origin};
      expectError(await f.request('GET', '/api/snapshot', undefined, {...options, headers}), 403,
        `§2 GET /api/snapshot with Sec-Fetch-Site ${site} and ${how}`);
      expectError(await f.request('POST', '/api/workflows', body, {...options, headers}), 403,
        `§2 POST /api/workflows with Sec-Fetch-Site ${site} and ${how}`);
    }
    expectError(await f.request('POST', '/api/login', {token: f.token},
      {auth: false, headers: {Origin: f.origin, 'Sec-Fetch-Site': site}}), 403, `§2 POST /api/login with Sec-Fetch-Site ${site}`);
    const blocked = await f.stream({headers: {'Sec-Fetch-Site': site}});
    expectEqual(blocked.status, 403, `§2 GET /api/events with Sec-Fetch-Site ${site}`);
    blocked.close();
  }
  for (const site of ['same-origin', 'none']) {
    expectStatus(await f.request('GET', '/api/snapshot', undefined, {headers: {'Sec-Fetch-Site': site}}), 200,
      `§2 Sec-Fetch-Site ${site} is not refused`);
  }
  expectEqual((await f.snapshot()).workflows.length, workflowsBefore, '§2 a request refused for its fetch site changes nothing');

  // The error statuses of §2. An invalid request target is answered and does not stop the controller.
  expectError(await f.request('GET', '//['), 400, '§2 an invalid request target');
  expectStatus(await f.request('GET', '/health', undefined, {auth: false}), 200, '§2 /health after an invalid request target');
  expectError(await f.request('GET', '/api/FAKE-unknown-route'), 404, '§2 an unknown route');
  expectError(await f.request('GET', '/api/runs/FAKE-absent'), 404, '§2 an unknown run');
  for (const route of ['/api/runs', '/api/activity', '/api/runs/FAKE-absent']) {
    expectError(await f.request('GET', route, undefined, {auth: false}), 401, '§2 GET ' + route + ' without authentication');
  }
  expectError(await f.request('POST', '/api/workflows', JSON.stringify({...body, instructions: 'x'.repeat(66000)}),
    {raw: true}), 413, '§2 a JSON body over 64 KiB');

  // A comment line at least every 20 seconds, on the stream that has been open since the start.
  await until('the first stream has been open for 21 seconds', () => clock() - stream.openedAt > 21000, 30000);
  expect(!stream.closed && stream.comments.some(at => at - stream.openedAt <= 20500),
    '§12 the stream stays open and sends a comment line at least every 20 seconds',
    {closed: stream.closed, commentsAtMs: stream.comments.map(at => Math.round(at - stream.openedAt))});
  const exit = await f.terminate('SIGINT');
  expect(exit.code === 0 && exit.ms < 5500, '§1 on SIGINT the controller exits 0 within 5 seconds', exit);
  await Promise.race([stream.done, delay(1500)]);
  expect(stream.closed, '§1 shutdown closes every open stream');
  f.assertPrivate(stream.text, 'GET /api/events');
}

// Case 12, hanging calls. §4: an operator request never waits for a Peerspan subprocess; §1: SIGTERM with a
// hanging call exits 0 within 5 seconds, and the interrupted work is reconciled under the same task identity.
async function case12_hangingCallAndShutdown() {
  const f = await fixture('hanging');
  await f.start();
  await f.code(f.connectionId, 'ready', 'the worker is ready before anything hangs');
  const workflow = await f.create();
  const answeredPromptly = async what => {
    const requests = [['GET', '/api/snapshot'], ['GET', '/api/runs'], ['GET', '/api/activity'],
      ['PATCH', '/api/workflows/' + workflow.id, {name: `FAKE edited while ${what} hangs`}],
      ['POST', `/api/workflows/${workflow.id}/run`, {}],
      ['POST', '/api/workflows', {name: `FAKE created while ${what} hangs`, connectionId: f.connectionId,
        instructions: 'FAKE only', intervalMinutes: 5, maxRunsPerDay: 1, acceptanceMinutes: 5}]];
    const times = [];
    for (const [method, route, body] of requests) {
      const at = clock();
      const response = await f.request(method, route, body);
      times.push(Math.round(clock() - at));
      expect(response.status < 300, `§4 ${method} ${route} answers from stored state while ${what} is hanging`, response.text);
    }
    const sorted = [...times].sort((a, b) => a - b);
    // The contract's bound is one second. The median must meet it; a single slow request gets 2.5 seconds,
    // which a request that waited for the 60-second hang still misses.
    expect(sorted.at(-1) < 2500 && sorted[Math.floor(sorted.length / 2)] < 1000,
      `§4 an operator request is answered within one second while ${what} is hanging (milliseconds per request)`, times);
  };
  await f.configure({hang: ['status']});
  await until('a status call is hanging', async () => (await f.hanging()).some(call => call.argv.includes('status')));
  await answeredPromptly('status');
  await f.configure({hang: ['submit']});
  await f.code(f.connectionId, 'ready', 'status answers again');
  await f.action(workflow.id, 'resume');
  await f.action(workflow.id, 'run');
  const hung = await until('a task submit call is hanging',
    async () => (await f.hanging()).find(call => call.argv.includes('submit')));
  await answeredPromptly('task submit');
  const reserved = (await f.snapshot()).runs.find(run => run.workflowId === workflow.id);
  expect(reserved?.state === 'submitting' && reserved.taskId === option(hung.argv, '--task'),
    '§4 the run reserved before the hanging submission is visible from stored state', reserved);

  const stream = await f.stream();
  await stream.change('§12 a stream opens while a call is hanging', () => true, 2000);
  const exit = await f.terminate('SIGTERM');
  expect(exit.code === 0 && exit.ms < 5500,
    '§1 on SIGTERM with a hanging Peerspan call the controller exits 0 within 5 seconds', exit);
  await Promise.race([stream.done, delay(1500)]);
  expect(stream.closed, '§1 shutdown closes every open stream');
  expect(await f.request('GET', '/health', undefined, {auth: false}).then(() => false, () => true),
    '§1 shutdown closes the listener');

  await f.configure({hang: []});
  await f.start();
  const recovered = await f.waitRun(reserved.id, 'queued');
  const touching = (await f.calls()).filter(call => call.argv.includes(reserved.taskId)).map(call => call.argv);
  const submits = touching.filter(argv => argv.includes('submit'));
  expect(recovered.taskId === reserved.taskId && submits.length === 2 && isDeepStrictEqual(submits[1], submits[0]),
    '§1 work interrupted by a shutdown is reconciled after the next start under the same task identity and payload', submits);
  expect(touching.slice(touching.indexOf(submits[0]) + 1, touching.indexOf(submits[1])).some(argv => argv.includes('inspect')),
    '§4 after a restart the same ID is inspected before it is submitted again', touching);
  await f.stop();
}

// Case 12, prompt scheduler passes. §4: the effect of run, resume, cancel and an enabled creation is picked
// up by a scheduler pass that starts within one second. The tick is six seconds here and each request is
// sent just after a periodic pass has ended, so an effect within three seconds cannot be the next tick.
async function case12_promptSchedulerPass() {
  const f = await fixture('slow-tick', {env: {MANAGED_TICK_MS: '6000'}});
  await f.start();
  await f.code(f.connectionId, 'ready', 'the first check with a six-second tick', 20000);
  const afterPeriodicPass = async () => {
    await delay(1500);   // a pass triggered by an earlier request ends first
    const from = (await f.calls()).length;
    let count = from, changedAt = clock();
    await until('a periodic scheduler pass begins and ends (six-second tick)', async () => {
      const now = (await f.calls()).length;
      if (now !== count) { count = now; changedAt = clock(); }
      return count > from && clock() - changedAt >= 700;
    }, 20000);
  };
  const prompt = async (what, request, effect) => {
    await afterPeriodicPass();
    await request();
    await until(`§4 the effect of ${what} is picked up by a scheduler pass that starts within one second ` +
      '(allowed here: three seconds; the next periodic tick is later)', effect, 3000);
  };
  const submitted = async count => (await f.submissions()).length === count;
  const later = await f.create({name: 'FAKE resumed later'});
  await f.action(later.id, 'run');   // due as soon as it is resumed; run never bypasses the paused state
  let workflow;
  await prompt('an enabled creation', async () => { workflow = await f.create({enabled: true}); }, () => submitted(1));
  const first = await f.newRun(workflow.id, 'queued', 15000);
  await prompt('cancel', () => f.request('POST', `/api/runs/${first.id}/cancel`, {}),
    async () => (await f.taskCalls('cancel', first.taskId)).length > 0);
  await f.cancelSent(first.taskId);
  await f.finish(first, 'cancelled', {timeout: 15000});
  expect(await submitted(1), '§2 run never bypasses the paused state', (await f.submissions()).length);
  await prompt('resume', () => f.action(later.id, 'resume'), () => submitted(2));
  await f.finish(await f.newRun(later.id, 'queued', 15000), 'succeeded', {timeout: 15000});
  await prompt('run', () => f.action(workflow.id, 'run'), () => submitted(3));
  await f.stop();
}

// Case 12, version 1 state. §13 and §1: migration in place with IDs and values retained, the backup copy,
// pausedBy of migrated workflows, no activity for the past, and a retained unresolved run reconciled under
// its task ID and exact payload. The input database is created here as §13 documents it; no database is
// read afterwards (the backup is checked for existence, size and mode only).
async function case12_versionOneMigration() {
  const f = await fixture('migration', {connect: false});
  const external = await observedDirectory(f);
  const at = minutes => new Date(Date.now() + minutes * 60000).toISOString();
  const moment = value => (value === null || value === undefined ? value : Date.parse(value));
  const connection = {id: 'fake-v1-connection', name: 'FAKE v1 worker', workerState: f.workerFile,
    hostDir: f.workerDir, hostId: ids.hostId, agentId: ids.agentId, senderState: f.senderDir};
  const observation = {id: 'fake-v1-observation', name: 'FAKE v1 observed', directory: external.dir};
  const workflowRow = (id, name, patch) => ({id, name, connectionId: connection.id, instructions: 'FAKE v1 instructions',
    intervalMinutes: 30, maxRunsPerDay: 9, acceptanceMinutes: 15, enabled: false, nextRunAt: at(600),
    failureStreak: 0, blockedReason: null, ...patch});
  const workflows = [
    workflowRow('fake-v1-active', 'FAKE v1 active', {enabled: true, createdAt: at(-300)}),
    workflowRow('fake-v1-tripped', 'FAKE v1 tripped', {failureStreak: 3,
      blockedReason: 'FAKE v1 failure circuit reason', createdAt: at(-200)}),
    workflowRow('fake-v1-paused', 'FAKE v1 paused', {failureStreak: 1, createdAt: at(-100)})];
  const submission = {peer: ids.hostId, agent: ids.agentId, senderState: f.senderDir,
    input: '- FAKE v1 exact payload: $(never) `executed` λ', deadline: at(12)};
  // §13: a run's `target` is not copied by migration, so any string will do. Version 1 IDs are UUIDs, and
  // every route accepts any ID of 1 to 64 letters, digits, `_` or `-`: the runs use UUIDs, the rest fake names.
  const target = 'FAKE-v1-target-that-migration-does-not-copy';
  const done = {id: randomUUID(), workflowId: 'fake-v1-active', taskId: hex('task', 'd'), state: 'succeeded',
    target, createdAt: at(-90), updatedAt: at(-80), output: 'FAKE v1 retained output', error: null, retryAt: null,
    finishedAt: at(-80), submission: {...submission, input: 'FAKE v1 earlier payload', deadline: at(-75)}};
  const open = {id: randomUUID(), workflowId: 'fake-v1-active', taskId: hex('task', 'e'), state: 'submitting',
    target, createdAt: at(-1), updatedAt: at(-1), output: null, error: null, retryAt: null, submission};
  await fs.mkdir(f.state, {mode: 0o700});
  const file = path.join(f.state, 'managed.sqlite');
  const db = new DatabaseSync(file);
  db.exec('PRAGMA user_version = 0; CREATE TABLE records(kind TEXT NOT NULL, id TEXT PRIMARY KEY, body TEXT NOT NULL)');
  const insert = db.prepare('INSERT INTO records(kind, id, body) VALUES (?, ?, ?)');
  const records = {connection: [connection], observation: [observation], workflow: workflows, run: [done, open]};
  for (const [kind, rows] of Object.entries(records)) for (const row of rows) insert.run(kind, row.id, JSON.stringify(row));
  db.close();
  await fs.chmod(file, 0o600);

  await f.start();   // the first revision 10 command that opens the state migrates it through to version 7
  const snapshot = await f.snapshot();   // meta.schemaVersion 7 is checked on every snapshot
  const backup = await fs.stat(path.join(f.state, 'managed.v1-backup.sqlite')).catch(() => null);
  expect(backup !== null && backup.size > 0 && (backup.mode & 0o777) === 0o600,
    '§1 before migrating, a copy of the version 1 database is saved as managed.v1-backup.sqlite, private (0600)',
    backup && {size: backup.size, mode: (backup.mode & 0o777).toString(8)});
  expectEqual(snapshot.connections.map(item => pick(item, 'id name hostId agentId mode')),
    [{...pick(connection, 'id name hostId agentId'), mode: 'file'}], '§13 the connection keeps its ID and values, in file mode');
  expectEqual(snapshot.observed.map(item => pick(item, 'id name available')),
    [{id: observation.id, name: observation.name, available: true}], '§13 the observation keeps its ID, name and directory');
  // §13: blockedReason is the scheduler's current explanation and is rewritten by its first pass, so it is not compared.
  const same ='id name connectionId instructions intervalMinutes maxRunsPerDay acceptanceMinutes enabled failureStreak';
  const comparable = row => row && {...pick(row, same), createdAt: moment(row.createdAt), nextRunAt: moment(row.nextRunAt)};
  expectEqual(snapshot.workflows.map(comparable), workflows.map(comparable),
    '§13 workflows keep their IDs and values, oldest first');
  expectEqual(snapshot.workflows.map(item => item.pausedBy), [null, 'failures', 'operator'],
    '§13 a disabled migrated workflow with failureStreak 3 or more has pausedBy failures, any other disabled one operator');
  expectEqual(snapshot.workflows.map(item => pick(item, 'schedule review')), Array(3).fill({schedule: null, review: 'none'}),
    '§1 (rev 3) migrated workflows have schedule null and review none');
  expectEqual(snapshot.runs.find(run => run.id === done.id)?.review, null, '§1 (rev 3) a migrated succeeded run needs no review');
  expectEqual(snapshot.workflows.map(item => pick(item, 'reviewerId reviewCriteria reworkLimit reworkPending')),
    Array(3).fill({reviewerId: null, reviewCriteria: null, reworkLimit: 0, reworkPending: null}),
    '§1 (rev 4) migrated workflows have reviewerId and reviewCriteria null, reworkLimit 0 and reworkPending null');
  expectEqual(snapshot.runs.filter(run => [done.id, open.id].includes(run.id))
    .map(run => pick(run, 'attempt reworkOf reviewTask reviewFallback reviewedBy')),
  Array(2).fill({attempt: 1, reworkOf: null, reviewTask: null, reviewFallback: null, reviewedBy: null}),
  '§1 (rev 4) migrated runs have attempt 1 and reworkOf null and need no agent review');
  expectEqual([snapshot.workflows.map(item => item.resultChecks), snapshot.runs.filter(run => [done.id, open.id]
    .includes(run.id)).map(run => run.checks)], [Array(3).fill([]), [null, null]],
  '§1 (rev 8) migrated workflows have resultChecks [] and migrated runs have checks null');
  expectEqual([snapshot.workflows.map(item => pick(item, 'after handoffPending')), snapshot.runs.filter(run => [done.id,
    open.id].includes(run.id)).map(run => run.handoffFrom)], [Array(3).fill({after: null, handoffPending: null}), [null, null]],
  '§1 (rev 9) migrated workflows have after and handoffPending null, and migrated runs have handoffFrom null');
  expectEqual([snapshot.meta.alerts, JSON.parse(await f.checkedCli('alerts'))], [{configured: false, host: null,
    failing: false}, {configured: false, host: null}], '§1 (rev 10) migrated state has no alerts configured: §8.1 ' +
    'meta.alerts and the output of alerts alone');
  const runView = row => row && {...pick(row, 'id workflowId taskId state output'), createdAt: moment(row.createdAt),
    finishedAt: moment(row.finishedAt)};
  expectEqual(runView(snapshot.runs.find(run => run.id === done.id)), runView(done),
    '§13 a terminal run keeps its ID, task ID, result and times');
  expect(snapshot.runs.some(run => run.id === open.id && run.taskId === open.taskId && run.workflowId === open.workflowId),
    '§13 the unresolved run keeps its ID and task ID', snapshot.runs.map(run => pick(run, 'id taskId state')));
  expectEqual(snapshot.activity.filter(entry => entry.runId === done.id ||
    ['workflow.created', 'connection.added', 'observation.added'].includes(entry.kind)), [],
  '§13 migration records no activity entries for the past');

  await f.awaitSubmissions(1, '§13 the unresolved version 1 run is submitted after a genuine not-found inspection');
  const [replay] = await f.submissions();
  expectEqual({task: option(replay.argv, '--task'), input: inputOf(replay.argv), peer: option(replay.argv, '--peer'),
    agent: option(replay.argv, '--agent'), deadline: option(replay.argv, '--deadline'), state: option(replay.argv, '--state')},
  {task: open.taskId, input: submission.input, peer: submission.peer, agent: submission.agent,
    deadline: submission.deadline, state: submission.senderState},
  '§13 an unresolved version 1 run is reconciled under its task ID and exact payload');
  const touching = (await f.calls()).filter(call => call.argv.includes(open.taskId)).map(call => call.argv);
  expect(touching[0].includes('inspect'), '§4 after migration, as after any restart, the same ID is inspected first', touching.slice(0, 3));
  const finished = await f.finish(await f.waitRun(open.id, 'queued'), 'succeeded', {output: 'FAKE migrated run completed'});
  expectEqual([pick(finished, 'id taskId output review'), (await f.submissions()).length, (await f.detail(open.id)).run.instructions],
    [{id: open.id, taskId: open.taskId, output: 'FAKE migrated run completed', review: null}, 1, submission.input],
    '§13 the migrated run completes under its own identity, submitted once, with its input as the run instructions; ' +
    '§1 (rev 3) a migrated run needs no review');
  const resumed = expectStatus(await f.request('POST', '/api/workflows/fake-v1-paused/resume', {}), 200,
    '§13 every route accepts any ID of 1 to 64 letters, digits, _ or -, such as a migrated one that is no UUID').data;
  expectEqual(pick(resumed, 'id enabled failureStreak'), {id: 'fake-v1-paused', enabled: true, failureStreak: 0},
    '§2 resume of a migrated workflow enables it and resets its failure count');
  await f.stop();
}

// Case 12, newer schema. §1: state written by a newer schema is refused with a nonzero exit and is not
// modified. The database is created here, and only the bytes of that file are compared afterwards.
async function case12_newerSchemaRefused() {
  const f = await fixture('newer-schema', {connect: false});
  await fs.mkdir(f.state, {mode: 0o700});
  const file = path.join(f.state, 'managed.sqlite');
  const db = new DatabaseSync(file);
  // §1 (rev 10): the current schema version is 7, so a newer one is 8.
  db.exec("PRAGMA user_version = 8; CREATE TABLE fake_future_schema(note TEXT NOT NULL); " +
    "INSERT INTO fake_future_schema VALUES ('FAKE state written by a newer schema')");
  db.close();
  await fs.chmod(file, 0o600);
  const original = await fs.readFile(file);
  const unmodified = async what => expect((await fs.readFile(file)).equals(original),
    `§1 ${what} modified state written by a newer schema`);
  const refused = {
    serve: ['serve', '--port', String(f.port)],
    connect: ['connect', '--name', 'FAKE refused', '--worker-state', f.workerFile, '--sender-state', f.senderDir],
    observe: ['observe', '--name', 'FAKE refused', '--directory', f.dir],
    // (rev 10) the alerts settings live in the state too (§8.1).
    'alerts --url': ['alerts', '--url', 'https://hooks.example.invalid/FAKE-newer-schema'], 'alerts --off': ['alerts', '--off']};
  for (const [name, args] of Object.entries(refused)) {
    const result = await f.cli(...args);
    expect(result.code !== 0 && result.code !== null,
      `§1 ${name} refuses state written by a newer schema with a nonzero exit (null: it kept running)`, result);
    await unmodified(name);
  }
  for (const args of [['status'], ['token'], ['doctor'], ['alerts']]) {
    await f.cli(...args);
    await unmodified(args.join(' '));
  }
}

await runCases('visibility', [case11_timelineHistoryAndActivity, case12_liveUpdatesAndFetchSite,
  case12_hangingCallAndShutdown, case12_promptSchedulerPass, case12_versionOneMigration, case12_newerSchemaRefused]);
