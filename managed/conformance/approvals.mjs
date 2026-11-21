#!/usr/bin/env node
// Contract-only black-box suite for docs/managed-contract.md revision 11, section 16, cases 32 to 34: approval before
// each run (sections 2, 4, 8, 9, 11 and 14.2), for interval, scheduled, requested, rework and handoff runs (sections
// 14, 14.1 and 15.2). No imports or reads of the managed implementation or its database: the documented CLI, HTTP,
// the explicitly fake Peerspan executable and throwaway state only. The FAKE worker is driven step by step through its
// task records, with FAKE SCRIPTED results, and MANAGED_CLOCK_FILE moves the controller's clock where a case needs a
// due time, a slot or a new UTC day. Section numbers (§) refer to the contract; times are compared as instants (§14).
import path from 'node:path';
import {dayNames, delay, expect, expectEqual, expectError, expectStatus, fixture, hex, ids, isTime, pick, runCases, snippet,
  until} from './harness.mjs';

const minute = 60000;
const at = value => (typeof value === 'number' ? value : Date.parse(value));
const iso = value => (Number.isFinite(at(value)) ? new Date(at(value)).toISOString() : String(value));
const near = (actual, expected, ms = 1000) => Math.abs(at(actual) - at(expected)) <= ms;
const operator = {approval: 'operator'};
const route = (id, action) => `/api/workflows/${id}/${action}`;
// §14: a daily UTC schedule with three slots a minute apart, and its first slot at or after an instant.
const slots = ['09:00', '09:01', '09:02'];
function firstSlot(notBefore) {
  const day = new Date(notBefore);
  day.setUTCHours(0, 0, 0, 0);
  for (let days = 0; days < 3; days++) {
    for (const time of slots) {
      const [hours, minutes] = time.split(':').map(Number);
      const slot = day.getTime() + days * 86400000 + (hours * 60 + minutes) * minute;
      if (slot >= notBefore) return slot;
    }
  }
  return NaN;
}

// A FAKE fixture with this suite's helpers. Workflows are created paused unless `enabled` (§2); harness defaults are
// intervalMinutes 1 and maxRunsPerDay 50.
async function gated(label, options = {}) {
  const f = await fixture(label, options);
  f.ready = () => f.code(f.connectionId, 'ready', 'the FAKE worker is ready and verified', 15000);
  f.log = async () => {
    const entries = [];
    for (let before = null; ;) {
      const query = '/api/activity?limit=200' + (before === null ? '' : '&before=' + encodeURIComponent(before));
      const data = expectStatus(await f.request('GET', query), 200, '§11 GET /api/activity').data;
      entries.push(...data.activity);
      if (data.nextBefore === null) return entries.reverse();   // oldest first
      before = data.nextBefore;
    }
  };
  f.entries = async (w, kind) => (await f.log()).filter(entry => entry.kind === kind && entry.workflowId === w.id);
  f.view = async w => {
    const s = await f.snapshot();
    return {s, w: s.workflows.find(item => item.id === w.id),
      item: s.attention.find(item => item.kind === 'approval_pending' && item.subject.id === w.id)};
  };
  f.waitFor = (w, test, why, timeout = 15000) => {
    let last;
    return until(() => `${why}; last seen: ${snippet(last && pick(last, 'enabled approvalPending approvedAt reworkPending ' +
      'handoffPending nextRunAt blockedReason'))}`, async () => { last = await f.workflow(w.id); return last && test(last) ? last : false; },
    timeout);
  };
  f.verdict = async (run, body) => expectStatus(await f.request('POST', `/api/runs/${run.id}/review`, body), 200,
    '§15 POST /api/runs/:id/review').data;
  f.runsOf = async w => (await f.snapshot()).runs.filter(run => run.workflowId === w.id);
  f.submitted = async (count, why) => expectEqual((await f.submissions()).length, count,
    `§14.2 ${why}: ${count} task submit invocation(s) in all`);
  // §14.2: the next run reserved uses the approval: the run's approvedAt is it, and the workflow's approvedAt becomes
  // null in the same step, so every snapshot that lists the run shows the workflow without it.
  f.approvedRun = async (w, approval, why) => {
    let last;
    const [run, current] = await until(() => `§14.2 ${why}: the approved run is reserved; workflow last seen: ${snippet(last)}`,
      async () => {
        const s = await f.snapshot();
        const found = s.runs.find(item => item.workflowId === w.id && !f.seen.has(item.id));
        const view = s.workflows.find(item => item.id === w.id);
        last = view && pick(view, 'enabled approvalPending approvedAt blockedReason');
        return found && [found, view];
      }, 15000);
    f.seen.add(run.id);
    expect(isTime(run.approvedAt) && at(run.approvedAt) === at(approval) && at(run.approvedAt) <= at(run.createdAt),
      `§14.2 ${why}: the run approvedAt is the approval it was reserved with (${approval}), given before the run`,
      pick(run, 'approvedAt createdAt'));
    expectEqual(pick(current, 'approvedAt approvalPending'), {approvedAt: null, approvalPending: null}, `§14.2 ${why}: ` +
      'the workflow approvedAt becomes null in the same step as the run is reserved with it');
    return run;
  };
  return f;
}

// A gated fixture whose FAKE worker host also has a second agent, connected in agent mode through a second sender
// state (as the reviewer agents of handoffs.mjs): each agent's session can be made not ready on its own (§3).
const secondAgent = {agentId: hex('agent', 8), sessionId: hex('session', 8), adapterId: hex('adapter', 8)};
async function twoWorkers(label, options = {}) {
  const f = await gated(label, options);
  const all = [ids, secondAgent];
  const sessions = new Map(all.map(item => [item.agentId, 'ready']));
  const agents = () => ({
    agents: all.map(item => ({id: item.agentId, name: 'FAKE-CONFORMANCE agent ' + item.agentId.slice(-4),
      sessions: [{id: item.sessionId, adapter_id: item.adapterId, connection: sessions.get(item.agentId)}]})),
    adapters: Object.fromEntries(all.map(item => [item.adapterId, {session_id: item.sessionId, state: 'ready',
      channel: 'verified', channel_verified_at: '2026-01-01T00:00:00Z'}]))});
  const secondSender = path.join(f.dir, 'PRIVATE-second-sender');
  await f.configure({...agents(), senderStates: [f.senderDir, secondSender]});
  f.setSession = async (item, connection) => { sessions.set(item.agentId, connection); await f.configure(agents()); };
  f.secondId = JSON.parse(await f.checkedCli('connect', '--name', 'FAKE-CONFORMANCE second worker', '--agent', secondAgent.agentId,
    '--host-state', f.workerDir, '--sender-state', secondSender)).id;
  return f;
}

// §14.2: a wait. The first scheduler pass that finds the workflow waiting sets approvalPending and records the one
// workflow.approval_requested of this wait (the `count`th of the workflow); while it waits, the approval_pending item
// (action, since its approvalPending) is present and the workflow holds no approval. `notBefore` is when the workflow
// became due; `replaces` is the approvalPending of a wait that this one follows at once, because the workflow came to
// wait for another run (a wait concerns one run: a new one has its own approvalPending and entry).
async function expectWait(f, w, count, why, {notBefore = null, replaces = null} = {}) {
  const first = await f.waitFor(w, item => item.approvalPending !== null && item.approvalPending !== replaces, `§14.2 ${why}: ` +
    'the workflow waits for approval, and the first scheduler pass that finds it waiting sets approvalPending' +
    (replaces === null ? '' : ` anew (the previous wait began ${replaces})`));
  await delay(500);   // later passes of the same wait (MANAGED_TICK_MS 100)
  const {w: now, item} = await f.view(w);
  expectEqual(now.approvalPending, first.approvalPending, `§14.2 ${why}: approvalPending stays the moment the wait began`);
  expect(item?.severity === 'action' && item.subject.name === now.name && at(item.since) === at(now.approvalPending),
    `§8 (rev 11) ${why}: the approval_pending item is present, an action whose subject is the workflow and whose since ` +
    'is its approvalPending', item);
  expect(now.enabled && now.approvedAt === null && typeof now.blockedReason === 'string' && now.blockedReason.trim() !== '',
    `§14.2 ${why}: an enabled workflow that holds no approval (approvedAt null); its blockedReason says that it waits`,
    pick(now, 'enabled approvedAt blockedReason'));
  expect(notBefore === null || at(now.approvalPending) >= at(notBefore), `§14.2 ${why}: the wait begins once the workflow ` +
    `is due, not before ${notBefore === null ? '' : iso(notBefore)}`, now.approvalPending);
  expect(replaces === null || at(now.approvalPending) > at(replaces), `§14.2 ${why}: a new wait for another run has its ` +
    'own, later approvalPending', {previous: replaces, now: now.approvalPending});
  const entries = await f.entries(w, 'workflow.approval_requested');
  expect(entries.length === count && entries.every(entry => entry.actor === 'system' && entry.runId === null &&
    entry.data === null) && near(entries.at(-1).at, now.approvalPending), `§11 (rev 11) ${why}: one ` +
    `workflow.approval_requested per wait (${count} so far), a system entry with data null, recorded by the pass that ` +
    'set approvalPending', entries.map(entry => pick(entry, 'seq at actor runId data')));
  return now;
}

// §14.2: no wait. Several scheduler passes later approvalPending is null, no approval_pending item is present, and no
// workflow.approval_requested was recorded beyond the `count` earlier waits.
async function expectNoWait(f, w, count, why) {
  await delay(900);
  const {w: now, item} = await f.view(w);
  expect(now.approvalPending === null && item === undefined, `§14.2 no wait ${why}: approvalPending null and no ` +
    'approval_pending item', {...pick(now, 'enabled approvalPending approvedAt nextRunAt blockedReason'), item});
  expectEqual((await f.entries(w, 'workflow.approval_requested')).length, count,
    `§11 no workflow.approval_requested ${why} beyond the ${count} earlier wait(s)`);
  return now;
}

// §14.2 approve: approvedAt the time of the request and approvalPending null, workflow.approved recorded (the `count`th).
async function approve(f, w, count) {
  const before = f.now();
  const approved = await f.action(w.id, 'approve');
  const after = f.now();
  expect(approved.id === w.id && approved.approvalPending === null && isTime(approved.approvedAt) &&
    at(approved.approvedAt) >= before - 1500 && at(approved.approvedAt) <= after + 1500, '§14.2 approve returns the ' +
    'workflow, its approvedAt the time of the request and its approvalPending null',
  {...pick(approved, 'id approvalPending approvedAt'), requested: [iso(before), iso(after)]});
  const entries = await f.entries(w, 'workflow.approved');
  expect(entries.length === count && entries.every(entry => entry.actor === 'operator' && entry.runId === null &&
    entry.data === null) && near(entries.at(-1).at, approved.approvedAt), `§11 (rev 11) approve records ` +
    `workflow.approved, an operator entry with data null (${count} so far)`, entries.map(entry => pick(entry, 'at actor runId data')));
  return approved;
}

// §14.2 skip: approvalPending null, workflow.skipped recorded (the `count`th); returns the workflow and the entry.
async function skip(f, w, count) {
  const skipped = await f.action(w.id, 'skip');
  expect(skipped.id === w.id && skipped.approvalPending === null, '§14.2 skip returns the workflow with approvalPending null',
    pick(skipped, 'id approvalPending'));
  const entries = await f.entries(w, 'workflow.skipped');
  expect(entries.length === count && entries.every(entry => entry.actor === 'operator' && entry.runId === null &&
    entry.data === null), `§11 (rev 11) skip records workflow.skipped, an operator entry with data null (${count} so far)`,
  entries.map(entry => pick(entry, 'at actor runId data')));
  return [skipped, entries.at(-1)];
}

// Case 32, fields. §2 and §9 (rev 11): approval at creation (none when omitted) and in PATCH; any other value, and
// approvalPending or approvedAt in a PATCH, is 400 and changes nothing; §11 workflow.edited lists approval only when it
// changes; §8 the three fields in the workflow that the routes return; §9 restore keeps approval. Nothing is enabled.
async function case32_fields() {
  const f = await gated('approval-fields');
  await f.start();
  const shape = 'approval approvalPending approvedAt';
  const fresh = approval => ({approval, approvalPending: null, approvedAt: null});
  const omitted = await f.create({name: 'FAKE approval omitted'});
  const none = await f.create({name: 'FAKE approval none', approval: 'none'});
  const gate = await f.create({name: 'FAKE approval operator', ...operator});
  expectEqual([omitted, none, gate].map(w => pick(w, shape)), [fresh('none'), fresh('none'), fresh('operator')], '§2 (rev 11) ' +
    'approval is none when omitted and accepts none or operator; §14.2 approvalPending and approvedAt are null');
  const values = [['agent (a review value)', 'agent'], ['in upper case', 'OPERATOR'], ['capitalized', 'Operator'],
    ['padded', ' operator'], ['empty', ''], ['null', null], ['true', true], ['false', false], ['a number', 1],
    ['an array', ['operator']], ['an object', {approval: 'operator'}], ['another word', 'always']];
  const body = approval => ({name: 'FAKE refused approval', connectionId: f.connectionId, instructions: 'FAKE fields only',
    intervalMinutes: 5, maxRunsPerDay: 5, acceptanceMinutes: 5, approval});
  for (const [what, value] of values) {
    expectError(await f.request('POST', '/api/workflows', body(value)), 400, `§14.2 POST /api/workflows refuses approval ${what}`);
  }
  expectEqual([(await f.snapshot()).workflows.length, (await f.log()).filter(entry => entry.kind === 'workflow.created').length],
    [3, 3], '§2 refused creations store nothing');
  const kept = await f.workflow(omitted.id);
  const stamp = '2026-01-01T00:00:00.000Z';
  const refused = [...values.map(([what, value]) => [`approval ${what}`, {approval: value}]),
    ['approvalPending null', {approvalPending: null}], ['approvalPending as a time', {approvalPending: stamp}],
    ['approvedAt null', {approvedAt: null}], ['approvedAt as a time', {approvedAt: stamp}],
    ['a valid name beside an invalid approval', {name: 'FAKE never renamed', approval: 'always'}],
    ['a valid approval beside approvedAt', {approval: 'operator', approvedAt: stamp}]];
  for (const [what, patch] of refused) {
    expectError(await f.request('PATCH', '/api/workflows/' + omitted.id, patch), 400, `§9 (rev 11) PATCH refuses ${what}`);
  }
  expectEqual(await f.workflow(omitted.id), kept, '§9 a refused PATCH changes nothing');
  const steps = [[{approval: 'operator'}, 'operator'], [{approval: 'operator'}, 'operator'],
    [{approval: 'none', name: 'FAKE approval renamed'}, 'none'], [{approval: 'none'}, 'none'],
    [{approval: 'operator', maxRunsPerDay: 9}, 'operator']];
  for (const [patch, wanted] of steps) {
    expectEqual(pick(await f.patch(omitted.id, patch), shape), fresh(wanted), '§9 PATCH returns the workflow with its ' +
      'approval: ' + JSON.stringify(patch));
  }
  expectEqual((await f.entries(omitted, 'workflow.edited')).map(entry => entry.data.fields), [['approval'], ['approval', 'name'],
    ['approval', 'maxRunsPerDay']], '§14.2 and §11 a change of approval is listed in workflow.edited, sorted with the other ' +
    'changed fields; an edit that changes no value records nothing, nor does a refused one');
  expectEqual(pick(await f.action(gate.id, 'pause'), shape), fresh('operator'), '§8 the workflow that pause returns has the fields');
  expectStatus(await f.request('POST', route(gate.id, 'archive'), {}), 200, '§9 archive');
  const restored = expectStatus(await f.request('POST', route(gate.id, 'restore'), {}), 200, '§9 restore').data;
  expectEqual(pick(restored, shape + ' enabled pausedBy'), {...fresh('operator'), enabled: false, pausedBy: 'operator'},
    '§9 restore returns the workflow paused, its approval as it was');
  await f.submitted(0, 'nothing enabled, nothing dispatched');
  await f.stop();
}

// Case 32, interval. §14.2: an enabled interval workflow, due at creation, waits: nothing is submitted whatever its
// worker's state (ready, not ready, ready again) and however many intervals pass; approvalPending, nextRunAt and the
// blockedReason (not the worker's reason) stay; one workflow.approval_requested per wait. A paused workflow never
// waits, also once run made it due (§2); pause ends a wait, and resume begins a new one.
async function case32_intervalWaits() {
  const f = await gated('approval-interval', {clock: '2026-04-06T10:00:00.000Z'});
  await f.start();
  await f.ready();
  const paused = await f.create({name: 'FAKE gated, left paused', ...operator});
  const w = await f.create({name: 'FAKE gated, every minute', ...operator, enabled: true});
  const first = await expectWait(f, w, 1, 'an interval workflow due at creation', {notBefore: w.nextRunAt});
  await f.configure({ready: false});
  const unready = await f.code(f.connectionId, 'session_not_ready', 'the FAKE worker session is disconnected');
  await f.clockAt(f.now() + 3 * minute, 'three intervals pass while it waits');
  const meanwhile = await expectWait(f, w, 1, 'the same wait, with the worker not ready');
  const same = 'approvalPending blockedReason nextRunAt';
  expectEqual(pick(meanwhile, same), pick(first, same), '§14.2 the wait goes on whatever the worker state and however many ' +
    'intervals pass: the same approvalPending, nextRunAt and blockedReason');
  expect(meanwhile.blockedReason !== unready.reason, '§14.2 while it waits, the blockedReason says it waits for the ' +
    'operator approval, not the worker readiness reason', {blockedReason: meanwhile.blockedReason, worker: unready.reason});
  await f.configure({ready: true});
  await f.ready();
  await f.clockAt(f.now() + 2000, 'a scheduler pass with the worker ready again');
  expectEqual(pick(await expectWait(f, w, 1, 'the same wait, with the worker ready again'), same), pick(first, same),
    '§14.2 the wait goes on with the worker ready again');
  await f.submitted(0, 'nothing is reserved for a workflow that waits, whatever its worker state');

  await f.action(paused.id, 'run');
  await expectNoWait(f, paused, 0, 'for a paused workflow, though run made it due');
  expectEqual((await f.action(w.id, 'pause')).approvalPending, null, '§14.2 a pause ends a wait at once: the pause ' +
    'response shows approvalPending null');
  for (const action of ['approve', 'skip']) {
    expectError(await f.request('POST', route(w.id, action), {}), 409, `§14.2 ${action} right after a pause is 409 (no wait)`);
  }
  await f.clockAt(f.now() + 2 * minute, 'two intervals pass while paused');
  await expectNoWait(f, w, 1, 'while paused');
  await f.action(w.id, 'resume');
  const second = await expectWait(f, w, 2, 'resume: a later wait is a new one');
  expect(at(second.approvalPending) > at(first.approvalPending), '§14.2 a new wait has its own approvalPending',
    [first.approvalPending, second.approvalPending]);
  await f.submitted(0, 'nothing is reserved without an approval');
  await f.stop();
}

// Cases 32 and 33, schedule. §14.2: a scheduled workflow waits at its slot (nextRunAt left), not before; skip moves it on
// to its first slot at least one minute after the request (§14); the next slot waits again; an approved run follows.
async function case32_scheduleWaitsAndSkip() {
  const f = await gated('approval-schedule', {clock: '2026-04-06T08:58:00.000Z'});   // a Monday
  await f.start();
  await f.ready();
  const w = await f.create({name: 'FAKE gated schedule', intervalMinutes: undefined, ...operator, enabled: true,
    schedule: {timeZone: 'UTC', days: dayNames, times: slots}});
  expectEqual(at(w.nextRunAt), at('2026-04-06T09:00:00.000Z'), '§14 nextRunAt at creation is the first slot, 09:00 UTC');
  await expectNoWait(f, w, 0, 'before the first slot');
  await f.clockAt('2026-04-06T09:00:20.000Z', 'the 09:00 slot passes');
  const waiting = await expectWait(f, w, 1, 'a scheduled workflow at its slot', {notBefore: w.nextRunAt});
  expectEqual(at(waiting.nextRunAt), at(w.nextRunAt), '§14 a slot that waits for approval leaves nextRunAt');
  await f.submitted(0, 'nothing is reserved at a slot that waits');
  const [skipped, entry] = await skip(f, w, 1);
  const wanted = firstSlot(at(entry.at) + minute);
  expect(at(skipped.nextRunAt) === wanted, `§14.2 skip moves a schedule on to its first slot at least one minute after the ` +
    `request (${iso(wanted)}; a slot less than a minute away is passed over)`, {nextRunAt: skipped.nextRunAt, skippedAt: entry.at});
  await expectNoWait(f, w, 1, 'after skip, before the next slot');
  expectEqual((await f.runsOf(w)).length, 0, '§14.2 skip creates no run');
  await f.clockAt(wanted + 10000, 'the slot after the skip passes');
  await expectWait(f, w, 2, 'the slot after the skip', {notBefore: wanted});
  const approved = await approve(f, w, 1);
  const done = await f.finish(await f.approvedRun(w, approved.approvedAt, 'the approved scheduled run'), 'succeeded',
    {output: 'FAKE SCRIPTED scheduled result'});
  expectEqual(at((await f.workflow(w.id)).nextRunAt), firstSlot(at(done.finishedAt) + minute), '§14 after the run, nextRunAt ' +
    'is the first slot at least one minute after its finishedAt');
  await expectNoWait(f, w, 2, 'before that slot');
  await f.submitted(1, 'one run for one approval');
  await f.stop();
}

// Case 32, no wait. §14.2: no wait while the workflow has an unresolved run, nor at its daily cap (UTC day, §4), though
// due; after an approved run the next one waits again; a new UTC day brings a new wait.
async function case32_noWaitWithRunOrAtCap() {
  const f = await gated('approval-cap', {clock: '2026-08-03T23:50:00.000Z'});
  await f.start();
  await f.ready();
  const w = await f.create({name: 'FAKE gated, two a day', ...operator, maxRunsPerDay: 2, acceptanceMinutes: 60,
    enabled: true});   // every minute
  await expectWait(f, w, 1, 'due at creation', {notBefore: w.nextRunAt});
  const first = await f.approvedRun(w, (await approve(f, w, 1)).approvedAt, 'the first approved run');
  await f.clockAt(f.now() + 3 * minute, 'three intervals pass while the run is unresolved');
  const busy = await expectNoWait(f, w, 1, 'while the workflow has an unresolved run');
  expect(at(busy.nextRunAt) < f.now(), 'fixture: nextRunAt has passed while the run is unresolved', busy.nextRunAt);
  const done = await f.finish(first, 'succeeded', {output: 'FAKE SCRIPTED result one'});
  await f.clockAt(f.now() + 2 * minute, 'the interval after the run passes');
  await expectWait(f, w, 2, 'after an approved run, the next run waits again', {notBefore: at(done.finishedAt) + minute});
  await f.submitted(1, 'one approval lets exactly one run go out');
  const second = await f.approvedRun(w, (await approve(f, w, 2)).approvedAt, 'the second approved run');
  await f.finish(second, 'succeeded', {output: 'FAKE SCRIPTED result two'});
  await f.clockAt(f.now() + 2 * minute, 'the workflow is due again, its two runs of the UTC day used');
  const capped = await expectNoWait(f, w, 2, 'at the daily cap');
  expect(at(capped.nextRunAt) < f.now() && capped.stats.runs === 2, 'fixture: due, with two runs today', pick(capped, 'nextRunAt stats'));
  await f.clockAt('2026-08-04T00:00:30.000Z', 'a new UTC day begins');
  await expectWait(f, w, 3, 'a new UTC day: under the cap again');
  await f.submitted(2, 'two approved runs and no other');
  await f.stop();
}

// Case 33, routes. §14.2: approve and skip are 404 for an unknown workflow, 409 for an archived one and 409 unless the
// workflow waits (without approval, paused, approved, with an unresolved run, restored); §2 a body other than {} is
// 400; refused requests change and record nothing; archive ends a wait.
async function case33_routes() {
  const f = await gated('approval-routes');
  await f.start();
  await f.ready();
  for (const action of ['approve', 'skip']) {
    expectError(await f.request('POST', route('FAKE-absent-workflow', action), {}), 404, `§14.2 ${action} of an unknown workflow`);
  }
  const plain = await f.create({name: 'FAKE without approval'});
  const pausedGate = await f.create({name: 'FAKE gated, paused', ...operator});
  const archived = await f.create({name: 'FAKE gated, archived while waiting', ...operator, intervalMinutes: 60, enabled: true});
  await expectWait(f, archived, 1, 'a workflow due at creation');
  const refuse = async (target, why) => {
    for (const action of ['approve', 'skip']) {
      expectError(await f.request('POST', route(target.id, action), {}), 409, `§14.2 ${action} is 409 ${why}`);
    }
  };
  expectStatus(await f.request('POST', route(archived.id, 'archive'), {}), 200, '§9 archive of a waiting workflow (no run)');
  await refuse(archived, 'right after the archive of a waiting workflow: an archive ends a wait at once');
  const w = await f.create({name: 'FAKE gated, waiting', ...operator, intervalMinutes: 60, enabled: true});
  const waiting = await expectWait(f, w, 1, 'a workflow due at creation');
  await refuse(plain, 'for a workflow without approval (it never waits)');
  await refuse(pausedGate, 'for a paused workflow (it does not wait)');
  await refuse(archived, 'for an archived workflow');
  for (const action of ['approve', 'skip']) {
    expectError(await f.request('POST', route(w.id, action), {note: 'FAKE unknown field'}), 400,
      `§2 ${action} accepts {}: an unknown field is 400`);
  }
  expectEqual((await f.workflow(w.id)).approvalPending, waiting.approvalPending, '§2 refused requests change nothing: it still waits');
  const approved = await approve(f, w, 1);
  await refuse(w, 'once approved: the workflow no longer waits');
  const run = await f.approvedRun(w, approved.approvedAt, 'the approved run');
  await refuse(w, 'while its run is unresolved');
  await f.finish(run, 'succeeded', {output: 'FAKE SCRIPTED result'});
  await refuse(w, 'after the run, before the next due time');
  const restored = expectStatus(await f.request('POST', route(archived.id, 'restore'), {}), 200, '§9 restore').data;
  expectEqual(pick(restored, 'approval approvalPending approvedAt enabled'), {approval: 'operator', approvalPending: null,
    approvedAt: null, enabled: false}, '§9 restore returns the workflow paused, its approval as it was; §14.2 the archive ' +
    'ended its wait at once (approvalPending null)');
  await refuse(archived, 'for a restored (paused) workflow');
  const counts = async kind => Promise.all([plain, pausedGate, archived, w].map(async item => (await f.entries(item, kind)).length));
  expectEqual([await counts('workflow.approved'), await counts('workflow.skipped')], [[0, 0, 0, 1], [0, 0, 0, 0]],
    '§11 only the accepted approve records workflow.approved; refused requests record nothing');
  await f.submitted(1, 'one run, the approved one');
  await f.stop();
}

// Case 33, approve and skip an interval workflow. §14.2: skip moves nextRunAt on by an interval from the request; approve
// lets exactly one run go out with its approvedAt; the next due time and run (§2) wait again; §8 neither approve nor
// skip is an intervention, so unattendedRuns keeps a run that finished before them.
async function case33_approveAndSkipInterval() {
  const f = await gated('approval-approve', {clock: '2026-04-07T10:00:00.000Z'});
  await f.start();
  await f.ready();
  const w = await f.create({name: 'FAKE gated, every thirty minutes', ...operator, intervalMinutes: 30, enabled: true});
  await expectWait(f, w, 1, 'an interval workflow due at creation', {notBefore: w.nextRunAt});
  const [skipped, entry] = await skip(f, w, 1);
  expect(near(skipped.nextRunAt, at(entry.at) + 30 * minute) && near(skipped.nextRunAt, f.now() + 30 * minute, 30000),
    '§14.2 skip moves nextRunAt on as if a run had finished at that moment: an interval (30 minutes) after the request',
    {nextRunAt: skipped.nextRunAt, skippedAt: entry.at});
  await expectNoWait(f, w, 1, 'after skip, before the next due time');
  expectEqual((await f.runsOf(w)).length, 0, '§14.2 skip creates no run');
  await f.clockAt(at(skipped.nextRunAt) + 5000, 'the interval after the skip passes');
  await expectWait(f, w, 2, 'the due time after the skip', {notBefore: skipped.nextRunAt});
  const approved = await approve(f, w, 1);
  const done = await f.finish(await f.approvedRun(w, approved.approvedAt, 'approve lets the run go out'), 'succeeded',
    {output: 'FAKE SCRIPTED result one'});
  const after = await expectNoWait(f, w, 2, 'after the run, before the next due time');
  expect(near(after.nextRunAt, at(done.finishedAt) + 30 * minute), '§4 the run schedules the next one an interval later',
    {nextRunAt: after.nextRunAt, finishedAt: done.finishedAt});
  await f.submitted(1, 'approve lets exactly one run go out');
  await f.clockAt(at(after.nextRunAt) + 5000, 'the next due time after the run');
  await expectWait(f, w, 3, 'the next run waits again', {notBefore: after.nextRunAt});
  await skip(f, w, 2);
  expectEqual(pick((await f.workflow(w.id)).stats, 'runs succeeded interventions unattendedRuns'), {runs: 1, succeeded: 1,
    interventions: 0, unattendedRuns: 1}, '§8 (rev 11) approving and skipping are no interventions: interventions 0, and the ' +
    'run that finished before the latest skip still counts in unattendedRuns');
  const asked = f.now();
  const requested = await f.action(w.id, 'run');
  const answered = f.now();
  const waiting = await expectWait(f, w, 4, 'run sets the next eligible time to now: the requested run waits too');
  expect(at(requested.nextRunAt) >= asked - 1500 && at(requested.nextRunAt) <= answered + 1500 &&
    at(waiting.nextRunAt) === at(requested.nextRunAt), '§2 run sets nextRunAt to now, and the wait leaves it',
  {nextRunAt: requested.nextRunAt, requested: [iso(asked), iso(answered)], waiting: waiting.nextRunAt});
  await f.submitted(1, 'nothing is reserved for the requested run before its approval');
  const second = await approve(f, w, 2);
  await f.finish(await f.approvedRun(w, second.approvedAt, 'the requested run, approved'), 'succeeded', {output: 'FAKE SCRIPTED result two'});
  const interventions = (await f.log()).filter(item => item.actor === 'operator' && item.workflowId === w.id &&
    !['workflow.created', 'run.reviewed', 'workflow.approved', 'workflow.skipped'].includes(item.kind)).map(item => item.kind);
  expectEqual([interventions, pick((await f.workflow(w.id)).stats, 'runs succeeded interventions unattendedRuns')],
    [['workflow.run_requested'], {runs: 2, succeeded: 2, interventions: 1, unattendedRuns: 1}], '§8 interventions count the ' +
    'operator entries other than workflow.created, run.reviewed, workflow.approved and workflow.skipped (here the run ' +
    'request); unattendedRuns the run that finished after it');
  await f.stop();
}

// Cases 32 and 33, rework. §14.2 and §15.2: a pending rework makes the workflow due before nextRunAt, and it waits; the
// approved run is the rework; skip drops a second pending rework, leaves nextRunAt and creates no run.
async function case32_reworkWaitsAndSkip() {
  const f = await gated('approval-rework');
  await f.start();
  await f.ready();
  const w = await f.create({name: 'FAKE gated, reviewed', ...operator, review: 'operator', reworkLimit: 2, intervalMinutes: 60,
    enabled: true, instructions: 'FAKE gated assignment: list the fake invoices'});
  await expectWait(f, w, 1, 'due at creation');
  const first = await f.approvedRun(w, (await approve(f, w, 1)).approvedAt, 'the first run');
  const one = await f.finish(first, 'succeeded', {output: 'FAKE SCRIPTED invoice list one'});
  await f.verdict(one, {verdict: 'rejected', note: 'FAKE note: add the totals'});
  await f.waitFor(w, item => item.reworkPending === first.id, '§15.2 the rejection makes a rework due');
  const waiting = await expectWait(f, w, 2, 'a pending rework', {notBefore: one.finishedAt});
  expect(at(waiting.nextRunAt) > f.now() + 50 * minute, 'fixture: nextRunAt is an interval ahead, so only the rework makes ' +
    'the workflow due', waiting.nextRunAt);
  await f.submitted(1, 'nothing is reserved for a rework that waits for approval');
  const rework = await f.approvedRun(w, (await approve(f, w, 2)).approvedAt, 'the approved rework');
  expectEqual(pick(rework, 'attempt reworkOf'), {attempt: 2, reworkOf: first.id}, '§15.2 the approved run is the rework');
  const two = await f.finish(rework, 'succeeded', {output: 'FAKE SCRIPTED invoice list two'});
  await f.verdict(two, {verdict: 'rejected'});
  await f.waitFor(w, item => item.reworkPending === rework.id, '§15.2 a second rejection makes a second rework due');
  const before = await expectWait(f, w, 3, 'a second pending rework');
  const [skipped] = await skip(f, w, 1);
  expect(skipped.reworkPending === null && at(skipped.nextRunAt) === at(before.nextRunAt), '§14.2 skip drops a pending ' +
    'rework and leaves nextRunAt (only without a rework or handoff does nextRunAt move on)', pick(skipped, 'reworkPending nextRunAt'));
  await expectNoWait(f, w, 3, 'once the rework was skipped');
  expectEqual([(await f.runsOf(w)).length, (await f.workflow(w.id)).reworkPending], [2, null], '§14.2 skip creates no run, ' +
    'and the dropped rework stays dropped');
  await f.submitted(2, 'two approved runs and no other');
  await f.stop();
}

// Cases 32 and 33, handoff. §14.2 and §14.1: an after workflow with nothing pending does not wait; a pending handoff
// waits; the approved run is the handoff run; a rework that becomes pending while the workflow waits for a handoff run
// is a new wait for another run; with both pending, skip drops the rework, the handoff then makes a new wait, and a
// second skip drops it; no run is created.
async function case32_handoffWaitsAndSkip() {
  const f = await gated('approval-handoff');
  await f.start();
  await f.ready();
  const up = await f.create({name: 'FAKE upstream without approval', intervalMinutes: 60, instructions: 'FAKE upstream assignment'});
  const down = await f.create({name: 'FAKE gated downstream', intervalMinutes: undefined, after: {workflowId: up.id}, ...operator,
    review: 'operator', reworkLimit: 1, enabled: true, instructions: 'FAKE downstream assignment'});
  await expectNoWait(f, down, 0, 'for an after workflow with nothing pending (no clock makes it due)');
  await f.action(up.id, 'run');
  await f.action(up.id, 'resume');
  const u1 = await f.finish(await f.newRun(up.id, 'queued'), 'succeeded', {output: 'FAKE SCRIPTED upstream result one'});
  await f.waitFor(down, item => item.handoffPending === u1.id, '§14.1 the counted upstream result is pending');
  await expectWait(f, down, 1, 'a pending handoff', {notBefore: u1.finishedAt});
  expectEqual((await f.runsOf(down)).length, 0, '§14.2 nothing is reserved for a handoff that waits for approval');
  const handoff = await f.approvedRun(down, (await approve(f, down, 1)).approvedAt, 'the approved handoff run');
  expectEqual(pick(handoff, 'handoffFrom attempt'), {handoffFrom: u1.id, attempt: 1}, '§14.1 the approved run is the handoff run');
  const draft = await f.finish(handoff, 'succeeded', {output: 'FAKE SCRIPTED downstream draft'});   // its review stays pending
  await f.action(up.id, 'run');
  const u2 = await f.finish(await f.newRun(up.id, 'queued'), 'succeeded', {output: 'FAKE SCRIPTED upstream result two'});
  await f.waitFor(down, item => item.handoffPending === u2.id, '§14.1 the second counted result is pending');
  const handoffWait = await expectWait(f, down, 2, 'the second pending handoff', {notBefore: u2.finishedAt});
  await f.verdict(draft, {verdict: 'rejected'});
  await f.waitFor(down, item => item.reworkPending === handoff.id, '§15.2 the rejection makes a rework due');
  await expectWait(f, down, 3, 'a rework became pending while the workflow waited for a handoff run: a new wait for ' +
    'another run (the rework goes first, §14.1)', {replaces: handoffWait.approvalPending});
  const [first] = await skip(f, down, 1);
  expectEqual(pick(first, 'reworkPending handoffPending nextRunAt'), {reworkPending: null, handoffPending: u2.id, nextRunAt: null},
    '§14.2 skip drops a pending rework first; a pending handoff is dropped only otherwise, so it stays');
  await expectWait(f, down, 4, 'the handoff still pending: a new wait');
  const [second] = await skip(f, down, 2);
  expectEqual(pick(second, 'reworkPending handoffPending nextRunAt'), {reworkPending: null, handoffPending: null, nextRunAt: null},
    '§14.2 skip drops a pending handoff when no rework is pending');
  await expectNoWait(f, down, 4, 'once both were skipped');
  expectEqual((await f.runsOf(down)).map(run => run.id), [handoff.id], '§14.2 skip creates no run: the handoff run is the ' +
    'downstream only run');
  await f.stop();
}

// Cases 33 and 34, worker. §14.2: a workflow waits with its worker not ready; once approved it no longer waits, the
// approval is held and the run still waits for a ready worker (§4), blocked by the worker; a pause keeps the approval
// for after resume. Then switching approval off while a workflow waits dispatches it normally.
async function case34_workerPauseAndSwitchOff() {
  const f = await gated('approval-worker', {config: {ready: false}});
  await f.start();
  const unready = await f.code(f.connectionId, 'session_not_ready', 'the FAKE worker session is disconnected', 15000);
  const w = await f.create({name: 'FAKE gated, worker not ready', ...operator, intervalMinutes: 60, enabled: true});
  const waiting = await expectWait(f, w, 1, 'a workflow whose worker is not ready', {notBefore: w.nextRunAt});
  expect(waiting.blockedReason !== unready.reason, '§14.2 while it waits, the blockedReason says it waits for the operator ' +
    'approval, whatever the worker state', {blockedReason: waiting.blockedReason, worker: unready.reason});
  const approved = await approve(f, w, 1);
  await f.waitFor(w, item => item.blockedReason !== waiting.blockedReason, '§14.2 once approved the workflow no longer ' +
    'waits for approval: its blockedReason no longer says so');
  await delay(900);
  const {s, w: held, item} = await f.view(w);
  expect(held.approvalPending === null && at(held.approvedAt) === at(approved.approvedAt) && item === undefined &&
    typeof held.blockedReason === 'string' && held.blockedReason !== '' && s.attention.some(entry =>
    entry.kind === 'worker_unready' && entry.subject.id === f.connectionId && entry.severity === 'action'), '§14.2 an approved ' +
    'run still follows §4: with the worker not ready the approval is held (approvedAt), the workflow does not wait (no ' +
    'approval_pending) and its worker blocks it', {...pick(held, 'approvalPending approvedAt blockedReason'), item});
  await f.submitted(0, 'no run without a ready worker, though approved');
  expectEqual(at((await f.action(w.id, 'pause')).approvedAt), at(approved.approvedAt), '§14.2 a pause keeps the approval');
  await f.configure({ready: true});
  await f.ready();
  await delay(900);
  const paused = await f.workflow(w.id);
  expect(at(paused.approvedAt) === at(approved.approvedAt) && paused.approvalPending === null, '§14.2 the approval is kept ' +
    'while paused, and a paused workflow does not wait', pick(paused, 'approvalPending approvedAt'));
  await f.submitted(0, 'nothing is reserved while paused, though approved and the worker ready');
  await f.action(w.id, 'resume');
  await f.finish(await f.approvedRun(w, approved.approvedAt, 'resume: the kept approval lets the run go out'), 'succeeded',
    {output: 'FAKE SCRIPTED result'});
  await expectNoWait(f, w, 1, 'once the run ended, before the next due time');
  await f.submitted(1, 'exactly one run for one approval');

  const off = await f.create({name: 'FAKE gated, then switched off', ...operator, intervalMinutes: 60, enabled: true});
  await expectWait(f, off, 1, 'a second workflow due at creation');
  expectEqual(pick(await f.patch(off.id, {approval: 'none'}), 'approval approvedAt'), {approval: 'none', approvedAt: null},
    '§9 PATCH switches approval off');
  const normal = await f.newRun(off.id, 'queued', 15000);
  expectEqual(normal.approvedAt, null, '§14.2 switching approval off while waiting dispatches normally: the run has approvedAt null');
  await f.waitFor(off, item => item.approvalPending === null, '§14.2 the wait ends without a decision: approvalPending is null');
  expectEqual([(await f.entries(off, 'workflow.edited')).map(entry => entry.data.fields), (await f.entries(off,
    'workflow.approved')).length, (await f.entries(off, 'workflow.skipped')).length, (await f.entries(off,
    'workflow.approval_requested')).length], [[['approval']], 0, 0, 1], '§11 the switch records workflow.edited with ' +
    'approval and no approve or skip; the one wait has its workflow.approval_requested');
  await f.finish(normal, 'succeeded', {output: 'FAKE SCRIPTED result without approval'});
  await f.stop();
}

// Case 34, restart. §14.2 and §1: a restart keeps a wait (the same approvalPending and item, no new
// workflow.approval_requested) and a held approval (approvedAt); the kept approval lets the run go out once the
// worker is ready, and the kept wait still needs an approval.
async function case34_restartKeepsWaitAndApproval() {
  const f = await gated('approval-restart', {config: {ready: false}});
  await f.start();
  await f.code(f.connectionId, 'session_not_ready', 'the FAKE worker session is disconnected', 15000);
  const a = await f.create({name: 'FAKE gated, left waiting', ...operator, intervalMinutes: 60, enabled: true});
  const b = await f.create({name: 'FAKE gated, approved before the restart', ...operator, intervalMinutes: 60, enabled: true});
  const waitA = await expectWait(f, a, 1, 'the first workflow, due at creation');
  await expectWait(f, b, 1, 'the second workflow, due at creation');
  const approvedB = await approve(f, b, 1);
  await f.waitFor(b, item => item.approvalPending === null && item.approvedAt !== null, 'fixture: the approval is held');
  await f.stop();
  const stoppedAt = f.now();
  await f.start();
  await until('§4 scheduler passes after the restart', async () => at((await f.snapshot()).meta.lastTickAt) > stoppedAt + 500, 15000);
  await delay(600);
  const {s} = await f.view(a);
  const [kept, held] = [a, b].map(w => s.workflows.find(item => item.id === w.id));
  expect(at(kept.approvalPending) === at(waitA.approvalPending) && s.attention.some(item => item.kind === 'approval_pending' &&
    item.subject.id === a.id), '§14.2 a restart keeps a wait: the same approvalPending and the approval_pending item',
  pick(kept, 'approvalPending approvedAt'));
  expect(held.approvalPending === null && at(held.approvedAt) === at(approvedB.approvedAt), '§14.2 a restart keeps an ' +
    'approval: approvedAt as approved, and no wait', pick(held, 'approvalPending approvedAt'));
  expectEqual([(await f.entries(a, 'workflow.approval_requested')).length, (await f.entries(b, 'workflow.approval_requested')).length],
    [1, 1], '§11 the kept wait is not a new one: no second workflow.approval_requested');
  await f.submitted(0, 'nothing while the worker is not ready');
  await f.configure({ready: true});
  const run = await f.approvedRun(b, approvedB.approvedAt, 'after the restart, the kept approval lets the run go out');
  await f.finish(run, 'succeeded', {output: 'FAKE SCRIPTED result after the restart'});
  const still = await expectWait(f, a, 1, 'the kept wait, with the worker ready');
  expectEqual([at(still.approvalPending), (await f.runsOf(a)).length], [at(waitA.approvalPending), 0], '§14.2 the kept wait ' +
    'goes on and nothing is reserved for it');
  await f.finish(await f.approvedRun(a, (await approve(f, a, 1)).approvedAt, 'the kept wait, approved after the restart'),
    'succeeded', {output: 'FAKE SCRIPTED result of the kept wait'});
  await f.submitted(2, 'one run for each approval');
  await f.stop();
}

// Case 33, a rework takes the place of the run waited for. §14.2: a wait concerns one run, so a rework that becomes
// pending while the workflow waits for its scheduled run is a new wait; an approval is for the run the workflow waited
// to make, so one given for a scheduled run (held: the worker is not ready) is withdrawn when a rework becomes pending
// first, and the rework waits for its own approval and goes out with it, not with the earlier one.
async function case33_reworkReplacesApprovedRun() {
  const f = await gated('approval-rework-replaces', {clock: '2026-05-04T10:00:00.000Z'});
  await f.start();
  await f.ready();
  const w = await f.create({name: 'FAKE gated, reviewed every minute', ...operator, review: 'operator', reworkLimit: 2,
    acceptanceMinutes: 60, enabled: true});
  await expectWait(f, w, 1, 'due at creation', {notBefore: w.nextRunAt});
  const first = await f.approvedRun(w, (await approve(f, w, 1)).approvedAt, 'the first run');
  const one = await f.finish(first, 'succeeded', {output: 'FAKE SCRIPTED result one'});   // its review stays pending
  await f.clockAt(f.now() + 2 * minute, 'the next due time passes');
  const scheduled = await expectWait(f, w, 2, 'the scheduled run, the first result still under review');
  await f.verdict(one, {verdict: 'rejected'});
  await expectWait(f, w, 3, 'a rework became pending while the workflow waited for its scheduled run: a new wait for ' +
    'another run', {replaces: scheduled.approvalPending});
  const rework = await f.approvedRun(w, (await approve(f, w, 2)).approvedAt, 'the approved rework');
  expectEqual(pick(rework, 'attempt reworkOf'), {attempt: 2, reworkOf: first.id}, '§15.2 the approved run is the rework');
  const two = await f.finish(rework, 'succeeded', {output: 'FAKE SCRIPTED result two'});   // under review too
  await f.clockAt(f.now() + 2 * minute, 'the next due time passes');
  await expectWait(f, w, 4, 'the scheduled run, the rework result still under review');
  await f.configure({ready: false});
  await f.code(f.connectionId, 'session_not_ready', 'the FAKE worker session is disconnected');
  const early = await approve(f, w, 3);
  await delay(800);
  expectEqual(pick(await f.workflow(w.id), 'approvalPending approvedAt'), {approvalPending: null, approvedAt: early.approvedAt},
    'fixture: the approval of the scheduled run is held while the worker is not ready');
  await f.verdict(two, {verdict: 'rejected'});
  await expectWait(f, w, 5, 'the approval was for the scheduled run: a rework that became pending before it went out ' +
    'withdraws it (approvedAt null), and the rework waits for its own approval');
  await f.configure({ready: true});
  await f.ready();
  await delay(900);
  await f.submitted(2, 'nothing goes out on the withdrawn approval, though the worker is ready');
  const own = await approve(f, w, 4);
  const third = await f.approvedRun(w, own.approvedAt, 'the rework goes out with its own approval, not the earlier one');
  expect(third.attempt === 3 && third.reworkOf === rework.id && at(third.approvedAt) > at(early.approvedAt), '§14.2 and §15.2 ' +
    'the run is the rework, reserved with the approval given for it', pick(third, 'attempt reworkOf approvedAt'));
  await f.stop();
}

// Case 33, a newer handoff takes the place of the run waited for. §14.2 and §14.1: the upstream runs on a second worker;
// a newer handoff that becomes pending while the downstream waits is a new wait; one that becomes pending after an
// approval (held: the downstream's worker is not ready) withdraws it, and the newest handoff waits for its own.
async function case33_newerHandoffReplacesApprovedRun() {
  const f = await twoWorkers('approval-newer-handoff');
  await f.start();
  await f.ready();
  await f.code(f.secondId, 'ready', 'the second FAKE worker is ready', 15000);
  const up = await f.create({name: 'FAKE upstream on the second worker', connectionId: f.secondId, intervalMinutes: 60,
    instructions: 'FAKE upstream assignment'});
  const down = await f.create({name: 'FAKE gated downstream', intervalMinutes: undefined, after: {workflowId: up.id}, ...operator,
    enabled: true, instructions: 'FAKE downstream assignment'});
  const upstreamRun = async index => {
    await f.action(up.id, 'run');
    if (index === 1) await f.action(up.id, 'resume');
    const run = await f.finish(await f.newRun(up.id, 'queued'), 'succeeded', {output: `FAKE SCRIPTED upstream result ${index}`});
    await f.waitFor(down, item => item.handoffPending === run.id, `§14.1 the counted upstream result ${index} is pending`);
    return run;
  };
  const u1 = await upstreamRun(1);
  const firstWait = await expectWait(f, down, 1, 'a pending handoff', {notBefore: u1.finishedAt});
  await upstreamRun(2);
  await expectWait(f, down, 2, 'a newer handoff became pending while the workflow waited: a new wait for another run',
    {replaces: firstWait.approvalPending});
  await f.setSession(ids, 'disconnected');
  await f.code(f.connectionId, 'session_not_ready', 'the downstream FAKE worker session is disconnected');
  const early = await approve(f, down, 1);
  await delay(800);
  expectEqual(pick(await f.workflow(down.id), 'approvalPending approvedAt'), {approvalPending: null, approvedAt: early.approvedAt},
    'fixture: the approval of the second handoff run is held while the worker is not ready');
  const u3 = await upstreamRun(3);
  await expectWait(f, down, 3, 'a newer handoff that became pending after the approval withdraws it (approvedAt null): ' +
    'the newest handoff waits for its own approval');
  await f.setSession(ids, 'ready');
  await f.ready();
  await delay(900);
  expectEqual((await f.runsOf(down)).length, 0, '§14.2 nothing goes out on the withdrawn approval, though the worker is ready');
  const own = await approve(f, down, 2);
  const run = await f.approvedRun(down, own.approvedAt, 'the newest handoff goes out with its own approval');
  expectEqual(run.handoffFrom, u3.id, '§14.1 the run is the newest handoff');
  await f.stop();
}

// Case 33, pause, PATCH and archive. §14.2: a pause ends a wait at once (the response, then 409 for approve and skip)
// and keeps an approval; a PATCH that changes no value keeps an approval, one that changes a value withdraws it; an
// archive withdraws an approval and ends a wait at once. Each time the workflow waits again before it runs. The worker
// is not ready until the end, so no approval is used before then.
async function case33_pausePatchAndArchive() {
  const f = await gated('approval-withdrawn', {config: {ready: false}});
  await f.start();
  await f.code(f.connectionId, 'session_not_ready', 'the FAKE worker session is disconnected', 15000);
  const w = await f.create({name: 'FAKE gated, edited and archived', ...operator, intervalMinutes: 60, enabled: true});
  await expectWait(f, w, 1, 'due at creation', {notBefore: w.nextRunAt});
  const refuse = async why => {
    for (const action of ['approve', 'skip']) {
      expectError(await f.request('POST', route(w.id, action), {}), 409, `§14.2 ${action} ${why} is 409`);
    }
  };
  expectEqual((await f.action(w.id, 'pause')).approvalPending, null, '§14.2 a pause ends a wait at once: the response ' +
    'shows approvalPending null');
  await refuse('right after a pause');
  await f.action(w.id, 'resume');
  await expectWait(f, w, 2, 'after resume');
  const first = await approve(f, w, 1);
  expectEqual(at((await f.action(w.id, 'pause')).approvedAt), at(first.approvedAt), '§14.2 a pause keeps the approval');
  await f.action(w.id, 'resume');
  const unchanged = await f.patch(w.id, {approval: 'operator', maxRunsPerDay: w.maxRunsPerDay, name: w.name});
  await delay(800);
  const kept = await f.workflow(w.id);
  expect(at(unchanged.approvedAt) === at(first.approvedAt) && at(kept.approvedAt) === at(first.approvedAt) &&
    kept.approvalPending === null, '§14.2 a PATCH that changes no value keeps the approval', pick(kept, 'approvalPending approvedAt'));
  await f.patch(w.id, {maxRunsPerDay: 7});
  await expectWait(f, w, 3, 'a PATCH that changes a value withdraws the approval: the workflow waits again');
  const second = await approve(f, w, 2);
  expectStatus(await f.request('POST', route(w.id, 'archive'), {}), 200, '§9 archive with an approval held');
  await refuse('right after the archive');
  const restored = expectStatus(await f.request('POST', route(w.id, 'restore'), {}), 200, '§9 restore').data;
  expectEqual(pick(restored, 'approvalPending approvedAt enabled'), {approvalPending: null, approvedAt: null, enabled: false},
    `§14.2 an archive withdraws the approval (given ${second.approvedAt}); restore returns the workflow paused`);
  await f.action(w.id, 'resume');
  await expectWait(f, w, 4, 'after the archive, restore and resume, the workflow waits again before it runs');
  expectStatus(await f.request('POST', route(w.id, 'archive'), {}), 200, '§9 archive of a waiting workflow');
  await refuse('right after the archive of a waiting workflow');
  expectEqual((await f.entries(w, 'workflow.edited')).map(entry => entry.data.fields), [['maxRunsPerDay']],
    '§11 only the PATCH that changed a value records workflow.edited');
  const again = expectStatus(await f.request('POST', route(w.id, 'restore'), {}), 200, '§9 restore').data;
  expectEqual(again.approvalPending, null, '§14.2 an archive ends a wait at once');
  await f.action(w.id, 'resume');
  await expectWait(f, w, 5, 'after the second restore and resume');
  await f.configure({ready: true});
  await f.ready();
  await delay(900);
  await f.submitted(0, 'no withdrawn approval is used once the worker is ready');
  const last = await approve(f, w, 3);
  await f.finish(await f.approvedRun(w, last.approvedAt, 'the run goes out with the one approval still held'), 'succeeded',
    {output: 'FAKE SCRIPTED result'});
  await f.submitted(1, 'one run for the approval that was not withdrawn');
  await f.stop();
}

await runCases('approvals', [case32_fields, case32_intervalWaits, case32_scheduleWaitsAndSkip, case32_noWaitWithRunOrAtCap,
  case33_routes, case33_approveAndSkipInterval, case32_reworkWaitsAndSkip, case32_handoffWaitsAndSkip,
  case34_workerPauseAndSwitchOff, case34_restartKeepsWaitAndApproval, case33_reworkReplacesApprovedRun,
  case33_newerHandoffReplacesApprovedRun, case33_pausePatchAndArchive]);
