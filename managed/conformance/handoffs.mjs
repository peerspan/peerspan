#!/usr/bin/env node
// Contract-only black-box suite for docs/managed-contract.md revision 9, section 16, cases 26 to 28: handoffs between
// workflows (sections 2, 8, 9, 11 and 14.1), with the verdicts, checks and reworks that decide when a result counts
// and what a handoff run is sent (sections 15, 15.1, 15.2 and 15.3). No imports or reads of the managed
// implementation or its database: the documented CLI, HTTP, the explicitly fake Peerspan executable and throwaway
// state only. The fake plays the worker and reviewer agents, either driven step by step through its task records or
// by its `scripts` (README). Expected inputs are written out from the contract; section numbers (§) refer to it.
import path from 'node:path';
import {delay, expect, expectEqual, expectError, expectStatus, fixture, hex, ids, inputOf, pick, runCases, snippet,
  until} from './harness.mjs';

const minute = 60000;
const reviewerAgent = {agentId: hex('agent', 7), sessionId: hex('session', 7), adapterId: hex('adapter', 7)};
const unresolved = ['submitting', 'queued', 'running'];
const after = workflowId => ({workflowId});
const accepted = {verdict: 'accepted'};

// §14.1, §15.1 and §15.2: the last part (a retained output) is used without its NUL characters; an input longer than
// `limit` bytes of UTF-8 has that part cut at a character (code point) boundary and ended with "…", keeping as much of
// it as lets the whole fit, and only "…" when even the rest and "…" alone are longer.
function fitted(lines, output, limit) {
  const last = output.replaceAll('\u0000', '');
  const prefix = lines.join('\n') + '\n';
  if (Buffer.byteLength(prefix + last) <= limit) return prefix + last;
  let room = limit - Buffer.byteLength(prefix) - Buffer.byteLength('…');
  const kept = [];
  for (const character of last) {
    room -= Buffer.byteLength(character);
    if (room < 0) break;
    kept.push(character);
  }
  return prefix + kept.join('') + '…';
}
// §14.1: the handoff input, at most 32,768 bytes; the upstream workflow's name is written without NUL characters.
const handoffInput = (instructions, upstreamName, output) => fitted([instructions, '', 'INPUT',
  `The result below is the latest accepted result of the workflow "${upstreamName.replaceAll('\u0000', '')}". Use it as the input of this assignment.`,
  '', 'RESULT'], output, 32768);
// §15.2 and §15.3, (rev 9) beginning with the rejected handoff run's assignment in place of the instructions.
const reworkInput = (assignment, note, previous) => fitted([assignment, '', 'REVISION REQUESTED',
  'A reviewer rejected your previous result for this assignment. Do the assignment again in full, addressing the review.',
  '', 'REVIEW', note ?? 'The reviewer gave no reasons.', '', 'PREVIOUS RESULT'], previous, 65536);
const checksReworkInput = (assignment, note, previous) => fitted([assignment, '', 'REVISION REQUESTED',
  'Your previous result for this assignment failed the result checks below. Do the assignment again in full, so that it passes them.',
  '', 'FAILED CHECKS', note, '', 'PREVIOUS RESULT'], previous, 65536);

// A fixture whose fake worker host has the fixture's own worker agent and `others`, each with a verified session
// (§3), and a second sender state for reviewer connections.
async function team(label, others = [], options = {}) {
  const f = await fixture(label, options);
  f.reviewSender = path.join(f.dir, 'PRIVATE-review-sender');
  const all = [ids, ...others];
  const sessions = new Map(all.map(item => [item.agentId, 'ready']));
  const agents = () => ({
    agents: all.map(item => ({id: item.agentId, name: 'FAKE-CONFORMANCE agent ' + item.agentId.slice(-4),
      sessions: [{id: item.sessionId, adapter_id: item.adapterId, connection: sessions.get(item.agentId)}]})),
    adapters: Object.fromEntries(all.map(item => [item.adapterId, {session_id: item.sessionId, state: 'ready',
      channel: 'verified', channel_verified_at: '2026-01-01T00:00:00Z'}]))});
  await f.configure({...agents(), scripts: [], senderStates: [f.senderDir, f.reviewSender]});
  f.setSession = async (item, connection) => { sessions.set(item.agentId, connection); await f.configure(agents()); };
  f.connectAgent = async (item, name) => JSON.parse(await f.checkedCli('connect', '--name', name, '--agent', item.agentId,
    '--host-state', f.workerDir, '--sender-state', f.reviewSender)).id;
  f.ready = (...connections) => Promise.all(connections.map(id => f.code(id, 'ready', 'the agent is ready and verified')));
  f.script = (...scripts) => f.configure({scripts: scripts.map(script => ({agent: ids.agentId, state: 'succeeded', ...script}))});
  // Created paused (§2). An upstream runs once when started: `run` while paused, then `resume` (§2, §9).
  f.upstream = patch => f.create({intervalMinutes: 60, ...patch});
  f.downstream = (upstream, patch) => f.create({intervalMinutes: undefined, after: after(upstream.id), ...patch});
  f.startOnce = async w => { await f.action(w.id, 'run'); await f.action(w.id, 'resume'); };
  f.verdict = async (run, body) => expectStatus(await f.request('POST', `/api/runs/${run.id}/review`, body), 200,
    '§15 POST /api/runs/:id/review ' + body.verdict).data;
  f.submitted = async run => {
    const [call] = await f.taskCalls('submit', run.taskId);
    expect(call, '§4 the run task is submitted', pick(run, 'id taskId state'));
    return inputOf(call.argv);
  };
  f.waitFor = (w, test, why, timeout) => {
    let last;
    return until(() => `${why}; last seen: ${snippet(last && pick(last, 'enabled handoffPending reworkPending blockedReason'))}`,
      async () => { last = await f.workflow(w.id); return last && test(last) ? last : false; }, timeout);
  };
  f.runsOf = async w => (await f.snapshot()).runs.filter(run => run.workflowId === w.id);
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
  f.edits = async w => (await f.log()).filter(entry => entry.kind === 'workflow.edited' && entry.workflowId === w.id)
    .map(entry => entry.data.fields);
  // §11 (rev 9): the workflow.handoff_due entries of a workflow, oldest first, as the upstream runs they name.
  f.handoffs = async w => (await f.log()).filter(entry => entry.kind === 'workflow.handoff_due' && entry.workflowId === w.id)
    .map(entry => { expectEqual(pick(entry, 'actor connectionId data'), {actor: 'system', connectionId: null, data: null},
      '§11 workflow.handoff_due is a system entry with data null'); return entry.runId; });
  return f;
}

// Case 26. §14.1, §2 and §9: after at creation and in PATCH with the exactly-one rule; the 400s (an unknown or
// archived upstream, the workflow itself, cycles of two and three, a malformed after, after null in a PATCH); switching
// to and from after, with the workflow.edited fields and nextRunAt; a PATCH repeating the current upstream, archived
// meanwhile, not checked again; a pending handoff kept by a repeated upstream and cleared by another one; an upstream
// archived later staying the upstream; the blockedReason of a waiting after workflow, whatever the state of its
// worker. One source workflow runs once; every other workflow with a clock stays paused.
async function case26_fields() {
  const f = await team('handoff-fields', [], {clock: '2026-03-04T12:00:00.000Z'});   // a Wednesday
  await f.start();
  await f.ready(f.connectionId);
  const weds = {timeZone: 'UTC', days: ['wed'], times: ['13:30']};
  const up = await f.upstream({name: 'FAKE upstream'});
  const scheduled = await f.create({name: 'FAKE scheduled', intervalMinutes: undefined, schedule: weds});
  const gone = await f.upstream({name: 'FAKE archived upstream'});
  expectStatus(await f.request('POST', `/api/workflows/${gone.id}/archive`, {}), 200, '§9 archive');
  const down = await f.downstream(up, {name: 'FAKE downstream'});
  expectEqual(pick(down, 'after intervalMinutes schedule nextRunAt handoffPending enabled'), {after: after(up.id),
    intervalMinutes: null, schedule: null, nextRunAt: null, handoffPending: null, enabled: false}, '§2 (rev 9) after takes the ' +
    'place of intervalMinutes and schedule; §14.1 an after workflow nextRunAt is null; handoffPending is null');
  expectEqual([up, scheduled].map(w => pick(w, 'after handoffPending')), Array(2).fill({after: null, handoffPending: null}),
    '§14.1 workflows have after and handoffPending in every shape, null without an upstream');
  const third = await f.downstream(down, {name: 'FAKE third in the chain'});   // third after down after up
  for (const [what, patch] of [['intervalMinutes', {intervalMinutes: 30}], ['a schedule', {intervalMinutes: undefined, schedule: weds}]]) {
    expectEqual((await f.create({name: 'FAKE after null', after: null, ...patch})).after, null,
      `§14.1 at creation, after null beside ${what} means no upstream`);
  }

  const body = patch => ({name: 'FAKE refused handoff', connectionId: f.connectionId, instructions: 'FAKE fields only',
    maxRunsPerDay: 5, acceptanceMinutes: 5, ...patch});
  const malformed = [['the upstream ID as a string', up.id], ['an array', [up.id]], ['an empty object', {}], ['true', true],
    ['a numeric workflowId', {workflowId: 7}], ['workflowId null', {workflowId: null}], ['another field name', {id: up.id}],
    ['an extra field', {workflowId: up.id, name: 'FAKE'}], ['an unknown upstream', after('FAKE-absent')],
    ['an empty workflowId', after('')], ['an archived upstream', after(gone.id)]];
  const refused = [['after beside intervalMinutes', {after: after(up.id), intervalMinutes: 5}],
    ['after beside a schedule', {after: after(up.id), schedule: weds}],
    ['all three', {after: after(up.id), intervalMinutes: 5, schedule: weds}], ['none of the three', {}],
    ['after null alone', {after: null}], ['after null and schedule null', {after: null, schedule: null}],
    ...malformed.map(([what, value]) => [what, {after: value}])];
  for (const [what, patch] of refused) {
    expectError(await f.request('POST', '/api/workflows', body(patch)), 400, `§14.1 POST refuses ${what}`);
  }
  expectEqual([(await f.snapshot()).workflows.length, (await f.log()).filter(entry => entry.kind === 'workflow.created').length],
    [6, 7], '§2 refused creations store nothing: six workflows and one archived, seven workflow.created entries');

  // PATCH: the workflow itself, cycles of two and three, after null, the combinations; a refused PATCH changes nothing.
  const patchRefusals = [[up, [['the workflow itself', {after: after(up.id)}],
    ['a two-step cycle (up after down, which runs after up)', {after: after(down.id)}],
    ['a three-step cycle (up after third, which runs after down, which runs after up)', {after: after(third.id)}]]],
  [down, [['the workflow itself', {after: after(down.id)}], ['a two-step cycle (down after third)', {after: after(third.id)}],
    ['after null', {after: null}], ['after beside intervalMinutes', {after: after(scheduled.id), intervalMinutes: 5}],
    ['after beside a schedule', {after: after(scheduled.id), schedule: weds}], ['schedule null', {schedule: null}],
    ['intervalMinutes null', {intervalMinutes: null}], ['handoffPending', {handoffPending: null}], ['nextRunAt', {nextRunAt: null}],
    ...malformed.map(([what, value]) => [what, {after: value}]),
    ['a valid name beside an archived upstream', {name: 'FAKE never renamed', after: after(gone.id)}]]],
  [scheduled, [['after null', {after: null}], ['after null beside a schedule', {after: null, schedule: weds}]]]];
  for (const [workflow, list] of patchRefusals) {
    const kept = await f.workflow(workflow.id);
    for (const [what, patch] of list) {
      expectError(await f.request('PATCH', '/api/workflows/' + workflow.id, patch), 400, `§14.1 PATCH refuses ${what}`);
    }
    expectEqual(await f.workflow(workflow.id), kept, '§9 a refused PATCH changes nothing');
  }
  expectEqual((await f.patch(down.id, {after: after(up.id)})).after, after(up.id), '§14.1 a PATCH may repeat the current upstream');
  expectEqual(pick(await f.patch(down.id, {after: after(up.id), name: 'FAKE downstream renamed'}), 'name after'),
    {name: 'FAKE downstream renamed', after: after(up.id)}, '§9 PATCH returns the edited workflow');

  // Switching to and from after (§14.1, §9, §14).
  const interval = await f.create({name: 'FAKE interval switched', intervalMinutes: 30});
  const shape = 'after intervalMinutes schedule nextRunAt handoffPending';
  expectEqual(pick(await f.patch(interval.id, {after: after(up.id)}), shape), {after: after(up.id), intervalMinutes: null,
    schedule: null, nextRunAt: null, handoffPending: null}, '§14.1 setting after switches an interval workflow to it; nextRunAt null');
  const back = await f.patch(interval.id, {intervalMinutes: 15});
  expectEqual(pick(back, 'after intervalMinutes schedule handoffPending'), {after: null, intervalMinutes: 15, schedule: null,
    handoffPending: null}, '§14.1 setting intervalMinutes switches an after workflow away from it');
  expect(Math.abs(Date.parse(back.nextRunAt) - f.now()) < 3000, '§14.1 switching an after workflow without a terminal run to ' +
    'an interval sets nextRunAt to now (the controller clock)', {nextRunAt: back.nextRunAt, now: new Date(f.now()).toISOString()});
  expectEqual(pick(await f.patch(scheduled.id, {after: after(down.id)}), shape), {after: after(down.id), intervalMinutes: null,
    schedule: null, nextRunAt: null, handoffPending: null}, '§14.1 setting after switches a scheduled workflow to it, here ' +
    'after a workflow that itself runs after another');
  const toSchedule = await f.patch(scheduled.id, {schedule: weds});
  expectEqual([pick(toSchedule, 'after intervalMinutes schedule'), Date.parse(toSchedule.nextRunAt)], [{after: null,
    intervalMinutes: null, schedule: weds}, Date.parse('2026-03-04T13:30:00.000Z')], '§14.1 switching to a schedule follows ' +
    '§14: nextRunAt is the first slot after the request (13:30 UTC today)');
  expectEqual((await f.patch(third.id, {after: after(up.id)})).after, after(up.id), '§14.1 PATCH changes the upstream');
  expectEqual([await f.edits(interval), await f.edits(scheduled), await f.edits(third), await f.edits(down)],
    [[['after', 'intervalMinutes'], ['after', 'intervalMinutes']], [['after', 'schedule'], ['after', 'schedule']], [['after']],
      [['name']]], '§11 a switch lists both fields that changed in workflow.edited; a new upstream lists after; a PATCH ' +
    'that repeats the current upstream changes nothing, and no refused PATCH records an entry');

  // §14.1: with a handoff pending, a PATCH that repeats the upstream keeps it, and one that points after at another
  // upstream sets handoffPending to null. The source is the one workflow this case dispatches, once.
  await f.script({input: '<fields-source>', output: 'FAKE source result'});
  const source = await f.upstream({name: 'FAKE source upstream', instructions: 'FAKE source assignment <fields-source>'});
  const retargeted = await f.downstream(source, {name: 'FAKE retargeted downstream'});
  await f.startOnce(source);
  const sourced = await f.newRun(source.id, 'succeeded');
  await f.waitFor(retargeted, w => w.handoffPending === sourced.id, '§14.1 the counted source result is pending (paused downstream)');
  expectEqual(pick(await f.patch(retargeted.id, {after: after(source.id)}), 'after handoffPending'), {after: after(source.id),
    handoffPending: sourced.id}, '§14.1 a PATCH that repeats the current upstream changes nothing: the pending handoff is kept');
  expectEqual(pick(await f.patch(retargeted.id, {after: after(up.id)}), 'after handoffPending'), {after: after(up.id),
    handoffPending: null}, '§14.1 pointing after at another upstream sets handoffPending to null');
  expectEqual(await f.edits(retargeted), [['after']], '§11 only the change of upstream records workflow.edited, listing after');

  // §14.1 Dispatch: an enabled after workflow without an unresolved run and with neither a handoff nor a rework
  // pending has a blockedReason that says it waits for a result of its upstream, whatever the state of its worker.
  await f.action(down.id, 'resume');
  await f.clockAt(f.now() + 2000, 'a scheduler pass after resume');
  const waiting = await f.workflow(down.id);
  expect(typeof waiting.blockedReason === 'string' && waiting.blockedReason.trim() !== '' && waiting.enabled &&
    waiting.nextRunAt === null, '§14.1 an enabled after workflow that waits has a blockedReason', pick(waiting, 'enabled nextRunAt blockedReason'));
  await f.setSession(ids, 'disconnected');
  await f.code(f.connectionId, 'session_not_ready', 'the worker session is disconnected');
  await f.clockAt(f.now() + 2000, 'a scheduler pass with the worker not ready');
  expectEqual((await f.workflow(down.id)).blockedReason, waiting.blockedReason, '§14.1 the blockedReason that says it waits for ' +
    'a result of its upstream holds whatever the state of its worker: the same with the worker not ready');
  await f.setSession(ids, 'ready');

  // An upstream archived later stays the upstream; a PATCH that repeats it is not checked again (§14.1).
  expectStatus(await f.request('POST', `/api/workflows/${up.id}/archive`, {}), 200, '§9 archive of the upstream');
  const view = await f.snapshot();
  expectEqual([view.workflows.find(w => w.id === down.id)?.after, view.archived.some(a => a.id === up.id)], [after(up.id), true],
    '§14.1 an upstream that is archived later stays the upstream');
  expectEqual(pick(await f.patch(down.id, {after: after(up.id), maxRunsPerDay: 7}), 'after maxRunsPerDay'), {after: after(up.id),
    maxRunsPerDay: 7}, '§14.1 a PATCH that repeats the current upstream is not checked again, though it is archived now');
  expectError(await f.request('PATCH', '/api/workflows/' + interval.id, {after: after(up.id)}), 400,
    '§14.1 a request that makes an archived workflow the upstream');
  expectEqual((await f.edits(down)).at(-1), ['maxRunsPerDay'], '§11 the repeated upstream is no change');
  expectStatus(await f.request('POST', `/api/workflows/${up.id}/restore`, {}), 200, '§9 restore of the upstream');
  expectEqual((await f.workflow(down.id)).after, after(up.id), '§14.1 the downstream still runs after the restored upstream');
  expectStatus(await f.request('POST', `/api/workflows/${third.id}/archive`, {}), 200, '§9 archive of a downstream');
  expectEqual((await f.snapshot()).archived.map(entry => pick(entry, 'id after')), [{id: third.id, after: after(up.id)},
    {id: gone.id, after: null}], '§8 (rev 9) archived entries, newest first, have after: an archived after workflow keeps its ' +
    'upstream, so a chain can be followed through it; one without an upstream has after null');
  const restored = expectStatus(await f.request('POST', `/api/workflows/${third.id}/restore`, {}), 200, '§9 restore').data;
  expectEqual(pick(restored, 'after handoffPending nextRunAt enabled pausedBy'), {after: after(up.id), handoffPending: null,
    nextRunAt: null, enabled: false, pausedBy: 'operator'}, '§9 restore returns the workflow paused with its other fields as they were');
  expectEqual((await f.submissions()).length, 1, '§14.1 no clock makes an after workflow due: only the source run was dispatched');
  await f.stop();
}

// Case 27, when a result counts. §14.1: a counted success hands off for upstream review none (with and without
// passing checks), operator and agent; a rejection by the operator, by the reviewer agent and by checks, a pending
// review and a failed run never do; two downstream workflows of one upstream are both handed off; the
// workflow.handoff_due entries; each handoff run's exact input, handoffFrom and assignment.
async function case27_whenAResultCounts() {
  const f = await team('handoff-counts', [reviewerAgent]);
  const reviewer = await f.connectAgent(reviewerAgent, 'FAKE-CONFORMANCE reviewer');
  await f.start();
  await f.ready(f.connectionId, reviewer);
  const byAgent = {review: 'agent', reviewerId: reviewer};
  const plans = [
    {what: 'review none', counts: true},
    {what: 'review operator, accepted', workflow: {review: 'operator'}, verdict: 'accepted', counts: true},
    {what: 'review agent, accepted by the reviewer', workflow: byAgent, reviewer: 'VERDICT: ACCEPT\nFAKE reasons: complete.', counts: true},
    {what: 'review none, checks passed', workflow: {resultChecks: [{kind: 'contains', text: 'FAKE result'}]}, counts: true},
    {what: 'review operator, rejected', workflow: {review: 'operator'}, verdict: 'rejected', counts: false},
    {what: 'review agent, rejected by the reviewer', workflow: byAgent, reviewer: 'VERDICT: REJECT\nFAKE reasons: no.', counts: false},
    {what: 'review none, rejected by failed checks', workflow: {resultChecks: [{kind: 'contains', text: 'FAKE-NEVER'}]}, counts: false},
    {what: 'review operator, still pending', workflow: {review: 'operator'}, counts: false},
    {what: 'review none, a failed run', state: 'failed', counts: false}];
  const tag = index => `<handoff-up-${index}>`;
  const resultOf = index => `FAKE result of upstream ${index}: λ`;
  await f.script({input: '<handoff-down>', output: 'FAKE downstream result'},
    ...plans.map((plan, index) => ({input: tag(index), state: plan.state ?? 'succeeded', output: resultOf(index)})),
    ...plans.flatMap((plan, index) => plan.reviewer ? [{agent: reviewerAgent.agentId, input: tag(index), output: plan.reviewer}] : []));
  const ups = [];
  for (const [index, plan] of plans.entries()) {
    ups.push(await f.upstream({name: `FAKE upstream ${index}, ${plan.what}`, instructions: `FAKE upstream assignment ${tag(index)}`,
      ...plan.workflow}));
  }
  const downs = [];
  for (const [index, upstream] of [...ups, ups[0]].entries()) {
    downs.push(await f.downstream(upstream, {name: `FAKE downstream ${index}`, instructions: `FAKE downstream ${index} <handoff-down>`}));
  }
  const upstreamOf = index => (index < ups.length ? index : 0);   // the last downstream is a second one of upstream 0
  for (const upstream of ups) await f.startOnce(upstream);
  let runs = [];
  await until(() => 'every upstream run ends and every agent review is given; so far ' +
    snippet(runs.map(run => run && pick(run, 'state review'))), async () => {
    const listed = (await f.snapshot()).runs;
    runs = ups.map(w => listed.find(run => run.workflowId === w.id));
    return runs.every((run, index) => run && !unresolved.includes(run.state) &&
      (!plans[index].reviewer || ['accepted', 'rejected'].includes(run.review)));
  }, 60000);
  const early = downs.filter((d, index) => [0, 2, 3].includes(upstreamOf(index))).map(d => d.name);
  let handedEarly = [];
  await until(() => '§14.1 the results that count without an operator verdict are handed off; so far ' + snippet(handedEarly),
    async () => {
      handedEarly = (await f.snapshot()).workflows.filter(w => downs.some(d => d.id === w.id) && w.handoffPending !== null)
        .map(w => w.name);
      return handedEarly.length >= early.length;
    });
  expectEqual(handedEarly, early, '§14.1 a result counts once it ends succeeded with review null or once the reviewer ' +
    'agent accepts it; an operator-reviewed result does not count before the verdict');
  for (const [index, plan] of plans.entries()) if (plan.verdict) await f.verdict(runs[index], {verdict: plan.verdict});
  runs = await Promise.all(runs.map(run => f.runById(run.id)));
  expectEqual(runs.map(run => [run.state, run.review, run.reviewedBy]), [['succeeded', null, null], ['succeeded', 'accepted',
    'operator'], ['succeeded', 'accepted', 'agent'], ['succeeded', null, null], ['succeeded', 'rejected', 'operator'],
  ['succeeded', 'rejected', 'agent'], ['succeeded', 'rejected', 'checks'], ['succeeded', 'pending', null], ['failed', null, null]],
  'fixture: the upstream results and verdicts as planned');
  const wanted = downs.map((d, index) => (plans[upstreamOf(index)].counts ? runs[upstreamOf(index)].id : null));
  let pending;
  await until(() => '§14.1 each downstream of a counted result gets that run as its handoffPending; observed ' + snippet(pending),
    async () => {
      const {workflows} = await f.snapshot();
      pending = downs.map(d => workflows.find(w => w.id === d.id).handoffPending);
      return wanted.every((id, index) => id === null || pending[index] === id);
    });
  await delay(800);
  const {workflows} = await f.snapshot();
  expectEqual(downs.map(d => workflows.find(w => w.id === d.id).handoffPending), wanted, '§14.1 a counted success hands off ' +
    '(review none with and without checks, operator, agent, and to both downstreams of one upstream); a rejection by the ' +
    'operator, the reviewer agent or checks, a pending review and a failed run never count');
  for (const [index, d] of downs.entries()) {
    expectEqual(await f.handoffs(d), wanted[index] === null ? [] : [wanted[index]], `§11 one workflow.handoff_due for each ` +
      `handoff, its runId the upstream run and its workflowId the downstream (${plans[upstreamOf(index)].what})`);
  }

  for (const d of downs) await f.action(d.id, 'resume');
  let handed = [];
  await until(() => 'the handed-off downstreams each run once; so far ' + snippet(handed.map(list => list.map(run => run.state))), async () => {
    const listed = (await f.snapshot()).runs;
    handed = downs.map(d => listed.filter(run => run.workflowId === d.id));
    return handed.every((list, index) => (wanted[index] === null ? true : list.length === 1 && list[0].state === 'succeeded'));
  }, 30000);
  await delay(1000);
  const final = await f.snapshot();
  for (const [index, d] of downs.entries()) {
    const list = final.runs.filter(run => run.workflowId === d.id);
    const w = final.workflows.find(item => item.id === d.id);
    const what = plans[upstreamOf(index)].what;
    if (wanted[index] === null) {
      expect(list.length === 0 && w.handoffPending === null && typeof w.blockedReason === 'string' && w.blockedReason !== '',
        `§14.1 no handoff run, and a blockedReason, when the upstream result does not count (${what})`, {runs: list.length, w: pick(w, 'handoffPending blockedReason')});
      continue;
    }
    expectEqual([list.map(run => pick(run, 'handoffFrom attempt reworkOf')), w.handoffPending], [[{handoffFrom: wanted[index],
      attempt: 1, reworkOf: null}], null], `§14.1 one handoff run with handoffFrom the upstream run; handoffPending becomes null (${what})`);
    const upstream = runs[upstreamOf(index)];
    const input = handoffInput(d.instructions, ups[upstreamOf(index)].name, resultOf(upstreamOf(index)));
    expectEqual(await f.submitted(list[0]), input, `§14.1 the handoff input: the instructions, the INPUT block naming the ` +
      `upstream workflow, and the upstream result (${what})`);
    expectEqual(pick((await f.detail(list[0].id)).run, 'instructions assignment handoffFrom'), {instructions: input, assignment: input,
      handoffFrom: upstream.id}, `§14.1 a handoff run assignment is its whole input (${what})`);
  }
  expectEqual(final.runs.filter(run => ups.some(w => w.id === run.workflowId)).map(run => run.handoffFrom), Array(9).fill(null),
    '§14.1 a run that is not a handoff has handoffFrom null');
  // The pending result counts once the operator accepts it, and the waiting downstream then runs on it.
  await f.verdict(runs[7], accepted);
  const late = await f.newRun(downs[7].id, 'succeeded');
  expectEqual(late.handoffFrom, runs[7].id, '§14.1 a result counts at the moment its review becomes accepted');
  await f.stop();
}

// Case 27, latest wins. §14.1: the latest counted result replaces a pending one (by the moment it counts, not by its
// age); a paused downstream keeps its handoff until resume; archive clears it and an archived downstream gets none;
// switching away from after clears it; an upstream archived later still hands off an earlier run accepted then;
// instructions and the upstream name read when the run is reserved; one run, not one per result; §9 switching a
// downstream with a terminal run to an interval.
async function case27_latestWinsPauseAndArchive() {
  const f = await team('handoff-latest');
  await f.start();
  await f.ready(f.connectionId);
  const up = await f.upstream({name: 'FAKE latest upstream', instructions: 'FAKE upstream assignment', review: 'operator'});
  const down = await f.downstream(up, {name: 'FAKE latest downstream', instructions: 'FAKE downstream assignment'});
  const other = await f.downstream(up, {name: 'FAKE downstream archived meanwhile', instructions: 'FAKE other assignment'});
  const away = await f.downstream(up, {name: 'FAKE downstream switched away', instructions: 'FAKE switched assignment'});
  const results = [];
  await f.startOnce(up);
  for (const index of [1, 2, 3, 4]) {
    if (index > 1) await f.action(up.id, 'run');
    results.push(await f.finish(await f.newRun(up.id, 'queued'), 'succeeded', {output: `FAKE upstream result ${index}`}));
  }
  const all = [down, other, away];
  const pendingOf = async () => { const {workflows} = await f.snapshot(); return all.map(d => workflows.find(w => w.id === d.id)?.handoffPending); };
  expectEqual(await pendingOf(), [null, null, null], '§14.1 results whose review is pending never count');
  await f.verdict(results[1], accepted);
  for (const d of all) await f.waitFor(d, w => w.handoffPending === results[1].id, '§14.1 the accepted second result is pending');
  await f.verdict(results[0], accepted);
  for (const d of all) {
    await f.waitFor(d, w => w.handoffPending === results[0].id, '§14.1 the latest counted result wins: the first result, ' +
      'accepted later, replaces the second, which was not dispatched');
  }
  expectStatus(await f.request('POST', `/api/workflows/${other.id}/archive`, {}), 200, '§9 archive of a downstream');
  const switched = await f.patch(away.id, {intervalMinutes: 30});
  expectEqual(pick(switched, 'after intervalMinutes handoffPending'), {after: null, intervalMinutes: 30, handoffPending: null},
    '§14.1 switching away from after sets handoffPending to null');
  await f.patch(up.id, {name: 'FAKE latest upstream, renamed'});
  await f.patch(down.id, {instructions: 'FAKE downstream assignment, edited while the handoff waits'});
  await f.verdict(results[2], accepted);
  await f.waitFor(down, w => w.handoffPending === results[2].id, '§14.1 the third result counts');
  expectStatus(await f.request('POST', `/api/workflows/${up.id}/archive`, {}), 200, '§9 archive of the upstream');
  await f.verdict(results[3], accepted);
  await f.waitFor(down, w => w.handoffPending === results[3].id, '§14.1 an upstream archived later stays the upstream: a ' +
    'verdict that accepts one of its earlier runs still counts');
  await delay(800);
  expectEqual([(await f.workflow(down.id)).handoffPending, (await f.runsOf(down)).length], [results[3].id, 0],
    '§14.1 a pause keeps handoffPending; a paused downstream is not dispatched');
  await f.action(down.id, 'resume');
  const handoff = await f.newRun(down.id, 'queued');
  expectEqual([pick(handoff, 'handoffFrom attempt reworkOf'), (await f.workflow(down.id)).handoffPending],
    [{handoffFrom: results[3].id, attempt: 1, reworkOf: null}, null], '§14.1 the run follows resume; handoffPending becomes null');
  expectEqual(await f.submitted(handoff), handoffInput('FAKE downstream assignment, edited while the handoff waits',
    'FAKE latest upstream, renamed', 'FAKE upstream result 4'), '§14.1 the instructions and the upstream name are read when ' +
    'the run is reserved');
  const done = await f.finish(handoff, 'succeeded', {output: 'FAKE downstream result'});
  await delay(1000);
  expectEqual((await f.runsOf(down)).length, 1, '§14.1 the latest counted result wins: one handoff run, not one per result');
  expectEqual([await f.handoffs(down), await f.handoffs(other), await f.handoffs(away)], [results.slice(0, 2).reverse()
    .concat(results.slice(2)).map(run => run.id), [results[1].id, results[0].id], [results[1].id, results[0].id]],
  '§11 workflow.handoff_due for each change, oldest first; none for an archived downstream or one switched away from after');
  const restored = expectStatus(await f.request('POST', `/api/workflows/${other.id}/restore`, {}), 200, '§9 restore').data;
  expectEqual(pick(restored, 'after handoffPending'), {after: after(up.id), handoffPending: null},
    '§14.1 archive sets handoffPending to null, and an archived downstream gets no handoff');
  const toInterval = await f.patch(down.id, {intervalMinutes: 30});
  expect(toInterval.after === null && toInterval.handoffPending === null &&
    Math.abs(Date.parse(toInterval.nextRunAt) - Date.parse(done.finishedAt) - 30 * minute) <= 1000, '§14.1 switching to an ' +
    'interval sets nextRunAt by the rule of §9: the latest terminal run finishedAt plus the interval',
  {...pick(toInterval, 'after handoffPending nextRunAt'), finishedAt: done.finishedAt});
  expectEqual(await f.edits(down), [['instructions'], ['after', 'intervalMinutes']], '§11 the switch lists both fields');
  await f.stop();
}

// Case 27, daily cap. §14.1 and §4: a handoff run counts toward the downstream's daily cap, and a pending handoff waits
// for the next UTC day, with daily_limit_reached meanwhile.
async function case27_dailyCap() {
  const f = await team('handoff-cap', [], {clock: '2026-08-03T23:40:00.000Z'});
  await f.start();
  await f.ready(f.connectionId);
  const up = await f.upstream({name: 'FAKE capped upstream', instructions: 'FAKE upstream assignment'});
  const down = await f.downstream(up, {name: 'FAKE capped downstream', instructions: 'FAKE capped assignment',
    maxRunsPerDay: 1, enabled: true});
  await f.startOnce(up);
  const one = await f.finish(await f.newRun(up.id, 'queued'), 'succeeded', {output: 'FAKE upstream result one'});
  const first = await f.newRun(down.id, 'queued');
  expectEqual(first.handoffFrom, one.id, '§14.1 an enabled downstream is due once a handoff is pending');
  await f.finish(first, 'succeeded');
  await f.action(up.id, 'run');
  const two = await f.finish(await f.newRun(up.id, 'queued'), 'succeeded', {output: 'FAKE upstream result two'});
  const limit = await until('§8 daily_limit_reached while the handoff waits for the cap', async () =>
    (await f.snapshot()).attention.find(item => item.kind === 'daily_limit_reached' && item.subject.id === down.id));
  const blocked = await f.workflow(down.id);
  expect(limit.severity === 'info' && blocked.handoffPending === two.id && blocked.blockedReason && blocked.stats.runs === 1 &&
    (await f.runsOf(down)).length === 1, '§14.1 the daily cap counts handoff runs: the second handoff waits for it',
  {limit, blocked: pick(blocked, 'handoffPending blockedReason stats')});
  await f.clockAt('2026-08-04T00:00:30.000Z', 'a new UTC day begins');
  const second = await f.newRun(down.id, 'queued');
  expectEqual([pick(second, 'handoffFrom attempt'), await f.submitted(second)], [{handoffFrom: two.id, attempt: 1},
    handoffInput('FAKE capped assignment', up.name, 'FAKE upstream result two')], '§14.1 the pending handoff runs on the next UTC day');
  await f.finish(second, 'succeeded');
  expectEqual(pick((await f.workflow(down.id)).stats, 'runs succeeded failed'), {runs: 2, succeeded: 2, failed: 0},
    '§8 statistics count handoff runs');
  await f.stop();
}

// Case 27, dispatch order. §4 (rev 9): when due workflows share a free target, the one whose nextRunAt is oldest goes
// first, and an after workflow ranks by the moment its pending input counted. An interval workflow I and an after
// workflow D share a worker that a FAKE blocker holds; D's upstream runs on another worker. Whichever fell due first
// (I by run, D by its input counting) is dispatched first once the blocker ends, and the other follows.
async function dispatchOrder(label, inputFirst) {
  const upstreamAgent = {agentId: hex('agent', 8), sessionId: hex('session', 8), adapterId: hex('adapter', 8)};
  const f = await team(label, [upstreamAgent], {clock: '2026-05-04T10:00:00.000Z'});
  const elsewhere = await f.connectAgent(upstreamAgent, 'FAKE-CONFORMANCE upstream worker');
  await f.start();
  await f.ready(f.connectionId, elsewhere);
  const hour = {acceptanceMinutes: 60};
  const blocker = await f.upstream({name: 'FAKE blocker of the shared worker', instructions: 'FAKE blocker assignment', ...hour});
  const up = await f.upstream({name: 'FAKE upstream elsewhere', connectionId: elsewhere, instructions: 'FAKE upstream assignment', ...hour});
  const interval = await f.upstream({name: 'FAKE interval workflow', instructions: 'FAKE interval assignment', ...hour});
  const down = await f.downstream(up, {name: 'FAKE after workflow', instructions: 'FAKE after assignment', enabled: true, ...hour});
  await f.startOnce(blocker);
  const held = await f.newRun(blocker.id, 'queued');
  const intervalFallsDue = () => f.startOnce(interval);   // run sets nextRunAt to now (§2), then resume enables it
  const inputCounts = async () => {
    await f.startOnce(up);
    const counted = await f.finish(await f.newRun(up.id, 'queued'), 'succeeded', {output: 'FAKE upstream result'});
    await f.waitFor(down, w => w.handoffPending === counted.id, '§14.1 the upstream result counts and is pending');
  };
  const [early, late] = inputFirst ? [inputCounts, intervalFallsDue] : [intervalFallsDue, inputCounts];
  await early();
  await f.clockAt(f.now() + 2 * minute, 'two minutes pass between the two moments');
  await late();
  await delay(600);
  const contenders = async () => (await f.snapshot()).runs.filter(run => [interval.id, down.id].includes(run.workflowId));
  expectEqual(await contenders(), [], '§4 neither is dispatched while the blocker holds the shared worker');
  await f.finish(held, 'succeeded');
  let fresh = [];
  await until(() => '§4 one of them is dispatched once the worker is free; so far ' + snippet(fresh.map(run => run.workflowName)),
    async () => (fresh = await contenders()).length > 0);
  const [first, second] = inputFirst ? [down, interval] : [interval, down];
  expectEqual(fresh.map(run => run.workflowName), [first.name], `§4 (rev 9) the workflow that fell due first goes first: ` +
    (inputFirst ? 'the after workflow, whose input counted before the interval workflow fell due' : 'the interval workflow, ' +
      'whose nextRunAt is older than the moment the after workflow input counted'));
  await f.finish(fresh[0], 'succeeded');
  const next = await f.newRun(second.id, 'queued');
  expect(next.workflowId === second.id, '§4 the other follows once the worker is free again', next);
  await f.stop();
}
async function case27_dispatchOrder() {
  await Promise.all([dispatchOrder('handoff-order-interval-first', false), dispatchOrder('handoff-order-input-first', true)]);
}

// Case 27, inputs. §14.1: a three-workflow chain passing a result through; NUL left out of the upstream name and
// output; a long upstream result cut to 32,768 bytes with "…"; only "…" when the rest alone is longer.
async function case27_chainAndInputs() {
  const f = await team('handoff-chain');
  await f.start();
  await f.ready(f.connectionId);
  const notes = 'FAKE research notes\u0000 with a NUL, λ 😀';
  const draft = 'FAKE draft built on the notes';
  const long = 'FAKE\u0000 long upstream result: ' + '€'.repeat(12000) + ' FAKE-TAIL';
  const bulky = 'FAKE instructions longer than the limit <only-down> ' + '€'.repeat(11000);   // 11,052 characters, 33,052 bytes
  await f.script({input: '<chain-a>', output: notes}, {input: '<chain-b>', output: draft},
    {input: '<chain-c>', output: 'FAKE summary of the draft'}, {input: '<long-up>', output: long},
    {input: '<long-down>', output: 'FAKE cut downstream result'}, {input: '<only-down>', output: 'FAKE only-ellipsis result'});
  const a = await f.upstream({name: 'FAKE chain\u0000 research', instructions: 'FAKE research assignment <chain-a>'});
  const b = await f.downstream(a, {name: 'FAKE chain draft', instructions: 'FAKE draft assignment <chain-b>', enabled: true});
  const c = await f.downstream(b, {name: 'FAKE chain summary', instructions: 'FAKE summary assignment <chain-c>', enabled: true});
  const l = await f.upstream({name: 'FAKE long upstream', instructions: 'FAKE long assignment <long-up>'});
  const cut = await f.downstream(l, {name: 'FAKE cut downstream', instructions: 'FAKE cut assignment <long-down>', enabled: true});
  const only = await f.downstream(l, {name: 'FAKE only-ellipsis downstream', instructions: bulky, enabled: true});
  const order = [a, b, c, l, cut, only];
  await f.startOnce(a);
  await f.startOnce(l);
  let runs = [];
  await until(() => '§14.1 the chain and both long handoffs run; so far ' + snippet(runs.map(run => run?.state)), async () => {
    const listed = (await f.snapshot()).runs;
    runs = order.map(w => listed.find(run => run.workflowId === w.id));
    return runs.every(run => run?.state === 'succeeded');
  }, 60000);
  const [ra, rb, rc, rl, rcut, ronly] = runs;
  expectEqual(runs.map(run => run.handoffFrom), [null, ra.id, rb.id, null, rl.id, rl.id], '§14.1 handoffFrom names the ' +
    'upstream run: a chain of three passes a result through, and two downstreams of one upstream both run on it');
  const expected = [handoffInput(b.instructions, a.name, notes), handoffInput(c.instructions, b.name, draft),
    handoffInput(cut.instructions, l.name, long), handoffInput(bulky, l.name, long)];
  expect(expected[0].includes('"FAKE chain research"') && expected[0].endsWith('\nFAKE research notes with a NUL, λ 😀') &&
    !expected[2].includes('\u0000') && expected[2].endsWith('€…') && Buffer.byteLength(expected[2]) > 32765 &&
    Buffer.byteLength(expected[2]) <= 32768 && expected[3].endsWith('Use it as the input of this assignment.\n\nRESULT\n…') &&
    Buffer.byteLength(expected[3]) > 32768, 'fixture: NUL left out, the long result cut to 32,768 bytes, and only … after ' +
    'instructions that alone are longer', expected.map(input => Buffer.byteLength(input)));
  for (const [index, run] of [rb, rc, rcut, ronly].entries()) {
    const what = ['the chain second step', 'the chain third step', 'a long result cut', 'only … when the rest is longer'][index];
    expectEqual(await f.submitted(run), expected[index], `§14.1 the exact handoff input: ${what}`);
    expectEqual(pick((await f.detail(run.id)).run, 'instructions assignment'), {instructions: expected[index],
      assignment: expected[index]}, `§14.1 the assignment is the whole input (${what})`);
  }
  await delay(800);
  expectEqual((await f.snapshot()).runs.length, 6, '§14.1 each workflow runs once: one counted result, one handoff each');
  await f.stop();
}

// Cases 27 and 28, rework. §14.1: a due rework goes before a pending handoff, which stays pending; a rework of a handoff
// run after the operator's rejection begins with the rejected run's assignment and keeps its handoffFrom (§15.2).
async function case27_reworkBeforeHandoff() {
  const f = await team('handoff-rework');
  await f.start();
  await f.ready(f.connectionId);
  const up = await f.upstream({name: 'FAKE rework upstream', instructions: 'FAKE upstream assignment'});
  const down = await f.downstream(up, {name: 'FAKE reviewed downstream', instructions: 'FAKE downstream assignment: summarize',
    review: 'operator', reworkLimit: 1, enabled: true});
  await f.startOnce(up);
  const one = await f.finish(await f.newRun(up.id, 'queued'), 'succeeded', {output: 'FAKE upstream result one'});
  const first = await f.newRun(down.id, 'queued');
  const assignment = handoffInput(down.instructions, up.name, one.output);
  expectEqual([first.handoffFrom, await f.submitted(first)], [one.id, assignment], '§14.1 the first handoff run');
  await f.action(down.id, 'pause');
  const draft = 'FAKE downstream draft\u0000 without the source';
  const rejected = await f.finish(first, 'succeeded', {output: draft});
  const note = 'FAKE note: cite the source';
  await f.verdict(rejected, {verdict: 'rejected', note});
  await f.waitFor(down, w => w.reworkPending === first.id, '§15.2 the rejection makes a rework due, kept while paused');
  await f.action(up.id, 'run');
  const two = await f.finish(await f.newRun(up.id, 'queued'), 'succeeded', {output: 'FAKE upstream result two'});
  await f.waitFor(down, w => w.handoffPending === two.id, '§14.1 the second counted result is pending beside the rework');
  await f.patch(down.id, {instructions: 'FAKE downstream assignment, edited'});
  await f.action(down.id, 'resume');
  const rework = await f.newRun(down.id, 'queued');
  expectEqual([pick(rework, 'attempt reworkOf handoffFrom'), pick(await f.workflow(down.id), 'reworkPending handoffPending')],
    [{attempt: 2, reworkOf: first.id, handoffFrom: one.id}, {reworkPending: null, handoffPending: two.id}], '§14.1 a due rework ' +
    'goes first and the handoff stays pending; the rework of a handoff run has the rejected run handoffFrom');
  expectEqual((await f.detail(first.id)).run.assignment, assignment, '§14.1 the handoff run assignment is its whole input');
  const input = reworkInput(assignment, note, draft);
  expectEqual(await f.submitted(rework), input, '§14.1 and §15.2 a rework of a handoff run begins with the rejected run ' +
    'assignment in place of the (since edited) instructions, then the review and the previous result without NUL');
  expectEqual(pick((await f.detail(rework.id)).run, 'instructions assignment'), {instructions: input, assignment},
    '§14.1 the rework assignment is the rejected run assignment');
  await f.finish(rework, 'succeeded', {output: 'FAKE reworked draft'});
  const second = await f.newRun(down.id, 'queued');
  expectEqual([pick(second, 'attempt reworkOf handoffFrom'), await f.submitted(second)], [{attempt: 1, reworkOf: null,
    handoffFrom: two.id}, handoffInput('FAKE downstream assignment, edited', up.name, 'FAKE upstream result two')],
  '§14.1 the pending handoff follows the rework, with the instructions read when it is reserved');
  await f.finish(second, 'succeeded');
  await f.stop();
}

// Case 28, rework after failed checks. §14.1 and §15.3: a handoff run whose long input was cut to 32,768 bytes is
// rejected by checks; its rework begins with that assignment, keeps handoffFrom and still fits 65,536 bytes.
async function case28_reworkAfterFailedChecks() {
  const f = await team('handoff-checks');
  await f.start();
  await f.ready(f.connectionId);
  const upstreamResult = 'FAKE long upstream result ' + '€'.repeat(12000);
  const draft = 'FAKE draft without the marker ' + 'ж'.repeat(20000);
  // The rework input contains FAILED CHECKS (§15.3), so the first script answers it.
  await f.script({input: 'FAILED CHECKS', output: 'FAKE-DONE: the reworked result'}, {input: '<checks-down>', output: draft},
    {input: '<checks-up>', output: upstreamResult});
  const up = await f.upstream({name: 'FAKE checked upstream', instructions: 'FAKE upstream assignment <checks-up>'});
  const check = {kind: 'contains', text: 'FAKE-DONE'};
  const down = await f.downstream(up, {name: 'FAKE checked downstream', instructions: 'FAKE downstream assignment <checks-down>',
    resultChecks: [check], reworkLimit: 1, enabled: true});
  await f.startOnce(up);
  let runs = [];
  await until(() => '§15.3 the handoff run and its rework end; so far ' + snippet(runs.map(run => pick(run, 'state review attempt'))),
    async () => { runs = await f.runsOf(down); return runs.length === 2 && runs.every(run => run.state === 'succeeded'); }, 40000);
  const [rework, first] = runs;
  const [upstream] = await f.runsOf(up);
  const note = 'The result does not contain "FAKE-DONE".';
  expectEqual(pick(first, 'attempt handoffFrom review reviewedBy reviewNote'), {attempt: 1, handoffFrom: upstream.id,
    review: 'rejected', reviewedBy: 'checks', reviewNote: note}, '§15.3 the handoff run is rejected by its checks');
  const assignment = handoffInput(down.instructions, up.name, upstreamResult);
  const input = checksReworkInput(assignment, note, draft);
  expect(Buffer.byteLength(assignment) > 32765 && Buffer.byteLength(assignment) <= 32768 && Buffer.byteLength(input) > 65530 &&
    Buffer.byteLength(input) <= 65536 && input.endsWith('ж…'), 'fixture: the assignment and the rework input are both cut',
  [assignment, input].map(text => Buffer.byteLength(text)));
  expectEqual((await f.detail(first.id)).run.assignment, assignment, '§14.1 the handoff assignment is its input, cut to 32,768 bytes');
  expectEqual(pick(rework, 'attempt reworkOf handoffFrom review checks'), {attempt: 2, reworkOf: first.id, handoffFrom: upstream.id,
    review: null, checks: [{check, passed: true, message: null}]}, '§14.1 the rework of a handoff run keeps its handoffFrom');
  expectEqual(await f.submitted(rework), input, '§14.1 and §15.3 the rework after failed checks begins with the rejected run ' +
    'assignment, then FAILED CHECKS and the previous result, cut to fit 65,536 bytes');
  expectEqual(pick((await f.detail(rework.id)).run, 'instructions assignment'), {instructions: input, assignment},
    '§14.1 the rework assignment is the rejected run assignment');
  await f.stop();
}

// Case 28, run. §14.1: run on an after workflow is 409 while the upstream has no counted result (no run, a failed
// run, a pending review, a rejection) and otherwise sets handoffPending to the upstream's latest counted run, also
// for an upstream archived since; it never bypasses the paused state; §9 only accepted requests record run_requested.
async function case28_runOnAfterWorkflow() {
  const f = await team('handoff-run');
  await f.start();
  await f.ready(f.connectionId);
  const up = await f.upstream({name: 'FAKE run upstream', instructions: 'FAKE upstream assignment', review: 'operator'});
  const down = await f.downstream(up, {name: 'FAKE run downstream', instructions: 'FAKE downstream assignment'});
  const refuse = async why => expectError(await f.request('POST', `/api/workflows/${down.id}/run`, {}), 409,
    '§14.1 run on an after workflow is 409 when the upstream has no run that counted as a success: ' + why);
  // One upstream run at a time: the first by run and resume, each later one by run once the previous has ended.
  let started = false;
  const upstreamRun = async (state, output) => {
    if (started) await f.action(up.id, 'run');
    else await f.startOnce(up);
    started = true;
    return f.finish(await f.newRun(up.id, 'queued'), state, {output});
  };
  await refuse('it has no run');
  await upstreamRun('failed', 'FAKE failed upstream');
  await refuse('a failed run');
  const two = await upstreamRun('succeeded', 'FAKE upstream result two');
  await refuse('a result whose review is pending');
  await f.verdict(two, {verdict: 'rejected'});
  await refuse('a rejected result');
  const three = await upstreamRun('succeeded', 'FAKE upstream result three');
  await f.verdict(three, accepted);
  await f.waitFor(down, w => w.handoffPending === three.id, '§14.1 the accepted result is handed off');
  await f.action(down.id, 'resume');
  await f.finish(await f.newRun(down.id, 'queued'), 'succeeded');
  const requested = await f.action(down.id, 'run');
  expectEqual(requested.handoffPending, three.id, '§14.1 run sets handoffPending to the upstream latest counted run');
  const again = await f.newRun(down.id, 'queued');
  expectEqual([again.handoffFrom, await f.submitted(again)], [three.id, handoffInput(down.instructions, up.name,
    'FAKE upstream result three')], '§14.1 run hands the same counted result off again');
  await f.finish(again, 'succeeded');
  await f.action(down.id, 'pause');
  const four = await upstreamRun('succeeded', 'FAKE upstream result four');
  await f.verdict(four, accepted);
  await f.waitFor(down, w => w.handoffPending === four.id, '§14.1 the fourth result is handed off');
  await f.action(down.id, 'resume');
  const handoffOfFour = await f.newRun(down.id, 'queued');
  expectEqual(handoffOfFour.handoffFrom, four.id, '§14.1 the handoff of the fourth result');
  await f.finish(handoffOfFour, 'succeeded');
  await f.action(down.id, 'pause');
  expectStatus(await f.request('POST', `/api/workflows/${up.id}/archive`, {}), 200, '§9 archive of the upstream');
  expectEqual((await f.action(down.id, 'run')).handoffPending, four.id, '§14.1 run hands off the latest counted run (the ' +
    'fourth, not the third), also once the upstream is archived: it stays the upstream');
  await delay(1000);
  expectEqual([(await f.runsOf(down)).length, (await f.workflow(down.id)).handoffPending], [3, four.id],
    '§14.1 run never bypasses the paused state: the handoff waits for resume');
  await f.action(down.id, 'resume');
  expectEqual((await f.newRun(down.id, 'queued')).handoffFrom, four.id, '§14.1 the requested handoff runs after resume');
  const requests = (await f.log()).filter(entry => entry.kind === 'workflow.run_requested' && entry.workflowId === down.id);
  expectEqual(requests.map(entry => pick(entry, 'actor runId data')), Array(2).fill({actor: 'operator', runId: null, data: null}),
    '§14.1 run records workflow.run_requested; §9 only an accepted request records one, not a 409');
  await f.stop();
}

await runCases('handoffs', [case26_fields, case27_whenAResultCounts, case27_latestWinsPauseAndArchive, case27_dailyCap,
  case27_dispatchOrder, case27_chainAndInputs, case27_reworkBeforeHandoff, case28_reworkAfterFailedChecks, case28_runOnAfterWorkflow]);
