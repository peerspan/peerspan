#!/usr/bin/env node
// Contract-only black-box suite for docs/managed-contract.md revision 4, section 16, cases 16 to 18: reviewer
// agents (sections 4, 7, 8, 11 and 15.1), rework of rejected results (section 15.2) and the workspace branches
// of runtime agents (section 10.1). No imports or reads of the managed implementation or its database: the
// documented CLI, HTTP, the explicitly fake Peerspan executable and throwaway state only. The fake plays the
// worker and reviewer agents, either driven step by step through its task records or by its `scripts`
// (README). Expected inputs, notes and branches are written out from the contract; section numbers (§) refer
// to it.
import path from 'node:path';
import {delay, expect, expectEqual, expectError, expectStatus, fixture, hex, ids, inputOf, isTime, option, pick,
  runCases, snippet, until} from './harness.mjs';

const minute = 60000;
// Worker agents of the fake worker host besides the fixture's own (ids, registered in file mode).
const agent = digit => ({agentId: hex('agent', digit), sessionId: hex('session', digit), adapterId: hex('adapter', digit)});
const reviewerAgent = agent(7), secondWorker = agent(8), secondReviewer = agent(9);
const hex66 = 'a1'.repeat(33);
const unresolved = ['submitting', 'queued', 'running'];

// §15.1 and §15.2: the last part (a retained output) is used without its NUL characters; then an input longer
// than 65,536 bytes of UTF-8 has that part cut at a character (code point) boundary and ended with "…",
// keeping as much of it as lets the whole input fit.
function fitted(lines, output) {
  const last = output.replaceAll('\u0000', '');
  const prefix = lines.join('\n') + '\n';
  if (Buffer.byteLength(prefix + last) <= 65536) return prefix + last;
  let room = 65536 - Buffer.byteLength(prefix) - Buffer.byteLength('…');
  const kept = [];
  for (const character of last) {
    room -= Buffer.byteLength(character);
    if (room < 0) break;
    kept.push(character);
  }
  return prefix + kept.join('') + '…';
}
// §15.1: the review input.
const reviewInput = (assignment, criteria, output) => fitted([
  'Review the result below, which an agent produced for the assignment that follows it. Decide whether the result does what the assignment asks.',
  'Begin your answer with one line that says exactly VERDICT: ACCEPT or VERDICT: REJECT. Then give your reasons briefly: the operator reads them, and after a rejection the agent may receive them with the assignment.',
  '', 'ASSIGNMENT', assignment, '', ...(criteria === null ? [] : ['CRITERIA', criteria, '']), 'RESULT'], output);
// §15.2: the rework input.
const reworkInput = (instructions, note, previous) => fitted([instructions, '', 'REVISION REQUESTED',
  'A reviewer rejected your previous result for this assignment. Do the assignment again in full, addressing the review.',
  '', 'REVIEW', note ?? 'The reviewer gave no reasons.', '', 'PREVIOUS RESULT'], previous);

// A fixture whose fake worker host has the fixture's own worker agent and `others`, each with a ready and
// verified session (§3), and a second sender state for reviewer connections, so that a submission shows
// which connection's sender state it went through.
async function team(label, others, options = {}) {
  const f = await fixture(label, options);
  f.reviewSender = path.join(f.dir, 'PRIVATE-review-sender');
  const all = [ids, ...others];
  const sessions = new Map(all.map(item => [item.agentId, 'ready']));
  const agents = () => ({
    agents: all.map(item => ({id: item.agentId, name: 'FAKE-CONFORMANCE agent ' + item.agentId.slice(-4),
      sessions: [{id: item.sessionId, adapter_id: item.adapterId, connection: sessions.get(item.agentId)}]})),
    adapters: Object.fromEntries(all.map(item => [item.adapterId, {session_id: item.sessionId, state: 'ready',
      channel: 'verified', channel_verified_at: '2026-01-01T00:00:00Z'}]))});
  await f.configure({...agents(), senderStates: [f.senderDir, f.reviewSender], scripts: [], inspectErrorAgents: []});
  f.setSession = async (item, connection) => { sessions.set(item.agentId, connection); await f.configure(agents()); };
  f.connectAgent = async (item, name, sender = f.reviewSender) => JSON.parse(await f.checkedCli('connect', '--name', name,
    '--agent', item.agentId, '--host-state', f.workerDir, '--sender-state', sender)).id;
  f.ready = (...connections) => Promise.all(connections.map(id => f.code(id, 'ready', 'the agent is ready and verified')));
  f.script = (...scripts) => f.configure({scripts});
  f.verdict = async (run, body, rule) => expectStatus(await f.request('POST', `/api/runs/${run.id}/review`, body), 200, rule).data;
  f.submitsTo = async item => (await f.submissions()).filter(call => option(call.argv, '--agent') === item.agentId);
  f.attentionFor = async (kind, id) => (await f.snapshot()).attention.find(item => item.kind === kind && item.subject.id === id);
  f.log = async () => {
    const entries = [];
    for (let before = null; ;) {
      const query = '/api/activity?limit=200' + (before === null ? '' : '&before=' + encodeURIComponent(before));
      const data = expectStatus(await f.request('GET', query), 200, '§11 GET /api/activity').data;
      entries.push(...data.activity);
      if (data.nextBefore === null) return entries;
      before = data.nextBefore;
    }
  };
  return f;
}
function untilRun(f, id, test, why, timeout) {
  let last;
  return until(() => `${why}; last seen: ${snippet(last && pick(last, 'state review reviewedBy reviewFallback reviewTask attempt'))}`,
    async () => { last = await f.runById(id); return last && test(last) ? last : false; }, timeout);
}
const reserved = (f, run, why = '§15.1 the review task is reserved') => untilRun(f, run.id, item => item.reviewTask?.taskId, why);
const oneErrorLine = result => result.code === 1 && result.stderr.trim() !== '' && result.stderr.trim().split('\n').length === 1;

// Case 16, fields. §15.1: the reviewerId rules at creation and in PATCH, one agent on both sides, a switch
// that clears the reviewer, reviewCriteria limits and trimming; §15.2: reworkLimit; §7: disconnect refused
// for a reviewer in use. No dispatch is needed, so this controller ticks once a second.
async function case16_reviewerFields() {
  const f = await team('reviewer-fields', [reviewerAgent, secondReviewer], {env: {MANAGED_TICK_MS: '1000'}});
  const worker = f.connectionId;
  const reviewer = await f.connectAgent(reviewerAgent, 'FAKE-CONFORMANCE reviewer');
  const other = await f.connectAgent(secondReviewer, 'FAKE-CONFORMANCE second reviewer');
  const twin = await f.connectAgent(ids, 'FAKE-CONFORMANCE worker twin', f.senderDir);   // the workflow's own agent
  const removed = await f.connectAgent(secondReviewer, 'FAKE-CONFORMANCE removed reviewer');
  await f.checkedCli('disconnect', '--id', removed);
  await f.start();
  const body = patch => ({name: 'FAKE reviewer fields', connectionId: worker, instructions: 'FAKE fields only',
    intervalMinutes: 60, maxRunsPerDay: 5, acceptanceMinutes: 5, ...patch});
  const refused = [
    ['review agent without reviewerId', {review: 'agent'}],
    ['review agent with reviewerId null', {review: 'agent', reviewerId: null}],
    ['a reviewerId without review (none by default)', {reviewerId: reviewer}],
    ['a reviewerId with review none', {review: 'none', reviewerId: reviewer}],
    ['a reviewerId with review operator', {review: 'operator', reviewerId: reviewer}],
    ['an unknown reviewer connection', {review: 'agent', reviewerId: 'FAKE-absent'}],
    ['a removed reviewer connection', {review: 'agent', reviewerId: removed}],
    ['the worker connection as its own reviewer', {review: 'agent', reviewerId: worker}],
    ['another connection to the worker agent as reviewer', {review: 'agent', reviewerId: twin}],
    ['one agent on both sides through the twin worker connection', {connectionId: twin, review: 'agent', reviewerId: worker}],
    ['a numeric reviewerId', {review: 'agent', reviewerId: 7}], ['review AGENT', {review: 'AGENT', reviewerId: reviewer}],
    ['numeric criteria', {reviewCriteria: 7}], ['criteria as an array', {reviewCriteria: ['FAKE criteria']}],
    ['criteria of 2,001 characters', {reviewCriteria: 'c'.repeat(2001)}],
    ['criteria of 2,001 characters as sent, 2,000 after trimming', {reviewCriteria: ' ' + 'c'.repeat(2000)}],
    ['criteria of 2,001 code points outside the BMP', {reviewCriteria: '\u{1F600}'.repeat(2001)}],
    ['criteria containing NUL', {reviewCriteria: 'FAKE criteria\u0000with NUL'}],
    ['instructions containing NUL (§2)', {instructions: 'FAKE instructions\u0000with NUL'}],
    ...[-1, 4, 1.5, '1', null, true].map(limit => [`reworkLimit ${JSON.stringify(limit)}`, {reworkLimit: limit}])];
  for (const [what, patch] of refused) {
    expectError(await f.request('POST', '/api/workflows', body(patch)), 400, `§15.1/§15.2 POST refuses ${what}`);
  }
  expectEqual((await f.snapshot()).workflows.length, 0, '§2 refused creations create nothing');

  const fields = 'review reviewerId reviewCriteria reworkLimit reworkPending';
  const agentReviewed = await f.create({name: 'FAKE agent-reviewed', review: 'agent', reviewerId: reviewer});
  expectEqual(pick(agentReviewed, fields), {review: 'agent', reviewerId: reviewer, reviewCriteria: null, reworkLimit: 0,
    reworkPending: null}, '§15.1 a workflow with a reviewer agent; criteria default to null; §15.2 reworkLimit defaults to 0');
  const operator = await f.create({name: 'FAKE operator-reviewed', review: 'operator', reviewerId: null,
    reviewCriteria: '  FAKE criteria: the totals add up \n', reworkLimit: 3});
  expectEqual(pick(operator, fields), {review: 'operator', reviewerId: null, reviewCriteria: 'FAKE criteria: the totals add up',
    reworkLimit: 3, reworkPending: null}, '§15.1 reviewerId null beside another review means no reviewer; criteria are ' +
    'stored trimmed and valid with operator review; §15.2 reworkLimit 3');
  const plain = await f.create({name: 'FAKE unreviewed', reviewCriteria: 'FAKE criteria without review', reworkLimit: 0});
  expectEqual(pick(plain, 'review reviewerId reviewCriteria'), {review: 'none', reviewerId: null,
    reviewCriteria: 'FAKE criteria without review'}, '§15.1 reviewCriteria is valid with every review');
  const longest = 'FAKE ' + 'c'.repeat(1995);
  const full = await f.create({name: 'FAKE longest criteria', review: 'agent', reviewerId: other, reviewCriteria: longest});
  expectEqual(full.reviewCriteria, longest, '§15.1 criteria of 2,000 characters are stored');
  const astral = '\u{1F600}'.repeat(2000);
  expectEqual((await f.create({name: 'FAKE astral criteria', reviewCriteria: astral})).reviewCriteria, astral,
    '§15.1 a character is a code point: criteria of 2,000 code points outside the BMP (4,000 UTF-16 units) are stored');
  const blank = await f.create({name: 'FAKE blank criteria', connectionId: twin, review: 'agent', reviewerId: reviewer,
    reviewCriteria: ' \n\t '});
  expectEqual(pick(blank, 'connectionId reviewerId reviewCriteria'), {connectionId: twin, reviewerId: reviewer,
    reviewCriteria: null}, '§15.1 an empty trimmed criteria string is stored as null');

  // PATCH: the workflow that results must follow the rules; a refused PATCH changes nothing.
  const route = '/api/workflows/';
  const refusals = [[agentReviewed, [['reviewerId null while review stays agent', {reviewerId: null}],
    ['the worker connection as reviewer', {reviewerId: worker}], ['another connection to the worker agent', {reviewerId: twin}],
    ['an unknown reviewer', {reviewerId: 'FAKE-absent'}], ['a removed reviewer', {reviewerId: removed}],
    ['a worker connection whose agent is the reviewer', {connectionId: reviewer}],
    ['review agent with reviewerId null', {review: 'agent', reviewerId: null}],
    ['review none with a reviewer in the same body', {review: 'none', reviewerId: reviewer}],
    ['review operator with a reviewer in the same body', {review: 'operator', reviewerId: other}],
    ['criteria of 2,001 characters', {reviewCriteria: 'c'.repeat(2001)}], ['reworkLimit 4', {reworkLimit: 4}],
    ['criteria containing NUL', {reviewCriteria: 'FAKE\u0000'}], ['instructions containing NUL (§2)', {instructions: 'FAKE\u0000'}],
    ['reworkLimit null', {reworkLimit: null}], ['reworkPending', {reworkPending: null}], ['reviewedBy', {reviewedBy: 'agent'}]]],
  [operator, [['a reviewerId while review stays operator', {reviewerId: reviewer}], ['review agent without a reviewer', {review: 'agent'}]]],
  [plain, [['a reviewerId while review stays none', {reviewerId: reviewer}]]],
  [blank, [['the worker connection whose agent is on the twin side', {reviewerId: worker}]]]];
  for (const [workflow, list] of refusals) {
    const kept = await f.workflow(workflow.id);
    for (const [what, patch] of list) {
      expectError(await f.request('PATCH', route + workflow.id, patch), 400, `§15.1 PATCH refuses ${what}`);
    }
    expectEqual(await f.workflow(workflow.id), kept, '§9 a refused PATCH changes nothing');
  }
  const edits = async id => (await f.log()).filter(entry => entry.kind === 'workflow.edited' && entry.workflowId === id)
    .map(entry => entry.data.fields).reverse();
  expectEqual((await f.patch(agentReviewed.id, {reviewerId: other})).reviewerId, other, '§15.1 PATCH changes the reviewer');
  expectEqual(pick(await f.patch(agentReviewed.id, {connectionId: reviewer}), 'connectionId reviewerId'),
    {connectionId: reviewer, reviewerId: other}, '§15.1 the former reviewer may become the worker once another agent reviews');
  expectEqual(pick(await f.patch(agentReviewed.id, {review: 'operator'}), 'review reviewerId'), {review: 'operator', reviewerId: null},
    '§15.1 setting review to operator also sets reviewerId to null');
  expectEqual(await edits(agentReviewed.id), [['reviewerId'], ['connectionId'], ['review', 'reviewerId']],
    '§15.1 a switch that clears reviewerId records workflow.edited listing both review and reviewerId');
  expectEqual(pick(await f.patch(operator.id, {review: 'agent', reviewerId: reviewer}), 'review reviewerId'),
    {review: 'agent', reviewerId: reviewer}, '§15.1 PATCH to review agent with a reviewer');
  expectEqual(pick(await f.patch(operator.id, {review: 'none', reviewerId: null}), 'review reviewerId reviewCriteria'),
    {review: 'none', reviewerId: null, reviewCriteria: 'FAKE criteria: the totals add up'}, '§15.1 PATCH to review none clears the reviewer');
  expectEqual(await edits(operator.id), [['review', 'reviewerId'], ['review', 'reviewerId']], '§11 both switches list review and reviewerId');
  expectEqual((await f.patch(plain.id, {reviewCriteria: '  FAKE new criteria  '})).reviewCriteria, 'FAKE new criteria',
    '§15.1 PATCH stores criteria trimmed');
  await f.patch(plain.id, {reviewCriteria: 'FAKE new criteria \n'});   // the same value once trimmed
  expectEqual((await f.patch(plain.id, {reviewCriteria: ''})).reviewCriteria, null, '§15.1 PATCH stores empty criteria as null');
  await f.patch(plain.id, {reviewCriteria: null});   // changes no value
  expectEqual((await f.patch(plain.id, {reworkLimit: 2})).reworkLimit, 2, '§15.2 PATCH sets reworkLimit');
  expectEqual(await edits(plain.id), [['reviewCriteria'], ['reviewCriteria'], ['reworkLimit']],
    '§11 workflow.edited names the changed fields; an edit that changes no value records nothing');

  // §7 (rev 4): a workflow that is not archived uses a connection as its worker or as its reviewer.
  const inUse = await f.cli('disconnect', '--id', other);
  expect(oneErrorLine(inUse) && (await f.snapshot()).connections.some(item => item.id === other),
    '§7 disconnect is refused while a paused workflow that is not archived uses the connection as its reviewer', inUse);
  expectStatus(await f.request('POST', `${route}${full.id}/archive`, {}), 200, '§9 archive');
  expectEqual(JSON.parse(await f.checkedCli('disconnect', '--id', other)), {id: other, removed: true},
    '§7 disconnect is accepted once only an archived workflow uses the connection as its reviewer');
  // §15.1: restored, it keeps the removed reviewer and its results fall back with reviewer_removed until a PATCH
  // gives it another; the reviewer rules are checked when a body has review, reviewerId or connectionId.
  const restored = expectStatus(await f.request('POST', `${route}${full.id}/restore`, {}), 200, '§9 restore').data;
  expectEqual(pick(restored, 'review reviewerId'), {review: 'agent', reviewerId: other},
    '§15.1 a restored workflow keeps the reviewerId of a removed connection');
  expectEqual((await f.patch(full.id, {name: 'FAKE restored without its reviewer'})).reviewerId, other,
    '§15.1 a PATCH without review, reviewerId or connectionId is not checked against the reviewer rules');
  expectError(await f.request('PATCH', route + full.id, {connectionId: worker}), 400,
    '§15.1 a PATCH with connectionId is checked against the reviewer rules: the reviewer connection was removed');
  await f.code(worker, 'ready', 'the worker is ready');
  await f.action(full.id, 'resume');
  await f.action(full.id, 'run');
  const orphan = await f.finish(await f.newRun(full.id, 'queued'), 'succeeded', {output: 'FAKE result without its reviewer'});
  const fell = await untilRun(f, orphan.id, run => run.reviewFallback === 'reviewer_removed',
    '§15.1 a result of a restored workflow whose reviewer was removed falls back with reviewer_removed');
  expect(fell.review === 'pending' && fell.reviewTask.connectionId === other && fell.reviewTask.taskId === null,
    '§15.1 it waits for the operator with no review task', fell);
  expectEqual((await f.patch(full.id, {reviewerId: reviewer})).reviewerId, reviewer, '§15.1 a PATCH gives it another reviewer');
  await f.stop();
}

// Case 16, the review task and its input. §15.1: submitted to the reviewer through its sender state with the
// exact input, with and without criteria, with a long output cut to 65,536 bytes; the deadline; §10 the
// detail's assignment, reviewTask and reviewEvents; §8 a run's own fields never those of its review task.
async function case16_reviewTaskInput() {
  const f = await team('review-input', [reviewerAgent]);
  const reviewer = await f.connectAgent(reviewerAgent, 'FAKE-CONFORMANCE reviewer');
  await f.start();
  await f.ready(f.connectionId, reviewer);
  const original = '- FAKE assignment: count the fake widgets; $(never) `executed` λ';
  const workflow = await f.create({instructions: original, review: 'agent', reviewerId: reviewer, intervalMinutes: 60,
    reviewCriteria: 'FAKE criteria at creation', acceptanceMinutes: 5, enabled: true});
  const first = await f.newRun(workflow.id, 'queued');
  expectEqual(pick(first, 'review reviewTask reviewFallback reviewedBy attempt reworkOf branch'), {review: null, reviewTask: null,
    reviewFallback: null, reviewedBy: null, attempt: 1, reworkOf: null, branch: null},
  '§15.1 an unresolved run has no review task; §15.2 a run reserved for the interval is attempt 1');
  // §9: the run keeps its assignment; criteria and acceptanceMinutes are read when the review task is reserved.
  const edited = 'FAKE edited assignment for later runs';
  const criteria = 'FAKE criteria read when the review task is reserved';
  await f.patch(workflow.id, {instructions: edited, reviewCriteria: '  ' + criteria + '\n', acceptanceMinutes: 30});
  const output = 'FAKE widget report: 12 fake widgets\n' + 'w'.repeat(2400) + ' €λ';
  const one = await f.finish(first, 'succeeded', {output});
  expect(one.review === 'pending' && one.reviewFallback === null && one.reviewTask?.connectionId === reviewer,
    '§15.1 a succeeded run of an agent-reviewed workflow is pending, with a reviewTask naming its reviewer', one);
  const reservedRun = await reserved(f, one);
  const task = reservedRun.reviewTask;
  await until('§15.1 the review task is submitted to the reviewer', async () => (await f.submitsTo(reviewerAgent)).length === 1);
  const [{argv}] = await f.submitsTo(reviewerAgent);
  expectEqual(['--task', '--peer', '--agent', '--state'].map(name => option(argv, name)),
    [task.taskId, ids.hostId, reviewerAgent.agentId, f.reviewSender], '§15.1 the review task is submitted under its own task ' +
    'ID to the reviewer connection host and agent, against the reviewer connection sender state');
  const expected = reviewInput(original, criteria, output);
  expectEqual(inputOf(argv), expected, '§15.1 the exact review input: the fixed lines, the run assignment, the criteria read ' +
    'at reservation and the retained output (not its 2,000-character preview)');
  const deadline = Date.parse(option(argv, '--deadline'));
  expect(Math.abs(deadline - Date.parse(task.createdAt) - 30 * minute) <= 5000, '§15.1 the deadline is the reservation ' +
    'time plus the current acceptanceMinutes (30)', {deadline: option(argv, '--deadline'), createdAt: task.createdAt});
  const detail = await f.detail(first.id);
  expectEqual(pick(detail.run, 'instructions assignment output'), {instructions: original, assignment: original, output},
    '§10 the detail: the exact input of the run, its assignment and its retained output');
  expectEqual(pick(detail.run.reviewTask, 'connectionId taskId input output outputTruncated'), {connectionId: reviewer,
    taskId: task.taskId, input: expected, output: null, outputTruncated: false}, '§10 the detail reviewTask has the exact input');

  // The review task's progress is in reviewEvents, never in the run's own fields or timeline.
  await f.remoteEvent(task.taskId, 'accepted');
  const progress = await f.remoteEvent(task.taskId, 'progress', {message: 'FAKE reviewer reading the result'});
  const during = await until('§10 reviewEvents shows the review task progress', async () => {
    const current = await f.detail(first.id);
    return current.reviewEvents.some(item => item.sequence === progress.sequence && item.kind === 'progress' &&
      item.message === 'FAKE reviewer reading the result') && current;
  });
  const own = 'id taskId state output outputTruncated error reason progress cancelRequestedAt createdAt startedAt finishedAt';
  expectEqual(pick(during.run, own), pick(detail.run, own), '§8 a run state, output, progress and times are those of its ' +
    'own task, never of its review task');
  expectEqual(pick(during.run, 'state progress'), {state: 'succeeded', progress: null}, '§8 the review task progress is not the run progress');
  expect(during.run.reviewTask.state === 'running' && !during.events.some(item => item.message === progress.message),
    '§15.1 reviewTask.state follows the review task; §10 the run timeline is the run own', during);
  const verdict = 'VERDICT: ACCEPT\nFAKE reasons: the widget count is present.';
  await f.remoteEvent(task.taskId, 'succeeded', {output: verdict});
  const accepted = await untilRun(f, first.id, run => run.review === 'accepted', '§15.1 the reviewer agent accepts');
  expect(accepted.reviewedBy === 'agent' && accepted.reviewNote === 'FAKE reasons: the widget count is present.' &&
    accepted.reviewTask.state === 'succeeded' && Math.abs(Date.parse(accepted.reviewedAt) -
    Date.parse(accepted.reviewTask.finishedAt)) <= 1000 && accepted.output === one.output,
  '§15.1 ACCEPT: review accepted by the agent, the reasons as the note, reviewedAt when the result was retained', accepted);
  const after = await f.detail(first.id);
  expect(after.run.reviewTask.output === verdict && after.run.reviewTask.outputTruncated === false &&
    after.reviewEvents.at(-1)?.kind === 'succeeded' && !JSON.stringify(after.reviewEvents).includes('FAKE reasons'),
  '§10 the detail keeps the review task output in full; its timeline keeps the terminal event without the output', after);

  // Without criteria, and with an output longer than the input allows: scripted reviews accept.
  await f.patch(workflow.id, {reviewCriteria: null});
  await f.script({agent: reviewerAgent.agentId, state: 'succeeded', output: 'VERDICT: ACCEPT'});
  const long = 'FAKE long widget report ' + '€'.repeat(30000) + 'λ'.repeat(10);
  const cut = reviewInput(edited, null, long);
  expect(cut.endsWith('…') && Buffer.byteLength(cut) <= 65536 && Buffer.byteLength(cut) > 65530,
    'fixture: the long output must be cut', Buffer.byteLength(cut));
  // NUL characters are left out of the output in the review input, before the 65,536-byte cut: cutting first
  // would keep fewer characters.
  const withNul = 'FAKE widget report\u0000 with NUL\u0000 characters';
  const nulInput = reviewInput(edited, null, withNul);
  const longNul = 'FAKE long report with NUL \u0000' + ('€'.repeat(9) + '\u0000').repeat(3000);
  const nulCut = reviewInput(edited, null, longNul);
  expect(!nulInput.includes('\u0000') && nulInput.endsWith('RESULT\nFAKE widget report with NUL characters') &&
    nulCut.endsWith('…') && Buffer.byteLength(nulCut) > 65530 && !nulCut.includes('\u0000'),
  'fixture: NUL characters left out, and the long result still cut', Buffer.byteLength(nulCut));
  for (const [result, input, why] of [['FAKE widget report two', reviewInput(edited, null, 'FAKE widget report two'),
    'without criteria the CRITERIA lines are left out; a later run carries the edited assignment'],
  [long, cut, 'an input over 65,536 bytes has the output cut at a character boundary and ended with …'],
  [withNul, nulInput, 'the review input has the retained output without its NUL characters'],
  [longNul, nulCut, 'NUL characters are left out before an input over 65,536 bytes is cut']]) {
    await f.action(workflow.id, 'run');
    const run = await f.finish(await f.newRun(workflow.id, 'queued'), 'succeeded', {output: result, timeout: 20000});
    const done = await untilRun(f, run.id, item => item.review === 'accepted', '§15.1 the scripted reviewer accepts');
    const call = (await f.submitsTo(reviewerAgent)).find(item => option(item.argv, '--task') === done.reviewTask.taskId);
    expectEqual(call && inputOf(call.argv), input, '§15.1 ' + why);
    const detail = await f.detail(run.id);
    expectEqual([detail.run.reviewTask.input, detail.run.output], [input, result],
      '§10 the detail has the exact review input, and the run retained output in full, NUL characters included');
  }
  await f.stop();
}

// Case 16, verdicts and fallbacks. §15.1: a verdict line with decoration and in lower case, the reasons as the
// note without a final branch line, each fallback a scripted reviewer can produce; §8 review_pending only for
// runs that wait for the operator, and the statistics; §11 the review.* entries and a system run.reviewed.
async function case16_verdictsAndFallbacks() {
  const f = await team('review-verdicts', [reviewerAgent]);
  const reviewer = await f.connectAgent(reviewerAgent, 'FAKE-CONFORMANCE reviewer');
  await f.start();
  await f.ready(f.connectionId, reviewer);
  const verdict = (review, reviewNote) => ({review, reviewedBy: 'agent', reviewNote, reviewFallback: null});
  const fallback = cause => ({review: 'pending', reviewedBy: null, reviewNote: null, reviewFallback: cause});
  const longReason = 'FAKE reasons ' + 'r'.repeat(2100);
  const cases = [
    ['an upper-case verdict in bold', {output: '**VERDICT: ACCEPT**\nFAKE reasons: every total adds up.'},
      verdict('accepted', 'FAKE reasons: every total adds up.')],
    ['a lower-case quoted heading after blank lines, no space, a final period; a tab, a bell and a final branch line',
      {output: '\n  \n> ## verdict:reject.  \n\nFAKE reasons: the totals are missing.\n\tFAKE indented line\u0007 with a bell\n\n' +
        'Branch: fake-review, unchanged from fake-main\n'},
      verdict('rejected', 'FAKE reasons: the totals are missing.\n\tFAKE indented line with a bell')],
    ['a verdict in backticks with spaces and no reasons', {output: '`Verdict:   Accept`'}, verdict('accepted', null)],
    ['underscores and reasons longer than 2,000 characters', {output: '__VERDICT: REJECT__\n' + longReason},
      verdict('rejected', longReason.slice(0, 1999) + '…')],
    ['reasons followed by a committed branch line', {output: `*VERDICT: ACCEPT*\nFAKE fine.\n\nBranch: codex.task_fake at commit ${hex66}`},
      verdict('accepted', 'FAKE fine.')],
    ['VERDICT: ACCEPTED', {output: 'VERDICT: ACCEPTED\nFAKE reasons'}, fallback('no_verdict')],
    ['a verdict after another first line', {output: 'FAKE preamble\nVERDICT: ACCEPT'}, fallback('no_verdict')],
    ['a verdict without its colon', {output: 'VERDICT ACCEPT'}, fallback('no_verdict')],
    ['a verdict line with more text', {output: 'VERDICT: REJECT because FAKE'}, fallback('no_verdict')],
    ['an empty output', {output: ''}, fallback('no_verdict')],
    ['a failed review task, whatever its output says', {state: 'failed', output: 'VERDICT: ACCEPT'}, fallback('failed')],
    ['a review task the sender rejects at submission', {submit: 'rejected', message: 'FAKE review not authorized'}, fallback('rejected')],
    ['a review task the receiver rejects', {state: 'rejected', message: 'FAKE reviewer declined'}, fallback('rejected')],
    ['a review task whose acceptance deadline passes', {state: 'expired', message: 'FAKE acceptance deadline passed'}, fallback('expired')],
    ['reasons of 2,100 code points outside the BMP, cut by code points',
      {output: '**VERDICT: REJECT**\n' + '\u{1F600}'.repeat(2100)}, verdict('rejected', '\u{1F600}'.repeat(1999) + '…')]];
  const tag = index => `<case-${String(index).padStart(2, '0')}>`;
  await f.script(...cases.flatMap(([, script], index) => [
    {agent: ids.agentId, input: tag(index), state: 'succeeded', output: `FAKE result ${tag(index)}`},
    {agent: reviewerAgent.agentId, input: tag(index), state: 'succeeded', ...script}]));
  const workflows = [];
  for (const [index, [what]] of cases.entries()) {
    workflows.push(await f.create({name: `FAKE verdict ${tag(index)}`, instructions: `FAKE verdict case ${tag(index)}: ${what}`,
      review: 'agent', reviewerId: reviewer, intervalMinutes: 60, enabled: true}));
  }
  let runs = [];
  const settled = run => run && (['accepted', 'rejected'].includes(run.review) || run.reviewFallback !== null);
  await until(() => '§15.1 every review ends in a verdict or a fallback; still open: ' + snippet(cases
    .map(([what], index) => [what, runs[index] && pick(runs[index], 'state review reviewFallback reviewTask')])
    .filter((unused, index) => !settled(runs[index]))), async () => {
    const {runs: listed} = await f.snapshot();
    runs = workflows.map(w => listed.find(run => run.workflowId === w.id));
    return runs.every(settled);
  }, 80000);
  const snapshot = await f.snapshot();
  for (const [index, [what, script, wanted]] of cases.entries()) {
    const run = runs[index];
    expectEqual(pick(run, 'state review reviewedBy reviewNote reviewFallback'), {state: 'succeeded', ...wanted}, '§15.1 ' + what);
    if (wanted.reviewFallback === null) {
      expect(Math.abs(Date.parse(run.reviewedAt) - Date.parse(run.reviewTask.finishedAt)) <= 1000,
        '§15.1 reviewedAt is the time the controller retained the review task result', pick(run, 'reviewedAt reviewTask'));
    }
    if (script.message) expectEqual(run.reviewTask.reason, script.message, '§15.1 reviewTask.reason follows its task (§8): ' + what);
    const item = snapshot.attention.find(entry => entry.kind === 'review_pending' && entry.subject.id === workflows[index].id);
    expect(Boolean(item) === (wanted.reviewFallback !== null), '§8 review_pending is raised once a run falls back to the ' +
      'operator, and never for an agent verdict: ' + what, item);
    const stats = snapshot.workflows.find(w => w.id === workflows[index].id).stats;
    expectEqual(pick(stats, 'succeeded failed awaitingReview interventions'), {succeeded: Number(wanted.review === 'accepted'),
      failed: Number(wanted.review === 'rejected'), awaitingReview: Number(wanted.review === 'pending'), interventions: 0},
    '§8 an agent verdict counts as the operator one does; a verdict is no intervention: ' + what);
  }
  const noVerdict = await f.detail(runs[5].id);
  expectEqual(noVerdict.run.reviewTask.output, 'VERDICT: ACCEPTED\nFAKE reasons', '§10 a review task output without a verdict is kept');
  await delay(800);
  expectEqual((await f.submitsTo(reviewerAgent)).length, cases.length, '§15.1 a run gets at most one review task');
  const log = await f.log();
  for (const [index, [what, , wanted]] of cases.entries()) {
    const of = kind => log.filter(entry => entry.kind === kind && entry.runId === runs[index].id)
      .map(entry => pick(entry, 'actor workflowId data'));
    const base = {actor: 'system', workflowId: workflows[index].id};
    expectEqual([of('review.dispatched'), of('review.finished'), of('run.reviewed'), of('review.fallback'), of('workflow.rework_due')],
      [[{...base, data: null}], [{...base, data: {state: runs[index].reviewTask.state}}],
        wanted.reviewFallback === null ? [{...base, data: {verdict: wanted.review}}] : [],
        wanted.reviewFallback === null ? [] : [{...base, data: {cause: wanted.reviewFallback}}], []],
    '§11 review.dispatched, review.finished {state}, a system run.reviewed {verdict} or review.fallback {cause}, and no ' +
      'rework with reworkLimit 0: ' + what);
  }
  // The operator decides a run that fell back.
  const decided = await f.verdict(runs[5], {verdict: 'accepted', note: 'FAKE operator verdict after no verdict'}, '§15 the operator verdict');
  expectEqual(pick(decided, 'review reviewedBy reviewNote reviewFallback'), {review: 'accepted', reviewedBy: 'operator',
    reviewNote: 'FAKE operator verdict after no verdict', reviewFallback: 'no_verdict'},
  '§15 the operator verdict on a run that fell back; reviewedBy operator; the fallback cause stays recorded');
  expect(!(await f.attentionFor('review_pending', workflows[5].id)), '§8 review_pending clears after the operator verdict');
  expectEqual((await f.log()).filter(entry => entry.kind === 'run.reviewed' && entry.runId === runs[5].id)
    .map(entry => pick(entry, 'actor data')), [{actor: 'operator', data: {verdict: 'accepted'}}], '§11 an operator run.reviewed');
  // §15.1: a verdict note with NUL is refused; notes are limited by code points.
  const astral = '\u{1F600}'.repeat(2000);
  for (const [what, note] of [['containing NUL', 'FAKE note\u0000with NUL'], ['of 2,001 code points', astral + '\u{1F600}']]) {
    expectError(await f.request('POST', `/api/runs/${runs[6].id}/review`, {verdict: 'rejected', note}), 400,
      `§15.1 a verdict note ${what} is 400`);
  }
  expectEqual((await f.runById(runs[6].id)).review, 'pending', '§15 refused verdicts change nothing');
  expectEqual((await f.verdict(runs[6], {verdict: 'rejected', note: astral}, '§15 a verdict with an astral note')).reviewNote,
    astral, '§15.1 a note of 2,000 code points outside the BMP (4,000 UTF-16 units) is accepted and stored');
  await f.stop();
}

// Case 16, order and the operator's verdict. §4 and §15.1: a review task holds its reviewer agent against a
// run of another workflow whose worker is that agent; reviews served before runs and oldest finishedAt first;
// reviews of a paused or archived workflow go on; the operator's verdict before the review task is reserved
// and while it is unresolved; §8 worker_unready as an action for a reviewer.
async function case16_orderAndOperatorVerdicts() {
  const f = await team('review-order', [reviewerAgent, secondWorker]);
  const reviewer = await f.connectAgent(reviewerAgent, 'FAKE-CONFORMANCE reviewer');
  const workerTwo = await f.connectAgent(secondWorker, 'FAKE-CONFORMANCE second worker', f.senderDir);
  await f.setSession(reviewerAgent, 'disconnected');
  await f.start();
  await f.ready(f.connectionId, workerTwo);
  await f.code(reviewer, 'session_not_ready', 'the reviewer session is disconnected');
  const severity = async () => (await f.attentionFor('worker_unready', reviewer))?.severity;
  expectEqual(await severity(), 'warning', '§8 worker_unready is a warning while nothing uses the connection');
  const reviewed = name => ({name, instructions: 'FAKE assignment of ' + name, review: 'agent', reviewerId: reviewer,
    intervalMinutes: 60, enabled: true});
  const later = await f.create({...reviewed('FAKE reviewed later'), connectionId: workerTwo});
  const y = await f.newRun(later.id, 'queued');
  const earlier = await f.create(reviewed('FAKE reviewed earlier'));
  const x = await f.newRun(earlier.id, 'queued');
  expectEqual(await severity(), 'action', '§8 worker_unready is an action when an enabled workflow uses the connection as its reviewer');
  const xDone = await f.finish(x, 'succeeded', {output: 'FAKE result X, finished first'});
  const yDone = await f.finish(y, 'succeeded', {output: 'FAKE result Y, finished second'});
  expect(Date.parse(xDone.finishedAt) < Date.parse(yDone.finishedAt) && Date.parse(y.createdAt) <= Date.parse(x.createdAt),
    'fixture: Y was reserved first and X finished first', [x, y, xDone, yDone].map(run => pick(run, 'createdAt finishedAt')));
  for (const run of [xDone, yDone]) {
    expect(run.review === 'pending' && run.reviewFallback === null && run.reviewTask?.connectionId === reviewer &&
      run.reviewTask.taskId === null, '§15.1 a succeeded run waits for its review task while the reviewer is not ready', run);
  }
  expect(!(await f.attentionFor('review_pending', earlier.id)) && (await f.workflow(earlier.id)).stats.awaitingReview === 1,
    '§8 a run that waits for its reviewer agent is pending (awaitingReview) but raises no review_pending');
  await f.action(earlier.id, 'pause');
  expectStatus(await f.request('POST', `/api/workflows/${later.id}/archive`, {}), 200, '§9 archive while a run waits for its review');
  expectEqual(await severity(), 'action', '§8 worker_unready stays an action while a run waits for a review task on the ' +
    'connection that is not yet reserved, though no enabled workflow uses it');

  // The operator decides Z before its review task is reserved.
  const third = await f.create(reviewed('FAKE decided by the operator'));
  const z = await f.finish(await f.newRun(third.id, 'queued'), 'succeeded', {output: 'FAKE result Z, decided by the operator'});
  const early = await f.verdict(z, {verdict: 'accepted', note: 'FAKE operator verdict before the review task'},
    '§15 the operator verdict on a run that waits for its reviewer agent');
  expectEqual(pick(early, 'review reviewedBy reviewNote reviewFallback'), {review: 'accepted', reviewedBy: 'operator',
    reviewNote: 'FAKE operator verdict before the review task', reviewFallback: null}, '§15 the operator may decide while the review is pending');
  await f.action(third.id, 'pause');
  // A workflow whose worker is the reviewer agent is due while the reviewer is not ready.
  const onReviewer = await f.create({name: 'FAKE work for the reviewer agent', connectionId: reviewer,
    instructions: 'FAKE assignment for the reviewer agent as a worker', intervalMinutes: 60, enabled: true});
  await f.setSession(reviewerAgent, 'ready');
  await until('§15.1 a review task is reserved once the reviewer is ready', async () => (await f.submitsTo(reviewerAgent)).length > 0);
  await delay(800);
  const xReview = (await f.runById(x.id)).reviewTask;
  const tasks = async () => (await f.submitsTo(reviewerAgent)).map(call => option(call.argv, '--task'));
  expectEqual(await tasks(), [xReview.taskId], '§4 review tasks are reserved before runs and oldest finishedAt first, and ' +
    'the reviewer agent holds one unresolved task: X review only, not Y review nor the run on the reviewer agent');
  expect(!(await f.snapshot()).runs.some(run => run.workflowId === onReviewer.id),
    '§4 a review task holds its reviewer agent against a run of another workflow whose worker is that agent');
  expect((await f.workflow(earlier.id)).enabled === false, '§15.1 the review of a paused workflow goes on');

  // The operator decides X while its review task is unresolved; the review task's end then changes nothing.
  const overruled = await f.verdict(xDone, {verdict: 'rejected', note: 'FAKE operator rejection while the reviewer works'},
    '§15 the operator verdict while the review task is unresolved');
  expect(overruled.review === 'rejected' && overruled.reviewedBy === 'operator' && unresolved.includes(overruled.reviewTask.state),
    '§15.1 the operator verdict ends the agent review; the review task goes on', overruled);
  const late = 'VERDICT: ACCEPT\nFAKE agent reasons that arrive after the operator verdict';
  await f.remoteEvent(xReview.taskId, 'succeeded', {output: late});
  const xEnd = await untilRun(f, x.id, run => run.reviewTask.state === 'succeeded', '§15.1 the review task goes on to its end');
  expectEqual(pick(xEnd, 'review reviewedBy reviewNote reviewedAt reviewFallback'), {...pick(overruled, 'review reviewedBy reviewNote reviewedAt'),
    reviewFallback: null}, '§15.1 after the operator verdict the review task end gives no verdict and no fallback');
  expectEqual((await f.detail(x.id)).run.reviewTask.output, late, '§15.1 the review task state and output are kept in reviewTask');

  // Y next (a review before the run on the reviewer agent), on an archived workflow; then that run.
  await until('§15.1 the next review task is reserved', async () => (await tasks()).length > 1);
  await delay(500);
  const yReview = (await f.runById(y.id)).reviewTask;
  expectEqual(await tasks(), [xReview.taskId, yReview.taskId], '§4 the review of Y is reserved before the waiting run; ' +
    '§15.1 the review of an archived workflow goes on');
  await f.remoteEvent(yReview.taskId, 'succeeded', {output: 'VERDICT: REJECT\nFAKE agent reasons for Y'});
  const yEnd = await untilRun(f, y.id, run => run.review === 'rejected', '§15.1 the reviewer rejects Y');
  expectEqual(pick(yEnd, 'reviewedBy reviewNote'), {reviewedBy: 'agent', reviewNote: 'FAKE agent reasons for Y'}, '§15.1 the agent verdict');
  const work = await f.newRun(onReviewer.id, 'queued');
  const calls = await f.submitsTo(reviewerAgent);
  expect(calls.length === 3 && option(calls[2].argv, '--task') === work.taskId &&
    inputOf(calls[2].argv) === 'FAKE assignment for the reviewer agent as a worker',
  '§4 once the reviews are done the reviewer agent takes the run of its own workflow; §15.1 no review task for Z',
  calls.map(call => option(call.argv, '--task')));
  expectEqual((await f.runById(z.id)).reviewTask.taskId, null, '§15.1 a verdict before reservation: no review task is reserved');
  await f.finish(work, 'succeeded');
  const log = await f.log();
  const of = (run, kind) => log.filter(entry => entry.runId === run.id && entry.kind === kind).map(entry => pick(entry, 'actor workflowId data'));
  expectEqual([of(x, 'review.dispatched'), of(x, 'review.finished'), of(x, 'run.reviewed'), of(x, 'review.fallback')],
    [[{actor: 'system', workflowId: earlier.id, data: null}], [{actor: 'system', workflowId: earlier.id, data: {state: 'succeeded'}}],
      [{actor: 'operator', workflowId: earlier.id, data: {verdict: 'rejected'}}], []],
  '§11 X: review.dispatched and review.finished, the operator run.reviewed only, no review.fallback');
  expectEqual(of(y, 'run.reviewed'), [{actor: 'system', workflowId: later.id, data: {verdict: 'rejected'}}], '§11 a system run.reviewed for Y');
  expectEqual(log.filter(entry => entry.runId === z.id && entry.kind.startsWith('review.')), [], '§11 no review.* entry for Z');
  await f.stop();
}

// Case 16, cancelling, releasing and recovering review tasks. §15.1: review/cancel and review/abandon with their
// 400, 404 and 409 rules, the cancelled, abandoned and reviewer_removed fallbacks; §10 cancel and abandon of a
// terminal run whose review task is unresolved; §7 disconnect refused for a reviewer with an unresolved review
// task; §8 a review task's problem as run_problem; §4 a restart reconciling a review task under its task ID.
async function case16_cancelAbandonAndRestart() {
  const f = await team('review-cancel', [reviewerAgent, secondReviewer]);
  const reviewerOne = await f.connectAgent(reviewerAgent, 'FAKE-CONFORMANCE first reviewer');
  const reviewerTwo = await f.connectAgent(secondReviewer, 'FAKE-CONFORMANCE second reviewer');
  await f.start();
  await f.ready(f.connectionId, reviewerOne, reviewerTwo);
  const workflow = await f.create({review: 'agent', reviewerId: reviewerOne, intervalMinutes: 60, enabled: true});
  const post = (run, action, body) => f.request('POST', `/api/runs/${run.id}/${action}`, body);
  const next = async output => {
    await f.action(workflow.id, 'run');
    return f.finish(await f.newRun(workflow.id, 'queued'), 'succeeded', {output});
  };
  const run1 = await f.newRun(workflow.id, 'queued');
  expectError(await f.request('POST', '/api/runs/FAKE-absent/review/cancel', {}), 404, '§15.1 review/cancel of an unknown run');
  expectError(await f.request('POST', '/api/runs/FAKE-absent/review/abandon', {confirm: run1.taskId}), 404,
    '§15.1 review/abandon of an unknown run');
  expectError(await post(run1, 'review/cancel', {}), 409, '§15.1 review/cancel is 409 unless the run has an unresolved review task');
  // §15.1 review/abandon: a malformed body is 400 first, then 404 for an unknown run, then 409 without an
  // unresolved review task, then 400 for a confirm that is not that task's ID.
  expectError(await f.request('POST', '/api/runs/FAKE-absent/review/abandon', {}), 400,
    '§15.1 review/abandon with a malformed body is 400 before 404');
  expectError(await post(run1, 'review/abandon', {confirm: run1.taskId}), 409,
    '§15.1 review/abandon of a run without a review task is 409 before a confirm mismatch');
  expectError(await post(run1, 'review/abandon', {confirm: 7}), 400, '§15.1 a confirm that is not a string is 400 before 409');
  const one = await f.finish(run1, 'succeeded', {output: 'FAKE result one'});
  const T1 = (await reserved(f, one)).reviewTask.taskId;
  expectError(await post(one, 'cancel', {}), 409, '§10 cancel acts on the run own task: a terminal run is 409 while its review task is unresolved');
  expectError(await post(one, 'abandon', {confirm: one.taskId}), 409, '§10 abandon of a terminal run is 409 while its review task is unresolved');
  for (const body of [{extra: true}, {confirm: T1}, []]) {
    expectError(await post(one, 'review/cancel', body), 400, '§15.1 review/cancel accepts only {}: ' + JSON.stringify(body));
  }
  for (const body of [{}, {confirm: one.taskId}, {confirm: 'FAKE'}, {confirm: T1, extra: true}, {confirm: [T1]}]) {
    expectError(await post(one, 'review/abandon', body), 400, '§15.1 review/abandon needs exactly {"confirm":REVIEW_TASK_ID}: ' +
      JSON.stringify(body));
  }
  // §4: a review task does not hold its run's workflow; the next result waits for the busy reviewer agent.
  const two = await next('FAKE result two');
  await delay(500);
  expect((await f.runById(two.id)).reviewTask.taskId === null && (await f.submitsTo(reviewerAgent)).length === 1,
    '§4 the first reviewer agent holds the first review task, so the second waits', await f.runById(two.id));
  expect(!(await f.attentionFor('review_pending', workflow.id)), '§8 no review_pending while the runs wait for the reviewer agent');
  await f.patch(workflow.id, {reviewerId: reviewerTwo});
  expectEqual([(await f.runById(one.id)).reviewTask.connectionId, (await f.runById(two.id)).reviewTask.connectionId],
    [reviewerOne, reviewerOne], '§9 a run keeps the reviewer it was reserved with');

  // review/cancel: recorded once; task cancel through the reviewer sender state; the remote decides.
  const cancelled = expectStatus(await post(one, 'review/cancel', {}), 200, '§15.1 review/cancel').data;
  expect(cancelled.id === one.id && isTime(cancelled.reviewTask.cancelRequestedAt) && cancelled.cancelRequestedAt === null &&
    unresolved.includes(cancelled.reviewTask.state), '§15.1 review/cancel records the review task cancelRequestedAt and returns ' +
    'the run; the run own cancelRequestedAt stays null', cancelled);
  const again = expectStatus(await post(one, 'review/cancel', {}), 200, '§15.1 a repeated review/cancel').data;
  expectEqual(again.reviewTask.cancelRequestedAt, cancelled.reviewTask.cancelRequestedAt, '§15.1 the cancel request is recorded once');
  const cancelCall = await f.cancelSent(T1);
  expectEqual([option(cancelCall.argv, '--peer'), option(cancelCall.argv, '--state')], [ids.hostId, f.reviewSender],
    '§15.1 task cancel for the review task goes to the reviewer host through the reviewer sender state');
  expect(unresolved.includes((await f.runById(one.id)).reviewTask.state), '§10 a cancel request never sets a terminal state by itself');
  const refused = await f.cli('disconnect', '--id', reviewerOne);
  expect(oneErrorLine(refused) && (await f.snapshot()).connections.some(item => item.id === reviewerOne),
    '§7 disconnect is refused while a review task on the connection is unresolved, though no workflow uses it now', refused);
  await f.setSession(reviewerAgent, 'disconnected');
  await f.code(reviewerOne, 'session_not_ready', 'the first reviewer session is disconnected');
  await f.remoteEvent(T1, 'cancelled');
  const fellBack = await untilRun(f, one.id, run => run.reviewFallback === 'cancelled', '§15.1 a cancelled review task falls back');
  expectEqual([pick(fellBack, 'review reviewedBy'), fellBack.reviewTask.state], [{review: 'pending', reviewedBy: null}, 'cancelled'],
    '§15.1 the run waits for the operator; the review task took its state from the remote record');
  await until('§8 review_pending appears once the run falls back', () => f.attentionFor('review_pending', workflow.id));
  expectEqual((await f.attentionFor('worker_unready', reviewerOne))?.severity, 'action',
    '§8 worker_unready is an action while a run waits for a review task on the connection that is not yet reserved');
  expectError(await post(one, 'review/cancel', {}), 409, '§15.1 review/cancel of a review task that ended');
  expectError(await post(one, 'review/abandon', {confirm: T1}), 409, '§15.1 review/abandon of a review task that ended');
  expectError(await post(one, 'review/abandon', {confirm: 'FAKE'}), 409, '§15.1 409 without an unresolved review task comes ' +
    'before the confirm check');
  expectEqual(JSON.parse(await f.checkedCli('disconnect', '--id', reviewerOne)), {id: reviewerOne, removed: true},
    '§7 disconnect is accepted once no workflow uses the reviewer and no review task on it is unresolved');
  const removed = await untilRun(f, two.id, run => run.reviewFallback === 'reviewer_removed',
    '§15.1 reviewer_removed: the reviewer connection was removed before the review task was reserved');
  expect(removed.review === 'pending' && removed.reviewTask.taskId === null, '§15.1 no review task for the removed reviewer', removed);

  // review/abandon releases the second reviewer agent, which a run of another workflow waits for.
  const three = await next('FAKE result three');
  const T3 = (await reserved(f, three)).reviewTask.taskId;
  const onSecond = await f.create({name: 'FAKE work for the second reviewer agent', connectionId: reviewerTwo,
    instructions: 'FAKE assignment for the second reviewer agent', intervalMinutes: 60, enabled: true});
  await delay(600);
  expect(!(await f.snapshot()).runs.some(run => run.workflowId === onSecond.id), '§4 the review task holds the second reviewer agent');
  const abandoned = expectStatus(await post(three, 'review/abandon', {confirm: T3}), 200, '§15.1 review/abandon').data;
  expect(abandoned.id === three.id && abandoned.state === 'succeeded' && abandoned.reviewTask.taskId === T3 &&
    abandoned.reviewTask.state === 'abandoned', '§15.1 the review task becomes abandoned; the response is the run', abandoned);
  await untilRun(f, three.id, run => run.reviewFallback === 'abandoned', '§15.1 an abandoned review task falls back');
  const freed = await f.newRun(onSecond.id, 'queued');
  const mentions = async () => (await f.calls()).filter(call => call.argv.includes(T3)).length;
  const settled = await mentions();
  await delay(1200);
  expectEqual(await mentions(), settled, '§15.1 the controller never again submits, inspects or cancels an abandoned review task');
  expectError(await post(three, 'review/abandon', {confirm: T3}), 409, '§15.1 review/abandon of an abandoned review task');
  await f.finish(freed, 'succeeded');
  expectEqual((await f.submitsTo(secondReviewer)).filter(call => inputOf(call.argv).startsWith('Review the result')).length, 1,
    '§15.1 a run gets at most one review task: the abandoned one is not replaced');

  // A review task's problem (a lost submit response, then failing inspections), its recovery, and a restart.
  await f.configure({scripts: [{agent: secondReviewer.agentId, submit: 'lost-accepted'}], inspectErrorAgents: [secondReviewer.agentId]});
  const four = await next('FAKE result four');
  const problem = await untilRun(f, four.id, run => run.reviewTask?.error, '§15.1 a review task whose inspection fails shows an error');
  const T4 = problem.reviewTask.taskId;
  expect(problem.error === null && unresolved.includes(problem.reviewTask.state), '§8 the run own error stays null', problem);
  const item = await until('§8 run_problem for the review task problem', () => f.attentionFor('run_problem', four.id));
  expectEqual(pick(item, 'severity subject'), {severity: 'warning', subject: {type: 'run', id: four.id, name: workflow.name}},
    '§8 a run unresolved review task with an error is a run_problem of that run');
  await f.configure({inspectErrorAgents: []});
  await until('§8 run_problem clears when the review task can be inspected', async () => !(await f.attentionFor('run_problem', four.id)));
  const problems = (await f.log()).filter(entry => ['run.problem', 'run.recovered'].includes(entry.kind) && entry.runId === four.id);
  expect(problems.length >= 2 && problems[0].kind === 'run.recovered' && problems.some(entry => entry.kind === 'run.problem') &&
    problems.every(entry => entry.actor === 'system' && entry.data?.task === 'review'),
  '§11 run.problem and run.recovered {task:"review"} for the review task error', problems);
  await f.stop();
  const before = (await f.calls()).length;
  await f.configure({scripts: []});
  await f.start();
  const firstCall = await until('the restarted controller acts on the review task',
    async () => (await f.calls()).slice(before).find(call => call.argv.includes(T4)));
  expect(firstCall.argv.includes('inspect'), '§4 after a restart the review task is inspected first under its task ID', firstCall.argv);
  await f.remoteEvent(T4, 'succeeded', {output: 'VERDICT: ACCEPT\nFAKE reasons after the restart'});
  const done = await untilRun(f, four.id, run => run.review === 'accepted', '§15.1 the reconciled review task gives its verdict');
  expectEqual(pick(done, 'reviewedBy reviewNote'), {reviewedBy: 'agent', reviewNote: 'FAKE reasons after the restart'},
    '§15.1 the verdict of the reconciled review task');
  expectEqual([done.reviewTask.taskId, (await f.taskCalls('submit', T4)).length], [T4, 1],
    '§4 the accepted review task keeps its task ID and is never submitted again');

  const log = await f.log();
  const entries = kind => log.filter(entry => entry.kind === kind).map(entry => pick(entry, 'actor runId workflowId data'));
  const ofRun = (run, data = null, actor = 'operator') => ({actor, runId: run.id, workflowId: workflow.id, data});
  expectEqual(entries('review.cancel_requested'), [ofRun(one)], '§11 review.cancel_requested once; a repeat records nothing');
  expectEqual(entries('review.abandoned'), [ofRun(three)], '§11 review.abandoned');
  const byRun = (a, b) => a.runId.localeCompare(b.runId);
  expectEqual(entries('review.fallback').sort(byRun), [ofRun(one, {cause: 'cancelled'}, 'system'),
    ofRun(two, {cause: 'reviewer_removed'}, 'system'), ofRun(three, {cause: 'abandoned'}, 'system')].sort(byRun),
  '§11 review.fallback {cause} for each fallback');
  expectEqual(entries('review.dispatched').sort(byRun), [one, three, four].map(run => ofRun(run, null, 'system')).sort(byRun),
    '§11 review.dispatched for each reserved review task');
  expectEqual(entries('review.finished').sort(byRun), [ofRun(one, {state: 'cancelled'}, 'system'),
    ofRun(three, {state: 'abandoned'}, 'system'), ofRun(four, {state: 'succeeded'}, 'system')].sort(byRun),
  '§11 review.finished {state} for every review task that ends, abandoned included (§15.1)');
  const interventions = log.filter(entry => entry.actor === 'operator' && entry.workflowId === workflow.id &&
    !['workflow.created', 'run.reviewed', 'workflow.approved', 'workflow.skipped'].includes(entry.kind));   // (rev 11) §8
  expectEqual((await f.workflow(workflow.id)).stats.interventions, interventions.length,
    '§8 interventions count the operator entries of the workflow, review.cancel_requested and review.abandoned included (§11)');
  await f.stop();
}

// Case 17, rework after the reviewer agent's rejections. §15.2: the exact rework input, attempt, reworkOf and
// assignment; a rework due before nextRunAt; no further rework once the limit is reached; §15.1 a rework
// reviewed against its assignment; the daily cap counting reworks (not review tasks) and the statistics.
async function case17_reworkAfterAgentRejection() {
  const f = await team('rework-agent', [reviewerAgent], {clock: '2026-08-03T23:45:00.000Z'});
  const reviewer = await f.connectAgent(reviewerAgent, 'FAKE-CONFORMANCE reviewer');
  await f.start();
  await f.ready(f.connectionId, reviewer);
  const reasons = 'FAKE reasons: the widget count is missing.';
  await f.script({agent: reviewerAgent.agentId, state: 'succeeded', output: `VERDICT: REJECT\n${reasons}\n\nBranch: none`});
  const instructions = 'FAKE rework assignment: count the fake widgets';
  const workflow = await f.create({instructions, review: 'agent', reviewerId: reviewer, reworkLimit: 2, intervalMinutes: 60, enabled: true});
  const reviewOf = async run => inputOf((await f.submitsTo(reviewerAgent)).find(call => option(call.argv, '--task') === run.reviewTask.taskId).argv);
  let previous = null;
  const rejected = [];
  for (const [index, output] of ['FAKE widget report, attempt one', 'FAKE widget report, attempt two',
    'FAKE widget report, attempt three'].entries()) {
    const run = await f.newRun(workflow.id, 'queued');
    expectEqual(pick(run, 'attempt reworkOf'), {attempt: index + 1, reworkOf: previous?.id ?? null},
      '§15.2 attempt is one more than the rejected run, and reworkOf names it');
    const [submit] = await f.taskCalls('submit', run.taskId);
    const input = index === 0 ? instructions : reworkInput(instructions, reasons, previous.output);
    expectEqual(inputOf(submit.argv), input, '§15.2 the exact rework input: instructions, the revision request, the review ' +
      'note and the previous result');
    expectEqual(pick((await f.detail(run.id)).run, 'instructions assignment'), {instructions: input, assignment: instructions},
      '§10 a rework assignment is the instructions without the revision request');
    if (previous) {
      const w = await f.workflow(workflow.id);
      expect(Date.parse(run.createdAt) < Date.parse(w.nextRunAt) &&
        Math.abs(Date.parse(w.nextRunAt) - Date.parse(previous.finishedAt) - 60 * minute) <= 1000 && w.failureStreak === 0 &&
        w.reworkPending === null, '§15.2 a rework is due whatever nextRunAt says; §4 the rejection changed neither the ' +
        'failure count nor nextRunAt; reworkPending is null once the rework is reserved', pick(w, 'nextRunAt failureStreak reworkPending'));
    }
    await f.finish(run, 'succeeded', {output});
    const done = await untilRun(f, run.id, item => item.review === 'rejected', '§15.1 the reviewer agent rejects');
    expectEqual(pick(done, 'reviewedBy reviewNote'), {reviewedBy: 'agent', reviewNote: reasons},
      '§15.1 the reasons without the final branch line');
    expectEqual([done.reviewTask.connectionId, await reviewOf(done)], [reviewer, reviewInput(instructions, null, output)],
      '§15.2 a rework is reviewed by the workflow reviewer, against its assignment (no revision request) and its own output');
    rejected.push(done);
    previous = done;
  }
  await delay(1000);
  const after = await f.workflow(workflow.id);
  expectEqual([after.reworkPending, (await f.submitsTo(ids)).length], [null, 3], '§15.2 no rework once the attempt exceeds the limit');
  expect(Math.abs(Date.parse(after.nextRunAt) - Date.parse(rejected[2].finishedAt) - 60 * minute) <= 1000,
    '§15.2 a rework own result sets nextRunAt', {nextRunAt: after.nextRunAt, finishedAt: rejected[2].finishedAt});
  expectEqual(pick(after.stats, 'runs succeeded failed awaitingReview'), {runs: 3, succeeded: 0, failed: 3, awaitingReview: 0},
    '§15.2 reworks are runs in the statistics; rejected results count as failed');
  expectEqual((await f.log()).filter(entry => entry.kind === 'workflow.rework_due').map(entry => pick(entry, 'actor workflowId runId data')),
    [{actor: 'system', workflowId: workflow.id, runId: rejected[1].id, data: {attempt: 3}},
      {actor: 'system', workflowId: workflow.id, runId: rejected[0].id, data: {attempt: 2}}],
  '§11 workflow.rework_due {attempt} with the rejected run as its runId, newest first');

  // The daily cap counts reworks but not review tasks.
  const capped = await f.create({name: 'FAKE capped rework', instructions: 'FAKE capped assignment', review: 'agent',
    reviewerId: reviewer, reworkLimit: 3, maxRunsPerDay: 2, intervalMinutes: 60, enabled: true});
  const c1 = await f.newRun(capped.id, 'queued');
  await f.finish(c1, 'succeeded', {output: 'FAKE capped report one'});
  const c2 = await f.newRun(capped.id, 'queued');
  expectEqual(pick(c2, 'attempt reworkOf'), {attempt: 2, reworkOf: c1.id},
    '§4 a review task is not counted by the daily cap: the rework is the second run of the day');
  await f.finish(c2, 'succeeded', {output: 'FAKE capped report two'});
  await untilRun(f, c2.id, item => item.review === 'rejected', '§15.1 the reviewer agent rejects the rework');
  const limit = await until('§8 daily_limit_reached while the rework waits for the cap', () => f.attentionFor('daily_limit_reached', capped.id));
  const blocked = await f.workflow(capped.id);
  expect(limit.severity === 'info' && blocked.reworkPending === c2.id && blocked.blockedReason && blocked.stats.runs === 2,
    '§15.2 a rework counts toward the daily cap and waits for it', {limit, blocked: pick(blocked, 'reworkPending blockedReason stats')});
  await f.clockAt('2026-08-04T00:00:30.000Z', 'a new UTC day begins');
  const c3 = await f.newRun(capped.id, 'queued');
  expectEqual(pick(c3, 'attempt reworkOf'), {attempt: 3, reworkOf: c2.id}, '§15.2 the rework is dispatched on the next UTC day');
  await f.finish(c3, 'failed', {output: 'FAKE capped report three failed'});
  expectEqual(pick((await f.workflow(capped.id)).stats, 'runs succeeded failed'), {runs: 3, succeeded: 0, failed: 3},
    '§8 statistics count the reworks');
  await f.stop();
}

// Case 17, rework after the operator's rejections. §15.2: with and without a note, a long previous result cut;
// reworkLimit read at the rejection; a paused workflow keeping its rework until resume; no rework when a later
// run exists or for an archived workflow; archive clearing reworkPending.
async function case17_reworkAfterOperatorRejection() {
  const f = await team('rework-operator', []);
  await f.start();
  await f.ready(f.connectionId);
  const instructions = 'FAKE operator-reviewed assignment: list the fake invoices';
  const workflow = await f.create({instructions, review: 'operator', reworkLimit: 0, intervalMinutes: 60, enabled: true});
  const reject = (run, note) => f.verdict(run, note === undefined ? {verdict: 'rejected'} : {verdict: 'rejected', note},
    '§15 an operator rejection');
  const pending = id => until('§15.2 reworkPending names the rejected run', async () => (await f.workflow(workflow.id)).reworkPending === id);
  const submitted = async count => { await delay(700); expectEqual((await f.submissions()).length, count, '§15.2 no rework dispatched'); };
  const runOnce = async output => {
    await f.action(workflow.id, 'run');
    return f.finish(await f.newRun(workflow.id, 'queued'), 'succeeded', {output, timeout: 20000});
  };
  const firstOutput = 'FAKE invoice list\u0000 one\u0000';
  const first = await f.finish(await f.newRun(workflow.id, 'queued'), 'succeeded', {output: firstOutput});
  await f.patch(workflow.id, {reworkLimit: 1});   // §9: read when the review becomes rejected
  await f.action(workflow.id, 'pause');
  const before = await f.workflow(workflow.id);
  await reject(first, '  FAKE operator note: add the totals  ');
  await pending(first.id);
  expectEqual(pick(await f.workflow(workflow.id), 'nextRunAt failureStreak enabled'), pick(before, 'nextRunAt failureStreak enabled'),
    '§15.2 an operator rejection makes a rework due, even while paused; §4 it changes neither the failure count nor nextRunAt');
  await submitted(1);
  await f.action(workflow.id, 'resume');
  const second = await f.newRun(workflow.id, 'queued');
  const reworked = reworkInput(instructions, 'FAKE operator note: add the totals', firstOutput);
  expect(reworked.endsWith('PREVIOUS RESULT\nFAKE invoice list one'), 'fixture: the NUL characters are left out', reworked);
  expectEqual([pick(second, 'attempt reworkOf'), inputOf((await f.taskCalls('submit', second.taskId))[0].argv)],
    [{attempt: 2, reworkOf: first.id}, reworked], '§15.2 the paused workflow kept its rework until resume; the input ' +
    'carries the stored (trimmed) note and the previous result without its NUL characters');
  expectEqual((await f.workflow(workflow.id)).reworkPending, null, '§15.2 reworkPending is null once the rework is reserved');
  const two = await f.finish(second, 'succeeded', {output: 'FAKE invoice list two'});
  await reject(two);
  await submitted(2);
  await f.patch(workflow.id, {reworkLimit: 3});
  expectEqual((await f.workflow(workflow.id)).reworkPending, null, '§15.2 no rework once the limit is reached, nor after raising it later');

  // Without a note; a long previous result with NUL characters, which are left out before it is cut (cutting
  // first would keep fewer characters).
  const long ='FAKE long invoice list \u0000' + ('€'.repeat(9) + '\u0000').repeat(2800) + 'λ'.repeat(3000);
  const three = await runOnce(long);
  await reject(three);
  const fourth = await f.newRun(workflow.id, 'queued');
  const cut = reworkInput(instructions, null, long);
  expect(cut.endsWith('…') && Buffer.byteLength(cut) <= 65536 && Buffer.byteLength(cut) > 65530 && !cut.includes('\u0000'),
    'fixture: the result must be cut, without NUL characters');
  expectEqual([pick(fourth, 'attempt reworkOf'), inputOf((await f.taskCalls('submit', fourth.taskId))[0].argv)],
    [{attempt: 2, reworkOf: three.id}, cut], '§15.2 without a note the review reads "The reviewer gave no reasons."; a long ' +
    'previous result loses its NUL characters and is then cut at a character boundary and ended with …, keeping as much ' +
    'as fits in 65,536 bytes');
  // A later run exists.
  const four = await f.finish(fourth, 'succeeded', {output: 'FAKE invoice list four'});
  await f.action(workflow.id, 'run');
  const fifth = await f.newRun(workflow.id, 'queued');
  await reject(four, 'FAKE note on a result already superseded');
  await delay(400);
  expectEqual((await f.workflow(workflow.id)).reworkPending, null, '§15.2 no rework when a later run of the workflow was reserved');
  // An archived workflow.
  const five = await f.finish(fifth, 'succeeded', {output: 'FAKE invoice list five'});
  const route = action => `/api/workflows/${workflow.id}/${action}`;
  expectStatus(await f.request('POST', route('archive'), {}), 200, '§9 archive');
  await reject(five, 'FAKE note on an archived workflow');
  expectEqual(expectStatus(await f.request('POST', route('restore'), {}), 200, '§9 restore').data.reworkPending, null,
    '§15.2 no rework for an archived workflow');
  await f.action(workflow.id, 'resume');
  await submitted(5);
  // Archive clears a pending rework.
  const six = await runOnce('FAKE invoice list six');
  expectEqual(pick(six, 'attempt reworkOf'), {attempt: 1, reworkOf: null}, '§15.2 a run requested by the operator is attempt 1');
  await f.action(workflow.id, 'pause');
  await reject(six, 'FAKE note before the archive');
  await pending(six.id);
  expectStatus(await f.request('POST', route('archive'), {}), 200, '§9 archive with a pending rework');
  expectEqual(expectStatus(await f.request('POST', route('restore'), {}), 200, '§9 restore').data.reworkPending, null,
    '§9 archive sets reworkPending to null');
  await f.action(workflow.id, 'resume');
  await submitted(6);
  expectEqual((await f.log()).filter(entry => entry.kind === 'workflow.rework_due').map(entry => pick(entry, 'actor runId data')).reverse(),
    [first, three, six].map(run => ({actor: 'system', runId: run.id, data: {attempt: 2}})),
  '§11 workflow.rework_due for each rejection that made a rework due, and no other');
  expectEqual(pick((await f.workflow(workflow.id)).stats, 'runs succeeded failed'), {runs: 6, succeeded: 0, failed: 6},
    '§8 reworks and rejected results in the statistics');
  await f.stop();
}

// Case 18. §10.1: each form read from a succeeded and a failed run, the longest NAME and the order of the
// forms, and branch null for an output without the empty line, a commit ID of another length or case, a name
// or FROM with `/`, a truncated output, and a run that is not succeeded or failed.
async function case18_workspaceBranches() {
  const f = await team('branches', []);
  await f.start();
  await f.ready(f.connectionId);
  const branch = (outcome, patch = {}) => ({name: null, outcome, commit: null, from: null, error: null, ...patch});
  const none = branch('none');
  const committed = name => branch('committed', {name, commit: hex66});
  const unchanged = (name, from) => branch('unchanged', {name, from});
  const notCommitted = (name, error) => branch('not_committed', {name, error});
  const outcomes = [
    ['succeeded', 'FAKE report\n\nBranch: none', none], ['failed', 'FAKE failure report\n\nBranch: none\n', none],
    ['succeeded', `FAKE report\nsecond line\n\nBranch: codex.task_fake at commit ${hex66}`, committed('codex.task_fake')],
    ['failed', `FAKE failure\n\nBranch: codex.task_fake at commit ${hex66}  \n`, committed('codex.task_fake')],
    ['succeeded', 'FAKE report\n\nBranch: fake-branch, unchanged from fake-main \n\t\n', unchanged('fake-branch', 'fake-main')],
    ['failed', 'FAKE failure\n\nBranch: fake-branch, unchanged from fake-main', unchanged('fake-branch', 'fake-main')],
    ['succeeded', 'FAKE report\n\nBranch: fake-branch, not committed: FAKE error: a/b is read-only',
      notCommitted('fake-branch', 'FAKE error: a/b is read-only')],
    ['failed', 'FAKE failure\n\nBranch: fake-branch, not committed: FAKE disk full', notCommitted('fake-branch', 'FAKE disk full')],
    ['succeeded', `FAKE\n\nBranch: fake x at commit y at commit ${hex66}`, committed('fake x at commit y')],
    ['succeeded', 'FAKE\n\nBranch: fake-a, unchanged from fake-b, unchanged from fake-c', unchanged('fake-a, unchanged from fake-b', 'fake-c')],
    ['succeeded', 'FAKE\n\nBranch: fake-a, not committed: one, not committed: two', notCommitted('fake-a, not committed: one', 'two')],
    ['succeeded', `FAKE\n\nBranch: fake-a, unchanged from fake-b at commit ${hex66}`, committed('fake-a, unchanged from fake-b')],
    ['succeeded', `FAKE\n\nBranch: ${'n'.repeat(255)}, unchanged from fake-main`, unchanged('n'.repeat(255), 'fake-main')],
    ['succeeded', `FAKE\n\nBranch: fake-a, not committed: ${'e'.repeat(1024)}`, notCommitted('fake-a', 'e'.repeat(1024))],
    // Only the 2,000-character preview is cut: the controller retained the whole output, so branch is read.
    ['succeeded', `FAKE long report ${'x'.repeat(3000)}\n\nBranch: fake-long, unchanged from fake-main`,
      unchanged('fake-long', 'fake-main')],
    ['failed', `FAKE long failure ${'x'.repeat(3000)}\n\nBranch: none`, none],
    ['succeeded', 'FAKE report\nBranch: none', null], ['failed', `FAKE failure\nBranch: fake at commit ${hex66}`, null],
    ['succeeded', `FAKE\n\nBranch: fake at commit ${'a1'.repeat(32)}`, null],
    ['succeeded', `FAKE\n\nBranch: fake at commit ${'a1'.repeat(34)}`, null],
    ['failed', `FAKE\n\nBranch: fake at commit ${'A1'.repeat(33)}`, null],
    ['succeeded', `FAKE\n\nBranch: fake/feature at commit ${hex66}`, null],
    ['succeeded', 'FAKE\n\nBranch: fake-branch, unchanged from origin/main', null],
    ['succeeded', 'FAKE\n\nBranch: fake-a, unchanged from b/c, unchanged from fake-d', null],
    ['succeeded', `FAKE\n\nBranch: ${'n'.repeat(256)}, unchanged from fake-main`, null],
    ['succeeded', `FAKE\n\nBranch: fake-a, not committed: ${'e'.repeat(1025)}`, null],
    ['succeeded', 'FAKE\n\nBranch: none\nFAKE line after the branch line', null], ['succeeded', 'Branch: none', null],
    ['expired', 'FAKE\n\nBranch: none', null], ['rejected', 'FAKE\n\nBranch: none', null]];
  const tag = index => `<branch-${String(index).padStart(2, '0')}>`;
  await f.script(...outcomes.map(([state, output], index) => ({agent: ids.agentId, input: tag(index),
    ...(state === 'rejected' ? {submit: 'rejected', message: output} : state === 'expired' ? {state, message: output} : {state, output})})));
  const workflows = [];
  for (const index of outcomes.keys()) {
    workflows.push(await f.create({name: `FAKE branch ${tag(index)}`, instructions: `FAKE branch case ${tag(index)}`,
      intervalMinutes: 60, enabled: true}));
  }
  let runs = [];
  await until(() => '§10.1 every scripted run ends; so far ' + snippet(runs.map(run => run?.state)), async () => {
    const {runs: listed} = await f.snapshot();
    runs = workflows.map(w => listed.find(run => run.workflowId === w.id));
    return runs.every(run => run && !unresolved.includes(run.state));
  }, 80000);
  for (const [index, [state, output, wanted]] of outcomes.entries()) {
    const why = `${state} run whose output ends ${JSON.stringify(output.slice(-60))}`;
    expectEqual(runs[index].state, state, 'fixture: the scripted state of the ' + why);
    const detail = (await f.detail(runs[index].id)).run;
    if (['succeeded', 'failed'].includes(state)) {
      expectEqual([runs[index].output, runs[index].outputTruncated, detail.output, detail.outputTruncated],
        [output.slice(0, 2000), output.length > 2000, output, false],
        '§10.1 the run output is unchanged: the branch line stays in it; §8 the snapshot shows a 2,000-character preview (' + why + ')');
    }
    expectEqual([runs[index].branch, detail.branch], [wanted, wanted], '§10.1 branch of a ' + why +
      '; a snapshot whose preview alone is cut has the same branch as the detail');
  }
  // A truncated output whose retained part ends with a branch line.
  const truncated = await f.create({name: 'FAKE branch truncated', instructions: 'FAKE branch case truncated',
    intervalMinutes: 60, enabled: true});
  const line = '\n\nBranch: none';
  const output = 'B'.repeat(262144 - line.length) + line + '\nFAKE-TAIL beyond the retained output';
  const big = await f.finish(await f.newRun(truncated.id, 'queued'), 'failed', {output, timeout: 20000});
  const detail = (await f.detail(big.id)).run;   // §10.1: the remote output was longer than the retained one
  expectEqual([detail.output.endsWith(line), detail.outputTruncated, detail.branch, big.branch], [true, true, null, null],
    '§10.1 branch is null when outputTruncated is true, even though the retained output ends with a branch line');
  await f.stop();
}

await runCases('reviewers', [case16_reviewerFields, case16_reviewTaskInput, case16_verdictsAndFallbacks,
  case16_orderAndOperatorVerdicts, case16_cancelAbandonAndRestart, case17_reworkAfterAgentRejection,
  case17_reworkAfterOperatorRejection, case18_workspaceBranches]);
