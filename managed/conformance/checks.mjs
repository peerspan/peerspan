#!/usr/bin/env node
// Contract-only black-box suite for docs/managed-contract.md revision 8, section 16, cases 23 to 25: result checks
// (sections 2, 8, 9, 11 and 15.3), applied by the controller to each result before any review (sections 15 and
// 15.1), and a failed result sent back for rework (section 15.2). No imports or reads of the managed implementation
// or its database: the documented CLI, HTTP, the explicitly fake Peerspan executable and throwaway state only. The
// fake plays the worker and reviewer agents, either driven step by step through its task records or by its
// `scripts` (README). Expected entries, messages, notes and inputs are written out from the contract; section
// numbers (§) refer to it.
import path from 'node:path';
import {delay, expect, expectEqual, expectError, expectStatus, fixture, hex, ids, inputOf, option, pick, runCases,
  snippet, until} from './harness.mjs';

const minute = 60000;
const hex66 = 'c3'.repeat(33);
const committedLine = `Branch: fake-checks at commit ${hex66}`;
const reviewerAgent = {agentId: hex('agent', 7), sessionId: hex('session', 7), adapterId: hex('adapter', 7)};
const unresolved = ['submitting', 'queued', 'running'];
const codePoints = value => [...value].length;   // §15.1: wherever text is counted, a character is a code point

// §15.3: the six kinds of check.
const contains = text => ({kind: 'contains', text});
const excludes = text => ({kind: 'excludes', text});
const minLength = chars => ({kind: 'minLength', chars});
const maxLength = chars => ({kind: 'maxLength', chars});
const branch = {kind: 'branch'};
const jsonKeys = (...keys) => ({kind: 'jsonKeys', keys});
// §15.3: the message of each failed check. Q, Q1 and Q2 are written as JSON strings, quotes included, the way
// JSON.stringify writes them; M (the result's length) and N in decimal without separators.
const says = {
  contains: text => `The result does not contain ${JSON.stringify(text)}.`,
  excludes: text => `The result contains ${JSON.stringify(text)}.`,
  minLength: (m, n) => `The result has ${m} characters; at least ${n} are required.`,
  maxLength: (m, n) => `The result has ${m} characters; at most ${n} are allowed.`,
  branch: 'The result does not end with a branch line of a commit.',
  notObject: 'The result is not a JSON object.',
  lacks: (...keys) => `The result's JSON object lacks ${keys.map(key => JSON.stringify(key)).join(', ')}.`};
const passed = check => ({check, passed: true, message: null});
const failed = (check, message) => ({check, passed: false, message});
const byChecks = {verdict: 'rejected', by: 'checks'};
// §15.3: when any check fails, review becomes rejected by checks, with the failed messages joined by LF as the note,
// treated as §15.1 treats a reviewer's reasons: control characters other than LF and tab removed, trimmed, and cut to
// its first 1,999 characters and … when longer than 2,000. When every check passes the run is reviewed as reserved:
// for review none, no review.
function verdictOf(entries) {
  const note = entries.filter(entry => !entry.passed).map(entry => entry.message).join('\n')
    .replace(/(?![\n\t])\p{Cc}/gu, '').trim();
  if (note === '') return {review: null, reviewedBy: null, reviewNote: null, reviewFallback: null};
  return {review: 'rejected', reviewedBy: 'checks', reviewFallback: null,
    reviewNote: codePoints(note) > 2000 ? [...note].slice(0, 1999).join('') + '…' : note};
}

// §15.1 and §15.2: the last part (a retained output) is used without its NUL characters; then an input longer than
// 65,536 bytes of UTF-8 has that part cut at a character boundary and ended with "…", keeping as much as fits.
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
// §15.1: the review input, unchanged by revision 8.
const reviewInput = (assignment, criteria, output) => fitted([
  'Review the result below, which an agent produced for the assignment that follows it. Decide whether the result does what the assignment asks.',
  'Begin your answer with one line that says exactly VERDICT: ACCEPT or VERDICT: REJECT. Then give your reasons briefly: the operator reads them, and after a rejection the agent may receive them with the assignment.',
  '', 'ASSIGNMENT', assignment, '', ...(criteria === null ? [] : ['CRITERIA', criteria, '']), 'RESULT'], output);
// §15.3: the rework input after failed checks, the §15.2 input with the revision request and the REVIEW heading changed.
const checksReworkInput = (instructions, note, previous) => fitted([instructions, '', 'REVISION REQUESTED',
  'Your previous result for this assignment failed the result checks below. Do the assignment again in full, so that it passes them.',
  '', 'FAILED CHECKS', note, '', 'PREVIOUS RESULT'], previous);

// A fixture whose fake worker host has the fixture's own worker agent and `others`, each with a ready and verified
// session (§3), and a second sender state for reviewer connections.
async function team(label, others = [], options = {}) {
  const f = await fixture(label, options);
  f.reviewSender = path.join(f.dir, 'PRIVATE-review-sender');
  const all = [ids, ...others];
  await f.configure({scripts: [], senderStates: [f.senderDir, f.reviewSender],
    agents: all.map(item => ({id: item.agentId, name: 'FAKE-CONFORMANCE agent ' + item.agentId.slice(-4),
      sessions: [{id: item.sessionId, adapter_id: item.adapterId, connection: 'ready'}]})),
    adapters: Object.fromEntries(all.map(item => [item.adapterId, {session_id: item.sessionId, state: 'ready',
      channel: 'verified', channel_verified_at: '2026-01-01T00:00:00Z'}]))});
  f.connectAgent = async (item, name) => JSON.parse(await f.checkedCli('connect', '--name', name, '--agent', item.agentId,
    '--host-state', f.workerDir, '--sender-state', f.reviewSender)).id;
  f.ready = (...connections) => Promise.all(connections.map(id => f.code(id, 'ready', 'the agent is ready and verified')));
  f.script = (...scripts) => f.configure({scripts});
  f.submitsTo = async item => (await f.submissions()).filter(call => option(call.argv, '--agent') === item.agentId);
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
  // §11: the fields of each workflow.edited entry of a workflow, oldest first.
  f.edits = async id => (await f.log()).filter(entry => entry.kind === 'workflow.edited' && entry.workflowId === id)
    .map(entry => entry.data.fields).reverse();
  return f;
}
function untilRun(f, id, test, why, timeout) {
  let last;
  return until(() => `${why}; last seen: ${snippet(last && pick(last, 'state review reviewedBy checks reviewTask'))}`,
    async () => { last = await f.runById(id); return last && test(last) ? last : false; }, timeout);
}
// Workflows that each get one run, which the fake worker agent completes at once with a scripted state and result
// (README `scripts`), matched by a tag in the workflow's instructions. Resolves once every run has ended.
async function scripted(f, cases) {
  const tag = index => `<checks-${String(index).padStart(2, '0')}>`;
  await f.script(...cases.map((item, index) => ({agent: ids.agentId, input: tag(index), state: item.state ?? 'succeeded',
    output: item.output})));
  const workflows = [];
  for (const [index, item] of cases.entries()) {
    workflows.push(await f.create({name: `FAKE checks ${tag(index)}`, instructions: `FAKE checks case ${tag(index)}: ${item.what}`,
      intervalMinutes: 60, enabled: true, resultChecks: item.checks ?? item.entries.map(entry => entry.check), ...item.workflow}));
  }
  let runs = [];
  await until(() => '§15.3 every scripted run ends; so far ' + snippet(runs.map(run => run && pick(run, 'state review'))), async () => {
    const {runs: listed} = await f.snapshot();
    runs = workflows.map(w => listed.find(run => run.workflowId === w.id));
    return runs.every(run => run && !unresolved.includes(run.state));
  }, 80000);
  return {workflows, runs};
}

// Case 23, fields. §15.3 and §2: every kind accepted at creation and in PATCH, stored as sent and in order, [] by
// default, and the 400s; §11 workflow.edited listing resultChecks only when the array changes; §8 and §9
// resultChecks in the workflow of every route. No dispatch is needed, so this controller ticks once a second.
async function case23_fields() {
  const f = await team('check-fields', [], {env: {MANAGED_TICK_MS: '1000'}});
  await f.start();
  const plain = await f.create({name: 'FAKE without checks'});
  expectEqual(plain.resultChecks, [], '§2 (rev 8) resultChecks is [] when omitted');
  const keys16 = [...Array.from({length: 15}, (unused, index) => `FAKE-key-${index}`), '😀'.repeat(100)];
  const every = [jsonKeys('zeta', 'summary'), branch, maxLength(262144), contains('  FAKE Total: \n﻿'),
    excludes('FAKE refusal'), minLength(1), contains('😀'.repeat(500)), jsonKeys(...keys16)];
  const all = await f.create({name: 'FAKE every kind', resultChecks: every});
  expectEqual(all.resultChecks, every, '§15.3 every kind is accepted at creation and stored as sent (T with its ' +
    'whitespace), in the operator order: 8 checks, N 1 and 262,144, T of 500 and K of 16 keys, one of 100 characters (code points)');
  const bounds = [minLength(40), maxLength(40), excludes('t'.repeat(500))];
  expectEqual((await f.create({name: 'FAKE equal bounds', resultChecks: bounds})).resultChecks, bounds,
    '§15.3 a minLength equal to a maxLength is accepted');
  // §15.3: each check with kind first, whatever the order of its fields as sent; a check may appear more than once.
  const kindFirst = list => list.map(check => Object.keys(check)[0]).every(name => name === 'kind');
  const shuffled = [{text: 'FAKE field order', kind: 'contains'}, {chars: 5, kind: 'minLength'}, branch, branch];
  const repeated = await f.create({name: 'FAKE field order and repeats', resultChecks: shuffled});
  expectEqual([repeated.resultChecks, kindFirst(repeated.resultChecks)], [[contains('FAKE field order'), minLength(5), branch,
    branch], true], '§15.3 each check is returned with kind first whatever the order of its fields; a check may appear twice');

  const body = resultChecks => ({name: 'FAKE refused checks', connectionId: f.connectionId, instructions: 'FAKE fields only',
    intervalMinutes: 60, maxRunsPerDay: 5, acceptanceMinutes: 5, resultChecks});
  const refused = [
    ['resultChecks null', null], ['a check instead of an array', branch], ['a string', 'branch'],
    ['a check that is null', [null]], ['a check that is an array', [['contains', 'FAKE']]], ['a check that is a string', ['branch']],
    ['an unknown kind', [{kind: 'regex', text: 'FAKE'}]], ['a kind in another case', [{kind: 'Contains', text: 'FAKE'}]],
    ['a kind that is not a string: ["contains"]', [{kind: ['contains'], text: 'FAKE'}]],
    ['a kind that is not a string: [["maxLength"]]', [{kind: [['maxLength']], chars: 5}]],
    ['a kind that is not a string: ["branch"]', [{kind: ['branch']}]], ['a numeric kind', [{kind: 7}]],
    ['a valid check before one whose kind is ["contains"]', [branch, {kind: ['contains'], text: 'FAKE'}]],
    ['a check without kind', [{text: 'FAKE'}]], ['contains without text', [{kind: 'contains'}]],
    ['minLength without chars', [{kind: 'minLength'}]], ['jsonKeys without keys', [{kind: 'jsonKeys'}]],
    ['an extra field on contains', [{...contains('FAKE'), chars: 1}]], ['an extra field on branch', [{...branch, text: 'FAKE'}]],
    ['jsonKeys with text for keys', [{kind: 'jsonKeys', text: 'FAKE'}]],
    ['T empty', [contains('')]], ['T only whitespace', [excludes(' \n\t ')]],
    ['T only ECMAScript whitespace (U+00A0, U+FEFF, U+2028, U+3000)', [contains(' ﻿ 　')]],
    ['T with NUL', [contains('FAKE\u0000')]],
    ['T of 501 characters', [contains('t'.repeat(501))]], ['T of 501 code points', [excludes('😀'.repeat(501))]],
    ['T not a string', [{kind: 'contains', text: 7}]],
    ['N 0', [minLength(0)]], ['N 262,145', [maxLength(262145)]], ['N 1.5', [minLength(1.5)]], ['N -1', [maxLength(-1)]],
    ['N as a string', [minLength('10')]], ['N null', [maxLength(null)]],
    ['K empty', [jsonKeys()]], ['K of 17 keys', [jsonKeys(...keys16, 'FAKE-key-16')]], ['a repeated key', [jsonKeys('a', 'b', 'a')]],
    ['a key of 101 characters', [jsonKeys('k'.repeat(101))]], ['an empty key', [jsonKeys('')]],
    ['a key with NUL', [jsonKeys('FAKE\u0000')]], ['a key that is not a string', [{kind: 'jsonKeys', keys: ['FAKE', 7]}]],
    ['K not an array', [{kind: 'jsonKeys', keys: 'FAKE'}]],
    ['nine checks', Array.from({length: 9}, (unused, index) => contains(`FAKE ${index}`))],
    ['a minLength above a maxLength', [minLength(10), maxLength(9)]],
    ['a maxLength before a greater minLength', [maxLength(9), minLength(10)]],
    ['a minLength above one of two maxLengths', [maxLength(100), minLength(50), maxLength(20)]]];
  for (const [what, value] of refused) {
    expectError(await f.request('POST', '/api/workflows', body(value)), 400, `§15.3 POST refuses ${what}`);
  }
  const created = await f.snapshot();
  expectEqual([created.workflows.length, created.archived.length, created.activity.filter(entry =>
    entry.kind === 'workflow.created').length], [4, 0, 4], '§2 refused creations store nothing: no workflow and no ' +
    'workflow.created entry beyond the four accepted');

  // PATCH: validated as at creation; a refused PATCH changes nothing.
  const route = '/api/workflows/' + plain.id;
  const first = [contains('FAKE first')];
  expectEqual((await f.patch(plain.id, {resultChecks: first})).resultChecks, first, '§9 PATCH sets resultChecks');
  const kept = await f.workflow(plain.id);
  for (const [what, value] of refused) {
    expectError(await f.request('PATCH', route, {resultChecks: value}), 400, `§9 PATCH refuses ${what}`);
  }
  expectError(await f.request('PATCH', route, {name: 'FAKE never renamed', resultChecks: [minLength(0)]}), 400,
    '§9 a PATCH with an invalid resultChecks is refused whole');
  expectEqual(await f.workflow(plain.id), kept, '§9 a refused PATCH changes nothing: the stored checks stay [contains]');

  // §15.3: a PATCH replaces the whole array; two arrays are equal when their checks are equal, in order, and two
  // checks are equal when they have the same kind and values, whatever the order of their fields.
  const reversed = [...every].reverse();
  const fieldsReversed = every.map(check => Object.fromEntries(Object.entries(check).reverse()));
  const spaced = [contains('FAKE first ')];
  const steps = [[{resultChecks: every}, every], [{resultChecks: structuredClone(every)}, every],
    [{resultChecks: fieldsReversed}, every], [{resultChecks: structuredClone(every), name: 'FAKE renamed checks'}, every],
    [{resultChecks: reversed}, reversed], [{resultChecks: spaced}, spaced], [{resultChecks: [contains('FAKE first ')]}, spaced],
    [{resultChecks: [...spaced, ...spaced]}, [...spaced, ...spaced]], [{resultChecks: []}, []], [{resultChecks: []}, []]];
  for (const [patch, wanted] of steps) {
    const returned = (await f.patch(plain.id, patch)).resultChecks;
    expectEqual([returned, kindFirst(returned)], [wanted, true], '§9 PATCH replaces the whole array, stored as sent and ' +
      'in order; §15.3 each check with kind first: ' + snippet(patch).slice(0, 80));
  }
  expectEqual(await f.edits(plain.id), [['resultChecks'], ['resultChecks'], ['name'], ['resultChecks'], ['resultChecks'],
    ['resultChecks'], ['resultChecks']], '§11 workflow.edited lists resultChecks only when the array changes, and no ' +
    'refused PATCH records one: an equal array (its checks with their fields in another order, or beside a changed ' +
    'name) is no change; the same checks in another order, a T that differs by a trailing space and a repeated check are');

  // §8: resultChecks is in the workflow's shape everywhere; §9 restore keeps it.
  expectEqual((await f.action(all.id, 'pause')).resultChecks, every, '§8 resultChecks in the workflow that pause returns');
  expectStatus(await f.request('POST', `/api/workflows/${all.id}/archive`, {}), 200, '§9 archive');
  const restored = expectStatus(await f.request('POST', `/api/workflows/${all.id}/restore`, {}), 200, '§9 restore').data;
  expectEqual(restored.resultChecks, every, '§9 restore returns the workflow with its other fields as they were');
  await f.stop();
}

// Case 23, reservation. §15.3 and §9: a run is checked with the checks its workflow had when it was reserved, so a
// PATCH of resultChecks leaves a reserved run's checks; a run reserved without checks has checks null.
async function case23_checksAtReservation() {
  const f = await team('check-reservation');
  await f.start();
  await f.ready(f.connectionId);
  const markerA = contains('FAKE-MARKER-A'), markerB = contains('FAKE-MARKER-B');
  const workflow = await f.create({instructions: 'FAKE reservation assignment', resultChecks: [markerA],
    intervalMinutes: 60, enabled: true});
  const output = 'FAKE report with FAKE-MARKER-A only';
  const first = await f.newRun(workflow.id, 'queued');
  expectEqual(pick(first, 'checks review'), {checks: null, review: null}, '§15.3 checks is null while the run is unresolved');
  await f.patch(workflow.id, {resultChecks: [markerB]});
  const one = await f.finish(first, 'succeeded', {output});
  expectEqual(pick(one, 'checks review reviewedBy'), {checks: [passed(markerA)], review: null, reviewedBy: null},
    '§15.3 a run reserved before a PATCH of resultChecks is checked with the checks it was reserved with ([A], not [B])');

  await f.action(workflow.id, 'run');
  const second = await f.newRun(workflow.id, 'queued');
  await f.patch(workflow.id, {resultChecks: []});
  const two = await f.finish(second, 'succeeded', {output});
  const entries = [failed(markerB, says.contains('FAKE-MARKER-B'))];
  expectEqual(pick(two, 'checks review reviewedBy reviewNote'), {checks: entries, review: 'rejected', reviewedBy: 'checks',
    reviewNote: says.contains('FAKE-MARKER-B')}, '§15.3 a run reserved with [B] is checked with [B] after a PATCH to []');
  expectEqual(pick((await f.detail(two.id)).run, 'checks review reviewedBy reviewNote'),
    pick(two, 'checks review reviewedBy reviewNote'), '§10 the run detail has the checks of the snapshot run');

  await f.action(workflow.id, 'run');
  const third = await f.newRun(workflow.id, 'queued');
  await f.patch(workflow.id, {resultChecks: [markerA, markerB]});
  const three = await f.finish(third, 'succeeded', {output: 'FAKE report without a marker'});
  expectEqual(pick(three, 'checks review reviewedBy'), {checks: null, review: null, reviewedBy: null},
    '§15.3 checks is null for a run reserved without checks, though its workflow has checks when it ends');
  expectEqual(pick((await f.workflow(workflow.id)).stats, 'runs succeeded failed'), {runs: 3, succeeded: 2, failed: 1},
    '§8 statistics by each run reserved checks');
  await f.stop();
}

// Case 24, each kind. §15.3: every check applied in order to a succeeded run's result, with the exact entries and
// messages: code points, NUL left out, T with a quote and a backslash, the retained output rather than its preview,
// jsonKeys in a code fence and with a branch line, results that are not JSON objects, missing keys in K's order,
// several failures joined and a long note cut; §11 the system run.reviewed of each rejection.
async function case24_eachKind() {
  const f = await team('check-kinds');
  await f.start();
  await f.ready(f.connectionId);
  const quoted = 'FAKE "quoted" C:\\fake\\dir\tλ😀';
  const control = 'FAKE\u007f DEL \u0085 NEL \u009f APC';   // control characters that JSON.stringify leaves as they are
  expectEqual([says.excludes(quoted), says.lacks('zeta', 'say "hi"'), says.contains(control)],
    ['The result contains "FAKE \\"quoted\\" C:\\\\fake\\\\dir\\tλ😀".', 'The result\'s JSON object lacks "zeta", "say \\"hi\\"".',
      'The result does not contain "FAKE\u007f DEL \u0085 NEL \u009f APC".'],
    'fixture: Q is written as JSON.stringify writes it: quote and backslash escaped, the tab as \\t, λ, 😀, DEL and C1 unescaped');
  expectEqual(verdictOf([failed(contains(control), says.contains(control))]).reviewNote,
    'The result does not contain "FAKE DEL  NEL  APC".', 'fixture: the note leaves out DEL and the C1 characters');
  const emoji = '😀'.repeat(10) + 'λ';   // 11 characters (code points), 21 UTF-16 code units
  const withNul = 'FAKE\u0000 widget\u0000 report';   // 18 characters without its NUL characters
  const long = 'FAKE long report ' + 'x'.repeat(2475) + 'FAKE-END';   // 2,500 characters
  const json = '{"summary":"FAKE","count":3}';
  const bigTexts = Array.from({length: 6}, (unused, index) => `FAKE-${index} ` + '😀'.repeat(400));
  const cases = [
    {what: 'contains and excludes passing, matched exactly', output: 'FAKE weekly report\nTotal: 12 fake widgets\nAll done.',
      entries: [passed(contains('Total: 12')), passed(excludes('total:')), passed(contains(' fake widgets\n'))]},
    {what: 'contains and excludes failing, case-sensitively', output: 'FAKE weekly report\ntotal: 12\nI cannot finish this.',
      entries: [failed(contains('Total:'), says.contains('Total:')), failed(excludes('I cannot'), says.excludes('I cannot')),
        passed(contains('total: 12')), passed(excludes('I CANNOT'))]},
    {what: 'T with a quote, a backslash, a tab and characters outside ASCII', output: `FAKE result: ${quoted} end`,
      entries: [passed(contains(quoted)), failed(excludes(quoted), says.excludes(quoted)),
        failed(contains('C:\\fake\\dir\\t'), says.contains('C:\\fake\\dir\\t'))]},
    {what: 'lengths in code points (11 characters, 21 UTF-16 units)', output: emoji,
      entries: [passed(minLength(11)), passed(maxLength(11))]},
    {what: 'minLength failing by code points', output: emoji,
      entries: [failed(minLength(12), says.minLength(11, 12)), passed(maxLength(20)), passed(contains('😀λ'))]},
    {what: 'maxLength failing by code points', output: emoji, entries: [failed(maxLength(10), says.maxLength(11, 10))]},
    {what: 'NUL left out of the result', output: withNul,
      entries: [passed(contains('E widget r')), passed(minLength(18)), passed(maxLength(18))]},
    {what: 'NUL left out of the length', output: withNul, entries: [failed(maxLength(17), says.maxLength(18, 17))]},
    {what: 'the retained output, not its 2,000-character preview; numbers without separators', output: long,
      entries: [failed(minLength(3000), says.minLength(2500, 3000)), passed(maxLength(262144)), passed(contains('FAKE-END'))]},
    {what: 'a committed branch line', output: `FAKE report\n\n${committedLine}`, entries: [passed(branch)]},
    {what: 'Branch: none', output: 'FAKE report\n\nBranch: none', entries: [failed(branch, says.branch)]},
    {what: 'an unchanged branch', output: 'FAKE report\n\nBranch: fake-checks, unchanged from fake-main',
      entries: [failed(branch, says.branch)]},
    {what: 'a branch not committed', output: 'FAKE report\n\nBranch: fake-checks, not committed: FAKE disk full',
      entries: [failed(branch, says.branch)]},
    {what: 'a commit line without the empty line before it', output: `FAKE report\n${committedLine}`,
      entries: [failed(branch, says.branch)]},
    {what: 'a JSON object', output: json, entries: [passed(jsonKeys('summary', 'count'))]},
    {what: 'a JSON object in a code fence, with whitespace around it',
      output: '\n  ```json\n{"summary": "FAKE", "count": 3}\n```  \n',
      entries: [passed(jsonKeys('count', 'summary')), passed(contains('```json'))]},
    {what: 'a fenced JSON object followed by a committed branch line', output: '```json\n' + json + '\n```\n\n' + committedLine,
      entries: [passed(jsonKeys('summary', 'count')), passed(branch)]},
    {what: 'a JSON object followed by Branch: none', output: json + '\n\nBranch: none\n',
      entries: [passed(jsonKeys('summary')), failed(branch, says.branch)]},
    {what: 'a result that is not JSON', output: 'FAKE plain text, no JSON here', entries: [failed(jsonKeys('summary'), says.notObject)]},
    {what: 'JSON after a line of text', output: 'Here is the FAKE JSON:\n' + json, entries: [failed(jsonKeys('summary'), says.notObject)]},
    {what: 'a JSON array', output: `[${json}]`, entries: [failed(jsonKeys('summary'), says.notObject)]},
    {what: 'JSON null', output: 'null', entries: [failed(jsonKeys('summary'), says.notObject)]},
    {what: 'a fence closed by four backticks', output: '```json\n' + json + '\n````', entries: [failed(jsonKeys('summary'), says.notObject)]},
    {what: 'missing keys in K order, a key with a quote and inherited names; a repeated key and a null value are present',
      output: '{"summary":"FAKE","alpha":null,"count":1,"count":2}',
      entries: [failed(jsonKeys('zeta', 'summary', 'say "hi"', 'alpha', 'toString', '__proto__', 'count'),
        says.lacks('zeta', 'say "hi"', 'toString', '__proto__'))]},
    {what: 'JSON text trimmed of ECMAScript whitespace (U+FEFF, U+00A0, U+2028), the fenced rest trimmed again',
      output: '﻿ ```json\n ' + json + ' \n``` \n', entries: [passed(jsonKeys('summary', 'count'))]},
    {what: 'a fence with CRLF line ends, split at LF', output: '```json\r\n' + json + '\r\n```',
      entries: [passed(jsonKeys('summary'))]},
    {what: 'a fence on CR alone: one line when split at LF, so no fence', output: '```json\r' + json + '\r```',
      entries: [failed(jsonKeys('summary'), says.notObject)]},
    {what: 'a fence on U+2028 alone: one line when split at LF, so no fence', output: '```json ' + json + ' ```',
      entries: [failed(jsonKeys('summary'), says.notObject)]},
    {what: 'control characters kept in the message and removed from the note', output: 'FAKE plain result',
      entries: [failed(contains(control), says.contains(control)), failed(excludes('FAKE'), says.excludes('FAKE'))]},
    {what: 'several failed checks, joined in order, and a repeated check with one entry each', output: 'FAKE short',
      entries: [failed(contains('Total'), says.contains('Total')), passed(minLength(5)), failed(maxLength(5), says.maxLength(10, 5)),
        failed(excludes('FAKE'), says.excludes('FAKE')), failed(branch, says.branch), failed(jsonKeys('a'), says.notObject),
        failed(contains('Total'), says.contains('Total'))]},
    {what: 'a note longer than 2,000 characters, cut by code points', output: 'FAKE result without the long texts',
      entries: bigTexts.map(text => failed(contains(text), says.contains(text)))}];
  const joined = cases.at(-1).entries.map(entry => entry.message).join('\n');
  expect(codePoints(joined) > 2000 && verdictOf(cases.at(-1).entries).reviewNote.endsWith('😀…'),
    'fixture: the joined messages exceed 2,000 characters and are cut inside the emoji', codePoints(joined));

  const {workflows, runs} = await scripted(f, cases);
  const log = await f.log();
  for (const [index, {what, output, entries}] of cases.entries()) {
    const run = runs[index];
    const verdict = verdictOf(entries);
    expectEqual(pick(run, 'state checks'), {state: 'succeeded', checks: entries},
      `§15.3 every check is applied in order, one {check,passed,message} entry each (${what})`);
    expectEqual(pick(run, 'review reviewedBy reviewNote reviewFallback reviewTask'), {...verdict, reviewTask: null},
      `§15.3 a failed check rejects the result by checks with the joined note; passing checks leave review none (${what})`);
    if (verdict.review) {
      expectEqual(Date.parse(run.reviewedAt), Date.parse(run.finishedAt),
        `§15.3 reviewedAt is the time the result was retained, equal to finishedAt (${what})`);
    }
    expectEqual(log.filter(entry => entry.runId === run.id && entry.kind === 'run.reviewed').map(entry => pick(entry, 'actor workflowId data')),
      verdict.review ? [{actor: 'system', workflowId: workflows[index].id, data: byChecks}] : [],
      `§11 a rejection by checks records a system run.reviewed {verdict:"rejected",by:"checks"}, and only it (${what})`);
    const detail = (await f.detail(run.id)).run;
    expectEqual([detail.output, detail.checks], [output, entries],
      `§10 the detail keeps the whole retained output, NUL included, and the same checks (${what})`);
    expectEqual(pick((await f.workflow(workflows[index].id)).stats, 'succeeded failed awaitingReview'),
      {succeeded: verdict.review ? 0 : 1, failed: verdict.review ? 1 : 0, awaitingReview: 0},
      `§15.3 a rejection by checks counts as a failed result in stats (${what})`);
  }
  await f.stop();
}

// Case 24, reviews. §15.3: a failed check rejects the result whatever review the run was reserved with (none,
// operator, agent): reviewedBy checks, the note, a system run.reviewed, no review task and no review_pending; passing
// checks leave the review as reserved, the review task going out with the unchanged input; checks null for a failed
// run and for a run reserved without checks; the verdict route's 409; the statistics and the failure circuit.
async function case24_rejectionBeforeReview() {
  const f = await team('check-review', [reviewerAgent]);
  const reviewer = await f.connectAgent(reviewerAgent, 'FAKE-CONFORMANCE reviewer');
  await f.start();
  await f.ready(f.connectionId, reviewer);
  const checks = [contains('FAKE-TOTAL'), excludes('FAKE-REFUSAL')];
  const good = 'FAKE-TOTAL: 3 fake widgets';
  const bad = 'FAKE-REFUSAL: the fake agent declines the assignment';
  const badEntries = [failed(checks[0], says.contains('FAKE-TOTAL')), failed(checks[1], says.excludes('FAKE-REFUSAL'))];
  const note = says.contains('FAKE-TOTAL') + '\n' + says.excludes('FAKE-REFUSAL');
  const criteria = 'FAKE criteria: a total is given';
  const byAgent = {review: 'agent', reviewerId: reviewer, reviewCriteria: criteria};
  const cases = [
    {what: 'review none, a failing result', output: bad, workflow: {}},
    {what: 'review none, a passing result', output: good, workflow: {}},
    {what: 'review operator, a failing result', output: bad, workflow: {review: 'operator'}},
    {what: 'review operator, a passing result', output: good, workflow: {review: 'operator'}},
    {what: 'review agent, a failing result', output: bad, workflow: byAgent},
    {what: 'review agent, a passing result', output: good, workflow: byAgent},
    {what: 'a failed run', output: bad, state: 'failed', workflow: {review: 'operator'}},
    {what: 'reserved without checks', output: bad, workflow: {resultChecks: []}}];
  const {workflows, runs} = await scripted(f, cases.map(item => ({...item, checks})));
  const [noneBad, nonePass, operatorBad, operatorPass, agentBad, agentPass, failedRun, unchecked] = runs;
  const notReserved = {connectionId: reviewer, taskId: null, state: null, error: null, reason: null, cancelRequestedAt: null,
    createdAt: null, finishedAt: null};
  for (const [run, reviewTask] of [[noneBad, null], [operatorBad, null], [agentBad, notReserved]]) {
    const what = cases[runs.indexOf(run)].what;
    expectEqual(pick(run, 'state checks review reviewedBy reviewNote reviewFallback reviewTask'), {state: 'succeeded',
      checks: badEntries, review: 'rejected', reviewedBy: 'checks', reviewNote: note, reviewFallback: null, reviewTask},
    `§15.3 a failed check rejects the result in the step that retains it, whatever review it was reserved with; a run ` +
      `reserved for an agent review keeps its reviewTask with the reviewer connectionId and every other field null (${what})`);
    expectEqual(Date.parse(run.reviewedAt), Date.parse(run.finishedAt),
      `§15.3 reviewedAt is the time the result was retained, equal to finishedAt (${what})`);
  }
  expectEqual((await f.detail(agentBad.id)).reviewEvents, [], '§10 no review task: reviewEvents is empty');
  expectEqual([pick(nonePass, 'checks review reviewedBy'), pick(operatorPass, 'checks review reviewedBy reviewTask')],
    [{checks: checks.map(passed), review: null, reviewedBy: null}, {checks: checks.map(passed), review: 'pending',
      reviewedBy: null, reviewTask: null}], '§15.3 passing checks leave the review as reserved: none, or pending for the operator');
  expectEqual([pick(failedRun, 'state checks review'), pick(unchecked, 'state checks review reviewedBy')],
    [{state: 'failed', checks: null, review: null}, {state: 'succeeded', checks: null, review: null, reviewedBy: null}],
    '§15.3 checks is null for a run that ends in another state than succeeded, and for a run reserved without checks');

  // The run whose checks passed waits for its reviewer agent, and its review task goes out with the §15.1 input.
  expect(agentPass.review === 'pending' && agentPass.reviewTask?.connectionId === reviewer && agentPass.reviewedBy === null,
    '§15.3 passing checks leave an agent review pending for the reviewer', agentPass);
  const reviewing = await untilRun(f, agentPass.id, run => run.reviewTask?.taskId, '§15.1 the review task is reserved');
  await until('§15.1 the review task is submitted to the reviewer agent', async () => (await f.submitsTo(reviewerAgent)).length > 0);
  expectEqual((await f.submitsTo(reviewerAgent)).map(call => [option(call.argv, '--task'), inputOf(call.argv)]),
    [[reviewing.reviewTask.taskId, reviewInput(workflows[5].instructions, criteria, good)]],
    '§15.3 the review input of section 15.1 is unchanged; one review task only, for the run whose checks passed');
  await f.remoteEvent(reviewing.reviewTask.taskId, 'succeeded', {output: 'VERDICT: ACCEPT\nFAKE reasons: the total is given.'});
  const accepted = await untilRun(f, agentPass.id, run => run.review === 'accepted', '§15.1 the reviewer agent accepts');
  expectEqual(pick(accepted, 'checks reviewedBy reviewNote'), {checks: checks.map(passed), reviewedBy: 'agent',
    reviewNote: 'FAKE reasons: the total is given.'}, '§15.1 the agent verdict on a result whose checks passed');
  await delay(1000);
  expectEqual([(await f.submitsTo(reviewerAgent)).length, (await f.runById(agentBad.id)).reviewTask], [1, notReserved],
    '§15.3 no review task is reserved for the run rejected by checks, also while its reviewer agent is free');

  // The verdict is final; the snapshot's attention, statistics and failure circuit.
  for (const run of [noneBad, operatorBad, agentBad]) {
    for (const verdict of [{verdict: 'accepted'}, {verdict: 'rejected', note: 'FAKE second verdict'}]) {
      expectError(await f.request('POST', `/api/runs/${run.id}/review`, verdict), 409,
        '§15.3 a rejection by checks is final like any verdict: §15 a run whose review is not pending is 409');
    }
  }
  expectError(await f.request('POST', `/api/runs/${agentBad.id}/review/cancel`, {}), 409,
    '§15.1 review/cancel is 409 without an unresolved review task');
  expectEqual(pick(await f.runById(operatorBad.id), 'review reviewedBy reviewNote'), {review: 'rejected', reviewedBy: 'checks',
    reviewNote: note}, '§15 refused verdicts change nothing');
  const snapshot = await f.snapshot();
  expectEqual(workflows.map(w => snapshot.attention.some(item => item.kind === 'review_pending' && item.subject.id === w.id)),
    [false, false, false, true, false, false, false, false], '§15.3 a run rejected by checks raises no review_pending item; ' +
    '§8 the passing run that waits for the operator does');
  const stats = (runsCount, succeeded, failedCount, awaitingReview) => ({runs: runsCount, succeeded, failed: failedCount,
    awaitingReview, interventions: 0});
  expectEqual(workflows.map(w => pick(snapshot.workflows.find(item => item.id === w.id).stats,
    'runs succeeded failed awaitingReview interventions')), [stats(1, 0, 1, 0), stats(1, 1, 0, 0), stats(1, 0, 1, 0),
    stats(1, 0, 0, 1), stats(1, 0, 1, 0), stats(1, 1, 0, 0), stats(1, 0, 1, 0), stats(1, 1, 0, 0)],
  '§15.3 a rejection by checks counts as a failed result in stats; §8 pending in neither count; verdicts are no interventions');
  for (const run of [noneBad, operatorBad, agentBad]) {
    const w = snapshot.workflows.find(item => item.id === run.workflowId);
    expect(w.failureStreak === 0 && w.enabled && w.pausedBy === null && w.reworkPending === null &&
      Math.abs(Date.parse(w.nextRunAt) - Date.parse(run.finishedAt) - 60 * minute) <= 1000,
    '§15.3 like any verdict, a rejection by checks changes neither the failure count, nor nextRunAt, nor the failure ' +
      'circuit; §15.2 no rework with reworkLimit 0', pick(w, 'failureStreak enabled pausedBy reworkPending nextRunAt'));
  }
  const log = await f.log();
  const reviewEntries = run => log.filter(entry => entry.runId === run.id && (['run.finished', 'run.reviewed',
    'workflow.rework_due'].includes(entry.kind) || entry.kind.startsWith('review.')))
    .map(entry => pick(entry, 'actor kind data')).sort((a, b) => a.kind.localeCompare(b.kind));
  for (const run of [noneBad, operatorBad, agentBad]) {
    expectEqual(reviewEntries(run), [{actor: 'system', kind: 'run.finished', data: {state: 'succeeded'}},
      {actor: 'system', kind: 'run.reviewed', data: byChecks}], '§11 a rejection by checks: run.finished {state:"succeeded"} ' +
      'and a system run.reviewed {verdict:"rejected",by:"checks"}, no review.* entry and no rework_due');
  }
  // The passing operator-reviewed run is decided as before.
  const decided = expectStatus(await f.request('POST', `/api/runs/${operatorPass.id}/review`, {verdict: 'accepted'}), 200,
    '§15 the operator verdict on a run whose checks passed').data;
  expectEqual(pick(decided, 'review reviewedBy checks'), {review: 'accepted', reviewedBy: 'operator', checks: checks.map(passed)},
    '§15 the operator accepts; the checks stay');
  await f.stop();
}

// Case 24, retention. §15.3: a result cut at retention is checked as retained (its first 262,144 characters); its
// branch is null (§10.1), so a branch check fails although the retained output ends with a commit's branch line.
async function case24_resultCutAtRetention() {
  const f = await team('check-retention');
  await f.start();
  await f.ready(f.connectionId);
  const checks = [contains('FAKE-HEAD'), minLength(262144), maxLength(262144), branch, contains('FAKE-TAIL')];
  const workflow = await f.create({instructions: 'FAKE retention assignment', resultChecks: checks, intervalMinutes: 60,
    enabled: true});
  const line = '\n\n' + committedLine;
  const output = 'FAKE-HEAD ' + 'B'.repeat(262144 - 10 - line.length) + line + '\nFAKE-TAIL beyond the retained output';
  const run = await f.finish(await f.newRun(workflow.id, 'queued'), 'succeeded', {output, timeout: 20000});
  const detail = (await f.detail(run.id)).run;
  expectEqual([detail.output.length, detail.outputTruncated, detail.output.endsWith(line), detail.branch], [262144, true, true, null],
    'fixture and §10.1: the retained output ends with a committed branch line, but the remote output was longer');
  const entries = [passed(checks[0]), passed(checks[1]), passed(checks[2]), failed(branch, says.branch),
    failed(checks[4], says.contains('FAKE-TAIL'))];
  for (const [view, where] of [[run, 'snapshot'], [detail, 'detail']]) {
    expectEqual(pick(view, 'checks review reviewedBy reviewNote'), {checks: entries, review: 'rejected', reviewedBy: 'checks',
      reviewNote: says.branch + '\n' + says.contains('FAKE-TAIL')}, `§15.3 a result cut at retention is checked as retained ` +
      `(262,144 characters, without the tail); its branch is null, so a branch check fails (${where})`);
  }
  await f.stop();
}

// Case 25. §15.3: a rework after failed checks has the exact input with FAILED CHECKS, attempt 2 and reworkOf the
// rejected run, and is checked with the checks its workflow had when the rework was reserved.
async function case25_reworkAfterFailedChecks() {
  const f = await team('check-rework');
  await f.start();
  await f.ready(f.connectionId);
  const instructions = 'FAKE rework assignment: report the FAKE-TOTAL line';
  const atFirst = [contains('FAKE-TOTAL'), maxLength(20000)];        // the rejected run's checks
  const atRework = [contains('FAKE-TOTAL'), excludes('FAKE draft')];  // the checks when the rework is reserved
  const later = [contains('FAKE-NEVER')];                              // the checks after that
  const workflow = await f.create({instructions, resultChecks: atFirst, reworkLimit: 1, intervalMinutes: 60, enabled: true});
  const first = await f.newRun(workflow.id, 'queued');
  await f.action(workflow.id, 'pause');
  const draft = 'FAKE draft without the total\u0000 ' + '€'.repeat(25000);
  expectEqual(codePoints(draft.replaceAll('\u0000', '')), 25029, 'fixture: the draft has 25,029 characters without its NUL');
  const note = says.contains('FAKE-TOTAL') + '\n' + says.maxLength(25029, 20000);
  const one = await f.finish(first, 'succeeded', {output: draft, timeout: 20000});
  expectEqual(pick(one, 'checks review reviewedBy reviewNote attempt reworkOf'), {checks: [failed(atFirst[0],
    says.contains('FAKE-TOTAL')), failed(atFirst[1], says.maxLength(25029, 20000))], review: 'rejected', reviewedBy: 'checks',
  reviewNote: note, attempt: 1, reworkOf: null}, '§15.3 both checks fail and the note joins their messages');
  await until('§15.3 a rejection by checks makes a rework due by the rules of §15.2: reworkPending names the rejected run, ' +
    'also while the workflow is paused', async () => (await f.workflow(workflow.id)).reworkPending === one.id);
  await f.patch(workflow.id, {resultChecks: atRework});
  await f.action(workflow.id, 'resume');
  const second = await f.newRun(workflow.id, 'queued');
  expectEqual(pick(second, 'attempt reworkOf checks'), {attempt: 2, reworkOf: one.id, checks: null},
    '§15.2 the rework is attempt 2 and its reworkOf names the rejected run');
  const expected = checksReworkInput(instructions, note, draft);
  expect(expected.endsWith('…') && Buffer.byteLength(expected) <= 65536 && Buffer.byteLength(expected) > 65530 &&
    !expected.includes('\u0000'), 'fixture: the previous result loses its NUL characters and is cut', Buffer.byteLength(expected));
  const [submit] = await f.taskCalls('submit', second.taskId);
  expectEqual(submit && inputOf(submit.argv), expected, '§15.3 the rework input after failed checks: the §15.2 input with ' +
    'the revision request "Your previous result for this assignment failed the result checks below. ..." and the heading ' +
    'FAILED CHECKS before the note; the previous result without NUL characters, cut to fit 65,536 bytes');
  expectEqual(pick((await f.detail(second.id)).run, 'instructions assignment'), {instructions: expected, assignment: instructions},
    '§10 the rework instructions are its exact input; its assignment is the instructions without the revision request');
  await f.patch(workflow.id, {resultChecks: later});
  const reworked = 'FAKE-TOTAL: 12 fake widgets\n' + 'w'.repeat(21000);
  const two = await f.finish(second, 'succeeded', {output: reworked, timeout: 20000});
  expectEqual(pick(two, 'checks review reviewedBy reviewNote'), {checks: atRework.map(passed), review: null, reviewedBy: null,
    reviewNote: null}, '§15.3 the rework is checked with the checks its workflow had when the rework was reserved: not ' +
    'those of the rejected run (21,028 characters fail maxLength 20,000), nor those set later');
  await delay(800);
  const w = await f.workflow(workflow.id);
  expectEqual([w.reworkPending, (await f.submissions()).length, pick(w.stats, 'runs succeeded failed')],
    [null, 2, {runs: 2, succeeded: 1, failed: 1}], '§15.2 no further rework once the result passes; §8 the rejection by ' +
    'checks counts as failed and the rework as a run');
  expectEqual((await f.log()).filter(entry => ['workflow.rework_due', 'run.reviewed'].includes(entry.kind))
    .map(entry => pick(entry, 'actor kind runId data')).sort((a, b) => a.kind.localeCompare(b.kind)),
  [{actor: 'system', kind: 'run.reviewed', runId: one.id, data: byChecks},
    {actor: 'system', kind: 'workflow.rework_due', runId: one.id, data: {attempt: 2}}],
  '§11 the system run.reviewed by checks and workflow.rework_due {attempt:2} for the rejected run, and none for the rework');
  await f.stop();
}

await runCases('checks', [case23_fields, case23_checksAtReservation, case24_eachKind, case24_rejectionBeforeReview,
  case24_resultCutAtRetention, case25_reworkAfterFailedChecks]);
