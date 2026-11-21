#!/usr/bin/env node
// Contract-only black-box suite for docs/managed-contract.md revision 3, section 16, cases 14 and 15:
// wall-clock schedules (section 14, driven by the MANAGED_CLOCK_FILE test clock of section 1) and operator
// review of results (sections 8, 11 and 15). No imports or reads of the managed implementation or its
// database: the documented CLI, HTTP, the explicitly fake Peerspan executable and throwaway state only.
// Expected slot instants are written out by hand from the time zone rules; section numbers (§) refer to
// that contract. Times are compared as instants (§14).
import {checkRun, dayNames, delay, expect, expectEqual, expectError, expectStatus, fixture, isTime, pick, runCases,
  until} from './harness.mjs';

const minute = 60000;
const instant = value => (value === null ? null : typeof value === 'number' ? value : Date.parse(value));
const iso = value => (value === null ? null : new Date(instant(value)).toISOString());
function sameInstant(actual, expected, rule) {
  expectEqual(instant(actual), instant(expected), `${rule} (expected ${iso(expected)}, observed ${actual})`);
}
// A workflow on a schedule: no intervalMinutes (§2: exactly one of the two).
const scheduled = (f, schedule, patch = {}) => f.create({intervalMinutes: undefined, schedule, ...patch});
const edits = async (f, id) => (await f.request('GET', '/api/activity?limit=200')).data.activity
  .filter(entry => entry.kind === 'workflow.edited' && entry.workflowId === id);
const attentionFor = async (f, kind, id) => (await f.snapshot()).attention.find(item => item.kind === kind && item.subject.id === id);

// Case 14, validation and nextRunAt at creation. §2 and §9: the exactly-one rule; §14: validation and
// normalization, the first slot after the request in several zones, a skipped and a repeated local time.
async function case14_validationAndCreation() {
  const f = await fixture('schedule-validation', {clock: '2026-03-04T12:00:00.000Z'});   // a Wednesday
  await f.start();
  const good = {timeZone: 'Europe/London', days: ['mon'], times: ['09:00']};
  const body = patch => ({name: 'FAKE schedule validation', connectionId: f.connectionId, instructions: 'FAKE only',
    maxRunsPerDay: 5, acceptanceMinutes: 5, ...patch});
  const count = async () => (await f.snapshot()).workflows.length;
  const invalid = [['a string', 'FAKE weekly'], ['an array', []], ['null and no interval', null],
    ['an unknown time zone', {...good, timeZone: 'FAKE/Nowhere'}], ['an empty time zone', {...good, timeZone: ''}],
    ['a 65-character time zone', {...good, timeZone: 'Europe/' + 'x'.repeat(58)}], ['a numeric time zone', {...good, timeZone: 0}],
    ['no days', {...good, days: []}], ['a repeated day', {...good, days: ['mon', 'mon']}],
    ['a day spelled out', {...good, days: ['monday']}], ['an upper-case day', {...good, days: ['MON']}],
    ['days as a string', {...good, days: 'mon'}], ['no times', {...good, times: []}],
    ['a one-digit hour', {...good, times: ['9:00']}], ['24:00', {...good, times: ['24:00']}], ['23:60', {...good, times: ['23:60']}],
    ['a time without a colon', {...good, times: ['0900']}], ['a time with seconds', {...good, times: ['09:00:00']}],
    ['a padded time', {...good, times: [' 09:00']}], ['a numeric time', {...good, times: [900]}],
    ['a repeated time', {...good, times: ['09:00', '09:00']}],
    ['25 times', {...good, times: Array.from({length: 25}, (unused, index) => '10:' + String(index).padStart(2, '0'))}],
    ['no timeZone', {days: ['mon'], times: ['09:00']}], ['no days field', {timeZone: 'UTC', times: ['09:00']}],
    ['no times field', {timeZone: 'UTC', days: ['mon']}], ['another field', {...good, everyMinutes: 5}]];
  for (const [what, schedule] of invalid) {
    expectError(await f.request('POST', '/api/workflows', body({schedule})), 400, `§14 POST refuses a schedule that is ${what}`);
  }
  expectError(await f.request('POST', '/api/workflows', body({intervalMinutes: 5, schedule: good})), 400,
    '§2 POST with both intervalMinutes and a schedule');
  expectError(await f.request('POST', '/api/workflows', body({})), 400, '§2 POST with neither intervalMinutes nor a schedule');
  for (const review of ['auto', 'OPERATOR', true]) {
    expectError(await f.request('POST', '/api/workflows', body({intervalMinutes: 5, review})), 400,
      `§15 POST refuses review ${JSON.stringify(review)}`);
  }
  expectEqual(await count(), 0, '§2 refused creations create nothing');

  // Normalization: days in mon..sun order, times ascending, a canonical zone unchanged; review defaults to none.
  const newYork = await scheduled(f, {timeZone: 'America/New_York', days: ['sun', 'wed', 'mon'], times: ['17:45', '08:00', '12:30']});
  expectEqual(pick(newYork, 'intervalMinutes schedule review'), {intervalMinutes: null, review: 'none',
    schedule: {timeZone: 'America/New_York', days: ['mon', 'wed', 'sun'], times: ['08:00', '12:30', '17:45']}},
  '§14 days are returned in mon..sun order and times ascending; §8 intervalMinutes is null; §15 review defaults to none');
  const times = Array.from({length: 24}, (unused, hour) => String(hour).padStart(2, '0') + ':' + String(59 - hour).padStart(2, '0'));
  const everyDay = await scheduled(f, {timeZone: 'UTC', days: [...dayNames].reverse(), times: [...times].reverse()});
  expectEqual(everyDay.schedule, {timeZone: 'UTC', days: dayNames, times},
    '§14 seven days and 24 times are accepted and returned in order');

  // The first slot after the request, at Wednesday 2026-03-04 12:00 UTC (07:00 in New York, 17:30 in Kolkata,
  // 01:00 on Thursday in Auckland).
  const zones = [
    [newYork, '2026-03-04T13:00:00.000Z', 'America/New_York: Wednesday 08:00 EST'],
    [everyDay, '2026-03-04T12:47:00.000Z', 'UTC: the 12:47 of 24 daily times'],
    [await scheduled(f, {timeZone: 'UTC', days: ['wed'], times: ['11:00', '13:30']}), '2026-03-04T13:30:00.000Z', 'UTC: 11:00 has passed'],
    [await scheduled(f, {timeZone: 'Asia/Kolkata', days: ['wed', 'sat'], times: ['17:00', '18:45']}), '2026-03-04T13:15:00.000Z',
      'Asia/Kolkata: Wednesday 18:45 IST'],
    [await scheduled(f, {timeZone: 'Europe/London', days: ['mon'], times: ['08:00']}), '2026-03-09T08:00:00.000Z',
      'Europe/London: next Monday 08:00 GMT'],
    [await scheduled(f, {timeZone: 'Pacific/Auckland', days: ['wed'], times: ['23:30']}), '2026-03-11T10:30:00.000Z',
      'Pacific/Auckland: Wednesday 23:30 there has passed, so next Wednesday 23:30 NZDT']];
  for (const [workflow, expected, why] of zones) sameInstant(workflow.nextRunAt, expected, '§14 nextRunAt at creation is the first slot after the request: ' + why);
  const zoneOf = index => zones[index][0].schedule.timeZone;
  expectEqual([0, 2, 4, 5].map(zoneOf), ['America/New_York', 'UTC', 'Europe/London', 'Pacific/Auckland'],
    '§14 a canonical time zone name is returned unchanged');
  // Assumption: IANA calls Asia/Kolkata canonical, while Node's ICU calls Asia/Calcutta canonical; either is accepted.
  expect(['Asia/Kolkata', 'Asia/Calcutta'].includes(zoneOf(3)), '§14 Asia/Kolkata is returned as a name of that zone', zoneOf(3));

  // PATCH: the exactly-one rule and validation; a refused PATCH changes nothing.
  const route = '/api/workflows/' + newYork.id;
  const kept = await f.workflow(newYork.id);
  for (const [what, patch] of [['both intervalMinutes and schedule', {intervalMinutes: 5, schedule: good}],
    ['schedule null', {schedule: null}], ['an invalid schedule', {schedule: {...good, days: []}}],
    ['intervalMinutes null', {intervalMinutes: null}], ['review null', {review: null}], ['review auto', {review: 'auto'}]]) {
    expectError(await f.request('PATCH', route, patch), 400, `§9 PATCH refuses ${what}`);
  }
  expectEqual(await f.workflow(newYork.id), kept, '§9 a refused PATCH changes nothing');

  // A local time the clocks skip takes place later by the length of the change.
  await f.clockAt('2026-03-08T06:00:00.000Z', 'Sunday 01:00 EST, an hour before New York moves from 02:00 to 03:00');
  const skipped = await scheduled(f, {timeZone: 'America/New_York', days: ['sun'], times: ['02:30']});
  sameInstant(skipped.nextRunAt, '2026-03-08T07:30:00.000Z', '§14 a skipped local time takes place later by the ' +
    'length of the change: 02:30 on the day New York moves from 02:00 to 03:00 is 03:30 EDT');
  await f.clockAt('2026-10-03T14:00:00.000Z', 'Sunday 00:30 on Lord Howe Island, which moves from 02:00 to 02:30');
  const halfHour = await scheduled(f, {timeZone: 'Australia/Lord_Howe', days: ['sun'], times: ['02:15']});
  sameInstant(halfHour.nextRunAt, '2026-10-03T15:45:00.000Z', '§14 a skipped local time takes place later by the ' +
    'length of the change: with a 30-minute change, 02:15 is 02:45 (UTC+11)');
  // A local time that occurs twice takes place at its first occurrence, and only there.
  await f.clockAt('2026-10-25T00:00:00.000Z', 'Sunday 01:00 BST, the day London repeats 01:00 to 02:00');
  const repeated = await scheduled(f, {timeZone: 'Europe/London', days: ['sun'], times: ['01:30']});
  sameInstant(repeated.nextRunAt, '2026-10-25T00:30:00.000Z', '§14 a repeated local time takes place at its first occurrence (01:30 BST)');
  await f.clockAt('2026-11-01T04:00:00.000Z', 'Sunday 00:00 EDT, the day New York repeats 01:00 to 02:00');
  const firstOccurrence = await scheduled(f, {timeZone: 'America/New_York', days: ['sun'], times: ['01:30']});
  sameInstant(firstOccurrence.nextRunAt, '2026-11-01T05:30:00.000Z', '§14 a repeated local time takes place at its first occurrence (01:30 EDT)');
  await f.clockAt('2026-11-01T05:45:00.000Z', 'between the two occurrences of 01:30 in New York');
  const secondOccurrence = await scheduled(f, {timeZone: 'America/New_York', days: ['sun'], times: ['01:30']});
  sameInstant(secondOccurrence.nextRunAt, '2026-11-08T06:30:00.000Z',
    '§14 the second occurrence of a repeated local time is not a slot: the next is a week later (01:30 EST)');

  // PATCH of schedule: a change gives the first slot after the request; an equal schedule changes nothing.
  const recorded = (await edits(f, repeated.id)).length;
  const same = await f.patch(repeated.id, {schedule: {timeZone: 'Europe/London', days: ['sun'], times: ['01:30']}});
  sameInstant(same.nextRunAt, repeated.nextRunAt, '§14 a PATCH whose schedule equals the current one does not change nextRunAt');
  expectEqual((await edits(f, repeated.id)).length, recorded, '§11 a PATCH that changes no value records nothing');
  const moved = await f.patch(repeated.id, {schedule: {timeZone: 'Europe/London', days: ['sun'], times: ['01:45']}});
  sameInstant(moved.nextRunAt, '2026-11-08T01:45:00.000Z',
    '§14 when PATCH changes schedule, nextRunAt is the first slot after the request (01:45 GMT has passed today)');
  const [edit] = await edits(f, repeated.id);
  expect(edit?.data.fields.includes('schedule'), '§11 the schedule edit records workflow.edited naming schedule', edit);
  // Nothing else changes it: paused workflows whose slots passed keep them (they are not made up).
  sameInstant((await f.workflow(zones[2][0].id)).nextRunAt, zones[2][1], '§14 slots that pass while a workflow is paused leave nextRunAt');
  sameInstant((await f.patch(skipped.id, {name: 'FAKE renamed skipped'})).nextRunAt, skipped.nextRunAt,
    '§14 another field edit does not change nextRunAt');
  await f.stop();
}

// Case 14, dispatch. §14: dispatch at a slot, the next slot at least one minute after a completion, missed
// slots run once (controller stopped, workflow paused), pause/resume/edit leaving nextRunAt, run setting it
// to now, and switching between interval and schedule by PATCH (§9).
async function case14_dispatchAtSlots() {
  const f = await fixture('schedule-dispatch', {clock: '2026-06-01T04:28:00.000Z'});   // 09:58 in Kolkata, a Monday
  await f.start();
  await f.code(f.connectionId, 'ready', 'the worker is ready before scheduling');
  // Kolkata has no daylight-saving time: 10:00, 10:01 and 10:03 IST are 04:30, 04:31 and 04:33 UTC every day.
  const slots = [1, 2, 3, 4, 5, 6].flatMap(day => ['04:30', '04:31', '04:33'].map(time =>
    Date.parse(`2026-06-0${day}T${time}:00.000Z`)));
  const firstSlotAtLeast = from => slots.find(slot => slot >= from);
  const workflow = await scheduled(f, {timeZone: 'Asia/Kolkata', days: dayNames, times: ['10:03', '10:00', '10:01']}, {enabled: true});
  const submitted = async () => (await f.submissions()).length;
  const nextRunAt = async () => (await f.workflow(workflow.id)).nextRunAt;
  sameInstant(workflow.nextRunAt, slots[0], '§14 nextRunAt at creation is the first slot after the request');
  await delay(1200);
  expectEqual(await submitted(), 0, '§14 a scheduled workflow is not dispatched before its slot');

  await f.clockAt(slots[0] + 2000, 'the 10:00 IST slot has passed');
  const first = await f.newRun(workflow.id, 'queued');
  expect(Date.parse(first.createdAt) >= slots[0], '§14 the workflow is dispatched at its slot', first.createdAt);
  const one = await f.finish(first, 'succeeded');
  const expected = firstSlotAtLeast(Date.parse(one.finishedAt) + minute);
  expectEqual(iso(expected), '2026-06-01T04:33:00.000Z', 'fixture timing: the run finished within a minute of its slot');
  sameInstant(await nextRunAt(), expected, '§14 after a run becomes terminal, nextRunAt is the first slot at least one ' +
    'minute after its finishedAt: 10:01 is less than a minute away, so 10:03');
  await delay(1200);
  expectEqual(await submitted(), 1, '§14 no run before that slot');

  // Missed slots while the controller is stopped: eight slots pass, one run follows.
  await f.stop();
  await f.setClock('2026-06-03T05:00:00.000Z');
  await f.start();
  const second = await f.newRun(workflow.id, 'queued');
  const two = await f.finish(second, 'succeeded');
  sameInstant(await nextRunAt(), firstSlotAtLeast(Date.parse(two.finishedAt) + minute),
    '§14 slots missed while the controller was stopped are not made up one by one: one run, then the next slot after it');
  sameInstant(await nextRunAt(), '2026-06-04T04:30:00.000Z', '§14 the next slot after the catch-up run is tomorrow 10:00 IST');
  await delay(1200);
  expectEqual(await submitted(), 2, '§14 missed slots run once');

  // Missed slots while paused: pause and resume leave nextRunAt; the due workflow runs once on resume.
  sameInstant((await f.action(workflow.id, 'pause')).nextRunAt, '2026-06-04T04:30:00.000Z', '§14 pause does not change nextRunAt');
  await f.clockAt('2026-06-05T06:00:00.000Z', 'four slots pass while the workflow is paused');
  expectEqual(await submitted(), 2, '§4 a paused workflow is not dispatched');
  sameInstant((await f.action(workflow.id, 'resume')).nextRunAt, '2026-06-04T04:30:00.000Z', '§14 resume does not change nextRunAt');
  const third = await f.newRun(workflow.id, 'queued');
  const three = await f.finish(third, 'succeeded');
  sameInstant(await nextRunAt(), '2026-06-06T04:30:00.000Z', '§14 slots missed while paused are not made up one by one');
  await delay(1200);
  expectEqual(await submitted(), 3, '§14 the paused-over slots ran once');
  sameInstant((await f.patch(workflow.id, {name: 'FAKE renamed schedule'})).nextRunAt, '2026-06-06T04:30:00.000Z',
    '§14 another field edit does not change nextRunAt');

  // Switching to an interval and back by PATCH.
  const toInterval = await f.patch(workflow.id, {intervalMinutes: 45});
  expectEqual(pick(toInterval, 'intervalMinutes schedule'), {intervalMinutes: 45, schedule: null},
    '§9 setting intervalMinutes on a scheduled workflow switches it to that interval');
  sameInstant(toInterval.nextRunAt, Date.parse(three.finishedAt) + 45 * minute,
    '§9 switching to an interval sets nextRunAt to the latest terminal run finishedAt plus the new interval');
  const evening = {timeZone: 'UTC', days: dayNames, times: ['23:00']};
  const toSchedule = await f.patch(workflow.id, {schedule: evening});
  expectEqual(pick(toSchedule, 'intervalMinutes schedule'), {intervalMinutes: null, schedule: evening},
    '§9 setting schedule switches the workflow to the schedule');
  sameInstant(toSchedule.nextRunAt, '2026-06-05T23:00:00.000Z', '§14 when PATCH changes schedule, nextRunAt is the first slot after the request');
  const recorded = await edits(f, workflow.id);
  expect(recorded.some(entry => entry.data.fields.includes('intervalMinutes')) && recorded[0].data.fields.includes('schedule'),
    '§11 the switching edits record workflow.edited naming the changed field', recorded.map(entry => entry.data));
  sameInstant((await f.patch(workflow.id, {schedule: {...evening, days: [...dayNames]}})).nextRunAt, toSchedule.nextRunAt,
    '§14 a PATCH whose schedule equals the current one changes nothing');
  expectEqual((await edits(f, workflow.id)).length, recorded.length, '§11 a PATCH that changes no value records nothing');

  // run: nextRunAt is now; the next slot follows that run.
  const requested = await f.action(workflow.id, 'run');
  expect(Math.abs(Date.parse(requested.nextRunAt) - f.now()) < 3000, '§14 after run nextRunAt is now (the controller clock)',
    {nextRunAt: requested.nextRunAt, controllerNow: iso(f.now())});
  const four = await f.finish(await f.newRun(workflow.id, 'queued'), 'succeeded');
  sameInstant(await nextRunAt(), '2026-06-05T23:00:00.000Z', '§14 after the requested run, the first slot at least a minute after it');
  expect(Date.parse(four.finishedAt) < Date.parse('2026-06-05T23:00:00.000Z'), 'fixture timing', four.finishedAt);
  await f.stop();
}

// Case 14, daily cap. §14: the daily cap counts the UTC day, not the schedule's local day (§4).
async function case14_dailyCapOnUtcDay() {
  const f = await fixture('schedule-daily-cap', {clock: '2026-12-07T22:58:00.000Z'});   // Monday 17:58 EST
  await f.start();
  await f.code(f.connectionId, 'ready', 'the worker is ready before scheduling');
  const workflow = await scheduled(f, {timeZone: 'America/New_York', days: dayNames, times: ['18:00', '20:00']},
    {enabled: true, maxRunsPerDay: 1});
  const nextRunAt = async () => (await f.workflow(workflow.id)).nextRunAt;
  sameInstant(workflow.nextRunAt, '2026-12-07T23:00:00.000Z', '§14 nextRunAt at creation: Monday 18:00 EST');
  await f.clockAt('2026-12-07T23:00:02.000Z', 'Monday 18:00 in New York, Monday in UTC');
  await f.finish(await f.newRun(workflow.id, 'queued'), 'succeeded');
  sameInstant(await nextRunAt(), '2026-12-08T01:00:00.000Z', '§14 the next slot is Monday 20:00 EST');
  await f.clockAt('2026-12-08T01:00:02.000Z', 'Monday 20:00 in New York, already Tuesday in UTC');
  const second = await f.newRun(workflow.id, 'queued');
  expect(second, '§14 the daily cap counts the UTC day: a second run on one local day is the first of a new UTC day');
  await f.finish(second, 'succeeded');
  sameInstant(await nextRunAt(), '2026-12-08T23:00:00.000Z', '§14 the next slot is Tuesday 18:00 EST');
  await f.clockAt('2026-12-08T23:00:02.000Z', 'Tuesday 18:00 in New York, still Tuesday in UTC');
  const limit = await until('§8 daily_limit_reached appears while the cap of one is used up for the UTC day',
    () => attentionFor(f, 'daily_limit_reached', workflow.id));
  const blocked = await f.workflow(workflow.id);
  expect(limit.severity === 'info' && blocked.blockedReason && (await f.submissions()).length === 2,
    '§14 a slot on a new local day is blocked when the UTC day already has its one run', {limit, blocked: pick(blocked, 'blockedReason nextRunAt')});
  sameInstant(blocked.nextRunAt, '2026-12-08T23:00:00.000Z', '§14 a cap-blocked slot leaves nextRunAt');
  await f.clockAt('2026-12-09T00:00:02.000Z', 'Wednesday begins in UTC (Tuesday 19:00 in New York)');
  const third = await f.newRun(workflow.id, 'queued');
  expect(Date.parse(third.createdAt) >= Date.parse('2026-12-09T00:00:00.000Z'), '§14 the due workflow runs once the UTC day changes', third);
  await f.finish(third, 'succeeded');
  sameInstant(await nextRunAt(), '2026-12-09T01:00:00.000Z', '§14 then the next slot: Tuesday 20:00 EST');
  await f.stop();
}

// Case 15. §15: review of a succeeded run, the verdict route, the stored note and the review_pending item;
// §8 statistics; §11 run.reviewed; §4: a verdict never changes the failure count, nextRunAt or dispatch.
async function case15_review() {
  const f = await fixture('review', {clock: '2026-07-01T09:00:00.000Z'});
  await f.start();
  await f.code(f.connectionId, 'ready', 'the worker is ready');
  const workflow = await f.create({review: 'operator', enabled: true});
  expectEqual(pick(workflow, 'review schedule intervalMinutes'), {review: 'operator', schedule: null, intervalMinutes: 1},
    '§15 a workflow created with review operator');
  const route = run => `/api/runs/${run.id}/review`;
  const current = () => f.workflow(workflow.id);
  // The interval is one minute: moving the clock two minutes on makes the workflow due, with no operator request.
  const nextRun = async why => { await f.clockAt(f.now() + 2 * minute, why); return f.newRun(workflow.id, 'queued'); };
  const verdict = async (run, payload, rule) => {
    const response = expectStatus(await f.request('POST', route(run), payload), 200, rule).data;
    checkRun(response);
    return response;
  };

  const first = await f.newRun(workflow.id, 'queued');
  expectEqual(first.review, null, '§15 review is null while a run is unresolved');
  expectError(await f.request('POST', route(first), {verdict: 'accepted'}), 409, '§15 a verdict on an unresolved run is 409');
  const one = await f.finish(first, 'succeeded', {output: 'FAKE report awaiting review'});
  expectEqual(pick(one, 'state review reviewedAt reviewNote'), {state: 'succeeded', review: 'pending', reviewedAt: null,
    reviewNote: null}, '§15 a succeeded run of a reviewed workflow waits for the verdict');
  let w = await current();
  expectEqual(pick(w.stats, 'runs succeeded failed successRate averageSeconds awaitingReview'), {runs: 1, succeeded: 0,
    failed: 0, successRate: null, averageSeconds: null, awaitingReview: 1}, '§8 a pending run is in neither count; awaitingReview counts it');
  expect(w.recent[0]?.review === 'pending' && Date.parse(w.nextRunAt) >= Date.parse(one.finishedAt) + 59000,
    '§8 recent carries the review; §15 a pending review leaves the interval schedule', pick(w, 'recent nextRunAt'));
  const pendingItem = await attentionFor(f, 'review_pending', workflow.id);
  expect(pendingItem?.severity === 'action' && Date.parse(pendingItem.since) === Date.parse(one.finishedAt),
    '§8 review_pending is an action item since the pending run finishedAt', pendingItem);

  // Dispatch is not held back by a pending review; a failed run of a reviewed workflow needs no review.
  const second = await nextRun('the interval passes while the first result awaits review');
  const two = await f.finish(second, 'failed', {output: 'FAKE failed report'});
  expectEqual(two.review, null, '§15 a failed run of a reviewed workflow has review null');

  // The verdict route: 404, 400 and 409.
  expectError(await f.request('POST', '/api/runs/FAKE-absent/review', {verdict: 'accepted'}), 404, '§15 a verdict on an unknown run');
  const invalid = [{}, {verdict: 'maybe'}, {verdict: 'ACCEPTED'}, {verdict: null}, {verdict: true}, {note: 'FAKE note only'},
    {verdict: 'accepted', note: 7}, {verdict: 'accepted', note: null}, {verdict: 'accepted', note: 'x'.repeat(2001)},
    {verdict: 'accepted', extra: true}, [], 'accepted'];
  for (const payload of invalid) {
    expectError(await f.request('POST', route(first), payload), 400, '§15 the verdict route refuses ' + JSON.stringify(payload).slice(0, 50));
  }
  expectError(await f.request('POST', route(second), {verdict: 'accepted'}), 409, '§15 a verdict on a run whose review is null is 409');
  expectEqual((await f.runById(first.id)).review, 'pending', '§15 refused verdicts change nothing');

  // A rejection: the stored note is trimmed; the run state, failure count and nextRunAt are untouched.
  const before = await current();
  const rejected = await verdict(first, {verdict: 'rejected', note: '  FAKE rejected: totals missing \n'}, '§15 a rejection');
  expect(rejected.id === first.id && rejected.state === 'succeeded' && rejected.review === 'rejected' &&
    rejected.reviewNote === 'FAKE rejected: totals missing' && isTime(rejected.reviewedAt) && rejected.output === one.output,
  '§15 the response is the run, still succeeded, with review rejected, the trimmed note and reviewedAt', rejected);
  for (const payload of [{verdict: 'accepted'}, {verdict: 'rejected'}]) {
    expectError(await f.request('POST', route(first), payload), 409, '§15 a verdict is final: ' + payload.verdict + ' again');
  }
  w = await current();
  expectEqual(pick(w.stats, 'succeeded failed successRate awaitingReview interventions unattendedRuns'), {succeeded: 0,
    failed: 2, successRate: 0, awaitingReview: 0, interventions: before.stats.interventions, unattendedRuns: before.stats.unattendedRuns},
  '§8 a rejected run counts as failed; verdicts are not interventions and leave unattendedRuns');
  expectEqual(pick(w, 'failureStreak nextRunAt enabled'), pick(before, 'failureStreak nextRunAt enabled'),
    '§15 a verdict never changes the failure count, nextRunAt or dispatch');
  expectEqual(pick((await f.detail(first.id)).run, 'state review reviewedAt reviewNote'),
    pick(rejected, 'state review reviewedAt reviewNote'), '§10 the run detail has the verdict');
  expect(!(await attentionFor(f, 'review_pending', workflow.id)), '§8 review_pending clears when no run is pending');

  // Two pending runs; accepted verdicts with an empty and a 2,000-character note.
  const three = await f.finish(await nextRun('the next interval'), 'succeeded');
  const four = await f.finish(await nextRun('the next interval, with a result still pending'), 'succeeded');
  w = await current();
  const twoPending = await attentionFor(f, 'review_pending', workflow.id);
  expect(w.stats.awaitingReview === 2 && Date.parse(twoPending?.since) === Date.parse(three.finishedAt) &&
    /(^|\D)2(\D|$)|\btwo\b/i.test(twoPending.message), '§8 awaitingReview 2; one review_pending item giving the number, ' +
    'since the earliest pending finishedAt', {stats: w.stats, item: twoPending});
  expectEqual((await verdict(four, {verdict: 'accepted', note: '   \n '}, '§15 an acceptance with a blank note')).reviewNote, null,
    '§15 an empty trimmed note is stored as null');
  const long = 'FAKE ' + 'n'.repeat(1995);
  expectEqual((await verdict(three, {verdict: 'accepted', note: long}, '§15 an acceptance with a 2,000-character note')).reviewNote,
    long, '§15 a note of 2,000 characters is stored');
  w = await current();
  const durations = [three, four].map(run => (Date.parse(run.finishedAt) - Date.parse(run.createdAt)) / 1000);
  expect(w.stats.succeeded === 2 && w.stats.failed === 2 && w.stats.successRate === 0.5 && w.stats.awaitingReview === 0 &&
    Math.abs(w.stats.averageSeconds - (durations[0] + durations[1]) / 2) <= 1 && w.stats.interventions === before.stats.interventions,
  '§8 accepted runs count as succeeded, with averageSeconds over them; verdicts are not interventions', {stats: w.stats, durations});
  const log = (await f.request('GET', '/api/activity?limit=200')).data.activity.filter(entry => entry.kind === 'run.reviewed');
  const byRun = (a, b) => a.runId.localeCompare(b.runId);
  expectEqual(log.map(entry => pick(entry, 'actor runId workflowId data')).sort(byRun),
    [[first, 'rejected'], [three, 'accepted'], [four, 'accepted']].map(([run, value]) => ({actor: 'operator', runId: run.id,
      workflowId: workflow.id, data: {verdict: value}})).sort(byRun),
    '§11 each verdict records run.reviewed {verdict}; a refused verdict records nothing');

  // An archived workflow with a pending run keeps its review_pending item until the verdict.
  const five = await f.finish(await nextRun('a last interval'), 'succeeded');
  expectStatus(await f.request('POST', `/api/workflows/${workflow.id}/archive`, {}), 200, '§9 archive');
  const archivedItem = await attentionFor(f, 'review_pending', workflow.id);
  expectEqual(archivedItem && pick(archivedItem, 'severity subject'), {severity: 'action',
    subject: {type: 'workflow', id: workflow.id, name: workflow.name}}, '§8 review_pending stays for an archived workflow');
  await verdict(five, {verdict: 'accepted'}, '§15 a verdict on a run of an archived workflow');
  expect(!(await attentionFor(f, 'review_pending', workflow.id)), '§8 review_pending clears after the last verdict');
  await f.stop();
}

// Case 15, reservation. §15 and §9: a run keeps the review requirement its workflow had when it was reserved.
async function case15_reviewRequirementAtReservation() {
  const f = await fixture('review-reservation', {clock: '2026-07-01T09:00:00.000Z'});
  await f.start();
  await f.code(f.connectionId, 'ready', 'the worker is ready');
  const workflow = await f.create({enabled: true});
  expectEqual(workflow.review, 'none', '§15 review defaults to none');
  const nextRun = async why => { await f.clockAt(f.now() + 2 * minute, why); return f.newRun(workflow.id, 'queued'); };
  const a = await f.newRun(workflow.id, 'queued');
  const before = await f.workflow(workflow.id);
  const toOperator = await f.patch(workflow.id, {review: 'operator'});
  expectEqual([toOperator.review, toOperator.nextRunAt], ['operator', before.nextRunAt],
    '§9 PATCH returns the new review; §14 another field edit leaves nextRunAt');
  expectEqual((await f.finish(a, 'succeeded')).review, null,
    '§15 a run reserved before review became operator keeps its requirement: no review');
  const b = await nextRun('the interval passes');
  await f.patch(workflow.id, {review: 'none'});
  expectEqual((await f.finish(b, 'succeeded')).review, 'pending',
    '§15 a run reserved while review was operator still needs review after a PATCH to none');
  const c = await nextRun('the interval passes again');
  expectEqual((await f.finish(c, 'succeeded')).review, null, '§15 a run reserved after the PATCH to none needs no review');
  expectEqual(pick((await f.workflow(workflow.id)).stats, 'runs succeeded failed awaitingReview'),
    {runs: 3, succeeded: 2, failed: 0, awaitingReview: 1}, '§8 statistics by each run requirement');
  expectEqual((await edits(f, workflow.id)).map(entry => entry.data), [{fields: ['review']}, {fields: ['review']}],
    '§11 each review change records workflow.edited {fields:["review"]}');
  await f.stop();
}

await runCases('schedules', [case14_validationAndCreation, case14_dispatchAtSlots, case14_dailyCapOnUtcDay, case15_review,
  case15_reviewRequirementAtReservation]);
