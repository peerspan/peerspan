#!/usr/bin/env node
// Contract-only black-box suite for docs/managed-contract.md revision 6, section 16, cases 20 and 21: the capacity
// of a worker agent (sections 3.1, 4 and 8; decision MGD-14) and scheduler passes that never wait for a slow
// Peerspan call (section 4; decision MGD-15); and revision 7.1, case 22: a ready verdict from one moment (section 3;
// decision MGD-16). No imports or reads of the managed implementation or its database: the documented CLI, HTTP,
// the explicitly fake Peerspan executable and throwaway state only. The fake plays runtime agents (README:
// `profiles`, `runtimeShow`), makes single calls hang (`hangWhen`) and makes calls slow (`delayWhen`). Section
// numbers (§) refer to that contract.
import path from 'node:path';
import {delay, expect, expectEqual, fixture, hex, ids, option, pick, runCases, snippet, until, writeJson} from './harness.mjs';

const runtimeAgent = {agentId: hex('agent', 5), sessionId: hex('session', 5), adapterId: hex('adapter', 5)};
const sessionAgent = {agentId: hex('agent', 6), sessionId: hex('session', 6), adapterId: hex('adapter', 6)};
const unresolved = ['submitting', 'queued', 'running'];
const monotonicNow = () => Number(process.hrtime.bigint() / 1000000n);   // the clock of the fake's `mono`
const verified = sessionId => ({session_id: sessionId, state: 'ready', channel: 'verified',
  channel_verified_at: '2026-01-01T00:00:00Z'});
const disabledRuntime = {enabled: false, socket: null, runtime: null, rule: 'FAKE rule'};

// A fixture whose fake worker host has the file-mode worker (ids), a runtime agent with a launch profile (and a
// session, so that a file-mode connection to it follows that session, §3.1) and a session agent. Each
// agent-mode connection gets its own worker host state directory, so a hang can target one connection.
async function capacityFixture(label, {connect = false, maxRuns = 3} = {}) {
  const f = await fixture(label, {connect});
  const R = runtimeAgent.agentId;
  f.profile = (patch = {}) => ({agent_id: R, harness: 'codex', harness_dir: path.join(f.dir, 'PRIVATE-harness'),
    from_branch: 'fake-main', network: 'FAKE-none', cpus: 2, memory_mib: 2048, timeout_seconds: 900, max_runs: maxRuns,
    credential: true, ...patch});
  const sessions = agent => [{id: agent.sessionId, adapter_id: agent.adapterId, connection: 'ready'}];
  await f.configure({agents: [{id: ids.agentId, name: 'FAKE-CONFORMANCE file worker', sessions: sessions(ids)},
    {id: R, name: 'FAKE-CONFORMANCE runtime agent', sessions: sessions(runtimeAgent)},
    {id: sessionAgent.agentId, name: 'FAKE-CONFORMANCE session agent', sessions: sessions(sessionAgent)}],
  adapters: Object.fromEntries([ids, runtimeAgent, sessionAgent].map(agent => [agent.adapterId, verified(agent.sessionId)])),
  profiles: [f.profile()], statusExit: 0, attention: [], hang: [], hangWhen: []});
  f.connectAgent = async (agent, name, hostDir = path.join(f.dir, 'PRIVATE-host-' + agent.agentId.slice(-4))) =>
    JSON.parse(await f.checkedCli('connect', '--name', name, '--agent', agent.agentId, '--host-state', hostDir,
      '--sender-state', f.senderDir)).id;
  f.connectFile = async (agent, name) => {
    const file = path.join(f.dir, 'PRIVATE-worker-' + agent.agentId.slice(-4) + '.json');
    await writeJson(file, {host_dir: path.join(f.dir, 'PRIVATE-file-host'), host_id: ids.hostId, agent_id: agent.agentId,
      adapter_id: agent.adapterId, session_id: agent.sessionId});
    return JSON.parse(await f.checkedCli('connect', '--name', name, '--worker-state', file, '--sender-state', f.senderDir)).id;
  };
  f.connection = async id => (await f.snapshot()).connections.find(item => item.id === id);
  f.open = async (workflows = null) => (await f.snapshot()).runs.filter(run => unresolved.includes(run.state) &&
    (workflows === null || workflows.some(w => w.id === run.workflowId)));
  f.workflowsOn = (connectionId, names) => Promise.all(names.map(name => f.create({name: 'FAKE capacity ' + name,
    connectionId, instructions: 'FAKE capacity assignment ' + name, intervalMinutes: 60, enabled: true})));
  return f;
}
// Waits until exactly `count` runs of `workflows` are unresolved, then checks that no more follow.
async function holding(f, workflows, count, why, settle = 800) {
  let last = [];
  await until(() => `${why}: ${count} unresolved run(s) expected, ${last.length} seen`, async () =>
    (last = await f.open(workflows)).length >= count, 8000);
  await delay(settle);
  const held = await f.open(workflows);
  expectEqual(held.length, count, why);
  return held;
}
const capacityOf = async (f, id, why, expected) => {
  let last;
  return until(() => `${why}: capacity ${expected} expected, last ${snippet(last && pick(last, 'capacity activeTasks readiness'))}`,
    async () => { last = await f.connection(id); return last?.capacity === expected && last; });
};

// Case 20, a runtime agent's capacity. §4: a ready_runtime agent with maxRuns 3 holds three runs of three
// workflows at once while a fourth waits; a capacity that falls below the tasks held leaves them unresolved and
// dispatches nothing until fewer are held; one run per workflow whatever the capacity; a runtime agent that is
// not ready has capacity 1; §8 capacity and activeTasks.
async function case20_runtimeCapacity() {
  const f = await capacityFixture('capacity-runtime');
  const runtime = await f.connectAgent(runtimeAgent, 'FAKE-CONFORMANCE runtime agent');
  await f.start();
  await f.code(runtime, 'ready_runtime', 'the runtime agent is ready');
  expectEqual(pick(await f.connection(runtime), 'capacity activeTasks'), {capacity: 3, activeTasks: 0},
    '§8 capacity is the runtime.maxRuns of a ready_runtime agent; activeTasks is 0 while it holds nothing');
  const workflows = await f.workflowsOn(runtime, ['A', 'B', 'C', 'D']);
  const held = await holding(f, workflows, 3, '§4 a ready_runtime agent with maxRuns 3 holds three runs, and a fourth ' +
    'workflow waits until one ends');
  expectEqual(new Set(held.map(run => run.workflowId)).size, 3, '§4 the three runs are of three workflows');
  expectEqual(pick(await f.connection(runtime), 'capacity activeTasks'), {capacity: 3, activeTasks: 3}, '§8 activeTasks 3');
  const waiting = workflows.find(w => !held.some(run => run.workflowId === w.id));
  await f.finish(held[0], 'succeeded');
  const fourth = await f.newRun(waiting.id, 'queued', 6000);
  const three = await holding(f, workflows, 3, '§4 the fourth workflow is dispatched once a run ends', 300);

  // The capacity falls below the tasks held: they stay unresolved, and nothing is dispatched until fewer are held.
  const first = workflows.find(w => w.id === held[0].workflowId);
  await f.configure({profiles: [f.profile({max_runs: 1})]});
  expectEqual((await capacityOf(f, runtime, '§8 capacity follows the profile', 1)).activeTasks, 3,
    '§4 the tasks a target holds are not affected when its capacity falls');
  await f.action(first.id, 'run');
  for (const [index, run] of three.entries()) {
    await f.finish(run, 'succeeded');
    if (index < 2) {
      await holding(f, workflows, 2 - index, '§4 no new task while the agent holds as many as its capacity or more', 600);
    }
  }
  const later = await f.newRun(first.id, 'queued', 6000);
  expectEqual((await f.taskCalls('cancel')).length, 0, '§4 tasks held when the capacity falls finish as before, uncancelled');
  expect(three.some(run => run.id === fourth.id), 'fixture: the fourth run was among those held', three);

  // One unresolved run per workflow, whatever the capacity.
  await f.configure({profiles: [f.profile()]});
  await capacityOf(f, runtime, '§8 capacity 3 again', 3);
  await f.action(first.id, 'run');
  await holding(f, workflows, 1, '§4 one unresolved run per workflow stays the rule whatever the capacity');
  // A runtime agent that is not ready has capacity 1; the task it holds goes on.
  await f.configure({runtimeShow: disabledRuntime});
  await f.code(runtime, 'runtime_disabled', 'the runtime switch is off');
  expectEqual(pick(await f.connection(runtime), 'capacity activeTasks'), {capacity: 1, activeTasks: 1},
    '§4 a runtime agent that is not ready has capacity 1; the task it holds is not affected');
  await f.finish(later, 'succeeded');
  expectEqual((await f.connection(runtime)).activeTasks, 0, '§8 activeTasks 0 once the task ends');
  await f.stop();
}

// Case 20, review tasks. §4: review tasks count against a reviewer's capacity, together with runs.
async function case20_reviewerCapacity() {
  const f = await capacityFixture('capacity-reviewer', {connect: true, maxRuns: 2});
  const reviewer = await f.connectAgent(runtimeAgent, 'FAKE-CONFORMANCE runtime reviewer');
  await f.start();
  await f.code(f.connectionId, 'ready', 'the worker is ready');
  await f.code(reviewer, 'ready_runtime', 'the runtime reviewer is ready');
  const reviewed = await f.create({review: 'agent', reviewerId: reviewer, intervalMinutes: 60, enabled: true});
  const one = await f.finish(await f.newRun(reviewed.id, 'queued'), 'succeeded', {output: 'FAKE result one'});
  await f.action(reviewed.id, 'run');
  const two = await f.finish(await f.newRun(reviewed.id, 'queued'), 'succeeded', {output: 'FAKE result two'});
  const tasks = await until('§4 a reviewer with capacity 2 holds both review tasks at once', async () => {
    const runs = (await f.snapshot()).runs.filter(run => [one.id, two.id].includes(run.id));
    return runs.length === 2 && runs.every(run => unresolved.includes(run.reviewTask?.state)) && runs;
  });
  expectEqual(pick(await f.connection(reviewer), 'capacity activeTasks'), {capacity: 2, activeTasks: 2},
    '§8 the reviewer holds two review tasks');
  const onReviewer = await f.create({name: 'FAKE run on the runtime reviewer', connectionId: reviewer,
    instructions: 'FAKE assignment of the runtime reviewer', intervalMinutes: 60, enabled: true});
  await holding(f, [onReviewer], 0, '§4 review tasks count against the reviewer capacity: a run waits while it holds two');
  await f.remoteEvent(tasks[0].reviewTask.taskId, 'succeeded', {output: 'VERDICT: ACCEPT'});
  await f.newRun(onReviewer.id, 'queued', 6000);
  expectEqual((await f.connection(reviewer)).activeTasks, 2, '§8 activeTasks counts runs and review tasks together');
  await f.stop();
}

// Case 20, capacity 1. §4: an agent that is not a runtime agent, a maxRuns of null, 0, 65 or a string, and a
// runtime agent that is not ready all hold one task; maxRuns 64 is a capacity of 64.
async function case20_capacityOfOne() {
  const f = await capacityFixture('capacity-one', {maxRuns: null});
  const runtime = await f.connectAgent(runtimeAgent, 'FAKE-CONFORMANCE runtime agent');
  const session = await f.connectAgent(sessionAgent, 'FAKE-CONFORMANCE session agent');
  await f.start();
  await f.code(runtime, 'ready_runtime', 'the runtime agent is ready');
  await f.code(session, 'ready', 'the session agent is ready');
  const oneAtATime = async (pair, why) => {
    const [held] = await holding(f, pair, 1, `§4 ${why} holds one task at a time`);
    await f.finish(held, 'succeeded');
    const [next] = await holding(f, pair, 1, `§4 ${why}: the other workflow follows`, 300);
    expect(next.id !== held.id, 'fixture: the second run is the other workflow', next);
    await f.finish(next, 'succeeded');
  };
  const sessionPair = await f.workflowsOn(session, ['S1', 'S2']);
  expectEqual((await f.connection(session)).capacity, 1, '§8 an agent that is not a runtime agent has capacity 1');
  await oneAtATime(sessionPair, 'an agent that is not a runtime agent');
  const runtimePair = await f.workflowsOn(runtime, ['R1', 'R2']);
  for (const [value, why] of [[null, 'maxRuns null'], [0, 'maxRuns 0'], [65, 'maxRuns 65'], ['3', 'maxRuns given as a string']]) {
    await f.configure({profiles: [f.profile({max_runs: value})]});
    await until(`§3.1 runtime.maxRuns follows the profile (${why})`, async () =>
      (await f.connection(runtime)).readiness.runtime?.maxRuns === value);
    expectEqual((await f.connection(runtime)).capacity, 1, `§4 a runtime agent with ${why} has capacity 1`);
    if (value !== null) for (const w of runtimePair) await f.action(w.id, 'run');
    await oneAtATime(runtimePair, 'a runtime agent with ' + why);
  }
  await f.configure({profiles: [f.profile({max_runs: 64})]});
  await capacityOf(f, runtime, '§4 maxRuns 64 is a capacity of 64', 64);
  for (const w of runtimePair) await f.action(w.id, 'run');
  await holding(f, runtimePair, 2, '§4 with maxRuns 64 both workflows run at once');
  await f.configure({profiles: [f.profile({max_runs: 64, credential: false})]});
  await f.code(runtime, 'runtime_credential_missing', 'the profile loses its credential');
  expectEqual(pick(await f.connection(runtime), 'capacity activeTasks'), {capacity: 1, activeTasks: 2},
    '§4 a runtime agent that is not ready has capacity 1, whatever its maxRuns');
  await f.stop();
}

// Case 20, two connections to one agent. §4: the capacity is the largest any connection to the agent reports
// while it is ready; §8 each connection shows its own capacity and the agent's activeTasks.
async function case20_twoConnections() {
  const f = await capacityFixture('capacity-two-connections');
  const agentMode = await f.connectAgent(runtimeAgent, 'FAKE-CONFORMANCE runtime agent, agent mode');
  const fileMode = await f.connectFile(runtimeAgent, 'FAKE-CONFORMANCE runtime agent, file mode');
  await f.start();
  await f.code(agentMode, 'ready_runtime', 'agent mode reads the launch profile');
  await f.code(fileMode, 'ready', 'file mode follows its worker state file (§3.1)');
  const viaFile = await f.workflowsOn(fileMode, ['F1', 'F2']);
  const viaAgent = await f.workflowsOn(agentMode, ['A1']);
  const held = await holding(f, [...viaFile, ...viaAgent], 3, '§4 the capacity of an agent named by two connections is ' +
    'the largest one reports while ready: workflows on the file-mode connection (capacity 1) run beside one on the agent-mode one');
  const snapshot = await f.snapshot();
  expectEqual([agentMode, fileMode].map(id => pick(snapshot.connections.find(item => item.id === id), 'capacity activeTasks')),
    [{capacity: 3, activeTasks: 3}, {capacity: 1, activeTasks: 3}],
  '§8 capacity is what each connection readiness gives; activeTasks is what the worker agent holds');
  // The agent-mode connection is no longer ready: the capacity is the file-mode connection's 1.
  await f.configure({runtimeShow: disabledRuntime});
  await f.code(agentMode, 'runtime_disabled', 'the runtime switch is off');
  const [f1] = held.filter(run => run.workflowId === viaFile[0].id);
  const rest = held.filter(run => run.id !== f1.id);
  await f.finish(f1, 'succeeded');
  await f.action(viaFile[0].id, 'run');
  await holding(f, [...viaFile, ...viaAgent], 2, '§4 only ready connections give capacity: with two tasks held, the ' +
    'file-mode connection (capacity 1) dispatches nothing', 600);
  await f.finish(rest[0], 'succeeded');
  await holding(f, [...viaFile, ...viaAgent], 1, '§4 nothing is dispatched while the agent holds its capacity', 600);
  await f.finish(rest[1], 'succeeded');
  await f.newRun(viaFile[0].id, 'queued', 6000);
  await f.stop();
}

// ---- Case 21: slow Peerspan calls ----

// §4: the healthy connection's new workflow is dispatched and its run reconciled within a few seconds, and its
// readiness checks go on.
async function healthyWorks(f, connectionId, why) {
  const before = await f.readiness(connectionId);
  const workflow = await f.create({name: 'FAKE healthy workflow', connectionId, intervalMinutes: 60, enabled: true});
  const run = await f.newRun(workflow.id, 'queued', 6000);
  await f.finish(run, 'succeeded', {output: 'FAKE healthy result', timeout: 6000});
  await advancing(f, connectionId, before, why);
}
// §4: a connection's checkedAt moves on (a stepped-back wall clock can hold it still for a while, §1).
const advancing = (f, connectionId, before, why) => until(`§4 the checkedAt of another connection advances (${why})`,
  async () => Date.parse((await f.readiness(connectionId)).checkedAt) > Date.parse(before.checkedAt), 12000);
// §4: no second call for the hanging connection or task starts while the first is in flight (calls that start
// within `window` milliseconds of the hang; `runtime show` is cut after 5 seconds, §3.1).
async function noSecondCall(f, hang, matches, why, window = 3500) {
  const wait = hang.mono + window - monotonicNow();
  if (wait > 0) await delay(wait);
  const later = (await f.calls()).filter(call => matches(call.argv) && call.mono > hang.mono && call.mono <= hang.mono + window);
  expectEqual(later.map(call => call.argv), [], `§4 no second ${why} starts while the first hangs`);
}
async function shutdown(f, why) {
  const result = await f.terminate('SIGTERM');
  expect(result.code === 0 && result.ms < 5000, `§1 and §4 shutdown exits 0 within 5 seconds while ${why} hangs`, result);
}
const hanging = (f, test, why) => until('§4 ' + why + ' hangs', async () => (await f.hanging()).find(call => test(call.argv)));

// Case 21, a hanging status. §4 and §3: the hanging connection stays checking; the other is checked and works.
async function case21_hangingStatus() {
  const f = await capacityFixture('slow-status', {connect: true});
  const slowDir = path.join(f.dir, 'PRIVATE-slow-host');
  await f.configure({hostIds: {[slowDir]: hex('host', 5, 64)}});   // a worker host of its own
  const slow = await f.connectAgent(sessionAgent, 'FAKE-CONFORMANCE slow host', slowDir);
  await f.configure({hangWhen: [{command: 'status', state: slowDir}]});
  await f.start();
  const hang = await hanging(f, argv => option(argv, '--state') === slowDir, 'the slow host status');
  await f.code(f.connectionId, 'ready', 'the other connection is checked while the slow one hangs', 8000);
  expectEqual((await f.readiness(slow)).code, 'checking', '§4 until its first check has ended, the hanging connection stays checking');
  await healthyWorks(f, f.connectionId, 'a status call of another connection hangs');
  await noSecondCall(f, hang, argv => argv.includes('status') && option(argv, '--state') === slowDir, 'status for the hanging connection');
  await shutdown(f, 'a status call');
}

// Case 21, a hanging runtime show. §4; §3.1: after 5 seconds the runtime agent is runtime_unavailable.
async function case21_hangingRuntimeShow() {
  const f = await capacityFixture('slow-runtime', {connect: true});
  const runtimeDir = path.join(f.dir, 'PRIVATE-runtime-host');
  await f.configure({hostIds: {[runtimeDir]: hex('host', 5, 64)}});   // a worker host of its own
  const runtime = await f.connectAgent(runtimeAgent, 'FAKE-CONFORMANCE runtime agent', runtimeDir);
  await f.start();
  await f.code(runtime, 'ready_runtime', 'the runtime agent is ready');
  await f.code(f.connectionId, 'ready', 'the other worker is ready');
  await f.configure({hangWhen: [{command: 'runtime', state: runtimeDir}]});
  const isRuntimeShow = argv => argv.includes('runtime') && !argv.includes('agent') && option(argv, '--state') === runtimeDir;
  const hang = await hanging(f, isRuntimeShow, 'the runtime agent runtime show');
  await healthyWorks(f, f.connectionId, 'a runtime show of another connection hangs');
  await noSecondCall(f, hang, isRuntimeShow, 'runtime show for the hanging runtime agent');
  await f.code(runtime, 'runtime_unavailable', '§3.1 a runtime show that has not exited within 5 seconds', 12000);
  await shutdown(f, 'a runtime show');
}

// Case 21, one task's hanging inspection. §4: other tasks and every connection go on.
async function case21_hangingInspect() {
  const f = await capacityFixture('slow-inspect', {connect: true});
  const other = await f.connectAgent(sessionAgent, 'FAKE-CONFORMANCE worker of the slow task');
  await f.start();
  await f.code(f.connectionId, 'ready', 'the worker is ready');
  await f.code(other, 'ready', 'the other worker is ready');
  const slowWorkflow = await f.create({name: 'FAKE slow task', connectionId: other, intervalMinutes: 60, enabled: true});
  const slowRun = await f.newRun(slowWorkflow.id, 'queued');
  const before = await f.readiness(other);
  await f.configure({hangWhen: [{command: 'inspect', task: slowRun.taskId}]});
  const hang = await hanging(f, argv => argv.includes('inspect') && argv.includes(slowRun.taskId), 'the inspection of one task');
  await healthyWorks(f, f.connectionId, 'the inspection of another task hangs');
  await advancing(f, other, before, 'the hanging task worker connection is still checked');
  await noSecondCall(f, hang, argv => argv.includes(slowRun.taskId), 'call naming the task whose inspection hangs');
  expectEqual((await f.runById(slowRun.id)).state, 'queued', '§4 the hanging task stays as it was');
  await shutdown(f, 'a task inspection');
}

// Case 21, a hanging submission. §4: a submission started by a pass is waited for in the same way.
async function case21_hangingSubmit() {
  const f = await capacityFixture('slow-submit', {connect: true});
  const other = await f.connectAgent(sessionAgent, 'FAKE-CONFORMANCE worker of the slow submission');
  await f.start();
  await f.code(f.connectionId, 'ready', 'the worker is ready');
  await f.code(other, 'ready', 'the other worker is ready');
  const before = await f.readiness(other);
  await f.configure({hangWhen: [{command: 'submit', agent: sessionAgent.agentId}]});
  const slowWorkflow = await f.create({name: 'FAKE slow submission', connectionId: other, intervalMinutes: 60, enabled: true});
  const hang = await hanging(f, argv => argv.includes('submit') && option(argv, '--agent') === sessionAgent.agentId,
    'the submission to one agent');
  const taskId = option(hang.argv, '--task');
  await healthyWorks(f, f.connectionId, 'a submission to another agent hangs');
  await advancing(f, other, before, 'the connection of the hanging submission is still checked');
  await noSecondCall(f, hang, argv => argv.includes(taskId), 'call naming the task whose submission hangs');
  const slowRun = (await f.snapshot()).runs.find(run => run.workflowId === slowWorkflow.id);
  expectEqual(pick(slowRun, 'taskId state'), {taskId, state: 'submitting'}, '§4 the run whose submission hangs stays submitting');
  await shutdown(f, 'a submission');
}

// Case 21, a slow check. §4: dispatch uses only readiness from a check that ended since the previous dispatch
// decision. A worker whose status takes 800 ms, longer than a pass waits, becomes unready while a check of it is in
// flight (the fake answers as the host is when it answers), and `run` is requested at once: no task is sent on the
// verdict of the check before, and the worker becomes unready.
async function case21_slowCheck() {
  const f = await capacityFixture('slow-check', {connect: true});
  const slowDir = path.join(f.dir, 'PRIVATE-slow-check-host');
  const slowHost = hex('host', 5, 64);
  await f.configure({hostIds: {[slowDir]: slowHost}});
  const slow = await f.connectAgent(sessionAgent, 'FAKE-CONFORMANCE slowly checked worker', slowDir);
  await f.configure({delayWhen: [{command: 'status', state: slowDir, ms: 1200}]});
  await f.start();
  await f.code(slow, 'ready', 'the slowly checked worker is ready', 15000);
  const workflow = await f.create({name: 'FAKE slowly checked workflow', connectionId: slow, intervalMinutes: 60, enabled: true});
  await f.finish(await f.newRun(workflow.id, 'queued', 15000), 'succeeded');
  const sent = async () => (await f.submissions()).filter(call => option(call.argv, '--agent') === sessionAgent.agentId).length;
  const isSlowStatus = argv => argv.includes('status') && option(argv, '--state') === slowDir;
  // A status call of the worker that started 250 to 700 ms ago and has not ended: inside its 1,200 ms, and after the
  // pass that started it has made its dispatch decision (one interval is 100 ms).
  const inFlight = () => until('§4 a slow check of the worker is in flight', async () => {
    const [calls, outcomes] = [await f.calls(), await f.outcomes()];
    const started = calls.filter(call => isSlowStatus(call.argv));
    const age = started.length ? monotonicNow() - started.at(-1).mono : Infinity;
    return outcomes.filter(call => isSlowStatus(call.argv)).length < started.length && age >= 250 && age <= 700 &&
      started.length;
  }, 15000);
  // The worker becomes unready while a check of it is in flight. Normally that check has not yet read the host (the
  // fake logs a delayed call's waking before it reads its configuration) and reports the change; on a loaded machine
  // it may already have read it. Either way no task may be sent: `run` is requested after the change, and a run is
  // reserved only on readiness from a check that began after it became due, which reads the host after the change.
  const unreadyInFlight = async (unready, late) => {
    const started = await inFlight();
    if (late) {   // the change comes just after the in-flight check has read the host, which it reports as ready
      await until('the in-flight check reads the host', async () =>
        (await f.delayed()).filter(call => isSlowStatus(call.argv)).length >= started, 15000);
    }
    await f.configure(unready);
    const read = (await f.delayed()).filter(call => isSlowStatus(call.argv)).length >= started;
    return {started, timing: read ? 'had already read the host before the change' : 'read the host after the change'};
  };
  const sessionGone = {agents: f.config.agents.map(item => item.id === sessionAgent.agentId
    ? {...item, sessions: item.sessions.map(session => ({...session, connection: 'disconnected'}))} : item)};
  const sessionBack = {agents: f.config.agents};
  for (const [code, why, unready, restore, late] of [
    ['session_not_ready', 'its session stops being ready', sessionGone, sessionBack, false],
    ['identity_changed', 'its status reports another host', {hostIds: {[slowDir]: hex('host', 6, 64)}},
      {hostIds: {[slowDir]: slowHost}}, false],
    ['session_not_ready', 'its session stops being ready just after the in-flight check read the host as ready',
      sessionGone, sessionBack, true]]) {
    const before = await sent();
    const {started, timing} = await unreadyInFlight(unready, late);
    await f.action(workflow.id, 'run');
    await until('the in-flight check ends', async () =>
      (await f.outcomes()).filter(call => isSlowStatus(call.argv)).length >= started, 15000);
    await delay(1500);
    expectEqual(await sent(), before, `§4 a run is reserved only on readiness from a check that began after it became ` +
      `due: the worker became unready (${why}) while a check of it was in flight (which ${timing}), then run was ` +
      `requested, and every check that began after that reads the host after the change`);
    await f.code(slow, code, `${why}, as the checks that read the host after the change report`, 10000);
    await f.configure(restore);
    await f.finish(await f.newRun(workflow.id, 'queued', 15000), 'succeeded');   // ready again: the requested run goes out
  }
  await f.stop();
}

// ---- Case 22: a ready verdict from one moment ----

const slowMs = 300;   // the delay of the read that completes a ready verdict
// §3 (rev 7.1). The worker host changes `changes` times, each in one step (one atomic write of the fake's
// configuration), between states[0] and states[1]. Each state is not ready (`codes`), but the reads a check makes
// before its slow last read (`earlier`) in states[0], together with that last read (`slow`) in states[1], would
// look ready. Each change into states[1] is made while a slow read is in flight, so that its check spans the change.
// Each state is held at least `hold` ms and until a read matching `earlier` that began after the change has ended,
// so that no state comes back within one check, however long checks take. The enabled workflow on the worker never
// gets a run and no check records ready; once the host is ready (`ready`) and stays so, the workflow is dispatched.
async function oneMoment(f, {connectionId, agentId, what, states, codes, ready, readyCode, earlier, slow, changes = 16,
  hold = 1000}) {
  await f.code(connectionId, codes[0], `${what} in its first state`, 15000);
  const workflow = await f.create({name: 'FAKE one moment', connectionId, intervalMinutes: 60, enabled: true});
  const changed = [];   // {mono, index}: when the host became states[index]
  const seen = {codes: new Set(), ready: [], runs: new Set()};
  const watch = async () => {
    const snapshot = await f.snapshot();
    const readiness = snapshot.connections.find(item => item.id === connectionId).readiness;
    seen.codes.add(readiness.code);
    if (readiness.ready) seen.ready.push(pick(readiness, 'code checkedAt'));
    for (const run of snapshot.runs) if (run.workflowId === workflow.id) seen.runs.add(run.id);
  };
  const watchFor = async (ms, done = async () => true) => {
    const start = monotonicNow();
    while (monotonicNow() - start < ms || !(await done())) {
      expect(monotonicNow() - start < ms + 10000, `fixture: a read of ${what} that began after a change of the host ` +
        'ended within 10 seconds');
      await watch();
      await delay(100);
    }
  };
  // The last slow read began at most 180 ms ago and has not woken (it reads the host only when it wakes).
  const slowInFlight = async () => {
    const last = (await f.calls()).filter(call => slow(call.argv)).at(-1);
    return last && monotonicNow() - last.mono <= slowMs * 0.6 &&
      !(await f.delayed()).some(call => slow(call.argv) && call.mono >= last.mono);
  };
  for (let change = 1; change <= changes; change++) {
    if (change % 2) await until(`fixture: a slow read of ${what} in flight`, slowInFlight, 10000);
    await f.configure(states[change % 2]);
    const mono = monotonicNow();
    changed.push({mono, index: change % 2});
    const before = (await f.calls()).filter(call => earlier(call.argv) && call.mono <= mono).length;
    // Calls of one connection's checks follow one another: the next to end is the first that began after the change.
    await watchFor(hold, async () => (await f.outcomes()).filter(call => earlier(call.argv)).length > before);
  }
  await watchFor(1500);   // the last state (states[0]) held, so that a run reserved on an earlier verdict shows

  // Checks whose earlier reads saw states[0] and whose slow last read saw states[1]: the race this case is about.
  const stateAt = mono => changed.findLast(entry => entry.mono <= mono)?.index ?? 0;
  const calls = await f.calls();
  let straddles = 0;
  for (const wake of (await f.delayed()).filter(call => slow(call.argv))) {
    const start = calls.filter(call => slow(call.argv) && call.mono <= wake.mono - slowMs).at(-1);
    const read = start && calls.filter(call => earlier(call.argv) && call.mono < start.mono).at(-1);
    if (read && stateAt(read.mono) === 0 && stateAt(wake.mono) === 1) straddles++;
  }
  const runs = (await f.snapshot()).runs.filter(run => run.workflowId === workflow.id);
  const sent = async () => (await f.submissions()).filter(call => option(call.argv, '--agent') === agentId);
  const flips = (await f.request('GET', '/api/activity?limit=200')).data.activity
    .filter(entry => entry.connectionId === connectionId && entry.kind === 'worker.ready');
  const evidence = {runs: runs.map(run => pick(run, 'state createdAt')), submissions: (await sent()).length,
    readySeen: seen.ready.slice(0, 3), workerReady: flips.map(entry => pick(entry, 'at data')), straddles,
    codes: [...seen.codes]};
  expect(seen.runs.size === 0 && runs.length === 0 && evidence.submissions === 0, `§16 case 22, §3 (rev 7.1) and §4: ` +
    `with the read that completes a ready verdict slow, ${what} whose host changed ${changes} times in one step between ` +
    'two states that are each not ready, but whose earlier and later reads together would look ready, never gets a run',
  evidence);
  expect(seen.ready.length === 0 && flips.length === 0, '§3 (rev 7.1) a ready verdict must describe one moment, and ' +
    `${what} was ready at none: no check records ready (§11: no worker.ready entry)`, evidence);
  expect(codes.every(code => seen.codes.has(code)), `fixture: the checks saw both states (${codes.join(', ')})`, evidence);
  expect(straddles >= changes / 4, `fixture: for at least half of the ${changes / 2} changes into the second state, a ` +
    `check of ${what} made its earlier reads before the change and its slow last read after it, so the case exercised ` +
    'the race of §3 (rev 7.1)', evidence);

  // Ready, and kept so: the due workflow is dispatched normally.
  await f.configure(ready);
  let last = null;
  await until(() => `§16 case 22 and §4: once ${what} is ready and stays so, its enabled due workflow is dispatched ` +
    `within a few seconds; last seen: ${snippet(last)}`, async () => {
    const snapshot = await f.snapshot();
    last = {readiness: pick(snapshot.connections.find(item => item.id === connectionId).readiness, 'code reason checkedAt'),
      blockedReason: snapshot.workflows.find(item => item.id === workflow.id).blockedReason,
      runs: snapshot.runs.filter(run => run.workflowId === workflow.id).map(run => pick(run, 'state error'))};
    return last.runs.some(run => run.state === 'queued');
  }, 8000);
  expectEqual([(await f.readiness(connectionId)).code, (await sent()).length], [readyCode, 1],
    `§3 ${what} is ${readyCode}, and §4 its workflow was submitted once`);
}

// Case 22, file mode. With `adapter connection` slow, the worker host alternates between A, the pinned host with
// its channel verified and an empty channel_verified_at (channel_unverified), and B, a verified time but status
// reporting another host (identity_changed): A's status and B's adapter report would look ready.
async function case22_oneMomentFile() {
  const f = await capacityFixture('one-moment-file', {connect: true});
  const adapters = channelVerifiedAt => ({...f.config.adapters, [ids.adapterId]: {...verified(ids.sessionId),
    channel_verified_at: channelVerifiedAt}});
  const states = [{hostId: ids.hostId, adapters: adapters('')},
    {hostId: hex('host', 7, 64), adapters: adapters('2026-01-01T00:00:00Z')}];
  await f.configure({...states[0], delayWhen: [{command: 'adapter', ms: slowMs}]});
  await f.start();
  await oneMoment(f, {connectionId: f.connectionId, agentId: ids.agentId, what: 'a file-mode worker', states,
    codes: ['channel_unverified', 'identity_changed'], ready: {hostId: ids.hostId, adapters: adapters('2026-01-01T00:00:00Z')},
    readyCode: 'ready', earlier: argv => argv.includes('status') && option(argv, '--state') === f.workerDir,
    slow: argv => argv.includes('adapter') && argv.includes('connection')});
  await f.stop();
}

// Case 22, a runtime agent in agent mode. With `runtime show` slow, the host alternates between R1, a profile with
// its credential and the runtime switch off (runtime_disabled), and R2, the switch on but a profile without its
// credential (runtime_credential_missing): R1's launch profile and R2's runtime show would look ready.
async function case22_oneMomentRuntime() {
  const f = await capacityFixture('one-moment-runtime');
  const hostDir = path.join(f.dir, 'PRIVATE-one-moment-host');
  const runtime = await f.connectAgent(runtimeAgent, 'FAKE-CONFORMANCE runtime agent', hostDir);
  const on = {enabled: true, socket: null, rule: 'FAKE rule', runtime: {version: 'FAKE-runtime 0.0', running: 0}};
  const states = [{profiles: [f.profile({credential: true})], runtimeShow: disabledRuntime},
    {profiles: [f.profile({credential: false})], runtimeShow: on}];
  await f.configure({...states[0], delayWhen: [{command: 'runtime', ms: slowMs}]});
  await f.start();
  await oneMoment(f, {connectionId: runtime, agentId: runtimeAgent.agentId, what: 'a runtime agent', states,
    codes: ['runtime_disabled', 'runtime_credential_missing'], ready: {profiles: [f.profile()], runtimeShow: on},
    readyCode: 'ready_runtime',
    earlier: argv => argv.includes('agent') && argv.includes('runtime') && option(argv, '--state') === hostDir,
    slow: argv => argv.includes('runtime') && !argv.includes('agent') && option(argv, '--state') === hostDir});
  await f.stop();
}

await runCases('capacity', [case20_runtimeCapacity, case20_reviewerCapacity, case20_capacityOfOne, case20_twoConnections,
  case21_hangingStatus, case21_hangingRuntimeShow, case21_hangingInspect, case21_hangingSubmit, case21_slowCheck,
  case22_oneMomentFile, case22_oneMomentRuntime]);
