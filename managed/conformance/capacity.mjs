#!/usr/bin/env node
// Contract-only black-box suite for docs/managed-contract.md revision 6, section 16, cases 20 and 21: the capacity
// of a worker agent (sections 3.1, 4 and 8; decision MGD-14) and scheduler passes that never wait for a slow
// Peerspan call (section 4; decision MGD-15). No imports or reads of the managed implementation or its database:
// the documented CLI, HTTP, the explicitly fake Peerspan executable and throwaway state only. The fake plays
// runtime agents (README: `profiles`, `runtimeShow`) and makes single calls hang (`hangWhen`). Section numbers
// (§) refer to that contract.
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
  f.profile = (patch = {}) => ({agent_id: R, harness: 'FAKE-harness', harness_dir: path.join(f.dir, 'PRIVATE-harness'),
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

await runCases('capacity', [case20_runtimeCapacity, case20_reviewerCapacity, case20_capacityOfOne, case20_twoConnections,
  case21_hangingStatus, case21_hangingRuntimeShow, case21_hangingInspect, case21_hangingSubmit]);
