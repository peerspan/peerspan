#!/usr/bin/env node
// Contract-only black-box suite for docs/managed-contract.md revision 5, section 16, case 19: runtime agents as
// local workers (sections 3, 3.1 and 6; decision MGD-13). No imports or reads of the managed implementation or
// its database: the documented CLI, HTTP, the explicitly fake Peerspan executable and throwaway state only. The
// fake answers `agent runtime show` and `runtime show` (README: `profiles`, `runtimeShow`, `runtimeMode`,
// `profilesMode`, `runtimeShowMode`). Section numbers (§) refer to that contract.
import path from 'node:path';
import {isDeepStrictEqual} from 'node:util';
import {delay, expect, expectEqual, fixture, hex, ids, inputOf, option, pick, runCases, until} from './harness.mjs';

const runtimeAgent = {agentId: hex('agent', 5), name: 'FAKE-CONFORMANCE runtime agent'};
const sessionAgent = {agentId: hex('agent', 6), sessionId: hex('session', 6), adapterId: hex('adapter', 6),
  name: 'FAKE-CONFORMANCE session agent'};
const hex66 = 'a1'.repeat(33);
const verified = sessionId => ({session_id: sessionId, state: 'ready', channel: 'verified',
  channel_verified_at: '2026-01-01T00:00:00Z'});
// An attention item of the worker host with a usable command; subject and detail must never be returned.
const advice = {kind: 'fake_runtime_host_advice', subject: 'PRIVATE-SUBJECT runtime host',
  detail: 'PRIVATE-DETAIL runtime host', command: 'peerspan runtime show'};
// §3.1: the readiness summary of the default launch profile below.
const summary = {fromBranch: 'fake-main', network: 'FAKE-none', cpus: 2, memoryMib: 2048, timeoutSeconds: 900, maxRuns: 3};

// A fixture whose fake worker host has a file-mode worker (ids), a runtime agent (a launch profile, no session)
// and a session agent (a ready session, no profile). Agent-mode connections use their own worker host state
// directory, so the fake's log tells their calls from a file-mode connection's.
async function runtimeFixture(label, {connect = false} = {}) {
  const f = await fixture(label, {connect});
  f.hostDir = path.join(f.dir, 'PRIVATE-runtime-host');
  // Paths and extra fields carry PRIVATE- markers: §8 forbids them in every response (checked on each one).
  f.profile = (agentId, patch = {}) => ({agent_id: agentId, harness: 'FAKE-harness', harness_dir: path.join(f.dir,
    'PRIVATE-harness'), from_branch: 'fake-main', network: 'FAKE-none', cpus: 2, memory_mib: 2048, timeout_seconds: 900,
  max_runs: 3, credential: true, fake_extra: 'PRIVATE-PROFILE-EXTRA', ...patch});
  f.runtimeShow = (patch = {}) => ({enabled: true, socket: path.join(f.dir, 'PRIVATE-runtime.sock'), rule: 'FAKE rule',
    runtime: {version: 'FAKE-runtime 0.0', image: path.join(f.dir, 'PRIVATE-rootfs.img'), max_cpus: 8,
      max_memory_mib: 16384, max_seconds: 3600, max_concurrent_runs: 4, running: 0, peerfs: 'FAKE peerfs',
      max_network: 'FAKE-full'}, fake_extra: 'PRIVATE-RUNTIME-EXTRA', ...patch});
  f.agentList = (sessionConnection = 'ready') => [
    {id: ids.agentId, name: 'FAKE-CONFORMANCE file worker', sessions: [{id: ids.sessionId, adapter_id: ids.adapterId,
      connection: 'ready'}]},
    {id: runtimeAgent.agentId, name: runtimeAgent.name, sessions: []},
    {id: sessionAgent.agentId, name: sessionAgent.name, sessions: [{id: sessionAgent.sessionId,
      adapter_id: sessionAgent.adapterId, connection: sessionConnection}]}];
  f.baseline = {agents: f.agentList(), adapters: {[ids.adapterId]: verified(ids.sessionId),
    [sessionAgent.adapterId]: verified(sessionAgent.sessionId)}, profiles: [f.profile(runtimeAgent.agentId)],
  runtimeShow: f.runtimeShow(), runtimeMode: 'normal', profilesMode: 'normal', profilesExit: 1, runtimeShowMode: 'normal',
  active: true, statusExit: 0, attention: [advice], hang: []};
  await f.configure(f.baseline);
  f.connectAgent = async (agent, name) => JSON.parse(await f.checkedCli('connect', '--name', name, '--agent', agent.agentId,
    '--host-state', f.hostDir, '--sender-state', f.senderDir)).id;
  const has = (argv, words) => words.every(word => argv.includes(word));
  const after = async (from, test) => (await f.calls()).slice(from).filter(call => test(call.argv));
  f.listings = (from = 0) => after(from, argv => has(argv, ['agent', 'runtime', 'show']));
  f.runtimeReads = (from = 0) => after(from, argv => has(argv, ['runtime', 'show']) && !argv.includes('agent'));
  f.adapterReads = (from = 0) => after(from, argv => has(argv, ['adapter', 'connection']));
  return f;
}
// §3.1: the command's words after the global flags `--state DIR` and `--json`.
const words = argv => argv.filter((arg, index) => arg !== '--json' && arg !== '--state' && argv[index - 1] !== '--state');

// Case 19, a ready runtime agent. §3: the checking readiness with runtime null; §3.1: ready_runtime without any
// session, the commands it runs, runtime from the profile, hints, the inactive-service advisory, a change of
// the profile followed; §8 no path in any response; §4 and §10.1 a run dispatched and completed with a branch line.
async function case19_readyRuntimeAndRun() {
  const f = await runtimeFixture('runtime-ready');
  const runtime = await f.connectAgent(runtimeAgent, 'FAKE-CONFORMANCE runtime agent');
  await f.configure({hang: ['agent-runtime']});   // the first check cannot finish
  await f.start();
  await until('§3.1 the first check runs agent runtime show (made to hang)',
    async () => (await f.hanging()).some(call => call.argv.includes('agent')));
  const checking = (await f.snapshot()).connections.find(item => item.id === runtime).readiness;
  expectEqual(pick(checking, 'ready code checkedAt hints runtime'), {ready: false, code: 'checking', checkedAt: null, hints: [],
    runtime: null}, '§3 (rev 5) until the first check after a start has finished, readiness is checking with runtime null');
  await f.configure({hang: []});
  const ready = await f.code(runtime, 'ready_runtime', 'an agent with a launch profile and a credential, without any session');
  expect(ready.ready === true && /runtime/i.test(ready.reason), '§3.1 ready_runtime is ready, and its reason says that ' +
    'tasks run in the host runtime', ready);
  expectEqual([ready.runtime, ready.hints], [summary, [{kind: advice.kind, command: advice.command}]], '§3.1 runtime is ' +
    '{fromBranch,network,cpus,memoryMib,timeoutSeconds,maxRuns} from the launch profile, nothing else; hints are the ' +
    'worker host status attention, as for any agent-mode connection');
  const from = (await f.calls()).length;
  await delay(600);
  const [listings, reads] = [await f.listings(from), await f.runtimeReads(from)];
  expect(listings.length > 0 && reads.length > 0 && listings.every(call => option(call.argv, '--state') === f.hostDir &&
    call.argv.includes('--json') && isDeepStrictEqual(words(call.argv), ['agent', 'runtime', 'show'])) &&
    reads.every(call => option(call.argv, '--state') === f.hostDir && call.argv.includes('--json') &&
      isDeepStrictEqual(words(call.argv), ['runtime', 'show'])), '§3.1 every check runs agent runtime show, with --json and ' +
    'no agent argument, then runtime show with --json, both against the worker host state',
  [...listings, ...reads].slice(0, 4).map(call => call.argv));
  expectEqual((await f.adapterReads()).length, 0, '§3.1 adapter connection is never invoked for a runtime agent');

  // §3.1: each value as the profile gives it when it is a string or an integer, and null otherwise.
  const odd = f.profile(runtimeAgent.agentId, {from_branch: null, network: 7, cpus: 1.5, memory_mib: '2048',
    timeout_seconds: true, max_runs: -1});
  delete odd.network;
  await f.configure({profiles: [f.profile(sessionAgent.agentId, {cpus: 64}), odd]});
  const changed = await until('§3.1 a change of the launch profile is a change of readiness runtime', async () => {
    const current = (await f.snapshot()).connections.find(item => item.id === runtime).readiness;
    return current.runtime?.cpus !== summary.cpus && current;
  });
  expectEqual(pick(changed, 'code runtime since'), {code: 'ready_runtime', since: ready.since, runtime: {fromBranch: null,
    network: null, cpus: null, memoryMib: '2048', timeoutSeconds: null, maxRuns: -1}}, '§3.1 strings and integers as the ' +
    'profile gives them, null for a missing or other value; only the pinned agent profile counts; since moves only with ready');
  await f.configure({profiles: f.baseline.profiles});
  await until('§3.1 the summary follows the profile back', async () =>
    isDeepStrictEqual((await f.snapshot()).connections.find(item => item.id === runtime).readiness.runtime, summary));

  // §3.1: an inactive user service adds the §3 advisory; the code stays ready_runtime.
  await f.configure({active: false});
  const inactive = await until('§3.1 the ready_runtime reason carries the inactive-service advisory', async () => {
    const current = (await f.snapshot()).connections.find(item => item.id === runtime).readiness;
    return /inactive|not active/i.test(current.reason) && current;
  });
  expect(inactive.code === 'ready_runtime' && inactive.ready === true && /service/i.test(inactive.reason) &&
    /runtime/i.test(inactive.reason) && inactive.since === ready.since, '§3.1 with service.active false the code stays ' +
    'ready_runtime and the reason carries the advisory of §3', inactive);
  await f.configure({active: true});

  // §3.1 and §4: senders submit to a runtime agent, and its runs are dispatched, as for any agent.
  const instructions = 'FAKE assignment for a runtime agent';
  const workflow = await f.create({connectionId: runtime, instructions, intervalMinutes: 60, enabled: true});
  const run = await f.newRun(workflow.id, 'queued');
  const [submit] = await f.submissions();
  expectEqual(['--peer', '--agent', '--state', '--task'].map(name => option(submit.argv, name)).concat(inputOf(submit.argv)),
    [ids.hostId, runtimeAgent.agentId, f.senderDir, run.taskId, instructions],
    '§3.1 a run is submitted to the runtime agent through the sender state, exactly as to any agent');
  const name = 'codex.' + run.taskId;
  const done = await f.finish(run, 'succeeded', {output: `FAKE runtime agent report\n\nBranch: ${name} at commit ${hex66}`});
  expectEqual(done.branch, {name, outcome: 'committed', commit: hex66, from: null, error: null},
    '§3.1 a runtime agent run output ends with the branch line of §10.1');
  await f.stop();
}

// Case 19, blocking codes. §3.1: runtime_disabled, runtime_unavailable (a failing runtime show, a report with
// error, malformed output and the other invalid reports) and runtime_credential_missing, in that order, each
// blocking dispatch, with runtime from the profile; §11 worker.unready and worker.ready with their codes.
async function case19_blockingCodes() {
  const f = await runtimeFixture('runtime-blocked');
  const runtime = await f.connectAgent(runtimeAgent, 'FAKE-CONFORMANCE runtime agent');
  await f.start();
  await f.code(runtime, 'ready_runtime', 'the runtime agent is ready');
  const gated = await f.create({connectionId: runtime, intervalMinutes: 60});
  const agentId = runtimeAgent.agentId;
  const noCredential = {profiles: [f.profile(agentId, {credential: false})]};
  const withoutCredential = f.profile(agentId);
  delete withoutCredential.credential;
  const off = f.runtimeShow({enabled: false, socket: null, runtime: null});
  const blocked = [
    ['runtime_disabled', 'the runtime switch is off', {runtimeShow: off}],
    ['runtime_disabled', 'the switch is off, whatever its report says', {runtimeShow: f.runtimeShow({enabled: false,
      runtime: {error: 'FAKE runtime stopped'}})}],
    ['runtime_disabled', 'a switched-off runtime comes before a missing credential', {...noCredential, runtimeShow: off}],
    ['runtime_unavailable', 'runtime show exits 1', {runtimeShowMode: 'error'}],
    ['runtime_unavailable', 'the runtime report is an error', {runtimeShow: f.runtimeShow({runtime: {error: 'FAKE runtime does not answer'}})}],
    ['runtime_unavailable', 'runtime show prints output that is not JSON', {runtimeShowMode: 'malformed'}],
    ['runtime_unavailable', 'runtime show prints an array', {runtimeShow: [f.runtimeShow()]}],
    ['runtime_unavailable', 'enabled is not a boolean', {runtimeShow: f.runtimeShow({enabled: 'true'})}],
    ['runtime_unavailable', 'runtime is null while the switch is on', {runtimeShow: f.runtimeShow({runtime: null})}],
    ['runtime_unavailable', 'an unavailable runtime comes before a missing credential', {...noCredential, runtimeShowMode: 'error'}],
    ['runtime_credential_missing', 'the profile credential is false', noCredential],
    ['runtime_credential_missing', 'the profile credential is the string "true"', {profiles: [f.profile(agentId, {credential: 'true'})]}],
    ['runtime_credential_missing', 'the profile has no credential field', {profiles: [withoutCredential]}]];
  for (const [code, why, patch] of blocked) {
    await f.configure(patch);
    const state = await f.code(runtime, code, why);
    expectEqual([state.ready, state.runtime], [false, summary], `§3.1 ${code} is not ready; runtime is the profile summary (${why})`);
    await f.action(gated.id, 'resume');
    await f.action(gated.id, 'run');
    await delay(400);
    expectEqual((await f.submissions()).length, 0, `§3.1 ${code} blocks new dispatch (${why})`);
    await f.action(gated.id, 'pause');
    await f.configure(f.baseline);
    await f.code(runtime, 'ready_runtime', 'restored after: ' + why);
  }
  await f.action(gated.id, 'resume');
  await f.newRun(gated.id, 'queued');   // ready_runtime dispatches again
  const log = (await f.request('GET', '/api/activity?limit=200')).data.activity
    .filter(entry => entry.connectionId === runtime && entry.kind.startsWith('worker.'));
  const codes = kind => [...new Set(log.filter(entry => entry.kind === kind).map(entry => entry.data.code))].sort();
  expectEqual([codes('worker.unready'), codes('worker.ready')],
    [['runtime_credential_missing', 'runtime_disabled', 'runtime_unavailable'], ['ready_runtime']],
    '§11 worker.unready and worker.ready {code} carry the runtime codes when ready changes');
  await f.stop();
}

// Case 19, sessions and the profile listing. §3.1: an agent without a profile, and every agent under an
// executable without `agent runtime`, following their sessions; a failing listing as status_invalid; the
// runtime check only after agent_missing; an agent becoming, and ceasing to be, a runtime agent without operator
// action.
async function case19_sessionsAndListing() {
  const f = await runtimeFixture('runtime-sessions');
  const runtime = await f.connectAgent(runtimeAgent, 'FAKE-CONFORMANCE runtime agent');
  const session = await f.connectAgent(sessionAgent, 'FAKE-CONFORMANCE session agent');
  await f.start();
  const both = (runtimeCode, sessionCode, why) => Promise.all([f.code(runtime, runtimeCode, why), f.code(session, sessionCode, why)]);
  const [, plain] = await both('ready_runtime', 'ready', 'one agent has a launch profile and the other none');
  expect(plain.runtime === null && (await f.adapterReads()).some(call => call.argv.includes(sessionAgent.adapterId)),
    '§3.1 an agent without a profile follows its sessions (adapter connection is read) and has runtime null', plain);
  await f.configure({agents: f.agentList('disconnected')});
  await f.code(session, 'session_not_ready', 'the agent without a profile has no ready session');
  await f.configure(f.baseline);
  await both('ready_runtime', 'ready', 'its session is ready again');

  // An executable older than runtime agents: every agent follows its sessions; the runtime agent has none.
  await f.configure({runtimeMode: 'older'});
  const [older] = await both('session_not_ready', 'ready', 'agent runtime show exits 2 with unrecognized subcommand');
  expectEqual(older.runtime, null, '§3.1 under an older executable the agent is not a runtime agent');
  await f.configure(f.baseline);
  await both('ready_runtime', 'ready', 'the executable knows runtime agents again');

  // A listing that cannot be read is status_invalid for every agent-mode connection.
  for (const [why, patch] of [['agent runtime show exits 1', {profilesMode: 'error'}],
    ['agent runtime show exits 2 without unrecognized subcommand', {profilesMode: 'error', profilesExit: 2}],
    ['its output is not JSON', {profilesMode: 'malformed'}], ['it prints a JSON object, not an array', {profilesMode: 'object'}]]) {
    await f.configure(patch);
    for (const state of await both('status_invalid', 'status_invalid', why)) {
      expect(/profile/i.test(state.reason), `§3.1 the reason says the host launch profiles could not be read (${why})`, state.reason);
    }
    await f.configure(f.baseline);
    await both('ready_runtime', 'ready', 'restored after: ' + why);
  }

  // §3.1: the listing is read only once the rows up to agent_missing do not apply.
  await f.configure({agents: f.agentList().filter(item => item.id !== runtimeAgent.agentId)});
  await f.code(runtime, 'agent_missing', 'the runtime agent with a profile is not in the status agents');
  await f.configure(f.baseline);

  // Becoming and ceasing to be a runtime agent, without operator action.
  await f.configure({profiles: [f.profile(runtimeAgent.agentId), f.profile(sessionAgent.agentId, {cpus: 4})]});
  const [, became] = await both('ready_runtime', 'ready_runtime', 'the session agent gains a launch profile');
  expectEqual(became.runtime, {...summary, cpus: 4}, '§3.1 an agent that gains a profile becomes a runtime agent');
  const adapterCalls = (await f.adapterReads()).length;
  await delay(600);
  expectEqual((await f.adapterReads()).length, adapterCalls, '§3.1 adapter connection is not invoked for a runtime agent');
  await f.configure({profiles: [f.profile(sessionAgent.agentId, {cpus: 4})]});
  const [ceased] = await both('session_not_ready', 'ready_runtime', 'the runtime agent loses its profile and has no session');
  expectEqual(ceased.runtime, null, '§3.1 an agent that loses its profile follows its sessions again');
  await f.configure(f.baseline);
  await both('ready_runtime', 'ready', 'the profiles as at the start');
  const log = (await f.request('GET', '/api/activity?limit=200')).data.activity;
  expect(log.some(entry => entry.kind === 'worker.unready' && entry.connectionId === runtime && entry.data.code === 'session_not_ready') &&
    log.some(entry => entry.kind === 'worker.ready' && entry.connectionId === runtime && entry.data.code === 'ready_runtime') &&
    !log.some(entry => entry.actor === 'operator' && entry.kind !== 'connection.added'),
  '§11 the changes were the controller own, recorded as worker entries, without operator action', log.slice(0, 12));
  await f.stop();
}

// Case 19, file and remote mode. §3.1: neither runs `agent runtime show` (nor `runtime show`), even for agents
// with launch profiles; a file-mode connection follows its worker state file, and a remote runtime agent that
// the sender's directory lists as not connected is session_not_ready; both have runtime null.
async function case19_fileAndRemoteModes() {
  const f = await runtimeFixture('runtime-file-remote', {connect: true});
  const network = 'net_' + 'a'.repeat(32), bob = hex('host', 'b', 64), remoteAgent = hex('agent', 'b');
  await f.configure({profiles: [f.profile(ids.agentId), f.profile(remoteAgent)], networks: {[network]: {
    refreshed_at: '2026-11-01T10:00:00.000Z', inbound: [], mine: [],
    reachable: [{address: 'fake-bob/fake-runtime', host_id: bob, agent_id: remoteAgent, connected: false, host_state: 'ok',
      actions: ['message.append', 'task.submit'], endpoint: {address: '192.0.2.10:7401', path: 'direct'},
      description: 'FAKE remote runtime agent'}],
    hosts: [{host_id: bob, person_id: null, person_label: 'fake-bob', state: 'ok', refreshed_at: '2026-11-01T09:59:00.000Z',
      error: null}]}}});
  const remote = JSON.parse(await f.checkedCli('connect', '--name', 'FAKE-CONFORMANCE remote runtime agent',
    '--remote', remoteAgent, '--sender-state', f.senderDir)).id;
  await f.start();
  const file = await f.code(f.connectionId, 'ready', 'file mode follows its worker state file, though its agent has a profile');
  const far = await f.code(remote, 'session_not_ready', 'the sender directory lists the remote runtime agent as not connected');
  await delay(1000);
  expectEqual([file.runtime, far.runtime, (await f.listings()).length, (await f.runtimeReads()).length], [null, null, 0, 0],
    '§3.1 file and remote mode never run agent runtime show or runtime show, and their runtime is null');
  await f.stop();
}

await runCases('runtime-agents', [case19_readyRuntimeAndRun, case19_blockingCodes, case19_sessionsAndListing,
  case19_fileAndRemoteModes]);
