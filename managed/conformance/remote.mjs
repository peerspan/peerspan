#!/usr/bin/env node
// Contract-only black-box suite for docs/managed-contract.md revision 3, section 16, case 13: workers on
// other machines (sections 3, 6 and 7.1, and the dispatch and recovery rules of section 4). No imports or
// reads of the managed implementation or its database: the documented CLI, HTTP, the explicitly fake
// Peerspan executable and throwaway state only. Section numbers (§) refer to that contract.
import fs from 'node:fs/promises';
import {delay, expect, expectEqual, expectError, expectStatus, fixture, hex, ids, inputOf, isTime, option, pick,
  runCases, senderHostId, until} from './harness.mjs';

// §7: every local command prints errors on stderr as one line, with exit 1.
const oneErrorLine = result => result.code === 1 && result.stderr.trim() !== '' &&
  result.stderr.trim().split('\n').length === 1;
const monotonicNow = () => Number(process.hrtime.bigint() / 1000000n);   // the clock of the fake's `mono`

// The sender host's directory (§6, §7.1). IDs follow §6; names, texts and addresses are visibly fake.
const network = {a: 'net_' + 'a'.repeat(32), b: 'net_' + 'b'.repeat(32), c: 'net_' + 'c'.repeat(32)};
const host = {bob: hex('host', 'b', 64), carol: hex('host', 'c', 64), laptop: hex('host', 'e', 64), twin: hex('host', 'f', 64)};
const agent = {worker: hex('agent', 'b'), second: hex('agent', 'c'), laptop: hex('agent', 'e'), local: hex('agent', 'd'),
  twinA: hex('agent', 7), twinB: hex('agent', 8)};
const address = {worker: 'fake-bob/fake-worker', second: 'fake-bob/fake-second', laptop: 'fake-alice/fake-laptop-worker',
  local: 'fake-alice/fake-local-worker', twin: 'fake-carol/fake-twin', nobody: 'fake-nobody/fake-none'};
const at = {a: '2026-11-01T10:00:00.000Z', bob: '2026-11-01T09:58:30.000Z', laptop: '2026-11-01T09:57:00.000Z',
  b: '2026-11-01T08:00:30.000Z', bobB: '2026-11-01T08:00:00.000Z', stale: '2026-11-01T09:00:00.000Z'};
const endpoint = {address: '192.0.2.10:7401', path: 'direct'};
const reachable = (hostId, agentId, addr, patch = {}) => ({address: addr, host_id: hostId, agent_id: agentId,
  connected: true, host_state: 'ok', actions: ['message.append', 'task.submit'], endpoint,
  description: 'FAKE remote worker', ...patch});
const mine = (hostId, agentId, addr, patch = {}) => ({address: addr, host_id: hostId, agent_id: agentId, connected: true,
  endpoint, description: 'FAKE worker of the sender person', ...patch});
const hostEntry = (hostId, refreshedAt, patch = {}) => ({host_id: hostId, person_id: null, person_label: 'fake-person',
  state: 'ok', refreshed_at: refreshedAt, error: null, ...patch});
// Network a: bob's worker (reachable), two agents sharing one address, the sender person's laptop and its own
// host (mine). Network b: another agent of bob, whose host entry carries another time.
const directoryA = (edit = () => {}) => {
  const directory = {refreshed_at: at.a,
    reachable: [reachable(host.bob, agent.worker, address.worker), reachable(host.carol, agent.twinA, address.twin),
      reachable(host.twin, agent.twinB, address.twin)],
    mine: [mine(host.laptop, agent.laptop, address.laptop), mine(senderHostId, agent.local, address.local)],
    inbound: [], hosts: [hostEntry(host.bob, at.bob), hostEntry(host.carol, at.a), hostEntry(host.laptop, at.laptop),
      hostEntry(host.twin, at.a)]};
  edit(directory);
  return directory;
};
const directoryB = () => ({refreshed_at: at.b, reachable: [reachable(host.bob, agent.second, address.second)], mine: [],
  inbound: [], hosts: [hostEntry(host.bob, at.bobB)]});
const onlyA = edit => ({networks: {[network.a]: directoryA(edit)}});
const entry = (directory, list, agentId) => directory[list].find(item => item.agent_id === agentId);
const hostOf = (directory, hostId) => directory.hosts.find(item => item.host_id === hostId);
// Attention items with private subject and detail: a hint keeps only kind and a usable command (§3).
const item = (kind, command) => ({kind, subject: 'PRIVATE-SUBJECT ' + kind, detail: 'PRIVATE-DETAIL ' + kind, command});
const senderAttention = [item('fake_sender_usable', 'peerspan agents --refresh'),
  item('fake_sender_path', 'peerspan --state /PRIVATE-SENDER-PATH status'), item('Fake-Bad-Kind', 'peerspan fake skipped')];
const senderHints = [{kind: 'fake_sender_usable', command: 'peerspan agents --refresh'}, {kind: 'fake_sender_path', command: null}];
const baseline = {...onlyA(), senderAttention, senderStatusExit: 0, senderHostId, agentsExit: 0, agentsMalformed: false,
  agentsOmit: [], rejectJson: false,
  // The worker host's own status is never read for a remote connection (§7, §7.1); this would show if it were.
  attention: [item('fake_worker_host_only', 'peerspan fake worker advice')]};

async function remoteFixture(label) {
  const f = await fixture(label, {connect: false, config: baseline});
  f.connect = async (name, target, ...args) => {
    const from = (await f.calls()).length;
    const result = await f.cli('connect', '--name', name, '--remote', target, ...args);
    expect(result.code === 0, `§7.1 connect --remote ${target} ${args.join(' ')} exits 0`, result);
    const printed = JSON.parse(result.stdout);
    expect(typeof printed.id === 'string' && printed.id !== '', '§7.1 connect prints the new id', result.stdout);
    return {...printed, calls: (await f.calls()).slice(from).map(call => call.argv)};
  };
  f.agentsCalls = async (from = 0) => (await f.calls()).slice(from).filter(call => call.argv.includes('agents'));
  return f;
}

// §7.1: connect reads only the sender status and runs agents --refresh, with --network exactly when given.
// `state` null: the connection has no sender state, so no call carries --state.
function registrationCalls(rule, calls, {state, net}) {
  expect(calls.length > 0 && calls.every(argv => argv.includes('--json') && (option(argv, '--state') ?? null) === state &&
    (argv.includes('status') || argv.includes('agents'))), `§7.1 ${rule}: registration reads nothing of the worker ` +
    'host: every call is status or agents, with --json, against the sender state (no --state when it has none)', calls);
  const directory = calls.filter(argv => argv.includes('agents'));
  expect(calls.some(argv => argv.includes('status')) && directory.length > 0 && directory.every(argv =>
    argv.includes('--refresh') && option(argv, '--network') === net), `§7.1 ${rule}: registration reads the sender ` +
    `status and runs agents --refresh${net ? ' --network ' + net : ' without --network'}`, calls);
}

// Case 13, registration. §7.1: by address and by agent ID, from reachable and from mine, --network passed
// through, the refusals; the pinned network in every check, and --refresh on the first check of a start.
async function case13_registration() {
  const f = await remoteFixture('remote-registration');
  const sender = ['--sender-state', f.senderDir];
  const register = async (rule, name, target, args, pinned, {state = f.senderDir, net} = {}) => {
    const {calls, ...printed} = await f.connect(name, target, ...args);
    expectEqual(printed, {id: printed.id, name, ...pinned, mode: 'remote'},
      `§7.1 ${rule}: connect pins the entry host_id and agent_id and prints {id,name,hostId,agentId,mode} with mode remote`);
    registrationCalls(rule, calls, {state, net});
    return printed;
  };
  const bob = {hostId: host.bob, agentId: agent.worker}, laptop = {hostId: host.laptop, agentId: agent.laptop};
  const byAddress = await register('by address, from reachable, in the only network', 'FAKE remote by address',
    address.worker, sender, bob);
  const byId = await register('by agent ID, from reachable, with --network', 'FAKE remote by id', agent.worker,
    ['--network', network.a, ...sender], bob, {net: network.a});
  const mineByAddress = await register('by address, from mine', 'FAKE mine by address', address.laptop, sender, laptop);
  const mineById = await register('by agent ID, from mine', 'FAKE mine by id', agent.laptop, sender, laptop);
  await f.configure({networks: {[network.a]: directoryA(), [network.b]: directoryB()}});
  const byNetwork = await register('with --network naming the second of two networks', 'FAKE remote in network b',
    address.second, ['--network', network.b, ...sender], {hostId: host.bob, agentId: agent.second}, {net: network.b});
  await f.configure({senderStates: [f.senderDir, 'default']});
  const byDefault = await register('without --sender-state', 'FAKE remote default sender', address.worker,
    ['--network', network.a], bob, {state: null, net: network.a});

  // Refusals: one error line, exit 1, and nothing registered (checked in the snapshot below).
  const refuse = async (what, args, message) => {
    const result = await f.cli('connect', '--name', 'FAKE refused', ...args);
    expect(oneErrorLine(result), `§7.1 refused when ${what}: one error line on stderr and exit 1`, result);
    if (message === 'agents') {
      expect(result.stderr.includes('peerspan agents'), `§7.1 ${what}: the message tells the operator to run ` +
        '`peerspan agents` and pass an address or agent ID it lists', result.stderr);
    } else if (message === 'id') {
      expect(/agent/i.test(result.stderr) && /\bid\b/i.test(result.stderr), `§7.1 ${what}: the message asks for the agent ID`,
        result.stderr);
    }
  };
  const inA = ['--network', network.a, ...sender];
  await refuse('no reachable or mine entry matches', ['--remote', address.nobody, ...inA], 'agents');
  await refuse('two entries match the address', ['--remote', address.twin, ...inA], 'id');
  await refuse('the match is on the sender own host (by address)', ['--remote', address.local, ...inA]);
  await refuse('the match is on the sender own host (by agent ID)', ['--remote', agent.local, ...inA]);
  await refuse('the sender is in two networks and --network is omitted, so agents exits 1', ['--remote', address.worker, ...sender]);
  await refuse('--network names a network the sender is not in', ['--remote', address.worker, '--network', network.c, ...sender]);
  await refuse('--host-state is given with --remote', ['--remote', address.worker, '--host-state', f.workerDir, ...inA]);
  await refuse('--network is given in agent mode', ['--agent', ids.agentId, '--host-state', f.workerDir, ...inA]);
  await refuse('--network is given in file mode', ['--worker-state', f.workerFile, ...inA]);
  await refuse('--remote and --agent are both given', ['--remote', address.worker, '--agent', ids.agentId, ...inA]);
  await refuse('--remote and --worker-state are both given', ['--remote', address.worker, '--worker-state', f.workerFile, ...inA]);
  for (const [what, patch] of [['the sender status exits 2', {senderStatusExit: 2}],
    ['the sender status exits 3', {senderStatusExit: 3}], ['agents exits 2', {agentsExit: 2}],
    ['agents prints no JSON', {agentsMalformed: true}], ['the directory lacks hosts', {agentsOmit: ['hosts']}]]) {
    await f.configure(patch);
    await refuse(what, ['--remote', address.worker, ...inA]);
    await f.configure({senderStatusExit: 0, agentsExit: 0, agentsMalformed: false, agentsOmit: []});
  }

  const from = (await f.calls()).length;
  await f.start();
  const registered = [byAddress, byId, mineByAddress, mineById, byNetwork, byDefault];
  expectEqual((await f.snapshot()).connections.map(item => pick(item, 'id name hostId agentId mode')), registered,
    '§8 connections are what connect printed, oldest first, with mode remote; refused registrations are absent');
  const times = {[byAddress.id]: at.bob, [byId.id]: at.bob, [mineByAddress.id]: at.laptop, [mineById.id]: at.laptop,
    [byNetwork.id]: at.bobB, [byDefault.id]: at.bob};
  for (const connection of registered) {
    const ready = await f.code(connection.id, 'ready', connection.name + ' is in the directory, connected and authorized');
    expectEqual(Date.parse(ready.directoryAt), Date.parse(times[connection.id]), `§7.1 directoryAt of ${connection.name} ` +
      'is the refreshed_at of the pinned host hosts entry in the pinned network directory');
    expect(/directory/i.test(ready.reason), '§7.1 the reason for ready says the evidence is the sender directory', ready.reason);
  }
  await delay(500);
  const checks = (await f.agentsCalls(from)).map(call => call.argv);
  expect(checks.every(argv => argv.filter(arg => arg === '--network').length === 1 && (option(argv, '--state') === undefined
    ? option(argv, '--network') === network.a : [network.a, network.b].includes(option(argv, '--network')))),
  '§7.1 every check runs agents with --network and the pinned network of its connection', checks);
  for (const [what, state, net] of [['network b', f.senderDir, network.b], ['the default sender', undefined, network.a]]) {
    const own = checks.filter(argv => option(argv, '--state') === state && option(argv, '--network') === net);
    expect(own.length >= 2 && own[0].includes('--refresh') && !own.slice(1).some(argv => argv.includes('--refresh')),
      `§7.1 the only connection checked through ${what} passes --refresh on its first check after the start and not again ` +
      'within 60 seconds', own);
  }
  // The pinned network, not the only one: a connection whose network is gone has no directory.
  await f.configure({networks: {[network.a]: directoryA()}});
  await f.code(byNetwork.id, 'directory_unavailable', 'its pinned network b is no longer one of the sender networks');
  expectEqual((await f.readiness(byAddress.id)).code, 'ready', '§7.1 connections pinned to network a stay ready');
  await f.configure({networks: {[network.b]: directoryB()}});
  await f.code(byNetwork.id, 'ready', 'network b is back, as the sender only network');
  for (const connection of [byAddress, mineById, byDefault]) {
    await f.code(connection.id, 'directory_unavailable', 'its pinned network a is gone, although the sender is in one network');
  }
  await f.stop();
}

// Case 13, readiness. §7.1: every remote readiness code a fake can produce, the order of the table, directoryAt,
// the sender hints, and no read of the worker host.
async function case13_readinessCodes() {
  const f = await remoteFixture('remote-readiness');
  const worker = await f.connect('FAKE remote worker', address.worker, '--network', network.a, '--sender-state', f.senderDir);
  const laptop = await f.connect('FAKE mine worker', address.laptop, '--network', network.a, '--sender-state', f.senderDir);
  await f.start();
  const restore = async why => {
    await f.configure(baseline);
    await Promise.all([f.code(worker.id, 'ready', 'restored after: ' + why), f.code(laptop.id, 'ready', 'restored after: ' + why)]);
  };
  const ready = await f.code(worker.id, 'ready', 'the reachable entry is connected, may task.submit and its host is ok');
  expectEqual(ready.hints, senderHints, '§7.1 hints of a remote connection are the sender host attention items by the ' +
    'rules of §3: a usable command kept, a command with / nulled, another kind skipped, no detail or subject');
  expectEqual(Date.parse(ready.directoryAt), Date.parse(at.bob),
    '§7.1 directoryAt is the refreshed_at of the pinned host entry in hosts, not of the directory');
  expect(/directory/i.test(ready.reason), '§7.1 the reason for ready says the evidence is the sender directory', ready.reason);
  const mineReady = await f.code(laptop.id, 'ready', 'a mine entry is ready without actions: the person own host reaches every agent');
  expectEqual([Date.parse(mineReady.directoryAt), mineReady.hints], [Date.parse(at.laptop), senderHints],
    '§7.1 directoryAt and hints of a connection registered from mine');

  // Codes decided by the directory. [connection, code, why, edit, directoryAt expected (undefined: not checked)]
  const directoryCases = [
    [worker, 'session_not_ready', 'the reachable entry is not connected', d => { entry(d, 'reachable', agent.worker).connected = false; }, at.bob],
    [laptop, 'session_not_ready', 'the mine entry is not connected', d => { entry(d, 'mine', agent.laptop).connected = false; }, at.laptop],
    [worker, 'not_authorized', 'the reachable entry actions lack task.submit',
      d => { entry(d, 'reachable', agent.worker).actions = ['message.append']; }, at.bob],
    [worker, 'not_authorized', 'no actions and not connected: not_authorized is the earlier row',
      d => { Object.assign(entry(d, 'reachable', agent.worker), {actions: [], connected: false}); }],
    [laptop, 'not_authorized', 'a reachable entry for the same agent lacks task.submit: the reachable entry is used',
      d => { d.reachable.push(reachable(host.laptop, agent.laptop, address.laptop, {actions: ['message.append']})); }],
    [worker, 'host_unreachable', 'the host entry state is error while its kept agent still says connected',
      d => { Object.assign(hostOf(d, host.bob), {state: 'error', error: 'FAKE host did not answer', refreshed_at: at.stale}); }, at.stale],
    [worker, 'host_unreachable', 'the host entry is pending', d => { Object.assign(hostOf(d, host.bob), {state: 'pending', refreshed_at: null}); }, null],
    [worker, 'host_unreachable', 'the host entry is unsupported', d => { hostOf(d, host.bob).state = 'unsupported'; }, at.bob],
    [laptop, 'host_unreachable', 'hosts has no entry for the pinned host of a mine entry',
      d => { d.hosts = d.hosts.filter(h => h.host_id !== host.laptop); }, null],
    [worker, 'host_unreachable', 'host error, no task.submit and not connected: host_unreachable is the earlier row', d => {
      hostOf(d, host.bob).state = 'error';
      Object.assign(entry(d, 'reachable', agent.worker), {actions: [], connected: false});
    }],
    [worker, 'agent_missing', 'no entry has the pinned agent', d => { d.reachable = d.reachable.filter(e => e.agent_id !== agent.worker); }, at.bob],
    [worker, 'agent_missing', 'the only entry with the pinned agent ID is on another host',
      d => { entry(d, 'reachable', agent.worker).host_id = host.carol; }],
    [worker, 'agent_missing', 'neither the entry nor its host is listed: agent_missing is the earlier row', d => {
      d.reachable = d.reachable.filter(e => e.agent_id !== agent.worker);
      d.hosts = d.hosts.filter(h => h.host_id !== host.bob);
    }, null],
    [laptop, 'agent_missing', 'the mine entry is gone', d => { d.mine = d.mine.filter(e => e.agent_id !== agent.laptop); }]];
  for (const [connection, code, why, edit, directoryAt] of directoryCases) {
    await f.configure(onlyA(edit));
    const state = await f.code(connection.id, code, why);
    if (directoryAt !== undefined) {
      expectEqual(state.directoryAt === null ? null : Date.parse(state.directoryAt), directoryAt === null ? null : Date.parse(directoryAt),
        `§7.1 directoryAt is the pinned host refreshed_at in the directory read, null without such an entry (${why})`);
    }
    if (code === 'session_not_ready') {
      expect(/directory/i.test(state.reason), '§7.1 the reason for session_not_ready says the evidence is the sender directory', state.reason);
    }
    expectEqual(state.hints, senderHints, `§7.1 the sender hints stay while the sender status is readable (${why})`);
    await restore(why);
  }

  // Codes decided by the directory as a whole, for both connections.
  const unavailable = [
    ['agents exits 1', {agentsExit: 1}], ['agents exits 2', {agentsExit: 2}], ['agents prints no JSON', {agentsMalformed: true}],
    ['the directory names another network_id', onlyA(d => { d.network_id = network.b; })],
    ['the pinned network is not one of the sender networks', {networks: {[network.b]: directoryB()}}],
    ['the directory lacks hosts', {agentsOmit: ['hosts']}],
    ['reachable is not an array', onlyA(d => { d.reachable = {}; })], ['mine is null', onlyA(d => { d.mine = null; })]];
  for (const [why, patch] of unavailable) {
    await f.configure(patch);
    for (const connection of [worker, laptop]) {
      const state = await f.code(connection.id, 'directory_unavailable', why);
      expectEqual([state.directoryAt, state.hints], [null, senderHints],
        `§7.1 without a usable directory directoryAt is null and the readable sender status still gives hints (${why})`);
    }
    await restore(why);
  }

  // Codes decided by the sender and the executable: [code, why, patch, the mine connection's code, hints empty].
  // The sender reporting bob's host concerns only the connection pinned to bob's host.
  const senderCases = [
    ['sender_is_worker', 'the sender status reports the pinned worker host', {senderHostId: host.bob}, 'ready'],
    ['sender_is_worker', 'and agents fails: sender_is_worker is the earlier row', {senderHostId: host.bob, agentsExit: 1},
      'directory_unavailable'],
    ['sender_unavailable', 'the sender status exits 2', {senderStatusExit: 2}, 'sender_unavailable', true],
    ['sender_unavailable', 'the sender status exits 3', {senderStatusExit: 3}, 'sender_unavailable', true],
    ['sender_unavailable', 'and agents fails: sender_unavailable is the earlier row', {senderStatusExit: 2, agentsExit: 1},
      'sender_unavailable', true],
    ['peerspan_incompatible', 'agents alone rejects --json', {rejectJson: ['agents']}, 'peerspan_incompatible'],
    ['peerspan_incompatible', 'status alone rejects --json', {rejectJson: ['status']}, 'peerspan_incompatible', true],
    ['peerspan_incompatible', 'every command rejects --json', {rejectJson: true}, 'peerspan_incompatible', true]];
  for (const [code, why, patch, mineCode, silent] of senderCases) {
    await f.configure(patch);
    const state = await f.code(worker.id, code, why);
    if (silent) expectEqual(state.hints, [], `§7.1 hints are empty when the sender status could not be read (${why})`);
    await f.code(laptop.id, mineCode, `the connection pinned to the laptop host, when ${why}`);
    await restore(why);
  }
  await fs.rename(f.fake, f.fake + '.moved');
  for (const connection of [worker, laptop]) {
    expectEqual((await f.code(connection.id, 'peerspan_unavailable', 'the executable cannot be started')).hints, [],
      '§7.1 hints are empty when the executable cannot be started');
  }
  await fs.rename(f.fake + '.moved', f.fake);
  await restore('the executable is back');

  // §7, §7.1: only the sender state is read; the worker host's status and adapter are never asked.
  const calls = (await f.calls()).map(call => call.argv);
  expect(calls.length > 0 && calls.every(argv => option(argv, '--state') === f.senderDir && (argv.includes('status') ||
    (argv.includes('agents') && option(argv, '--network') === network.a))),
  '§7.1 every check reads the sender status and runs agents --network with the pinned network, against the sender state; ' +
    'no worker host status and no adapter connection', calls.filter(argv => option(argv, '--state') !== f.senderDir ||
    !(argv.includes('status') || argv.includes('agents'))).slice(0, 3));
  await f.stop();
}

// Case 13, refresh. §7.1: --refresh on the first check after a start, and not again within 60 seconds; a check
// that begins 60 seconds after the previous refreshing check passes it again (MGD-7). Real time: about 70 s.
async function case13_refreshCadence() {
  const f = await remoteFixture('remote-refresh');
  const worker = await f.connect('FAKE remote refreshed', address.worker, '--network', network.a, '--sender-state', f.senderDir);
  const refreshes = calls => calls.filter(call => call.argv.includes('--refresh'));
  let from = (await f.calls()).length;
  await f.start();
  await f.code(worker.id, 'ready', 'the first check after a start');
  await delay(3000);
  let calls = await f.agentsCalls(from);
  expect(calls.length >= 4 && calls[0].argv.includes('--refresh') && refreshes(calls).length === 1,
    '§7.1 the first check after a start passes --refresh to agents, and the next checks within 60 seconds do not',
    calls.map(call => call.argv.filter(arg => arg.startsWith('--')).join(' ')));
  await f.stop();
  from = (await f.calls()).length;
  await f.start();
  await f.code(worker.id, 'ready', 'the first check after a restart');
  calls = await f.agentsCalls(from);
  expect(calls[0]?.argv.includes('--refresh'), '§7.1 the first check after a restart passes --refresh again, ' +
    'whatever the time since the last refresh', calls.slice(0, 2).map(call => call.argv));
  const first = calls[0].mono;
  const second = await until('§7.1 a check that begins at least 60 seconds after the previous check that passed --refresh ' +
    'passes it again (allowed here: 68 seconds)', async () => refreshes(await f.agentsCalls(from))[1],
  Math.max(1000, first + 68000 - monotonicNow()));
  calls = (await f.agentsCalls(from)).filter(call => call.mono < second.mono);
  expect(second.mono - first >= 59000 && calls.length >= 10,
    '§7.1 no check within 60 seconds of the previous refreshing check passes --refresh, while checks go on',
    {millisecondsBetweenRefreshes: second.mono - first, checksBetween: calls.length});
  await f.stop();
}

// Case 13, work. §7.1 and §4: a remote run's submission, inspection, completion and cancellation through the
// sender state, nothing naming a worker host's state; a restart reconciling a remote run under its task ID while
// the worker is not ready; disconnect refused while in use.
async function case13_dispatchAndRestart() {
  const f = await remoteFixture('remote-work');
  const worker = await f.connect('FAKE remote assignee', address.worker, '--network', network.a, '--sender-state', f.senderDir);
  await f.start();
  await f.code(worker.id, 'ready', 'before dispatch');
  const instructions = '- FAKE remote step one\n--state FAKE-not-an-option $(touch NEVER_EXECUTE) λ';
  const workflow = await f.create({connectionId: worker.id, enabled: true, instructions});
  const first = await f.newRun(workflow.id, 'queued');
  const [submit] = await f.submissions();
  expectEqual(['--task', '--peer', '--agent', '--state'].map(name => option(submit.argv, name)),
    [first.taskId, host.bob, agent.worker, f.senderDir],
    '§7.1 a remote run is submitted with task submit to the pinned host and agent, through the sender state');
  expect(submit.argv.includes('--json') && inputOf(submit.argv) === instructions && isTime(option(submit.argv, '--deadline')),
    '§4 the submission carries --json, the exact instructions as one --input=TEXT and an RFC 3339 deadline', submit.argv);
  await f.remoteEvent(first.taskId, 'accepted');
  await f.waitRun(first.id, 'running');
  const done = await f.finish(first, 'succeeded', {output: 'FAKE remote result'});
  expectEqual([done.output, (await f.detail(first.id)).run.output], ['FAKE remote result', 'FAKE remote result'],
    '§7.1 the result of a remote run is retained');
  for (const sub of ['inspect', 'events']) {
    const used = await f.taskCalls(sub, first.taskId);
    expect(used.length > 0 && used.every(call => option(call.argv, '--peer') === host.bob && option(call.argv, '--state') === f.senderDir),
      `§7.1 task ${sub} of a remote run names the pinned host and runs against the sender state`, used.map(call => call.argv));
  }

  await f.action(workflow.id, 'run');
  const second = await f.newRun(workflow.id, 'queued');
  expectStatus(await f.request('POST', `/api/runs/${second.id}/cancel`, {}), 200, '§10 cancel of a remote run');
  await f.cancelSent(second.taskId);
  const [cancel] = await f.taskCalls('cancel', second.taskId);
  expectEqual([option(cancel.argv, '--peer'), option(cancel.argv, '--state')], [host.bob, f.senderDir],
    '§7.1 cancellation of a remote run uses task cancel --peer HOST against the sender state');
  await f.finish(second, 'cancelled');

  // A submission whose response is lost after the sender accepted it; every inspection fails until the stop.
  await f.configure({submitMode: 'lost-accepted', inspectMode: 'error'});
  await f.action(workflow.id, 'run');
  await f.awaitSubmissions(3, '§4 the third run is submitted once in the pass that reserved it');
  const lost = await f.newRun(workflow.id);
  expect(['submitting', 'queued'].includes(lost.state), '§4 a run whose submit response was lost is still unresolved', lost);
  await f.stop();
  // §4: recovery does not require the worker to still be ready. The worker leaves the directory meanwhile.
  await f.configure({submitMode: 'normal', inspectMode: 'normal',
    ...onlyA(d => { d.reachable = d.reachable.filter(e => e.agent_id !== agent.worker); })});
  const from = (await f.calls()).length;
  await f.start();
  await f.code(worker.id, 'agent_missing', 'the worker left the sender directory while the controller was stopped');
  const recovered = await f.waitRun(lost.id, 'queued');
  const touching = (await f.calls()).slice(from).filter(call => call.argv.includes(lost.taskId)).map(call => call.argv);
  expect(recovered.taskId === lost.taskId && touching[0]?.includes('inspect') && option(touching[0], '--peer') === host.bob &&
    option(touching[0], '--state') === f.senderDir && (await f.taskCalls('submit', lost.taskId)).length === 1,
  '§4 after a restart a remote run is reconciled under its task ID: inspected first through the sender state, never ' +
    'submitted again, though its worker is not ready', {recovered: pick(recovered, 'taskId state'), touching: touching.slice(0, 3)});
  const finished = await f.finish(recovered, 'succeeded', {output: 'FAKE reconciled remote result'});
  expectEqual([finished.id, finished.taskId, finished.output], [lost.id, lost.taskId, 'FAKE reconciled remote result'],
    '§4 the reconciled remote run completes under its own identity');
  expectEqual((await f.submissions()).length, 3, '§4 no replacement work was created');

  const refused = await f.cli('disconnect', '--id', worker.id);
  expect(oneErrorLine(refused), '§7.1 disconnect of a remote connection is refused while a workflow uses it', refused);
  expectStatus(await f.request('POST', `/api/workflows/${workflow.id}/archive`, {}), 200, '§9 archive');
  expectEqual(JSON.parse(await f.checkedCli('disconnect', '--id', worker.id)), {id: worker.id, removed: true},
    '§7.1 disconnect works for a remote connection as for the other modes');
  expectError(await f.request('POST', `/api/runs/${lost.id}/cancel`, {}), 409, '§10 cancel of a terminal remote run');
  const calls = (await f.calls()).map(call => call.argv);
  expect(calls.every(argv => option(argv, '--state') === f.senderDir &&
    !argv.some(arg => arg.includes(f.workerDir) || arg.includes(f.workerFile))),
  '§7.1 no Peerspan call names a worker host state: every call runs against the sender state',
  calls.filter(argv => option(argv, '--state') !== f.senderDir).slice(0, 3));
  await f.stop();
}

await runCases('remote', [case13_registration, case13_readinessCodes, case13_refreshCadence, case13_dispatchAndRestart]);
