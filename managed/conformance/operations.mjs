#!/usr/bin/env node
// Contract-only black-box suite for docs/managed-contract.md revision 2, section 14, cases 7 to 10:
// workers and local commands, workflow editing and archiving, cancellation, and abandon.
// Cases 11 and 12 are in visibility.mjs. No imports or reads of the managed implementation or its
// database: the documented CLI, HTTP, the explicitly fake Peerspan executable and throwaway state only.
// Section numbers (§) in comments and failure messages refer to that contract.
import fs from 'node:fs/promises';
import path from 'node:path';
import {command, delay, expect, expectEqual, expectError, expectStatus, fixture, freePort, hex, ids, inputOf,
  isTime, jsonLines, observedDirectory, option, pick, privateAttention, runCases, senderHostId, until,
  wallClockSteppedBack, writeJson} from './harness.mjs';

// §7: every local command prints errors on stderr as one line, with exit 1.
const oneErrorLine = result => result.code === 1 && result.stderr.trim() !== '' &&
  result.stderr.trim().split('\n').length === 1;

// Case 7, local commands. §7: both connect forms and their refusals, disconnect, unobserve, doctor and
// exit codes; §1: configuration commands may run while the controller is serving.
async function case07_workerRegistrationAndLocalCommands() {
  const f = await fixture('local-commands', {connect: false});
  const worker = {id: ids.agentId, name: 'FAKE worker alpha',
    sessions: [{id: ids.sessionId, adapter_id: ids.adapterId, connection: 'ready'}]};
  const twins = [5, 6].map(digit => ({id: hex('agent', digit), name: 'FAKE twin', sessions: []}));
  await f.configure({agents: [worker, ...twins], statusExit: 0, attention: []});
  const hostArgs = ['--host-state', f.workerDir, '--sender-state', f.senderDir];
  const register = async (rule, name, mode, ...args) => {
    const logged = (await f.calls()).length;
    const result = await f.cli('connect', '--name', name, ...args);
    expect(result.code === 0, `§7 ${rule}: connect exits 0`, result);
    const printed = JSON.parse(result.stdout);
    expect(typeof printed.id === 'string' && printed.id !== '', `§7 ${rule}: connect prints the new id`, result.stdout);
    expectEqual(printed, {id: printed.id, name, hostId: ids.hostId, agentId: worker.id, mode},
      `§7 ${rule}: connect prints {id,name,hostId,agentId,mode}`);
    return {...printed, calls: (await f.calls()).slice(logged).map(call => call.argv)};
  };
  // The state directories a connect read status for, with --json ("default": no --state argument).
  const statusRead = calls => calls.filter(argv => argv.includes('status') && argv.includes('--json'))
    .map(argv => option(argv, '--state') ?? 'default').sort();
  const {calls: nameCalls, ...byName} = await register('agent mode by name', 'FAKE by name', 'agent',
    '--agent', worker.name, ...hostArgs);
  expectEqual([nameCalls.length, statusRead(nameCalls)], [2, [f.workerDir, f.senderDir].sort()],
    '§7 agent-mode connect runs status once against --host-state and reads the sender host status once, with --json');
  await f.configure({statusExit: 1, attention: [privateAttention]});
  const {calls: idCalls, ...byId} = await register('agent mode by ID, with a status that exits 1', 'FAKE by id',
    'agent', '--agent', worker.id, ...hostArgs);
  expectEqual(idCalls.length, 2, '§7 connect reads the worker status and the sender status once each');
  const {calls: defaultCalls, ...byDefault} = await register('agent mode without --host-state',
    'FAKE default state', 'agent', '--agent', worker.id, '--sender-state', f.senderDir);
  expectEqual(statusRead(defaultCalls), ['default', f.senderDir].sort(),
    '§7 without --host-state the worker status call carries no --state argument');
  const {calls: fileCalls, ...fileMode} = await register('file mode', 'FAKE file mode', 'file',
    '--worker-state', f.workerFile, '--sender-state', f.senderDir);
  expectEqual(statusRead(fileCalls).filter(read => read === f.senderDir).length, 1,
    '§7 file-mode connect also reads the sender host status once');
  expectEqual(JSON.parse(await f.checkedCli('disconnect', '--id', byDefault.id)), {id: byDefault.id, removed: true},
    '§7 disconnect of an unused connection prints {id,removed:true}');

  const refusals = {
    'no agent has that name or ID': ['connect', '--name', 'FAKE refused', '--agent', 'FAKE nobody', ...hostArgs],
    'two agents share the name': ['connect', '--name', 'FAKE refused', '--agent', 'FAKE twin', ...hostArgs],
    'neither --worker-state nor --agent': ['connect', '--name', 'FAKE refused'],
    'both --worker-state and --agent': ['connect', '--name', 'FAKE refused', '--worker-state', f.workerFile,
      '--agent', worker.id],
    '--host-state without --agent': ['connect', '--name', 'FAKE refused', '--worker-state', f.workerFile,
      '--host-state', f.workerDir],
    'sender and worker are one host (agent mode)': ['connect', '--name', 'FAKE refused', '--agent', worker.id,
      '--host-state', f.workerDir, '--sender-state', f.workerDir],
    'sender and worker are one host (file mode)': ['connect', '--name', 'FAKE refused',
      '--worker-state', f.workerFile, '--sender-state', f.workerDir],
    'a name that is blank after trimming': ['connect', '--name', '   ', '--agent', worker.id, ...hostArgs],
    'a name over 100 characters': ['connect', '--name', 'x'.repeat(101), '--agent', worker.id, ...hostArgs],
    'disconnect of an unknown ID': ['disconnect', '--id', 'FAKE-absent'],
    'unobserve of an unknown ID': ['unobserve', '--id', 'FAKE-absent']};
  for (const [what, args] of Object.entries(refusals)) {
    const result = await f.cli(...args);
    expect(oneErrorLine(result), `§7 ${what}: one error line on stderr and exit 1`, result);
    if (args.includes('FAKE nobody') || args.includes('FAKE twin')) {
      expect(/agent/i.test(result.stderr) && /\bid\b/i.test(result.stderr),
        `§7 ${what}: the message tells the operator to pass the agent ID`, result.stderr);
    }
  }
  // A sender whose status cannot be read is accepted; readiness reports it until the sender answers.
  await f.configure({senderStatusExit: 2});
  const {calls: downCalls, ...senderDown} = await register('a sender whose status cannot be read',
    'FAKE sender down', 'file', '--worker-state', f.workerFile, '--sender-state', f.senderDir);
  const external = await observedDirectory(f);
  const observation = JSON.parse(await f.checkedCli('observe', '--name', 'FAKE observed', '--directory', external.dir));

  await f.start();
  const first = await f.snapshot();
  expectEqual(first.connections.map(item => pick(item, 'id name hostId agentId mode')),
    [byName, byId, fileMode, senderDown],
    '§8 connections are what connect printed, oldest first; refused and removed registrations are absent');
  await f.code(senderDown.id, 'sender_unavailable', 'the sender status has not been readable since the registration');
  await f.configure({senderStatusExit: 0});
  await f.code(senderDown.id, 'ready', 'the sender answers');
  const second = await f.cli('serve', '--port', String(await freePort()));
  expectEqual(second.code, 73, '§7 a second writer refused by the process lock exits 73');

  // Disconnect is refused while the connection is in use, and accepted afterwards.
  const workflow = await f.create({connectionId: byName.id, enabled: true});
  const run = await f.newRun(workflow.id, 'queued');
  const [submit] = await f.submissions();
  expectEqual([option(submit.argv, '--peer'), option(submit.argv, '--agent'), option(submit.argv, '--state')],
    [ids.hostId, worker.id, f.senderDir],
    '§7 an agent-mode connection submits to its pinned host and agent through its sender state');
  const refusedWhile = async why => {
    const result = await f.cli('disconnect', '--id', byName.id);
    expect(oneErrorLine(result), `§7 disconnect is refused ${why}`, result);
    const now = await f.snapshot();
    expect(now.connections.some(item => item.id === byName.id) && now.workflows.some(item => item.id === workflow.id),
      `§7 a refused disconnect changes nothing (${why})`, now.connections.map(item => item.id));
  };
  await refusedWhile('while one of its runs is unresolved');
  const done = await f.finish(run, 'succeeded', {output: 'FAKE output kept after disconnect'});
  await refusedWhile('while a workflow that is not archived uses the connection');
  expectStatus(await f.request('POST', `/api/workflows/${workflow.id}/archive`, {}), 200, '§9 archive');
  expectEqual(JSON.parse(await f.checkedCli('disconnect', '--id', byName.id)), {id: byName.id, removed: true},
    '§7 disconnect is accepted once only an archived workflow uses the connection');
  await until('§1 a removed connection leaves the snapshot without a restart',
    async () => !(await f.snapshot()).connections.some(item => item.id === byName.id));
  expectEqual(pick((await f.detail(run.id)).run, 'id taskId state output'),
    pick(done, 'id taskId state output'), '§7 retained runs keep their history after disconnect');
  expect(oneErrorLine(await f.cli('disconnect', '--id', byName.id)), '§7 a removed connection is an unknown ID');

  // Unobserve removes the registration and never touches the observed directory.
  expect((await f.snapshot()).observed.some(item => item.id === observation.id), '§5 observe registers the directory');
  expectEqual(JSON.parse(await f.checkedCli('unobserve', '--id', observation.id)),
    {id: observation.id, removed: true}, '§7 unobserve prints {id,removed:true}');
  await until('§7 unobserve removes the observation registration',
    async () => !(await f.snapshot()).observed.some(item => item.id === observation.id));
  expectEqual((await fs.readdir(external.dir)).sort(), Object.keys(external.files).sort(),
    '§7 unobserve never touches the observed directory');
  for (const [name, content] of Object.entries(external.files)) {
    expectEqual(await fs.readFile(path.join(external.dir, name), 'utf8'), content, '§7 unobserve left ' + name);
  }

  // Doctor: six checks in order, one line each. Each probe runs against its own fake fixture directory.
  const doctor = async (rule, expected, {env = {}, state = f.state, fake} = {}) => {
    const probeDir = path.join(f.dir, 'FAKE-doctor-' + rule.replaceAll(' ', '-'));
    await fs.mkdir(probeDir, {mode: 0o700});
    await writeJson(path.join(probeDir, 'config.json'), fake ?? f.config);
    const result = await command(['doctor', '--state', state], {...f.env, FAKE_PEERSPAN_FIXTURE: probeDir, ...env});
    const lines = result.stdout.split('\n').filter(Boolean);
    expect(lines.length === 6 && lines.every(line => /^(ok|problem) /.test(line)),
      `§7 doctor (${rule}) prints one line for each of its six checks, starting with "ok " or "problem "`, result);
    expectEqual(lines.map(line => line.split(' ')[0]), expected, `§7 doctor (${rule}); the checks in order are ` +
      'Node, Linux, flock, private state, the executable starting, the executable accepting --json');
    expect((result.code === 0) === expected.every(word => word === 'ok'),
      `§7 doctor (${rule}) exits 0 only when no line starts with "problem "`, result);
    expect(!(result.stdout + result.stderr).includes(f.token), `§7 doctor (${rule}) never prints the access token`);
    return (await jsonLines(path.join(probeDir, 'calls.jsonl'))).map(call => call.argv);
  };
  const ok = Array(6).fill('ok');
  expectEqual(await doctor('working executable', ok), [['--json', 'status']],
    '§7 the last two doctor checks are one probe: --json status with no --state argument');
  await doctor('daemon not running', ok, {fake: {statusMode: 'daemon-not-running'}});
  await doctor('executable rejecting --json', [...ok.slice(0, 5), 'problem'], {fake: {rejectJson: true}});
  const absent = path.join(f.dir, 'never-created-state');
  await doctor('missing executable', [...ok.slice(0, 4), 'problem', 'problem'],
    {state: absent, env: {PEERSPAN_BIN: path.join(f.dir, 'FAKE-missing-peerspan')}});
  expectEqual(await fs.stat(absent).catch(() => null), null, '§7 doctor creates no state');
  const loose = path.join(f.dir, 'loose-state');
  await fs.mkdir(loose);
  await fs.chmod(loose, 0o755);
  await doctor('state directory not private', ['ok', 'ok', 'ok', 'problem', 'ok', 'ok'], {state: loose});
  expectEqual((await fs.stat(loose)).mode & 0o777, 0o755, '§7 doctor changes nothing');
  await f.stop();
}

// Case 7, readiness. §3: every readiness code, since, hints, and the candidate sessions of agent mode;
// §6: the status exit 2 object and the executable that rejects --json; §7: a replaced session is followed.
async function case07_readinessCodesAndHints() {
  const f = await fixture('readiness-codes');
  const verified = (sessionId, patch = {}) => ({session_id: sessionId, state: 'ready', channel: 'verified',
    channel_verified_at: '2026-01-01T00:00:00Z', ...patch});
  const session = (digit, patch = {}) => ({id: hex('session', digit), adapter_id: hex('adapter', digit),
    connection: 'ready', ...patch});
  const agents = sessions => [{id: ids.agentId, name: 'FAKE worker', sessions}];
  const pinned = {id: ids.sessionId, adapter_id: ids.adapterId, connection: 'ready'};
  const item = (kind, suggested) => ({kind, subject: 'PRIVATE-SUBJECT ' + kind, detail: 'PRIVATE-DETAIL ' + kind,
    command: suggested});
  const usable = item('fake_usable', 'peerspan adapter reconnect fake-usable');
  const baseline = {hostId: ids.hostId, active: true, statusExit: 1, statusMalformed: false, statusMode: 'normal',
    statusOmit: [], rejectJson: false, attention: [usable], agents: agents([pinned]),
    adapters: {[ids.adapterId]: verified(ids.sessionId)}, senderStatusExit: 0, senderHostId,
    senderAttention: [item('fake_sender_only', 'peerspan fake sender advice')]};
  await f.configure(baseline);
  const agentMode = JSON.parse(await f.checkedCli('connect', '--name', 'FAKE agent mode', '--agent', ids.agentId,
    '--host-state', f.workerDir, '--sender-state', f.senderDir)).id;
  const fileMode = f.connectionId;
  await f.start();
  const both = (code, why) => Promise.all([f.code(fileMode, code, why), f.code(agentMode, code, why)]);

  let [ready] = await both('ready', 'all evidence holds and status exits 1 with attention');
  expectEqual(ready.hints, [{kind: 'fake_usable', command: usable.command}], '§3 a hint is {kind,command}; a short ' +
    '"peerspan " command without / or \\ is usable; attention items of the sender host are not hints');
  await f.configure({active: false});
  const [inactive] = await both('ready_service_inactive', 'service.active is false');
  expect(/service/i.test(inactive.reason) && /inactive|not active/i.test(inactive.reason),
    '§3 the reason carries the advisory that the user service is inactive', inactive.reason);
  expectEqual(inactive.since, ready.since, '§3 since moves only when ready changes');
  await f.configure(baseline);
  await both('ready', 'service.active is true again');

  // Codes decided by status alone, for both connection modes. `silent` marks a status that could not be read.
  const blocked = [
    ['session_not_ready', 'the only session is disconnected', {agents: agents([{...pinned, connection: 'disconnected'}])}],
    ['agent_missing', 'the pinned agent is not listed', {agents: [{id: hex('agent', 9), name: 'FAKE other', sessions: []}]}],
    ['status_invalid', 'status is not JSON', {statusMalformed: true}, 'silent'],
    ['status_invalid', 'status exits 3', {statusExit: 3}],
    ['status_invalid', 'status lacks agents', {statusOmit: ['agents']}],
    ['status_invalid', 'status lacks attention', {statusOmit: ['attention']}],
    ['status_invalid', 'service.active is not a boolean', {active: 'yes'}],
    ['daemon_not_running', 'status exits 2 with the daemon-not-running object', {statusMode: 'daemon-not-running'}, 'silent'],
    ['daemon_not_running', 'status exits 2 with any other output', {statusExit: 2}],
    ['peerspan_incompatible', 'the executable rejects --json', {rejectJson: true}, 'silent'],
    ['identity_changed', 'status reports another host_id', {hostId: hex('host', 9, 64)}]];
  for (const [code, why, patch, silent] of blocked) {
    await f.configure(patch);
    for (const state of await both(code, why)) {
      // §1: recorded times never decrease, and stand still for as long as the wall clock was stepped back.
      const moved = Date.parse(state.since) - Date.parse(ready.since);
      expect(wallClockSteppedBack(50) ? moved >= 0 : moved > 0, `§3 since moves when ready changes (${why})`,
        {before: ready.since, now: state.since});
      if (silent) expectEqual(state.hints, [], `§3 hints are empty whenever status could not be read (${why})`);
    }
    await f.configure(baseline);
    [ready] = await both('ready', 'restored after: ' + why);
  }

  // The sender host: unreadable, or the worker host itself. Both block dispatch; a ready worker dispatches.
  const gated = await f.create();
  const senderTrouble = [
    ['sender_unavailable', 'the sender status exits 2', {senderStatusExit: 2}],
    ['sender_unavailable', 'the sender status exits 3', {senderStatusExit: 3}],
    ['sender_is_worker', 'the sender status reports the pinned worker host', {senderHostId: ids.hostId}]];
  for (const [code, why, patch] of senderTrouble) {
    await f.configure(patch);
    await both(code, why);
    await f.action(gated.id, 'resume');
    await f.action(gated.id, 'run');
    await delay(500);
    expectEqual((await f.submissions()).length, 0, `§3 ${code} blocks new dispatch (${why})`);
    await f.action(gated.id, 'pause');
    await f.configure(baseline);
    await both('ready', 'restored after: ' + why);
  }
  await f.action(gated.id, 'resume');
  await f.finish(await f.newRun(gated.id, 'queued'), 'succeeded');
  await f.action(gated.id, 'pause');
  await fs.rename(f.fake, f.fake + '.moved');
  for (const state of await both('peerspan_unavailable', 'the executable cannot be started')) {
    expectEqual(state.hints, [], '§3 hints are empty when the executable cannot be started');
  }
  await fs.rename(f.fake + '.moved', f.fake);
  await both('ready', 'the executable is back');

  const unverified = {
    'the channel is unverified': verified(ids.sessionId, {channel: 'unverified'}),
    'channel_verified_at is empty': verified(ids.sessionId, {channel_verified_at: ''}),
    'the adapter state is not ready': verified(ids.sessionId, {state: 'disconnected'}),
    'the adapter reports another session': verified(hex('session', 9)),
    'the adapter reports another adapter': verified(ids.sessionId, {adapter_id: hex('adapter', 9)}),
    'adapter connection fails': {exit: 1}};
  for (const [why, entry] of Object.entries(unverified)) {
    await f.configure({adapters: {[ids.adapterId]: entry}});
    await both('channel_unverified', why);
    await f.configure(baseline);
    await both('ready', 'restored after: ' + why);
  }

  // Codes that only file mode can have: they come from the worker state file.
  const fileOnly = [
    ['worker_state_invalid', 'the worker state file is missing', null],
    ['worker_state_invalid', 'the worker state file is not the documented JSON', {FAKE: 'not the documented JSON'}],
    ['identity_changed', 'the worker state file names another agent', {...f.worker, agent_id: hex('agent', 8)}],
    ['identity_changed', 'the worker state file names another host directory', {...f.worker, host_dir: f.workerDir + '-other'}]];
  for (const [code, why, content] of fileOnly) {
    if (content === null) await fs.rename(f.workerFile, f.workerFile + '.moved');
    else await writeJson(f.workerFile, content);
    await f.code(fileMode, code, why);
    expectEqual((await f.readiness(agentMode)).code, 'ready', `§7 agent mode does not depend on the worker state file (${why})`);
    if (content === null) await fs.rename(f.workerFile + '.moved', f.workerFile);
    else await writeJson(f.workerFile, f.worker);
    await f.code(fileMode, 'ready', 'restored after: ' + why);
  }

  // Hints: status order, kinds outside ^[a-z_]{1,64}$ skipped, unusable commands null, never detail or subject.
  const mixed = [usable, item('fake_path', 'peerspan --state /PRIVATE-HINT-PATH repair'),
    item('Fake-Bad-Kind', 'peerspan fake skipped'), item('fake_backslash', 'peerspan repair PRIVATE\\HINT'),
    item('fake_other_program', 'rm -rf PRIVATE-HINT'), item('f'.repeat(65), 'peerspan fake skipped'),
    item('fake_too_long', 'peerspan ' + 'x'.repeat(192)), item('fake_longest', 'peerspan ' + 'x'.repeat(191)),
    item('fake_control', 'peerspan fake\u0007bell'), item('fake_unicode', 'peerspan fake λ')];
  await f.configure({attention: mixed});
  const hinted = await until('§3 hints follow the attention items of the latest status', async () => {
    const state = await f.readiness(fileMode);
    return state.hints.length !== 1 && state;
  });
  const nulled = ['fake_path', 'fake_backslash', 'fake_other_program', 'fake_too_long', 'fake_control', 'fake_unicode'];
  expectEqual(hinted.hints, mixed.filter(entry => /^[a-z_]{1,64}$/.test(entry.kind))
    .map(entry => ({kind: entry.kind, command: nulled.includes(entry.kind) ? null : entry.command})),
  '§3 hints keep status order, skip other kinds, and null a command that is not "peerspan …", is over 200 ' +
    'printable ASCII characters, or contains / or \\');
  expectEqual(pick(hinted, 'ready code'), {ready: true, code: 'ready'}, '§3 hints never change ready');
  const twelve = [...'abcdefghijkl'].map(letter => item('fake_item_' + letter, 'peerspan fake ' + letter));
  await f.configure({attention: twelve});
  const capped = await until('§3 hints follow a status with twelve attention items', async () => {
    const state = await f.readiness(agentMode);
    return state.hints[0]?.kind === 'fake_item_a' && state;
  });
  expectEqual(capped.hints, twelve.slice(0, 10).map(entry => pick(entry, 'kind command')),
    '§3 at most ten hints, in the order status reports them');
  await f.configure(baseline);

  // Agent mode follows a replaced session without operator action: the new session attaches, then the
  // old one disconnects. File mode stays pinned to the session named by its worker state file.
  const before = await f.code(agentMode, 'ready', 'before the session is replaced');
  const next = session(7);
  const adapterCalls = async adapterId => (await f.calls())
    .filter(call => call.argv.includes('connection') && call.argv.includes(adapterId)).length;
  await f.configure({agents: agents([pinned, next]),
    adapters: {[ids.adapterId]: verified(ids.sessionId), [next.adapter_id]: verified(next.id)}});
  await delay(600);
  await f.configure({agents: agents([{...pinned, connection: 'disconnected'}, next]),
    adapters: {[ids.adapterId]: verified(ids.sessionId, {state: 'disconnected'}), [next.adapter_id]: verified(next.id)}});
  await f.code(fileMode, 'session_not_ready', 'file mode stays pinned to the session named by the worker state file');
  await until('§3 the replacement session adapter connection is checked', async () => await adapterCalls(next.adapter_id) > 0);
  const followed = await f.readiness(agentMode);
  expectEqual(pick(followed, 'code since'), {code: 'ready', since: before.since},
    '§7 readiness follows a replaced session without operator action, and the worker never stopped being ready');
  await writeJson(f.workerFile, {...f.worker, session_id: next.id, adapter_id: next.adapter_id});
  await f.code(fileMode, 'ready', 'the worker state file names the new session and adapter of the same identities');

  // Agent-mode candidates: sessions with an adapter_id whose connection is ready, in ascending session ID
  // order, at most four checked, stopping at the first verified one. Status lists them out of order.
  const candidates = [session('e'), {id: hex('session', 0), connection: 'ready'},
    session(1, {connection: 'disconnected'}), session('a'), session('b'), session('c'), session('d')];
  const answers = Object.fromEntries(['a', 'b', 'c', 'd'].map(letter =>
    [hex('adapter', letter), verified(hex('session', letter), {channel: 'unverified'})]));
  answers[hex('adapter', 'e')] = verified(hex('session', 'e'));
  answers[hex('adapter', 1)] = verified(hex('session', 1));
  await f.configure({agents: agents(candidates), adapters: answers});
  await f.code(agentMode, 'channel_unverified', 'the first four ready candidates by session ID are unverified');
  await delay(500);
  expectEqual([await adapterCalls(hex('adapter', 'e')), await adapterCalls(hex('adapter', 1))], [0, 0],
    '§3 adapter connection is invoked for at most four ready candidates in ascending session ID order, ' +
    'and never for a candidate that is not ready');
  answers[hex('adapter', 'd')] = verified(hex('session', 'd'));
  await f.configure({adapters: answers});
  await f.code(agentMode, 'ready', 'the fourth ready candidate is verified; sessions without adapter_id or not ready do not count');
  // Now the first candidate is verified, and a verified session that sorts second appears afterwards.
  answers[hex('adapter', 'a')] = verified(hex('session', 'a'));
  await f.configure({adapters: answers});
  await delay(600);
  const runnerUp = {id: 'session_' + 'a'.repeat(31) + 'b', adapter_id: 'adapter_' + 'a'.repeat(31) + 'b', connection: 'ready'};
  answers[runnerUp.adapter_id] = verified(runnerUp.id);
  await f.configure({agents: agents([...candidates, runnerUp]), adapters: answers});
  await delay(700);
  expectEqual([(await f.readiness(agentMode)).code, await adapterCalls(runnerUp.adapter_id)], ['ready', 0],
    '§3 adapter connection checks stop at the first verified candidate');
  await f.stop();
}

// Case 8. §9: PATCH, the nextRunAt rules, archive and restore; §4: the single --input=TEXT argument, one
// uninspected submission, and one target per worker agent whichever sender; §10: a run's instructions;
// §7: disconnect while a run of the connection is unresolved.
async function case08_workflowEditingAndArchiving() {
  const f = await fixture('workflows');
  const otherSender = path.join(f.dir, 'PRIVATE-sender-second');
  await f.configure({senderStates: [f.senderDir, otherSender]});
  const second = JSON.parse(await f.checkedCli('connect', '--name', 'FAKE second sender',
    '--worker-state', f.workerFile, '--sender-state', otherSender)).id;
  await f.start();
  const hyphenated = '- FAKE first step\n--json --state FAKE-not-an-option $(touch NEVER_EXECUTE) `not-a-shell` λ';
  const created = await f.create({instructions: hyphenated, intervalMinutes: 5});
  const route = '/api/workflows/' + created.id;
  const before = await f.workflow(created.id);
  expectEqual(pick(before, 'enabled pausedBy instructions'), {enabled: false, pausedBy: 'operator', instructions: hyphenated},
    '§8 a workflow created paused has pausedBy operator');

  const invalid = [null, [], {}, {enabled: true}, {name: 'FAKE valid', enabled: false}, {name: 'FAKE valid', extra: 1},
    {id: 'FAKE'}, {nextRunAt: new Date().toISOString()}, {name: ''}, {name: 'x'.repeat(101)}, {instructions: ''},
    {instructions: 'x'.repeat(12001)}, {intervalMinutes: 0}, {intervalMinutes: 10081}, {intervalMinutes: '5'},
    {maxRunsPerDay: 0}, {maxRunsPerDay: 1001}, {maxRunsPerDay: 1.5}, {acceptanceMinutes: 0},
    {acceptanceMinutes: 1441}, {connectionId: 'FAKE-missing'}];
  for (const body of invalid) {
    expectError(await f.request('PATCH', route, body), 400, '§9 PATCH refuses ' + JSON.stringify(body).slice(0, 70));
  }
  expectError(await f.request('PATCH', '/api/workflows/FAKE-absent', {name: 'FAKE'}), 404, '§2 PATCH of an unknown workflow');
  expectEqual(await f.workflow(created.id), before, '§9 a refused PATCH changes nothing');
  const early = await f.patch(created.id, {name: 'FAKE renamed', intervalMinutes: 7});
  expectEqual(pick(early, 'name intervalMinutes enabled nextRunAt instructions'),
    {name: 'FAKE renamed', intervalMinutes: 7, enabled: false, nextRunAt: before.nextRunAt, instructions: hyphenated},
    '§9 PATCH returns the edited workflow, never enables it, and leaves nextRunAt alone without a terminal run');

  // Reserve a run whose submission is lost before it reaches the sender daemon, then edit the workflow.
  // Every inspection fails meanwhile, so the run stays reserved after its one uninspected submit attempt.
  await f.configure({submitMode: 'lost-missing', inspectMode: 'error'});
  expectEqual(pick(await f.action(created.id, 'resume'), 'enabled nextRunAt'),
    {enabled: true, nextRunAt: before.nextRunAt}, '§9 resume does not change nextRunAt');
  await f.action(created.id, 'run');
  await f.awaitSubmissions(1, '§4 a run is submitted once, without a preceding inspection, in the pass that reserved it');
  const reserved = await f.newRun(created.id);
  const [original] = await f.submissions();
  expectEqual((await f.calls()).find(item => item.argv.includes(reserved.taskId))?.argv, original.argv,
    '§4 the first Peerspan call for a newly reserved run is its submission');
  expectEqual(inputOf(original.argv), hyphenated,
    '§4 instructions that begin with a hyphen travel byte-identically in one --input=TEXT argument');
  expectEqual(['--task', '--peer', '--agent', '--state'].map(name => option(original.argv, name)),
    [reserved.taskId, ids.hostId, ids.agentId, f.senderDir], '§4 every other submit value keeps its own argument');
  const edit = {name: 'FAKE edited', instructions: 'FAKE edited instructions: only a later run may carry these',
    acceptanceMinutes: 60, connectionId: second};
  expectEqual(pick(await f.patch(created.id, edit), Object.keys(edit).join(' ')), edit,
    '§9 PATCH returns the workflow with the new values');
  const refused = await f.cli('disconnect', '--id', f.connectionId);
  expect(oneErrorLine(refused) && (await f.snapshot()).connections.some(item => item.id === f.connectionId),
    '§7 disconnect is refused while a run of the connection is unresolved, even though no workflow uses it now', refused);
  await f.configure({submitMode: 'normal', inspectMode: 'normal'});
  await f.awaitSubmissions(2, '§4 the reserved run is submitted again after a genuine not-found inspection');
  expectEqual((await f.submissions())[1].argv, original.argv,
    '§9 an edit never changes a reserved run: the replayed submission is byte-identical');
  const firstDone = await f.finish(await f.waitRun(reserved.id, 'queued'), 'failed');

  // The nextRunAt rules, with a terminal run.
  const rescheduled = await f.patch(created.id, {intervalMinutes: 45});
  expect(Math.abs(Date.parse(rescheduled.nextRunAt) - Date.parse(firstDone.finishedAt) - 45 * 60000) <= 1000,
    '§9 when intervalMinutes changes, nextRunAt becomes the latest terminal run finishedAt plus the new interval',
    {nextRunAt: rescheduled.nextRunAt, finishedAt: firstDone.finishedAt});
  expectEqual((await f.patch(created.id, {maxRunsPerDay: 40})).nextRunAt, rescheduled.nextRunAt,
    '§9 nextRunAt is unchanged by an edit that does not change intervalMinutes');
  for (const action of ['pause', 'resume']) {
    expectEqual((await f.action(created.id, action)).nextRunAt, rescheduled.nextRunAt, `§9 ${action} does not change nextRunAt`);
  }
  await delay(500);
  expectEqual((await f.submissions()).length, 2, '§9 a resumed workflow runs when its schedule says so, not at once');

  // The next dispatch uses the edited values; each run keeps the instructions it was submitted with.
  await f.action(created.id, 'run');
  const next = await f.newRun(created.id, 'queued');
  const latest = (await f.submissions()).at(-1).argv;
  const acceptance = (Date.parse(option(latest, '--deadline')) - Date.now()) / 60000;
  expect(inputOf(latest) === edit.instructions && option(latest, '--state') === otherSender &&
    option(latest, '--task') === next.taskId && acceptance > 50 && acceptance < 61,
  '§9 the next dispatch uses the edited instructions, connection and acceptance window', latest);
  expectEqual([(await f.detail(reserved.id)).run.instructions, (await f.detail(next.id)).run.instructions],
    [hyphenated, edit.instructions], '§10 a run detail has the exact input submitted for that run, whatever later edits say');

  // Archive is refused with an unresolved run; an archived workflow is never dispatched.
  expectError(await f.request('POST', route + '/archive', {}), 409, '§9 archive while the workflow has an unresolved run');
  for (const action of ['archive', 'restore']) {
    expectError(await f.request('POST', '/api/workflows/FAKE-absent/' + action, {}), 404, `§2 ${action} of an unknown workflow`);
  }
  // §4 (MGD-6): the target is the worker agent, whichever sender. This workflow reaches the same agent
  // through the first connection's sender while the run submitted through the second is unresolved.
  const holder = await f.create({name: 'FAKE same agent through the other sender', connectionId: f.connectionId, enabled: true});
  expectError(await f.request('POST', `/api/workflows/${holder.id}/archive`, {unknown: true}), 400, '§9 archive accepts only {}');
  expectError(await f.request('POST', `/api/workflows/${holder.id}/restore`, {}), 409, '§9 restore of a workflow that is not archived');
  await delay(600);
  expectEqual((await f.submissions()).length, 3,
    '§4 two connections that reach one worker agent through different sender states never hold it at the same time');
  await f.finish(next, 'failed');
  const holding = await f.newRun(holder.id, 'queued');
  expectEqual(option((await f.submissions()).at(-1).argv, '--state'), f.senderDir,
    '§4 once the agent is free, the waiting workflow is dispatched through its own sender state');
  await f.action(created.id, 'run');
  expectEqual(pick(await f.workflow(created.id), 'enabled failureStreak'), {enabled: true, failureStreak: 1},
    '§4 one failed run since resume reset the failure circuit: the workflow is enabled with a failure count of 1');
  const submitted = (await f.submissions()).length;
  expectStatus(await f.request('POST', route + '/archive', {}), 200, '§9 archive of a workflow without an unresolved run');
  const view = await f.snapshot();
  expect(!view.workflows.some(item => item.id === created.id), '§9 an archived workflow leaves workflows', view.workflows.map(item => item.name));
  expectEqual(view.archived.map(item => pick(item, 'id name')), [{id: created.id, name: 'FAKE edited'}],
    '§9 an archived workflow is listed in archived');
  expect(isTime(view.archived[0].archivedAt), '§8 archivedAt is a time', view.archived[0]);
  expectEqual(view.runs.filter(item => item.workflowId === created.id).map(item => pick(item, 'id state')),
    [{id: next.id, state: 'failed'}, {id: reserved.id, state: 'failed'}], '§8 runs of an archived workflow stay in runs');
  const history = expectStatus(await f.request('GET', '/api/runs?workflowId=' + created.id), 200, '§10 history of an archived workflow');
  expectEqual(history.data.runs.map(item => item.id), [next.id, reserved.id], '§9 archive keeps the workflow runs in run history');
  for (const [method, suffix, body] of [['POST', '/pause', {}], ['POST', '/resume', {}], ['POST', '/run', {}],
    ['POST', '/archive', {}], ['PATCH', '', {name: 'FAKE refused'}]]) {
    expectError(await f.request(method, route + suffix, body), 409, `§9 ${method} ${suffix || 'edit'} of an archived workflow`);
  }
  await f.finish(holding, 'succeeded');
  await delay(700);
  expectEqual((await f.submissions()).length, submitted,
    '§9 an archived workflow is never dispatched, even when it was due and its target became free');

  const restored = expectStatus(await f.request('POST', route + '/restore', {}), 200, '§9 restore').data;
  const kept = 'id name connectionId instructions intervalMinutes maxRunsPerDay acceptanceMinutes createdAt';
  expectEqual(pick(restored, 'enabled pausedBy failureStreak ' + kept), {enabled: false, pausedBy: 'operator', failureStreak: 0,
    id: created.id, ...edit, intervalMinutes: 45, maxRunsPerDay: 40, createdAt: before.createdAt},
  '§9 restore returns the workflow paused by the operator, with a failure count of 0 and its other fields as they were');
  const back = await f.snapshot();
  expectEqual([back.archived.length, back.workflows.find(item => item.id === created.id)?.recent.map(item => item.id)],
    [0, [next.id, reserved.id]], '§9 a restored workflow returns to workflows with its runs and leaves archived');
  expectError(await f.request('POST', route + '/restore', {}), 409, '§9 restore of a workflow that is no longer archived');
  expectStatus(await f.request('POST', `/api/workflows/${holder.id}/archive`, {}), 200, '§9 archive');
  expectEqual(JSON.parse(await f.checkedCli('disconnect', '--id', f.connectionId)), {id: f.connectionId, removed: true},
    '§7 disconnect is accepted once only an archived workflow uses the connection and none of its runs is unresolved');
  await f.stop();
}

// Case 9. §10: cancel; §4: the failure count and the successor after an operator-requested cancellation
// (decision MGD-1).
async function case09_cancellation() {
  const f = await fixture('cancellation');
  await f.start();
  const workflow = await f.create({enabled: true});
  const cancelRoute = run => `/api/runs/${run.id}/cancel`;
  const streak = async () => (await f.workflow(workflow.id)).failureStreak;
  // One real failure first, so "unchanged" below can be told from both an increment and a reset.
  await f.finish(await f.newRun(workflow.id, 'queued'), 'failed');
  expectEqual(await streak(), 1, '§4 a failed run increments the failure count');

  // A queued run: the request records cancelRequestedAt, task cancel is sent, the state waits for the remote.
  await f.action(workflow.id, 'run');
  const queued = await f.newRun(workflow.id, 'queued');
  expectEqual(queued.cancelRequestedAt, null, '§8 cancelRequestedAt is null before a cancel request');
  expectError(await f.request('POST', '/api/runs/FAKE-absent/cancel', {}), 404, '§10 cancel of an unknown run');
  expectError(await f.request('POST', cancelRoute(queued), {unknown: true}), 400, '§10 cancel accepts only {}');
  const asked = expectStatus(await f.request('POST', cancelRoute(queued), {}), 200, '§10 cancel of a queued run').data;
  expect(asked.id === queued.id && isTime(asked.cancelRequestedAt) && ['queued', 'running'].includes(asked.state),
    '§10 cancel records cancelRequestedAt, returns the run and sets no terminal state', asked);
  const repeat = expectStatus(await f.request('POST', cancelRoute(queued), {}), 200, '§10 a repeated cancel').data;
  expectEqual(repeat.cancelRequestedAt, asked.cancelRequestedAt, '§10 cancelRequestedAt is recorded once');
  await f.cancelSent(queued.taskId);
  const [call] = await f.taskCalls('cancel', queued.taskId);
  expect(call.argv.includes('--json') && option(call.argv, '--peer') === ids.hostId &&
    option(call.argv, '--state') === f.senderDir, '§10 the controller invokes task cancel --peer HOST ID with ' +
    '--json, through the sender state the run was submitted with', call.argv);
  const inspected = (await f.taskCalls('inspect', queued.taskId)).length;
  await until('§10 after a successful task cancel the controller keeps inspecting',
    async () => (await f.taskCalls('inspect', queued.taskId)).length >= inspected + 2);
  await delay(400);
  expectEqual(pick(await f.runById(queued.id), 'state finishedAt'), {state: 'queued', finishedAt: null},
    '§10 a cancel request never sets a terminal state by itself: the state waits for the remote record');
  expectEqual((await f.taskCalls('cancel', queued.taskId)).length, 1,
    '§10 once one task cancel invocation exits 0, the controller only inspects');
  await f.remoteEvent(queued.taskId, 'cancelled', {message: 'FAKE agent confirmed the stop'});
  const cancelled = await f.waitRun(queued.id, 'cancelled');
  expectEqual(pick(cancelled, 'reason cancelRequestedAt'),
    {reason: 'FAKE agent confirmed the stop', cancelRequestedAt: asked.cancelRequestedAt},
    '§8 reason is the terminal event message of a cancelled run');
  const after = await f.workflow(workflow.id);
  expectEqual(after.failureStreak, 1, '§4 a run cancelled at the operator request leaves the failure count unchanged');
  expect(Date.parse(after.nextRunAt) >= Date.parse(cancelled.finishedAt) + 59000,
    '§4 an operator-cancelled run still schedules the next run after the interval, at least one minute later',
    {nextRunAt: after.nextRunAt, finishedAt: cancelled.finishedAt});
  expectError(await f.request('POST', cancelRoute(queued), {}), 409, '§10 cancel of a terminal run');
  const log = expectStatus(await f.request('GET', '/api/activity?limit=200'), 200, '§11 activity').data.activity;
  expectEqual(log.filter(entry => entry.kind === 'run.cancel_requested' && entry.runId === queued.id)
    .map(entry => pick(entry, 'actor workflowId data')), [{actor: 'operator', workflowId: workflow.id, data: null}],
  '§11 one run.cancel_requested entry: a repeated cancel request records nothing');

  // A submission that never reached the sender daemon: its one uninspected attempt (§4) is lost before
  // acceptance and every inspection fails, so the run stays submitting. No submit may follow the cancel.
  await f.configure({submitMode: 'lost-missing', inspectMode: 'error'});
  const attempts = (await f.submissions()).length + 1;
  await f.action(workflow.id, 'run');
  await f.awaitSubmissions(attempts, '§4 a run is submitted once, without a preceding inspection, in the pass that reserved it');
  const unsent = await f.newRun(workflow.id);
  expectEqual(unsent.state, 'submitting', '§4 a run whose submission is uncertain is still submitting');
  const askedUnsent = expectStatus(await f.request('POST', cancelRoute(unsent), {}), 200, '§10 cancel of a submitting run').data;
  expect(askedUnsent.state === 'submitting' && isTime(askedUnsent.cancelRequestedAt),
    '§10 cancel of a submitting run records the request without a terminal state', askedUnsent);
  await f.configure({submitMode: 'normal', inspectMode: 'normal'});
  await f.waitRun(unsent.id, 'cancelled');
  await delay(400);
  expectEqual([(await f.submissions()).length, (await f.taskCalls('submit', unsent.taskId)).length,
    await fs.stat(f.remoteFile(unsent.taskId)).catch(() => null)], [attempts, 1, null],
  '§10 after a genuine not-found inspection a cancel-requested submitting run becomes cancelled and is ' +
    'never submitted again: the sender daemon never held the task');
  expectEqual(await streak(), 1, '§4 a never-sent run cancelled by the operator leaves the failure count unchanged');

  // A running run: a failing task cancel is repeated until one invocation exits 0; the agent finishes anyway.
  await f.action(workflow.id, 'run');
  const active = await f.newRun(workflow.id, 'queued');
  await f.remoteEvent(active.taskId, 'accepted');
  await f.waitRun(active.id, 'running');
  await f.configure({cancelMode: 'error'});
  expectStatus(await f.request('POST', cancelRoute(active), {}), 200, '§10 cancel of a running run');
  await until('§10 a failing task cancel invocation is repeated on later passes',
    async () => (await f.taskOutcomes('cancel', active.taskId)).filter(item => item.code !== 0).length >= 3);
  expectEqual((await f.runById(active.id)).state, 'running', '§10 a failing task cancel leaves the run state unchanged');
  await f.configure({cancelMode: 'normal'});
  await f.cancelSent(active.taskId);
  await delay(600);
  const outcomes = await f.taskOutcomes('cancel', active.taskId);
  expectEqual([outcomes.filter(item => item.code === 0).length, outcomes.at(-1).code,
    (await f.taskCalls('cancel', active.taskId)).length - outcomes.length], [1, 0, 0],
  '§10 task cancel is repeated until one invocation exits 0, and never after it');
  expectEqual((await f.runById(active.id)).state, 'running', '§10 the state is unchanged until the remote reports');
  const finished = await f.finish(active, 'succeeded', {output: 'FAKE finished anyway'});
  expect(finished.output === 'FAKE finished anyway' && isTime(finished.cancelRequestedAt),
    '§10 when the agent finishes anyway the run takes the agent result from the remote record', finished);
  expectEqual(await streak(), 0, '§4 a run that succeeds after a cancel request is a success like any other');
  expectError(await f.request('POST', cancelRoute(active), {}), 409, '§10 cancel of a terminal run');
  await f.stop();
}

// Case 10. §10: abandon; §4: reservations, the failure count and the successor (decision MGD-2).
async function case10_abandon() {
  const f = await fixture('abandon');
  await f.start();
  const workflow = await f.create({enabled: true});
  await f.finish(await f.newRun(workflow.id, 'queued'), 'failed');
  await f.action(workflow.id, 'run');
  const stuck = await f.newRun(workflow.id, 'queued');
  await f.configure({inspectMode: 'error'});   // the worker's record can no longer be read
  await until('the unreachable run shows a problem', async () => (await f.runById(stuck.id)).error !== null);
  const route = `/api/runs/${stuck.id}/abandon`;
  const mentions = async () => (await f.calls()).filter(call => call.argv.includes(stuck.taskId)).length;

  // The confirmation rule.
  for (const body of [{}, {confirm: hex('task', 'f')}, {confirm: stuck.id}, {confirm: true},
    {confirm: stuck.taskId, extra: true}, {confirm: stuck.taskId.toUpperCase()}]) {
    expectError(await f.request('POST', route, body), 400, '§10 abandon needs exactly {"confirm":TASK_ID}; refused ' + JSON.stringify(body));
  }
  expectError(await f.request('POST', '/api/runs/FAKE-absent/abandon', {confirm: stuck.taskId}), 404, '§10 abandon of an unknown run');
  expectEqual((await f.runById(stuck.id)).state, 'queued', '§10 a refused abandon changes nothing');
  const released = expectStatus(await f.request('POST', route, {confirm: stuck.taskId}), 200, '§10 abandon').data;
  expect(released.id === stuck.id && released.taskId === stuck.taskId && released.state === 'abandoned' &&
    isTime(released.finishedAt), '§10 abandon returns the run, now abandoned, with its task identity retained', released);
  expectError(await f.request('POST', route, {confirm: stuck.taskId}), 409, '§10 abandon of a terminal run');
  expectError(await f.request('POST', `/api/runs/${stuck.id}/cancel`, {}), 409, '§10 cancel of an abandoned run');
  const after = await f.workflow(workflow.id);
  expectEqual(pick(after, 'failureStreak enabled'), {failureStreak: 1, enabled: true},
    '§4 an abandoned run leaves the failure count unchanged');
  expect(Date.parse(after.nextRunAt) >= Date.parse(released.finishedAt) + 59000,
    '§4 an abandoned run still schedules the next run after the interval, at least one minute later',
    {nextRunAt: after.nextRunAt, finishedAt: released.finishedAt});
  expectEqual(pick(after.stats, 'succeeded failed'), {succeeded: 0, failed: 1}, '§8 an abandoned run is not a failed run in stats');

  // No later Peerspan call for that task. A pass that began before the request may still be finishing,
  // so the count is taken after a short settle; from then on it must not move, even though the fake
  // would now answer an inspection with a finished task.
  await delay(500);
  const settled = await mentions();
  await f.configure({inspectMode: 'normal'});
  await f.remoteEvent(stuck.taskId, 'succeeded', {output: 'FAKE late result that must never be fetched'});
  await f.action(workflow.id, 'run');
  const fresh = await f.newRun(workflow.id, 'queued');
  expect(fresh.taskId !== stuck.taskId && fresh.id !== stuck.id,
    '§10 reservations are released: a new run dispatches for the workflow and its target under a new task ID', fresh);
  await delay(800);
  expectEqual([await mentions(), (await f.runById(stuck.id)).state], [settled, 'abandoned'],
    '§10 the controller never again submits, inspects or cancels an abandoned task');
  await f.stop();
  await f.start();
  await f.waitRun(fresh.id, 'queued');
  await delay(800);
  expectEqual([await mentions(), (await f.runById(stuck.id)).state], [settled, 'abandoned'],
    '§10 an abandoned task stays untouched after a restart');
  const log = expectStatus(await f.request('GET', '/api/activity?limit=200'), 200, '§11 activity').data.activity;
  expectEqual(log.filter(entry => entry.kind === 'run.abandoned').map(entry => pick(entry, 'actor runId workflowId data')),
    [{actor: 'operator', runId: stuck.id, workflowId: workflow.id, data: null}], '§11 abandon records run.abandoned');
  await f.stop();
}

await runCases('operations', [case07_workerRegistrationAndLocalCommands, case07_readinessCodesAndHints,
  case08_workflowEditingAndArchiving, case09_cancellation, case10_abandon]);
