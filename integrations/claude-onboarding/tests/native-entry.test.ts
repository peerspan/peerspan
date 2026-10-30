/**
 * Independent GU-01b/GU-03a conformance, derived from section 2 of
 * docs/guided-session-contract.md and Claude Code's official native API.
 *
 * Run with Claude Code 2.1.303: claude plugin test integrations/claude-onboarding
 * No production module is imported; the native runtime loads it. Processes,
 * prompts, storage and interface operations are stubbed at their public boundary.
 * The mock clock avoids real waits. These fixtures do not prove model receipt.
 * Actual hot reload clears the native module environment; the kit only supplies
 * fresh modules per test. Real reload remains a separate native acceptance check.
 *
 * Official references: https://code.claude.com/docs/en/plugins/mods/test and
 * https://code.claude.com/docs/en/plugins/mods/reference, plus the 2.1.303 types.
 */
import { expect, mock, test } from 'claude-code/testing'
import type { Engine, Mounted, TestOptions } from 'claude-code/testing'
import type { On, PromptSubmitInput, PromptSubmitResult } from 'claude-code'

const ACK = 'mcp__peerspan__delivery_acknowledge'
const CWD = '/private current project/$(never-execute)'
const ORIGINAL_SESSION = 'native-original-conversation'
const RAW = 'DO_NOT_DISPLAY /private/provider-file psi2-SENSITIVE psl2-SENSITIVE adapter_token_SECRET'
const TIME = '2026-10-29T00:00:00Z'
const KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
const hex = (digit: string, count = 64) => digit.repeat(count)

function network(digit: string, name: string) {
  return {
    id: 'net_' + hex(digit), name, mode: 'decentralized', context_id: 'ctx_' + hex(digit),
    genesis_root_public_key: KEY, root_state_id: 'drs_' + hex(digit), root_public_key: KEY,
    root_epoch: 0, member: 'local-owner', host_public_key: KEY, person_public_key: KEY,
    provider: null, provider_state: { state: 'not_selected', code: '-', error: '-', required_ids: [] },
    authority: { state: 'unbound', not_after: '-', required_ids: [], conflict_ids: [] },
    delivery: { pending_proof_ids: [], peer_errors: [] }, created_at: TIME,
  }
}

function session(digit: string, state: string | null, channel: string | null) {
  const id = 'session_' + hex(digit, 32)
  const adapter_id = state === null ? null : 'adapter_' + hex(digit, 32)
  return {
    id, integration: 'claude-code', adapter_id, expires_at: state === null ? null : '2026-11-01T00:00:00Z',
    renewable: state !== null,
    connection: state === null ? null : {
      adapter_id, session_id: id, state, recoverable: true,
      lease_expires_at: state === 'ready' ? '2026-10-29T00:00:15Z' : null,
      last_seen_at: TIME, channel, channel_verified_at: channel === 'verified' ? TIME : null,
      protocol_version: '2025-06-18',
    },
  }
}

function request(digit: string, state: string) {
  return {
    request_id: 'link_' + hex(digit, 32), role: 'requester', mode: 'new', state,
    network_id: 'net_' + hex('1'), context_id: 'ctx_' + hex('1'), migration_proposal_id: '-',
    person_public_key: KEY, host_public_key: KEY, device_public_key: KEY,
    created_at: TIME, expires_at: '2026-10-29T01:00:00Z', request_packet_id: 'dpk_' + hex(digit),
    owner_offer_id: '-', selection_id: '-', administrator_offer_id: '-', owner_finalization_id: '-',
    manifest_id: '-', activation_id: '-', outcome_id: '-', selection_approved: false,
    commit_approved: false, completed: ['request_created'], attention: [], next: [],
  }
}

function empty() {
  return { version: 1, observed_at: TIME, host_id: 'host_' + hex('a'), networks: [], agents: [], requests: [], attention: [] }
}

const LONG_NAME = 'LongNetworkName'.repeat(500)
function populated(): any {
  return {
    ...empty(),
    networks: [network('1', 'Design room'), network('2', 'Sa\x1b[31mfe\x1b[0m\u202e room'),
      network('3', 'psi2-PRIVATE_INVITATION psl2-PRIVATE_PAIRING'), network('4', LONG_NAME)],
    agents: [
      { id: 'agent_' + hex('1', 32), name: 'alpha', sessions: [session('1', 'ready', 'verified'), session('2', 'ready', 'unverified')] },
      { id: 'agent_' + hex('2', 32), name: 'beta', sessions: [session('3', 'offline', 'verified'), session('4', null, null)] },
      { id: 'agent_' + hex('3', 32), name: 'gamma', sessions: [] },
    ],
    requests: [request('1', 'pending'), request('2', 'pending'), request('3', 'linked'), request('4', 'cancelled')],
    unknown_private_path: '/private/UNKNOWN_FIELD_MUST_NOT_BE_SHOWN',
    unknown_token: 'adapter_token_UNKNOWN_FIELD',
  }
}

function world(on: On, headless = false) {
  const clock = mock.clock(on, { now: 1000 })
  const w = {
    clock, sessionId: ORIGINAL_SESSION,
    commands: [] as any[], tools: [] as any[], processes: [] as any[], prompts: [] as any[],
    opened: [] as any[], closed: [] as any[], notices: [] as string[], forbidden: [] as string[],
    run: (_event: any): any => ({ value: { exitCode: 0, stdout: JSON.stringify(empty()), stderr: '' } }),
    submit: async (event: PromptSubmitInput): Promise<PromptSubmitResult> => ({ text: event.text, origin: event.origin }),
  }
  on('session.start', ($, e) => ({ cwd: e.cwd }))
  on('session.end', ($, e) => ({ sessionId: e.sessionId }))
  on('session.id', () => ({ value: w.sessionId }))
  on('session.cwd', () => ({ value: CWD }))
  on('session.surfaces', () => ({ value: headless ? [] : ['terminal'] }))
  on('session.surface', () => ({ value: headless ? null : 'terminal' }))
  on('command.register', ($, e) => { w.commands.push(e); return { value: undefined } })
  on('tool.register', ($, e) => { w.tools.push(e); return { value: undefined } })
  on('command.run', () => ({ text: 'unhandled fixture command' }))
  on('tool.call', () => ({ deny: 'unhandled fixture tool' }))
  on('process.run', ($, e) => { w.processes.push(e); return w.run(e) })
  on('prompt.submit', async ($, e) => { w.prompts.push(e); return w.submit(e) })
  on('ui.open', ($, e) => { w.opened.push(e); return { value: { isPlaced: !headless } } })
  on('ui.close', ($, e) => { w.closed.push(e); return { value: undefined } })
  on('ui.panes', () => ({ value: [] }))
  on('ui.render', () => ({ type: 'Text', props: {}, children: ['native core fallback'] }))
  on('ui.toast', ($, e) => { w.notices.push(e.text); return { value: undefined } })
  on('ui.log', ($, e) => { w.notices.push(e.text); return { value: undefined } })
  on('ui.status', ($, e) => { w.notices.push(String(e.text ?? '')); return { value: undefined } })
  on('store.set', () => { w.forbidden.push('store.set'); return { deny: 'no persistence in this fixture' } })
  on('fs.write', () => { w.forbidden.push('fs.write'); return { deny: 'no file writes in this fixture' } })
  on('process.spawn', async function* () { w.forbidden.push('process.spawn'); throw new Error('no spawning in this fixture') })
  on('http.fetch', () => { w.forbidden.push('http.fetch'); return { deny: 'no network in this fixture' } })
  on('model.complete', () => { w.forbidden.push('model.complete'); return { deny: 'no model in this fixture' } })
  on('session.send', () => { w.forbidden.push('session.send'); return { isDelivered: false } })
  return w
}

type World = ReturnType<typeof world>
type Pane = Mounted<'terminal', 'Pane'>

async function start($: Engine, interactive = true) {
  await $.session.start({ cwd: CWD, surface: interactive ? 'terminal' : null, isInteractive: interactive })
}

async function pane($: Engine): Promise<Pane> {
  return $.ui.mount({
    plugin: 'peerspan', surface: 'terminal', component: 'Pane', requestId: 'peerspan',
    viewport: { columns: 100, rows: 40 },
    props: { title: 'Peerspan', isFocused: true, bodyColumns: 80, placement: 'inline',
      scroll: { offset: 0, bodyRows: 30 }, view: {} },
  })
}

async function enter($: Engine) {
  await $.command.run({ command: 'peerspan', args: '', origin: { kind: 'composer' },
    presentation: { isFullscreen: false, columns: 100 } })
  return pane($)
}

async function text(ui: Pane, w?: World) {
  return (await ui.findAll({})).map(element => element.text).join('\n') + '\n' + (w?.notices.join('\n') ?? '')
}

async function key(ui: Pane, label: string) {
  const button = await ui.find({ type: 'Button', text: new RegExp('^' + label + '$') })
  expect(button, `native control ${label}`).toBeDefined()
  expect(button?.key).toBeDefined()
  return button!.key!
}

async function press(ui: Pane, label: string) {
  return ui.press({ key: await key(ui, label) })
}

async function stateIs(ui: Pane, state: string) {
  expect(await text(ui)).toContain('This conversation: ' + state)
}

function challenge(w: World, index = w.prompts.length - 1) {
  const match = /\{"probe_id":"([0-9a-f]{32})"\}/.exec(w.prompts[index]?.text ?? '')
  expect(match, 'fixed local prompt carries the public 128-bit challenge').toBeDefined()
  return match![1]
}

async function acknowledge($: Engine, probe_id: unknown, agentId?: string) {
  return $.tool.call({ tool: ACK, probe_id, ...(agentId ? { agentId } : {}) })
}

function refused(answer: any, probe: string) {
  expect(typeof answer?.deny === 'string' || answer?.isError === true, 'native acknowledgment refusal').toBe(true)
  expect(JSON.stringify(answer)).not.toContain(probe)
}

function noUnexpectedEffects(w: World) {
  expect(w.forbidden).toEqual([])
  for (const process of w.processes) {
    expect(process.argv).toEqual(['peerspan', 'onboarding'])
    expect(process.init?.timeoutMs).toBe(5000)
  }
}

test('load registers one command and one narrow tool without observing or prompting', async ($, on) => {
  const w = world(on)
  await start($)
  expect(w.commands.map(command => command.name)).toEqual(['peerspan'])
  expect(w.tools.map(tool => tool.name)).toEqual(['delivery_acknowledge'])
  const schema = w.tools[0].inputSchema
  expect(schema.type).toBe('object')
  expect(schema.required).toEqual(['probe_id'])
  expect(Object.keys(schema.properties)).toEqual(['probe_id'])
  expect(schema.properties.probe_id.type).toBe('string')
  expect(schema.additionalProperties).toBe(false)
  await w.clock.advance(120_000)
  expect(w.processes).toEqual([])
  expect(w.prompts).toEqual([])
  noUnexpectedEffects(w)
})

test('entry and Refresh only run literal default observation argv; unknown arguments run nothing', async ($, on) => {
  const w = world(on)
  await start($)
  for (const args of ['--state /elsewhere', '--approve', 'invite someone', '; echo unsafe']) {
    const result = await $.command.run({ command: 'peerspan', args,
      origin: { kind: 'composer' }, presentation: { isFullscreen: false, columns: 100 } })
    expect(result.text).toMatch(/usage|\/peerspan/i)
  }
  expect(w.processes).toEqual([])
  expect(w.prompts).toEqual([])
  const ui = await enter($)
  expect(w.opened).toHaveLength(1)
  expect(w.opened[0]).toMatchObject({ id: 'peerspan', title: 'Peerspan' })
  await press(ui, 'Refresh')
  expect(w.processes).toHaveLength(2)
  await stateIs(ui, 'unverified')
  await w.clock.advance(120_000)
  expect(w.processes).toHaveLength(2)
  expect(w.prompts).toEqual([])
  noUnexpectedEffects(w)
})

// Native 2.1.303 supports TestOptions.options at runtime; its published testing
// declaration omits that field. This was independently checked with a throwaway mod.
const configured: TestOptions & { options: Record<string, string> } = {
  options: { executable: '/fixture bin/peerspan;$(literal)', state: '/private host state/$(literal)' },
}
test('trusted executable and state paths remain single literal argv elements', configured, async ($, on) => {
  const w = world(on)
  await start($)
  const ui = await enter($)
  await press(ui, 'Refresh')
  expect(w.processes).toHaveLength(2)
  for (const process of w.processes) {
    expect(process.argv).toEqual([configured.options.executable, '--state', configured.options.state, 'onboarding'])
    expect(process.init?.timeoutMs).toBe(5000)
  }
  expect(await text(ui, w)).not.toContain(configured.options.executable)
  expect(await text(ui, w)).not.toContain(configured.options.state)
  expect(w.prompts).toEqual([])
  expect(w.forbidden).toEqual([])
})

test('headless entry gives a read-only summary and never starts a conversation check', async ($, on) => {
  const w = world(on, true)
  await start($, false)
  const answer = await $.command.run({ command: 'peerspan', args: '', origin: { kind: 'sdk' },
    presentation: { isFullscreen: false, columns: 80 } })
  expect(answer.text).toContain('Host: running')
  expect(answer.text).toContain('This conversation: unverified')
  expect(w.processes).toHaveLength(1)
  expect(w.prompts).toEqual([])
  noUnexpectedEffects(w)
})

test('empty and populated observations keep counts, safe names and conversation evidence distinct', async ($, on) => {
  const w = world(on)
  await start($)
  const ui = await enter($)
  let shown = await text(ui)
  for (const label of ['Networks', 'Local agents', 'Pending connections', 'Live adapters', 'Verified adapter channels']) {
    expect(shown).toMatch(new RegExp(label + ':\\s*0\\b'))
  }
  w.run = () => ({ value: { exitCode: 0, stdout: JSON.stringify(populated()), stderr: RAW } })
  await press(ui, 'Refresh')
  shown = await text(ui, w)
  for (const [label, count] of [['Networks', 4], ['Local agents', 3], ['Pending connections', 2],
    ['Live adapters', 2], ['Verified adapter channels', 1]] as const) {
    expect(shown).toMatch(new RegExp(label + ':\\s*' + count + '\\b'))
  }
  expect(shown).toContain('Design room')
  expect(shown).toContain('Safe room')
  expect(shown).not.toMatch(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/)
  for (const hidden of [LONG_NAME, 'psi2-PRIVATE_INVITATION', 'psl2-PRIVATE_PAIRING', RAW,
    'host_' + hex('a'), 'net_' + hex('1'), 'agent_' + hex('1', 32), 'session_' + hex('1', 32),
    'adapter_' + hex('1', 32), '/private/UNKNOWN_FIELD_MUST_NOT_BE_SHOWN', 'adapter_token_UNKNOWN_FIELD', ORIGINAL_SESSION]) {
    expect(shown).not.toContain(hidden)
  }
  await stateIs(ui, 'unverified')
  expect(w.prompts).toEqual([])
  noUnexpectedEffects(w)
})

test('all seven private token formats are redacted after terminal and bidi decoration is removed', async ($, on) => {
  const w = world(on)
  await start($)
  const ui = await enter($)
  const prefixes = ['psi2-', 'psl2-', 'peerspan-invite-v1.', 'peerspan-member-invite-v1.',
    'peerspan-person-invite-v1.', 'token_', 'instance_']
  for (const [index, prefix] of prefixes.entries()) {
    const plainSecret = `q${index}secret`
    const decoratedSecret = `z${index}secret`
    const split = Math.floor(prefix.length / 2)
    const plain = prefix + plainSecret
    const decorated = prefix.slice(0, split) + '\x1b[31m\u202e' + prefix.slice(split)
      + '\u202c\x1b[0m' + decoratedSecret
    // Both complete labels are shorter than the 80-character display bound;
    // a clipped prefix cannot make a missed redaction look like a passing case.
    expect(plain.length < 80 && decorated.length < 80).toBe(true)
    w.run = () => ({ value: { exitCode: 0, stdout: JSON.stringify({ ...empty(),
      networks: [network('1', plain), network('2', decorated)] }), stderr: '' } })
    await press(ui, 'Refresh')
    const shown = await text(ui, w)
    expect(shown).toContain('Host: running')
    expect(shown).toMatch(/Networks:\s*2\b/)
    expect(shown).not.toContain(prefix)
    expect(shown).not.toContain(plainSecret)
    expect(shown).not.toContain(decoratedSecret)
    expect(shown).not.toMatch(/[\x1b\u202a-\u202e\u2066-\u2069]/)
  }
  expect(w.prompts).toEqual([])
  noUnexpectedEffects(w)
})

test('failed, denied, malformed, unsupported and invalid reads invalidate a successful host view', async ($, on) => {
  const w = world(on)
  await start($)
  const ui = await enter($)
  const failures = [
    { value: { exitCode: 1, stdout: RAW, stderr: RAW } },
    { deny: 'process timed out after five seconds: ' + RAW },
    { value: { exitCode: 0, stdout: '{malformed ' + RAW, stderr: RAW } },
    { value: { exitCode: 0, stdout: JSON.stringify({ ...empty(), version: 2 }), stderr: RAW } },
    { value: { exitCode: 0, stdout: JSON.stringify({ ...empty(), agents: {} }), stderr: RAW } },
    { value: { exitCode: 0, stdout: JSON.stringify({ ...empty(), networks: [{ name: 9 }] }), stderr: RAW } },
  ]
  for (const failure of failures) {
    w.run = () => ({ value: { exitCode: 0, stdout: JSON.stringify(populated()), stderr: '' } })
    await press(ui, 'Refresh')
    expect(await text(ui)).toContain('Design room')
    w.run = () => failure
    await press(ui, 'Refresh')
    const shown = await text(ui, w)
    expect(shown).toContain('Host: unavailable')
    expect(shown).not.toContain('Host: running')
    expect(shown).not.toContain('Design room')
    expect(shown).not.toContain(RAW)
    expect(shown).not.toContain('{malformed')
    await stateIs(ui, 'unverified')
  }
  expect(w.prompts).toEqual([])
  noUnexpectedEffects(w)
})

test('only the explicit control submits a local plugin prompt and a main-engine acknowledgment verifies', async ($, on) => {
  const w = world(on)
  w.run = () => ({ value: { exitCode: 0, stdout: JSON.stringify(populated()), stderr: '' } })
  await start($)
  const ui = await enter($)
  await press(ui, 'Refresh')
  expect(w.prompts).toEqual([])
  const before = w.processes.length
  await press(ui, 'Check this conversation')
  expect(w.prompts).toHaveLength(1)
  await stateIs(ui, 'waiting')
  expect(await ui.find({ type: 'Button', text: /^Check this conversation$/ })).toBeUndefined()
  const probe = challenge(w)
  const prompt = w.prompts[0]
  expect(prompt.origin).toEqual({ kind: 'plugin', name: 'peerspan' })
  expect(prompt.asUser).toBeUndefined()
  expect(prompt.text).toContain(ACK)
  expect(prompt.attachments).toBeUndefined()
  expect(prompt.context).toBeUndefined()
  for (const hidden of ['Design room', 'host_', 'net_', 'agent_', 'session_', 'adapter_', 'psi2-', 'psl2-',
    ORIGINAL_SESSION, CWD, RAW, '/private/UNKNOWN_FIELD_MUST_NOT_BE_SHOWN']) {
    expect(prompt.text).not.toContain(hidden)
  }
  const answer: any = await acknowledge($, probe)
  expect(answer.deny).toBeUndefined()
  expect(answer.isError).not.toBe(true)
  expect(JSON.stringify(answer)).not.toContain(probe)
  expect(JSON.stringify(answer)).not.toContain('host_')
  await stateIs(ui, 'verified')
  expect(w.processes).toHaveLength(before)
  noUnexpectedEffects(w)
})

test('wrong, unknown, reused and superseded challenges are refused without granting evidence', async ($, on) => {
  const w = world(on)
  await start($)
  const ui = await enter($)
  refused(await acknowledge($, hex('f', 32)), hex('f', 32))
  await stateIs(ui, 'unverified')
  await press(ui, 'Check this conversation')
  const first = challenge(w)
  const wrong = first[0] === 'f' ? '0' + first.slice(1) : 'f' + first.slice(1)
  refused(await acknowledge($, wrong), wrong)
  await stateIs(ui, 'waiting')
  await acknowledge($, first)
  await stateIs(ui, 'verified')
  refused(await acknowledge($, first), first)
  await stateIs(ui, 'verified')
  await press(ui, 'Check this conversation')
  const second = challenge(w)
  expect(second).not.toBe(first)
  expect(w.prompts[1].text.replace(second, '<challenge>')).toBe(w.prompts[0].text.replace(first, '<challenge>'))
  refused(await acknowledge($, first), first)
  await stateIs(ui, 'waiting')
  await acknowledge($, second)
  await stateIs(ui, 'verified')
  noUnexpectedEffects(w)
})

const pluginCaller = {
  name: 'untrusted-caller',
  register(on: On) {
    on('command.run', { command: 'fixture-plugin-ack' }, async ($, e) => {
      const result = await $.tool.call({ tool: 'mcp__peerspan__delivery_acknowledge', probe_id: e.args })
      return { text: JSON.stringify(result) }
    })
  },
}
test('plugin origin and subagent loops cannot verify a main conversation challenge', { plugins: [pluginCaller] }, async ($, on) => {
  const w = world(on)
  await start($)
  const ui = await enter($)
  await press(ui, 'Check this conversation')
  const probe = challenge(w)
  const plugin = await $.command.run({ command: 'fixture-plugin-ack', args: probe,
    origin: { kind: 'composer' }, presentation: { isFullscreen: false, columns: 100 } })
  refused(JSON.parse(plugin.text!), probe)
  await stateIs(ui, 'waiting')
  refused(await acknowledge($, probe, 'fixture-subagent'), probe)
  await stateIs(ui, 'waiting')
  await acknowledge($, probe)
  await stateIs(ui, 'verified')
  noUnexpectedEffects(w)
})

test('changing the native conversation clears evidence and rejects its previous challenge', async ($, on) => {
  const w = world(on)
  await start($)
  const ui = await enter($)
  await press(ui, 'Check this conversation')
  const probe = challenge(w)
  w.sessionId = 'native-different-conversation'
  refused(await acknowledge($, probe), probe)
  await ui.redraw()
  await stateIs(ui, 'unverified')
  await press(ui, 'Check this conversation')
  const fresh = challenge(w)
  expect(fresh).not.toBe(probe)
  await acknowledge($, fresh)
  await stateIs(ui, 'verified')
  noUnexpectedEffects(w)
})

test('the sixty-second deadline is strict and a late timer cannot expire a newer check', async ($, on) => {
  const w = world(on)
  await start($)
  const ui = await enter($)
  await press(ui, 'Check this conversation')
  const first = challenge(w)
  await w.clock.advance(59_999)
  await acknowledge($, first)
  await stateIs(ui, 'verified')
  await press(ui, 'Check this conversation')
  const second = challenge(w)
  await w.clock.advance(1)
  await stateIs(ui, 'waiting')
  await w.clock.advance(59_999)
  await stateIs(ui, 'timed_out')
  refused(await acknowledge($, second), second)
  await stateIs(ui, 'timed_out')
  noUnexpectedEffects(w)
})

test('overlapping presses queue exactly one prompt while submission is still pending', async ($, on) => {
  const w = world(on)
  w.submit = async e => { await w.clock.sleep(1000); return { text: e.text, origin: e.origin } }
  await start($)
  const ui = await enter($)
  const control = await key(ui, 'Check this conversation')
  const first = ui.press({ key: control })
  void first.catch(() => undefined) // Keep a regression from creating an unhandled rejection.
  const second = ui.press({ key: control }).catch(() => undefined) // It may already have disappeared.
  await w.clock.settle()
  expect(w.prompts).toHaveLength(1)
  await stateIs(ui, 'waiting')
  await w.clock.advance(1000)
  await Promise.all([first, second])
  expect(w.prompts).toHaveLength(1)
  await stateIs(ui, 'waiting')
  noUnexpectedEffects(w)
})

for (const failure of ['drop', 'throw'] as const) {
  test(`a ${failure === 'drop' ? 'refused/dropped' : 'throwing'} submission becomes blocked with controlled text`, async ($, on) => {
    const w = world(on)
    w.submit = async () => { if (failure === 'throw') throw new Error(RAW); return { drop: RAW } }
    await start($)
    const ui = await enter($)
    await press(ui, 'Check this conversation')
    const probe = challenge(w)
    await stateIs(ui, 'blocked')
    expect(await text(ui, w)).not.toContain(RAW)
    refused(await acknowledge($, probe), probe)
    await stateIs(ui, 'blocked')
    noUnexpectedEffects(w)
  })
}

for (const late of ['queued', 'drop', 'throw'] as const) {
test(`a late ${late} submission cannot overwrite a newer verified check after close and reopen`, async ($, on) => {
  const w = world(on)
  let submissions = 0
  w.submit = async e => {
    if (++submissions === 1) {
      await w.clock.sleep(5000)
      if (late === 'drop') return { drop: RAW }
      if (late === 'throw') throw new Error(RAW)
    }
    return { text: e.text, origin: e.origin }
  }
  await start($)
  const ui = await enter($)
  const oldPress = ui.press({ key: await key(ui, 'Check this conversation') })
  void oldPress.catch(() => undefined)
  await w.clock.settle()
  const old = challenge(w)
  await press(ui, 'Close')
  expect(w.closed.some(close => close.id === 'peerspan')).toBe(true)
  await ui.unmount()
  const fresh = await enter($)
  await stateIs(fresh, 'unverified')
  await press(fresh, 'Check this conversation')
  const current = challenge(w)
  expect(current).not.toBe(old)
  await acknowledge($, current)
  await stateIs(fresh, 'verified')
  await w.clock.advance(5000)
  await oldPress
  await stateIs(fresh, 'verified')
  refused(await acknowledge($, old), old)
  noUnexpectedEffects(w)
})
}

test('observation failure invalidates the host without erasing independent conversation evidence', async ($, on) => {
  const w = world(on)
  await start($)
  const ui = await enter($)
  await press(ui, 'Check this conversation')
  await acknowledge($, challenge(w))
  await stateIs(ui, 'verified')
  w.run = () => ({ deny: RAW })
  await press(ui, 'Refresh')
  expect(await text(ui, w)).toContain('Host: unavailable')
  expect(await text(ui, w)).not.toContain(RAW)
  await stateIs(ui, 'verified')
  noUnexpectedEffects(w)
})

for (const lifecycle of ['close', 'end'] as const) {
  test(`${lifecycle} clears verified evidence and cancels old check lifetime`, async ($, on) => {
    const w = world(on)
    await start($)
    const ui = await enter($)
    await press(ui, 'Check this conversation')
    const old = challenge(w)
    await acknowledge($, old)
    await stateIs(ui, 'verified')
    if (lifecycle === 'close') {
      await press(ui, 'Close')
      expect(w.closed.some(close => close.id === 'peerspan')).toBe(true)
    } else {
      await $.session.end({ reason: 'clear', sessionId: ORIGINAL_SESSION, resume: { id: ORIGINAL_SESSION } })
      w.sessionId = 'native-after-clear'
    }
    await ui.unmount()
    const fresh = await enter($)
    await stateIs(fresh, 'unverified')
    refused(await acknowledge($, old), old)
    await w.clock.advance(60_000)
    await stateIs(fresh, 'unverified')
    noUnexpectedEffects(w)
  })
}

test('a fresh native module starts unverified and never restores evidence from storage', async ($, on) => {
  const w = world(on)
  await start($)
  const ui = await enter($)
  await stateIs(ui, 'unverified')
  refused(await acknowledge($, hex('e', 32)), hex('e', 32))
  await w.clock.advance(60_000)
  await stateIs(ui, 'unverified')
  expect(w.prompts).toEqual([])
  noUnexpectedEffects(w)
})
