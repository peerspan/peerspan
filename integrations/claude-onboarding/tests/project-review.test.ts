/**
 * Independent section-4 conformance. The native runtime loads the product;
 * this file imports no production module. Only documented native effects are
 * stubbed. Response fixtures follow section 3, including its review digest.
 * Run on retained Claude Code 2.1.303 with DISABLE_UPDATES=1, without inference.
 * Real native/daemon acceptance and actual hot reload remain separate checks.
 */
import { expect, mock, test } from 'claude-code/testing'
import type { Engine, Mounted, TestOptions } from 'claude-code/testing'
import type { On } from 'claude-code'

const HOST = 'host_' + 'a'.repeat(64)
const ROOT = '/private workspace/Project $(literal)'
const NATIVE = 'native-private-conversation'
const CWD = '/different/shell-working-directory'
const NOW = Date.parse('2026-10-29T12:00:00Z')
const RAW = 'DO_NOT_ECHO /private/provider-error psi2-provider-secret'
const id = (kind: string, n: number, size = 32) => kind + '_' + n.toString(16).padStart(size, '0')
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value))
const quoted = (value: string) => JSON.stringify(value).replace(/[\u200b\u202a-\u202e]/g,
  character => '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0'))
const timestamp = (milliseconds: number) => new Date(milliseconds).toISOString().replace('.000Z', 'Z')
const contextOf = (root = ROOT, native = NATIVE) => ({ project_root: root, native_session_id: native, integration: 'claude-code' })
const registryAgent = (n: number, name = 'Choice ' + n, owner = 'Owner ' + n, capabilities: string[] = []) => ({
  id: id('agent', n), name, owner, capabilities, created_at: timestamp(NOW - 1000),
})

function canonical(value: any): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']'
  if (value !== null && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}'
  }
  return JSON.stringify(value)
}

async function fixtureFlow(options: any = {}): Promise<any> {
  const n = options.n ?? 1
  const agent = options.agent ?? { id: id('agent', 100 + n), name: 'Reviewed agent', owner: 'Reviewed owner', capabilities: [] }
  const create = options.create ?? true
  const review = {
    version: 1, kind: 'attach_project', flow_id: id('flow', n), host_id: options.host ?? HOST,
    ...(options.context ?? contextOf()), create_agent: create,
    agent: { id: agent.id, name: agent.name, owner: agent.owner, capabilities: [...agent.capabilities] },
    session_id: id('session', 200 + n), expires_at: timestamp(options.expires ?? NOW + 900_000),
    effects: { register_agent: create, attach_session: true, issue_adapter_credential: false,
      grant_network_access: false, share_files: false, share_conversation: false, capability_calls: false },
  }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256',
    new TextEncoder().encode('peerspan-project-review-v1\n' + canonical(review))))
  const state = options.state ?? 'review'
  return { version: 1, flow_id: review.flow_id, state,
    review_id: 'review_' + Array.from(digest, b => b.toString(16).padStart(2, '0')).join(''), review,
    attachment: state === 'attached' || options.attached
      ? { agent_id: agent.id, session_id: review.session_id } : null,
    next_action: state === 'review' ? 'review' : state === 'attached' ? 'continue_adapter_setup' : 'restart_review' }
}

function fixture(on: On, headless = false) {
  const clock = mock.clock(on, { now: NOW })
  const w = {
    clock, root: ROOT, native: NATIVE, agents: [] as any[], retained: null as any, sequence: 10,
    calls: [] as any[], trace: [] as any[], outside: [] as string[], prompts: [] as any[],
    tools: [] as any[], forbidden: [] as string[],
    read: async (_kind: string, _payload: any, _event: any): Promise<any> => undefined,
  }
  w.read = async (kind, payload) => {
    if (kind === 'snapshot') return { version: 1, observed_at: timestamp(w.clock.now()), host_id: HOST,
      networks: [], requests: [], attention: [], agents: w.agents.map(a => ({ id: a.id, name: a.name, sessions: [] })) }
    if (kind === 'lookup') return { version: 1, host_id: HOST, context: payload, flow: w.retained, agents: w.agents }
    if (kind === 'prepare') {
      const existing = payload.agent.kind === 'existing'
      const agent = existing ? w.agents.find(a => a.id === payload.agent.id)
        : registryAgent(++w.sequence, payload.agent.name.trim(), payload.agent.owner.trim())
      w.retained = await fixtureFlow({ n: ++w.sequence, context: {
        project_root: payload.project_root, native_session_id: payload.native_session_id, integration: payload.integration,
      }, agent, create: !existing, expires: w.clock.now() + 900_000 })
      return w.retained
    }
    if (kind === 'inspect') return w.retained
    if (kind === 'decide') {
      w.retained = { ...w.retained, state: payload.decision === 'approve' ? 'attached' : 'declined',
        attachment: payload.decision === 'approve'
          ? { agent_id: w.retained.review.agent.id, session_id: w.retained.review.session_id } : null,
        next_action: payload.decision === 'approve' ? 'continue_adapter_setup' : 'restart_review' }
      return w.retained
    }
    throw Error('Unexpected public process request')
  }
  on('session.start', ($, e) => ({ cwd: e.cwd }))
  on('session.end', ($, e) => ({ sessionId: e.sessionId }))
  on('classic.CwdChanged', () => ({}))
  on('session.root', () => { w.trace.push({ kind: 'root', value: w.root }); return { value: w.root } })
  on('session.id', () => { w.trace.push({ kind: 'native', value: w.native }); return { value: w.native } })
  on('session.cwd', () => ({ value: CWD }))
  on('session.surfaces', () => ({ value: headless ? [] : ['terminal'] }))
  on('session.surface', () => ({ value: headless ? null : 'terminal' }))
  on('command.register', () => ({ value: undefined }))
  on('tool.register', ($, e) => { w.tools.push(e); return { value: undefined } })
  on('command.run', () => ({ text: 'unhandled fixture command' }))
  on('tool.call', () => ({ deny: 'unregistered fixture tool' }))
  on('process.run', async ($, e) => {
    const tail = e.argv.slice(e.argv.indexOf('onboarding') + 1)
    const kind = tail.length === 0 ? 'snapshot' : tail[1]
    const payload = e.init?.stdin ? JSON.parse(e.init.stdin) : undefined
    const call = { ...e, kind, payload }
    w.calls.push(call)
    w.trace.push({ kind, payload, argv: e.argv })
    const value = await w.read(kind, payload, e)
    if (value?.fixtureDeny) return { deny: RAW }
    if (value?.fixtureRaw) return { value: { exitCode: 0, stdout: value.fixtureRaw, stderr: RAW } }
    return { value: { exitCode: 0, stdout: JSON.stringify(value), stderr: '' } }
  })
  on('prompt.submit', ($, e) => { w.prompts.push(e); return { text: e.text, origin: e.origin } })
  on('ui.open', () => ({ value: { isPlaced: !headless } }))
  on('ui.close', () => ({ value: undefined }))
  on('ui.panes', () => ({ value: [] }))
  on('ui.render', () => ({ type: 'Text', props: {}, children: ['native core fallback'] }))
  on('ui.toast', ($, e) => { w.outside.push(e.text); return { value: undefined } })
  on('ui.log', ($, e) => { w.outside.push(e.text); return { value: undefined } })
  on('ui.status', ($, e) => { w.outside.push(String(e.text ?? '')); return { value: undefined } })
  on('store.set', () => { w.forbidden.push('store.set'); return { deny: 'no persistence' } })
  on('fs.write', () => { w.forbidden.push('fs.write'); return { deny: 'no project file writes' } })
  on('process.spawn', async function* () { w.forbidden.push('process.spawn'); throw Error('no spawning') })
  on('http.fetch', () => { w.forbidden.push('http.fetch'); return { deny: 'no network' } })
  on('model.complete', () => { w.forbidden.push('model.complete'); return { deny: 'no inference' } })
  on('session.send', () => { w.forbidden.push('session.send'); return { isDelivered: false } })
  return w
}

type World = ReturnType<typeof fixture>
type Pane = Mounted<'terminal', 'Pane'>
const count = (w: World, kind: string) => w.calls.filter(call => call.kind === kind).length
const last = (w: World, kind: string) => w.calls.filter(call => call.kind === kind).at(-1)

async function start($: Engine, interactive = true) {
  await $.session.start({ cwd: CWD, surface: interactive ? 'terminal' : null, isInteractive: interactive })
}
async function enter($: Engine, w: World): Promise<Pane> {
  const answer = await $.command.run({ command: 'peerspan', args: '', origin: { kind: 'composer' },
    presentation: { isFullscreen: false, columns: 100 } })
  w.outside.push(answer.text ?? '', ...(answer.context ?? []))
  return $.ui.mount({ plugin: 'peerspan', surface: 'terminal', component: 'Pane', requestId: 'peerspan',
    viewport: { columns: 100, rows: 40 }, props: { title: 'Peerspan', isFocused: true, bodyColumns: 80,
      placement: 'inline', scroll: { offset: 0, bodyRows: 30 }, view: {} } })
}
async function shown(ui: Pane) { return (await ui.findAll({})).map(e => e.text).join('\n') }
async function button(ui: Pane, label: string | RegExp) {
  const result = await ui.find({ type: 'Button', text: typeof label === 'string' ? new RegExp('^' + label + '$') : label })
  expect(result, 'native project control').toBeDefined()
  return result!.key!
}
async function press(ui: Pane, label: string | RegExp) { return ui.press({ key: await button(ui, label) }) }
async function input(ui: Pane, label: string) {
  const result = (await ui.findAll({ type: 'Input' })).find(element => element.props.label === label)
  expect(result, 'native project input').toBeDefined()
  return result!
}
async function noDecision(ui: Pane) {
  expect(await ui.find({ type: 'Button', text: /^Approve attachment$/ })).toBeUndefined()
  expect(await ui.find({ type: 'Button', text: /^Decline attachment$/ })).toBeUndefined()
}
async function connect($: Engine, w: World) {
  await start($)
  const ui = await enter($, w)
  await press(ui, 'Connect this project')
  return ui
}
function effects(w: World, executable = 'peerspan', state?: string) {
  expect(w.forbidden).toEqual([])
  const prefix = [executable, ...(state ? ['--state', state] : []), 'onboarding']
  for (const call of w.calls) {
    const suffix = call.kind === 'snapshot' ? [] : ['project', call.kind,
      ...(call.kind === 'inspect' ? [call.argv.at(-1)] : ['--stdin'])]
    expect(call.argv).toEqual([...prefix, ...suffix])
    expect(call.init?.timeoutMs).toBe(5000)
    expect(call.argv.includes(w.root)).toBe(false)
    expect(call.argv.includes(w.native)).toBe(false)
    if (call.kind === 'inspect' || call.kind === 'snapshot') expect(call.init?.stdin).toBeUndefined()
  }
  expect(w.tools.map(tool => tool.name)).toEqual(['delivery_acknowledge'])
}
function outsidePrivate(w: World, values: string[]) {
  const outside = w.outside.join('\n') + '\n' + w.prompts.map(p => p.text).join('\n')
  for (const value of [ROOT, NATIVE, RAW, ...values]) expect(outside).not.toContain(value)
}
async function expectedDecision(w: World, captured: any, choice: string) {
  expect(last(w, 'decide').payload).toEqual({ flow_id: captured.flow_id, review_id: captured.review_id,
    project_root: captured.review.project_root, native_session_id: captured.review.native_session_id,
    integration: captured.review.integration, decision: choice })
}

test('initial, headless and unknown-argument entry remain observation-only until explicit Connect', async ($, on) => {
  const w = fixture(on)
  await start($)
  expect(w.calls).toEqual([])
  for (const args of ['--approve', 'connect', 'project /private/path']) {
    const answer = await $.command.run({ command: 'peerspan', args, origin: { kind: 'composer' },
      presentation: { isFullscreen: false, columns: 100 } })
    w.outside.push(answer.text ?? '')
  }
  expect(w.calls).toEqual([])
  const ui = await enter($, w)
  await press(ui, 'Refresh')
  expect(w.calls.map(call => call.kind)).toEqual(['snapshot', 'snapshot'])
  expect(w.trace.filter(event => event.kind === 'root')).toEqual([])
  await press(ui, 'Connect this project')
  expect(w.calls.map(call => call.kind)).toEqual(['snapshot', 'snapshot', 'lookup'])
  expect(last(w, 'lookup').payload).toEqual(contextOf())
  expect(w.trace.some(event => event.kind === 'root' && event.value === ROOT)).toBe(true)
  expect(w.trace.some(event => event.kind === 'native' && event.value === NATIVE)).toBe(true)
  expect(await shown(ui)).toContain('Project: choose an agent')
  expect(w.prompts).toEqual([])
  outsidePrivate(w, [])
  effects(w)
})

test('headless summary never performs a private project lookup or preparation', async ($, on) => {
  const w = fixture(on, true)
  await start($, false)
  const answer = await $.command.run({ command: 'peerspan', args: '', origin: { kind: 'sdk' },
    presentation: { isFullscreen: false, columns: 80 } })
  w.outside.push(answer.text ?? '', ...(answer.context ?? []))
  expect(answer.text).toContain('Host: running')
  expect(w.calls.map(call => call.kind)).toEqual(['snapshot'])
  expect(w.prompts).toEqual([])
  outsidePrivate(w, [])
  effects(w)
})

test('unavailable initial observations cannot start a private project flow', async ($, on) => {
  const w = fixture(on)
  w.read = async () => ({ fixtureDeny: true })
  await start($)
  const ui = await enter($, w)
  expect(await ui.find({ type: 'Button', text: /^Connect this project$/ })).toBeUndefined()
  expect(await shown(ui)).toMatch(/unavailable/i)
  expect(w.calls.map(call => call.kind)).toEqual(['snapshot'])
  outsidePrivate(w, [])
  effects(w)
})

test('editable defaults, input submission and agent paging do not prepare; explicit selection pins its ID', async ($, on) => {
  const w = fixture(on)
  w.agents = Array.from({ length: 12 }, (_, n) => registryAgent(n + 1, 'Name "' + (n + 1) + '"', 'Owner \\' + (n + 1)))
  const ui = await connect($, w)
  expect((await input(ui, 'New agent name')).props.value).toBe('Project $(literal)')
  expect((await input(ui, 'Owner label')).props.value).toBe('local owner')
  const nameInput = await input(ui, 'New agent name')
  await ui.input({ key: nameInput.key!, text: 'Draft agent', kind: 'change' })
  await ui.input({ key: nameInput.key!, text: 'Draft agent' })
  const ownerInput = await input(ui, 'Owner label')
  await ui.input({ key: ownerInput.key!, text: 'Draft owner' })
  expect(count(w, 'prepare')).toBe(0)
  expect((await ui.findAll({ type: 'Button', text: /^Review agent / })).length).toBe(10)
  await press(ui, 'More agents')
  expect((await ui.findAll({ type: 'Button', text: /^Review agent / })).length).toBe(2)
  expect(count(w, 'prepare')).toBe(0)
  await press(ui, 'Previous agents')
  expect((await ui.findAll({ type: 'Button', text: /^Review agent / })).length).toBe(10)
  await press(ui, 'More agents')
  const selected = w.agents[11]
  const choices = await ui.findAll({ type: 'Button', text: /^Review agent / })
  const choice = choices.find(element => element.text.includes(JSON.stringify(selected.name)))
  expect(choice).toBeDefined()
  expect(await shown(ui)).toContain(JSON.stringify(selected.owner))
  await ui.press({ key: choice!.key! })
  expect(last(w, 'prepare').payload).toEqual({ ...contextOf(), agent: { kind: 'existing', id: selected.id } })
  expect(count(w, 'prepare')).toBe(1)
  expect(count(w, 'decide')).toBe(0)
  effects(w)
})

// 2.1.303 supports per-test trusted options, although its published TestOptions
// declaration omits the options field (checked with an independent throwaway mod).
const configured: TestOptions & { options: Record<string, string> } = {
  options: { executable: '/fixture bin/peerspan;$(literal)', state: '/private host state/$(literal)' },
}
test('explicit new-agent draft uses literal configured argv and stdin only', configured, async ($, on) => {
  const w = fixture(on)
  const ui = await connect($, w)
  await ui.input({ key: (await input(ui, 'New agent name')).key!, text: 'New "agent" $(literal)' })
  await ui.input({ key: (await input(ui, 'Owner label')).key!, text: 'Owner \\label' })
  expect(count(w, 'prepare')).toBe(0)
  await press(ui, 'Review new agent')
  expect(last(w, 'prepare').payload).toEqual({ ...contextOf(), agent: {
    kind: 'new', name: 'New "agent" $(literal)', owner: 'Owner \\label' } })
  expect(count(w, 'prepare')).toBe(1)
  expect(count(w, 'decide')).toBe(0)
  expect(await shown(ui)).toContain('Record this local session attachment')
  outsidePrivate(w, ['New "agent" $(literal)', 'Owner \\label'])
  effects(w, configured.options.executable, configured.options.state)
})

test('invalid root-derived defaults use project-agent and never choose an existing same-named agent', async ($, on) => {
  const w = fixture(on)
  w.agents = [registryAgent(1, 'project-agent')]
  await start($)
  for (const root of ['/', '/private/*', '/private/' + 'é'.repeat(65)]) {
    w.root = root
    const ui = await enter($, w)
    await press(ui, 'Connect this project')
    expect((await input(ui, 'New agent name')).props.value).toBe('project-agent')
    expect(count(w, 'prepare')).toBe(0)
    if (root.endsWith('é')) await press(ui, 'Review new agent')
    await press(ui, 'Close')
    await ui.unmount()
  }
  expect(last(w, 'prepare').payload.agent.kind).toBe('new')
  effects(w)
})

test('retained review resumes with full reversible terms, effects and private internal references', async ($, on) => {
  const w = fixture(on)
  const agent = registryAgent(1, 'Full-' + 'n'.repeat(90) + '"\\\u202e', 'Owner \\"東京"\u200b', ['descriptive', 'metadata "label"'])
  w.agents = [agent, registryAgent(2, 'Unrelated first default')]
  w.retained = await fixtureFlow({ agent, create: false })
  const flow = clone(w.retained)
  const ui = await connect($, w)
  const text = await shown(ui)
  const normalizedEscapes = text.replace(/\\u([0-9a-fA-F]{4})/g, (_, digits) => '\\u' + digits.toLowerCase())
  expect(count(w, 'prepare')).toBe(0)
  expect(text).toContain(JSON.stringify(ROOT))
  expect(text).toContain('Conversation: current conversation')
  expect(text).toContain('Agent record: existing')
  expect(text).toContain('Review expires')
  expect(text).toContain(flow.review.expires_at)
  expect(text).toContain('Full-' + 'n'.repeat(90))
  expect(normalizedEscapes).toContain(quoted(agent.name))
  expect(normalizedEscapes).toContain(quoted(agent.owner))
  expect(text.includes('\\u202e') || text.includes('\\u202E')).toBe(true)
  expect(text.includes('\\u200b') || text.includes('\\u200B')).toBe(true)
  expect(text).not.toMatch(/[\u202a-\u202e\u200b]/)
  for (const value of [JSON.stringify(agent.capabilities[0]), JSON.stringify(agent.capabilities[1]), 'Adapter credentials: none', 'Network access: none',
    'File sharing: none', 'Conversation sharing: none', 'Capability calls: none', 'Record this local session attachment']) {
    expect(text).toContain(value)
  }
  for (const value of [HOST, flow.flow_id, flow.review_id, agent.id, flow.review.session_id, NATIVE]) expect(text).not.toContain(value)
  expect(await ui.find({ type: 'Button', text: /^Approve attachment$/ })).toBeDefined()
  expect(await ui.find({ type: 'Button', text: /^Decline attachment$/ })).toBeDefined()
  outsidePrivate(w, [agent.name, agent.owner, flow.review_id])
  effects(w)
})

test('malformed, mismatched and unreviewed flow terms never expose decision controls', { timeoutMs: 15_000 }, async ($, on) => {
  const w = fixture(on)
  const valid = await fixtureFlow()
  const ui = await connect($, w)
  const mutations: ((flow: any) => void)[] = [
    f => { f.version = 2 }, f => { f.extra = true }, f => { f.review.extra = false },
    f => { f.review.agent.extra = false }, f => { f.review.effects.extra_power = false },
    f => { f.review.effects.share_files = true }, f => { f.review.host_id = id('host', 2, 64) },
    f => { f.review.native_session_id = 'different-native' }, f => { f.review.project_root = '/other/root' },
    f => { f.review.integration = 'opencode' }, f => { f.review.agent.name = 'x'.repeat(129) },
    f => { f.review.agent.capabilities = Array.from({ length: 101 }, () => 'metadata') },
    f => { f.review.agent.capabilities = ['x'.repeat(257)] }, f => { f.flow_id = 'bad-flow' },
    f => { f.next_action = 'continue_adapter_setup' }, f => { f.attachment = { agent_id: id('agent', 2), session_id: id('session', 2) } },
  ]
  for (const mutate of mutations) {
    const broken = clone(valid)
    mutate(broken)
    w.retained = broken
    await press(ui, 'Refresh')
    // The first Connect made this a private project view; Refresh must lookup.
    await noDecision(ui)
    expect(await shown(ui)).toMatch(/unavailable|invalid|changed|cannot|represent/i)
  }
  w.retained = valid
  const normal = w.read
  for (const mutate of [
    (value: any) => { value.version = 2 }, (value: any) => { value.host_id = id('host', 2, 64) },
    (value: any) => { value.context.native_session_id = 'different-native' },
    (value: any) => { value.agents = {} },
  ]) {
    w.read = async (kind, payload, e) => {
      const value = clone(await normal(kind, payload, e))
      if (kind === 'lookup') mutate(value)
      return value
    }
    await press(ui, 'Refresh')
    await noDecision(ui)
  }
  expect(count(w, 'decide')).toBe(0)
  expect(count(w, 'prepare')).toBe(0)
  effects(w)
})

test('all private prefixes, including decorated ones, block an unambiguous human review', { timeoutMs: 15_000 }, async ($, on) => {
  const w = fixture(on)
  const ui = await connect($, w)
  for (const [index, prefix] of ['psi2-', 'psl2-', 'peerspan-invite-v1.', 'peerspan-member-invite-v1.',
    'peerspan-person-invite-v1.', 'token_', 'instance_'].entries()) {
    for (const decorated of [false, true]) {
      const payload = 'q' + index + 'secret'
      const cut = Math.floor(prefix.length / 2)
      const privateName = decorated ? prefix.slice(0, cut) + '\x1b[31m\u202e' + prefix.slice(cut) + payload : prefix + payload
      w.retained = await fixtureFlow({ n: 20 + index, agent: registryAgent(20 + index, privateName) })
      await press(ui, 'Refresh')
      await noDecision(ui)
      const text = await shown(ui)
      expect(text).toMatch(/unavailable|private|cannot|invalid/i)
      expect(text).not.toContain(prefix)
      expect(text).not.toContain(payload)
    }
  }
  expect(count(w, 'decide')).toBe(0)
  outsidePrivate(w, [])
  effects(w)
})

for (const choice of ['approve', 'decline'] as const) {
  test(`native ${choice} captures the exact review and checks trusted context before and after inspection`, async ($, on) => {
    const w = fixture(on)
    w.retained = await fixtureFlow()
    const captured = clone(w.retained)
    const ui = await connect($, w)
    const before = w.trace.length
    await press(ui, choice === 'approve' ? 'Approve attachment' : 'Decline attachment')
    expect(count(w, 'inspect')).toBe(1)
    expect(count(w, 'decide')).toBe(1)
    await expectedDecision(w, captured, choice)
    const trace = w.trace.slice(before)
    const inspect = trace.findIndex(e => e.kind === 'inspect')
    const decide = trace.findIndex(e => e.kind === 'decide')
    for (const kind of ['root', 'native']) {
      expect(trace.slice(0, inspect).some(e => e.kind === kind)).toBe(true)
      expect(trace.slice(inspect + 1, decide).some(e => e.kind === kind)).toBe(true)
    }
    expect(last(w, 'inspect').argv.at(-1)).toBe(captured.flow_id)
    if (choice === 'approve') {
      expect(await shown(ui)).toContain('Project: attachment recorded')
      expect(await shown(ui)).toContain('Adapter connection is next')
    } else expect(await shown(ui)).toMatch(/declined/i)
    expect(w.prompts).toEqual([])
    outsidePrivate(w, [captured.review_id])
    effects(w)
  })
}

test('changed inspected terms, hash, state, host or native context prevent every owner decision', { timeoutMs: 15_000 }, async ($, on) => {
  const w = fixture(on)
  const valid = await fixtureFlow()
  w.retained = valid
  const normal = w.read
  const ui = await connect($, w)
  const mutations: ((flow: any) => void)[] = [f => { f.review.agent.name = 'Changed terms' },
    f => { f.review_id = 'review_' + 'f'.repeat(64) }, f => { f.state = 'expired'; f.next_action = 'restart_review' },
    f => { f.review.host_id = id('host', 2, 64) }]
  for (const mutate of mutations) {
    w.retained = clone(valid)
    w.read = normal
    await press(ui, 'Refresh')
    w.read = async (kind, payload, e) => {
      if (kind === 'inspect') { const response = clone(valid); mutate(response); return response }
      return normal(kind, payload, e)
    }
    await press(ui, 'Approve attachment')
    expect(count(w, 'decide')).toBe(0)
    await noDecision(ui)
  }
  for (const when of ['before-inspect', 'after-inspect']) {
    w.root = ROOT
    w.native = NATIVE
    w.retained = clone(valid)
    w.read = normal
    await press(ui, 'Refresh')
    if (when === 'before-inspect') w.root = '/different/native-root'
    else w.read = async (kind, payload, e) => {
      if (kind === 'inspect') { w.native = 'different-native-after-inspect'; return valid }
      return normal(kind, payload, e)
    }
    await press(ui, 'Approve attachment')
    expect(count(w, 'decide')).toBe(0)
    await noDecision(ui)
  }
  effects(w)
})

test('overlapping approval presses send one inspected exact decision', async ($, on) => {
  const w = fixture(on)
  w.retained = await fixtureFlow()
  const normal = w.read
  w.read = async (kind, payload, e) => { if (kind === 'inspect') await w.clock.sleep(1000); return normal(kind, payload, e) }
  const ui = await connect($, w)
  const key = await button(ui, 'Approve attachment')
  const first = ui.press({ key })
  void first.catch(() => undefined)
  const second = ui.press({ key }).catch(() => undefined)
  await w.clock.settle()
  await w.clock.advance(1000)
  await Promise.all([first, second])
  expect(count(w, 'inspect')).toBe(1)
  expect(count(w, 'decide')).toBe(1)
  effects(w)
})

test('failed lookup or preparation and a failed Refresh remove actionable reviews with controlled diagnostics', async ($, on) => {
  const w = fixture(on)
  w.retained = await fixtureFlow()
  const normal = w.read
  const ui = await connect($, w)
  for (const failure of [{ fixtureDeny: true }, { fixtureRaw: '{malformed ' + RAW }]) {
    w.read = async (kind, payload, e) => kind === 'lookup' ? failure : normal(kind, payload, e)
    await press(ui, 'Refresh')
    await noDecision(ui)
    expect(await shown(ui)).not.toContain(RAW)
    w.read = normal
    await press(ui, 'Refresh')
    expect(await ui.find({ type: 'Button', text: /^Approve attachment$/ })).toBeDefined()
  }
  await press(ui, 'Back to Peerspan')
  w.retained = null
  await press(ui, 'Connect this project')
  w.read = async (kind, payload, e) => kind === 'prepare' ? { fixtureDeny: true } : normal(kind, payload, e)
  await press(ui, 'Review new agent')
  await noDecision(ui)
  expect(await shown(ui)).not.toContain(RAW)
  expect(count(w, 'decide')).toBe(0)
  outsidePrivate(w, [])
  effects(w)
})

test('lost decision response is outcome-unknown and Refresh resolves it by lookup without retry', async ($, on) => {
  const w = fixture(on)
  w.retained = await fixtureFlow()
  const normal = w.read
  w.read = async (kind, payload, e) => {
    if (kind === 'decide') { await normal(kind, payload, e); return { fixtureDeny: true } }
    return normal(kind, payload, e)
  }
  const ui = await connect($, w)
  await press(ui, 'Approve attachment')
  expect(count(w, 'decide')).toBe(1)
  await noDecision(ui)
  expect(await shown(ui)).toMatch(/unknown|uncertain/i)
  expect(await shown(ui)).not.toContain(RAW)
  await w.clock.advance(10_000)
  expect(count(w, 'decide')).toBe(1)
  await press(ui, 'Refresh')
  expect(await shown(ui)).toContain('Project: attachment recorded')
  expect(count(w, 'decide')).toBe(1)
  outsidePrivate(w, [])
  effects(w)
})

test('failed inspection and mismatched decision results cannot report an attachment', async ($, on) => {
  const w = fixture(on)
  const valid = await fixtureFlow()
  w.retained = valid
  const normal = w.read
  const ui = await connect($, w)
  w.read = async (kind, payload, e) => kind === 'inspect' ? { fixtureDeny: true } : normal(kind, payload, e)
  await press(ui, 'Approve attachment')
  expect(count(w, 'decide')).toBe(0)
  await noDecision(ui)
  expect(await shown(ui)).not.toContain(RAW)
  for (const mutate of [
    (flow: any) => { flow.review_id = 'review_' + 'f'.repeat(64) },
    (flow: any) => { flow.flow_id = id('flow', 999) },
    (flow: any) => { flow.attachment.agent_id = id('agent', 999) },
    (flow: any) => { flow.review.agent.owner = 'Unreviewed owner' },
  ]) {
    w.retained = clone(valid)
    w.read = normal
    await press(ui, 'Refresh')
    w.read = async (kind, payload, e) => {
      const response = clone(await normal(kind, payload, e))
      if (kind === 'decide') mutate(response)
      return response
    }
    await press(ui, 'Approve attachment')
    expect(await shown(ui)).not.toContain('Project: attachment recorded')
    await noDecision(ui)
  }
  expect(count(w, 'decide')).toBe(4)
  outsidePrivate(w, [])
  effects(w)
})

test('an already-sent old decision cannot replace the review of a different native context', async ($, on) => {
  const w = fixture(on)
  w.retained = await fixtureFlow()
  const captured = clone(w.retained)
  const normal = w.read
  w.read = async (kind, payload, e) => {
    const response = clone(await normal(kind, payload, e))
    if (kind === 'decide') await w.clock.sleep(1000)
    return response
  }
  const ui = await connect($, w)
  const pending = ui.press({ key: await button(ui, 'Approve attachment') })
  void pending.catch(() => undefined)
  await w.clock.settle()
  expect(count(w, 'decide')).toBe(1)
  await expectedDecision(w, captured, 'approve')
  await press(ui, 'Close')
  await ui.unmount()
  w.root = '/new/private/context-after-sent-decision'
  w.native = 'new-native-after-sent-decision'
  w.retained = await fixtureFlow({ n: 3, context: contextOf(w.root, w.native) })
  const fresh = await enter($, w)
  await press(fresh, 'Connect this project')
  await w.clock.advance(1000)
  await pending
  expect(await shown(fresh)).not.toContain('Project: attachment recorded')
  expect(await shown(fresh)).toContain(JSON.stringify(w.root))
  expect(await fresh.find({ type: 'Button', text: /^Approve attachment$/ })).toBeDefined()
  expect(count(w, 'decide')).toBe(1)
  effects(w)
})

test('a pending old inspection cannot decide after Close and a newer displayed review', async ($, on) => {
  const w = fixture(on)
  const old = await fixtureFlow()
  const newer = await fixtureFlow({ n: 2 })
  w.retained = old
  const normal = w.read
  w.read = async (kind, payload, e) => {
    if (kind === 'inspect') { const captured = clone(w.retained); await w.clock.sleep(1000); return captured }
    return normal(kind, payload, e)
  }
  const ui = await connect($, w)
  const pending = ui.press({ key: await button(ui, 'Approve attachment') })
  void pending.catch(() => undefined)
  await w.clock.settle()
  await press(ui, 'Close')
  await ui.unmount()
  // Another owner-local participant replaced the old attempt after the old read.
  w.retained = newer
  const fresh = await enter($, w)
  await press(fresh, 'Connect this project')
  await w.clock.advance(1000)
  await pending
  expect(count(w, 'decide')).toBe(0)
  expect(await fresh.find({ type: 'Button', text: /^Approve attachment$/ })).toBeDefined()
  effects(w)
})

for (const phase of ['lookup', 'prepare']) {
test(`a late ${phase} response cannot replace a different native context after Close`, async ($, on) => {
  const w = fixture(on)
  const normal = w.read
  let delayed = true
  w.read = async (kind, payload, e) => {
    const value = await normal(kind, payload, e)
    if (kind === phase && delayed) { delayed = false; await w.clock.sleep(1000) }
    return value
  }
  await start($)
  const ui = await enter($, w)
  if (phase === 'prepare') await press(ui, 'Connect this project')
  const pending = ui.press({ key: await button(ui, phase === 'lookup' ? 'Connect this project' : 'Review new agent') })
  void pending.catch(() => undefined)
  await w.clock.settle()
  await press(ui, 'Close')
  await ui.unmount()
  w.root = '/new/private/project'
  w.native = 'new-native-context'
  w.retained = await fixtureFlow({ n: 3, context: contextOf(w.root, w.native) })
  const fresh = await enter($, w)
  await press(fresh, 'Connect this project')
  await w.clock.advance(1000)
  await pending
  expect(await fresh.find({ type: 'Button', text: /^Approve attachment$/ })).toBeDefined()
  expect(await shown(fresh)).toContain(JSON.stringify(w.root))
  expect(await shown(fresh)).not.toContain(JSON.stringify(ROOT))
  expect(count(w, 'prepare')).toBe(phase === 'prepare' ? 1 : 0)
  expect(count(w, 'decide')).toBe(0)
  effects(w)
})
}

test('fixed expiry disables controls and prevents a decision after a pending inspection reaches the deadline', async ($, on) => {
  const w = fixture(on)
  w.retained = await fixtureFlow({ expires: NOW + 1000 })
  const normal = w.read
  w.read = async (kind, payload, e) => { if (kind === 'inspect') await w.clock.sleep(1500); return normal(kind, payload, e) }
  const ui = await connect($, w)
  const pending = ui.press({ key: await button(ui, 'Approve attachment') })
  void pending.catch(() => undefined)
  await w.clock.settle()
  await w.clock.advance(1000)
  await noDecision(ui)
  expect(await shown(ui)).toMatch(/deadline|expir/i)
  await w.clock.advance(500)
  await pending
  expect(count(w, 'decide')).toBe(0)
  effects(w)
})

test('expiry during an already-sent decision requests Refresh without asserting that no commit occurred', async ($, on) => {
  const w = fixture(on)
  w.retained = await fixtureFlow({ expires: NOW + 1000 })
  const normal = w.read
  w.read = async (kind, payload, e) => {
    const response = await normal(kind, payload, e)
    if (kind === 'decide') await w.clock.sleep(1500)
    return response
  }
  const ui = await connect($, w)
  const pending = ui.press({ key: await button(ui, 'Approve attachment') })
  void pending.catch(() => undefined)
  await w.clock.settle()
  expect(count(w, 'decide')).toBe(1)
  await w.clock.advance(1000)
  await noDecision(ui)
  const text = await shown(ui)
  expect(text).toMatch(/deadline|expir/i)
  expect(await ui.find({ type: 'Button', text: /^Refresh$/ })).toBeDefined()
  expect(text).not.toMatch(/no commit|nothing was (recorded|committed)|not (recorded|committed)/i)
  await w.clock.advance(500)
  await pending
  await press(ui, 'Refresh')
  expect(await shown(ui)).toContain('Project: attachment recorded')
  expect(count(w, 'decide')).toBe(1)
  effects(w)
})

test('classic.CwdChanged immediately clears private terms and blocks pending callbacks and old expiry', async ($, on) => {
  const w = fixture(on)
  const old = await fixtureFlow({ expires: NOW + 1000 })
  w.retained = old
  const normal = w.read
  w.read = async (kind, payload, e) => {
    if (kind === 'inspect') { const response = clone(w.retained); await w.clock.sleep(1500); return response }
    return normal(kind, payload, e)
  }
  const ui = await connect($, w)
  const pending = ui.press({ key: await button(ui, 'Approve attachment') })
  void pending.catch(() => undefined)
  await w.clock.settle()
  const callsBefore = w.calls.length
  w.root = '/different/private/project-after-event'
  await $.classic.CwdChanged({ old_cwd: ROOT, new_cwd: w.root })
  await ui.redraw()
  await noDecision(ui)
  expect(await shown(ui)).not.toContain(JSON.stringify(ROOT))
  expect(await shown(ui)).not.toContain(JSON.stringify(old.review.agent.name))
  expect(w.calls.length).toBe(callsBefore)
  await ui.unmount()
  w.retained = await fixtureFlow({ n: 4, context: contextOf(w.root, w.native) })
  const fresh = await enter($, w)
  await press(fresh, 'Connect this project')
  await w.clock.advance(1000)
  expect(await fresh.find({ type: 'Button', text: /^Approve attachment$/ })).toBeDefined()
  await w.clock.advance(500)
  await pending
  expect(count(w, 'decide')).toBe(0)
  expect(await shown(fresh)).toContain(JSON.stringify(w.root))
  expect(await fresh.find({ type: 'Button', text: /^Approve attachment$/ })).toBeDefined()
  effects(w)
})

test('old expiry timers cannot disable a newer review after Close and reopen', async ($, on) => {
  const w = fixture(on)
  w.retained = await fixtureFlow({ expires: NOW + 1000 })
  const ui = await connect($, w)
  await w.clock.advance(500)
  await press(ui, 'Close')
  await ui.unmount()
  w.retained = await fixtureFlow({ n: 2, expires: NOW + 900_000 })
  const fresh = await enter($, w)
  await press(fresh, 'Connect this project')
  await w.clock.advance(500)
  expect(await fresh.find({ type: 'Button', text: /^Approve attachment$/ })).toBeDefined()
  expect(count(w, 'decide')).toBe(0)
  effects(w)
})

for (const state of ['declined', 'expired', 'invalidated']) {
  test(`retained ${state} flow requires explicit replacement and subsequent agent choice`, async ($, on) => {
    const w = fixture(on)
    w.retained = await fixtureFlow({ state, expires: state === 'expired' ? NOW - 1000 : NOW + 900_000 })
    const old = clone(w.retained)
    const ui = await connect($, w)
    await noDecision(ui)
    expect(count(w, 'prepare')).toBe(0)
    await press(ui, 'Review a replacement')
    expect(count(w, 'prepare')).toBe(0)
    await press(ui, 'Review new agent')
    expect(last(w, 'prepare').payload.replace_flow_id).toBe(old.flow_id)
    expect(count(w, 'prepare')).toBe(1)
    expect(count(w, 'decide')).toBe(0)
    effects(w)
  })
}

test('Back, Close and session.end clear private callback authority without deciding or canceling durable reviews', async ($, on) => {
  const w = fixture(on)
  w.retained = await fixtureFlow()
  const ui = await connect($, w)
  await press(ui, 'Back to Peerspan')
  expect(count(w, 'prepare')).toBe(0)
  expect(count(w, 'decide')).toBe(0)
  await press(ui, 'Connect this project')
  expect(count(w, 'lookup')).toBe(2)
  await $.session.end({ reason: 'clear', sessionId: NATIVE, resume: { id: NATIVE } })
  w.native = 'native-after-clear'
  await ui.redraw()
  await noDecision(ui)
  expect(count(w, 'decide')).toBe(0)
  outsidePrivate(w, [])
  effects(w)
})

test('a conversation check after leaving a private review submits only its public challenge', async ($, on) => {
  const w = fixture(on)
  w.retained = await fixtureFlow()
  const flow = clone(w.retained)
  const ui = await connect($, w)
  await press(ui, 'Back to Peerspan')
  const callsBefore = w.calls.length
  await press(ui, 'Check this conversation')
  expect(w.prompts.length).toBe(1)
  expect(w.prompts[0].text).toContain('mcp__peerspan__delivery_acknowledge')
  outsidePrivate(w, [flow.flow_id, flow.review_id, flow.review.agent.name, flow.review.agent.owner])
  expect(w.calls.length).toBe(callsBefore)
  expect(count(w, 'decide')).toBe(0)
  effects(w)
})
