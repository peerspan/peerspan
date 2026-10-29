/**
 * Independent section17 native owner-consent cases on pinnedClaude2.1.303.
 * Public native effects only, no production imports/authentication/inference.
 * Backend template/signature validity and real terminal/reload/model acceptance
 * remain separate gates. The kit dispatches the current drawing: retained old
 * rendered-handler closure authority remains source/manual evidence. Delayed
 * effects explicitly signal registered virtual sleeps before time/navigation.
 * Original212 native cases and owner_onboarding6 are unchanged.
 */
import { expect, mock, test } from 'claude-code/testing'
import type { Engine, Mounted, TestOptions } from 'claude-code/testing'
import type { On } from 'claude-code'

const NOW = Date.parse('2026-10-29T12:00:00Z')
const HOST = 'host_75877bb41d393b5fb8455ce60ecd8dda001d06316496b14dfa7f895656eeca4a'
const ROOT = '/private project/Native $(literal)'
const NATIVE = 'private-native-adapter-conversation'
const TOKEN = 'token_' + 'b'.repeat(64)
const READY = 'mcp__peerspan__adapter_ready'
const SEEN = 'mcp__peerspan__message_seen'
const REPLY = 'mcp__peerspan__message_reply'
const SENDER = 'host_' + 'd'.repeat(64)
const PERSON = 'person_' + 'e'.repeat(64)
const SOCKET = '/private host state/adapter.sock'
const RAW = 'PRIVATE_PROVIDER_ERROR token_DO_NOT_ECHO /private/provider-path'
const CODE = 'psi2-UFJJVkFURV9JTlZJVEVfU0VDUkVU'
const CODE2 = 'psi2-UFJJVkFURV9TRUNPTkRfU0VDUkVU'
const KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
const GENESIS_KEY = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
const INVITER_KEY = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI='
const RELAY_KEY = 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM='
const HELPER_KEY = 'BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ='
const id = (kind: string, n: number) => kind + '_' + n.toString(16).padStart(32, '0')
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value))
const stamp = (milliseconds: number) => new Date(milliseconds).toISOString().replace('.000Z', 'Z')
const quote = (value: string) => JSON.stringify(value).replace(/[\u200b\u202a-\u202e]/g,
  character => '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0'))
const context = (parent: any) => ({ project_flow_id: parent.flow_id, project_review_id: parent.review_id,
  project_root: parent.review.project_root, native_session_id: parent.review.native_session_id, integration: 'claude-code' })
const effects = { issue_adapter_credential: true, receive_authorized_work: true, reply_to_authorized_work: true,
  handle_authorized_tasks: true, task_artifacts: true, register_agent: false, attach_session: false,
  grant_network_access: false, directory_access: false, outbound_routes: false, capability_calls: false,
  share_files: false, share_conversation: false }

function canonical(value: any): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']'
  if (value !== null && typeof value === 'object') return '{' + Object.keys(value).sort()
    .map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}'
  return JSON.stringify(value)
}
async function digest(domain: string, review: any) {
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(domain + '\n' + canonical(review))))
  return 'review_' + Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
}
async function parentFlow(options: any = {}) {
  const n = options.n ?? 1
  const review = { version: 1, kind: 'attach_project', flow_id: id('flow', n), host_id: options.host ?? HOST,
    project_root: options.root ?? ROOT, native_session_id: options.native ?? NATIVE, integration: 'claude-code',
    create_agent: false, agent: options.agent ?? { id: id('agent', n), name: 'Reviewed native agent', owner: 'Reviewed owner', capabilities: [] },
    session_id: id('session', n), expires_at: stamp(NOW + 900_000),
    effects: { register_agent: false, attach_session: true, issue_adapter_credential: false, grant_network_access: false,
      share_files: false, share_conversation: false, capability_calls: false } }
  const state = options.state ?? 'attached'
  return { version: 1, flow_id: review.flow_id, state, review_id: await digest('peerspan-project-review-v1', review), review,
    attachment: state === 'attached' ? { agent_id: review.agent.id, session_id: review.session_id } : null,
    next_action: state === 'attached' ? 'continue_adapter_setup' : state === 'review' ? 'review' : 'restart_review' }
}
function connection(child: any, now: number, options: any = {}) {
  const ready = options.ready ?? false
  const verified = options.verified ?? false
  return { adapter_id: child.review.adapter_id, session_id: child.review.session_id,
    state: ready ? 'ready' : 'registered', recoverable: ready,
    lease_expires_at: ready ? stamp(options.lease ?? Math.min(now + 15_000, Date.parse(child.review.credential_expires_at))) : null,
    last_seen_at: ready ? stamp(now) : null, channel: ready ? verified ? 'verified' : 'unverified' : null,
    channel_verified_at: verified ? stamp(now) : null, protocol_version: ready ? 'claude-mod-v1' : null }
}
async function adapterFlow(parent: any, options: any = {}) {
  const n = options.n ?? 10
  const review = { version: 1, kind: 'authorize_adapter', flow_id: id('flow', n), host_id: parent.review.host_id,
    ...context(parent), agent: clone(parent.review.agent), session_id: parent.review.session_id, adapter_id: id('adapter', n),
    expires_at: stamp(options.expires ?? NOW + 900_000),
    credential_expires_at: stamp(options.credentialExpires ?? (options.expires ?? NOW + 900_000) + 85_500_000),
    renewable: false, effects: clone(effects) }
  const state = options.state ?? 'review'
  const flow: any = { version: 1, flow_id: review.flow_id, state,
    review_id: await digest('peerspan-adapter-review-v1', review), review, authorization: null, connection: null,
    next_action: state === 'review' ? 'review' : state === 'authorized' ? 'connect_adapter' : 'restart_review' }
  if (state === 'authorized' || options.issued) {
    flow.authorization = { adapter_id: review.adapter_id, session_id: review.session_id, agent_id: review.agent.id,
      expires_at: review.credential_expires_at, renewable: false }
    flow.connection = connection(flow, NOW)
  }
  return flow
}
async function transport(child: any) {
  // The pinned mod runtime exposes digest, not importKey/sign. This is the
  // standard SHA256 HMAC construction for this fixture's 32-byte token key.
  const innerPad = new Uint8Array(64).fill(0x36), outerPad = new Uint8Array(64).fill(0x5c)
  for (let index = 0; index < 32; index++) { innerPad[index] ^= 0xbb; outerPad[index] ^= 0xbb }
  const message = 'peerspan-guided-adapter-instance-v1\n' + child.flow_id + '\n' + child.review_id
  const bytes = new TextEncoder().encode(message), inner = new Uint8Array(64 + bytes.length)
  inner.set(innerPad); inner.set(bytes, 64)
  const innerHash = new Uint8Array(await crypto.subtle.digest('SHA-256', inner))
  const outer = new Uint8Array(64 + innerHash.length); outer.set(outerPad); outer.set(innerHash, 64)
  const signature = new Uint8Array(await crypto.subtle.digest('SHA-256', outer))
  return { version: 1, adapter_id: child.review.adapter_id, session_id: child.review.session_id, token: TOKEN,
    instance_id: 'instance_' + Array.from(signature, byte => byte.toString(16).padStart(2, '0')).join(''), adapter_socket: SOCKET }
}

function fixture(on: On) {
  const clock = mock.clock(on, { now: NOW })
  const w = { clock, started: false, root: ROOT, native: NATIVE, host: HOST, surface: 'terminal' as string | null,
    surfaces: ['terminal'], parent: null as any, child: null as any, sequence: 20,
    ownerValue: null as any, requestState: 'pending', networks: [] as any[], invitation: null as any, previewValue: null as any, joining: null as any, identities: [{ public_key: KEY, sources: ["generated"] }] as any[], code: CODE, codes: [CODE, CODE2],
    calls: [] as any[], trace: [] as any[], httpCalls: [] as any[], outside: [] as string[], tools: [] as any[],
    forbidden: [] as string[], prompts: [] as any[], materials: [] as any[], inFlight: 0, maxInFlight: 0,
    messages: [] as any[], held: {} as Record<string, any>, seen: new Set<string>(), replies: {} as Record<string, any>,
    run: async (_kind: string, _payload: any, _e: any): Promise<any> => undefined,
    fetch: async (_e: any): Promise<any> => undefined,
    submit: async (e: any): Promise<any> => ({ text: e.text, origin: e.origin }) }
  w.run = async (kind, payload) => {
    if (kind === 'join.owner.lookup') return ownerResponse(w)
    if (kind === 'join.owner.prepare') { w.ownerValue ??= await ownerRecord(w); return ownerResponse(w) }
    if (kind === 'join.owner.approve') {
      w.ownerValue = { ...w.ownerValue, state: 'approved', next_action: w.requestState === 'pending' ? 'provide_original_signature' : 'follow_join_progress' }
      return ownerResponse(w)
    }
    if (kind === 'snapshot') return { version: 1, observed_at: stamp(clock.now()), host_id: w.host,
      networks: w.networks, agents: [], requests: [], attention: [] }
    if (kind === 'join.progress') return await progressResponse(w)
    if (kind === 'join.lookup') return { version: 1, host_id: w.host, context: payload.context, flow: w.joining }
    if (kind === 'join.identities') return { version: 1, host_id: w.host, context: payload.context, identities: clone(w.identities) }
    if (kind === 'join.inspect') return w.joining
    if (kind === 'join.prepare') {
      if (w.joining && !payload.replace_flow_id) return w.joining
      w.joining = await joinFlow(w.parent, w.previewValue ?? await previewResponse(w), payload.person_public_key, { n: ++w.sequence })
      return w.joining
    }
    if (kind === 'join.decide') {
      const approved = payload.decision === 'approve'
      w.joining = { ...w.joining, state: approved ? 'requested' : 'declined',
        outcome: approved ? { request_id: id64('link', w.sequence), network_id: w.joining.review.invitation.network.id,
          context_id: w.joining.review.invitation.network.context_id, person_public_key: w.joining.review.person_public_key } : null,
        next_action: approved ? 'await_participant_reviews' : 'none' }
      return w.joining
    }
    if (kind === 'invitation.preview') return w.previewValue ?? await previewResponse(w)
    if (kind === 'invitation.lookup') return { version: 1, host_id: w.host, context: payload.context, flow: w.invitation }
    if (kind === 'invitation.prepare') {
      w.invitation = await invitationFlow(w.parent, w.networks.find(network => network.id === payload.network_id),
        { n: ++w.sequence, member: payload.member.trim(), pin: payload.expected_person_public_key,
          expires: clock.now() + 900_000, invitationExpires: clock.now() + 3_600_000 })
      return w.invitation
    }
    if (kind === 'invitation.inspect') return w.invitation
    if (kind === 'invitation.decide') {
      w.invitation = { ...w.invitation, state: payload.decision === 'approve' ? 'issued' : 'declined',
        invitation: payload.decision === 'approve' ? { invitation_id: id64('di', w.sequence), expires_at: w.invitation.review.invitation_expires_at } : null,
        next_action: payload.decision === 'approve' ? 'share_private_invitation' : 'restart_review' }
      return w.invitation
    }
    if (kind === 'invitation.handoff') return privateHandoff(w.invitation, w.code)
    if (kind === 'project.lookup') return { version: 1, host_id: w.host, context: payload, flow: w.parent,
      agents: w.parent ? [{ ...w.parent.review.agent, created_at: stamp(NOW - 1000) }] : [] }
    if (kind === 'project.inspect') return w.parent
    if (kind === 'adapter.lookup') return { version: 1, host_id: w.host, context: payload, flow: w.child }
    if (kind === 'adapter.prepare') { w.child = await adapterFlow(w.parent, { n: ++w.sequence }); return w.child }
    if (kind === 'adapter.inspect') return w.child
    if (kind === 'adapter.decide') {
      const choice = payload.decision
      w.child = { ...w.child, state: choice === 'approve' ? 'authorized' : 'declined',
        next_action: choice === 'approve' ? 'connect_adapter' : 'restart_review',
        authorization: choice === 'approve' ? { adapter_id: w.child.review.adapter_id, session_id: w.child.review.session_id,
          agent_id: w.child.review.agent.id, expires_at: w.child.review.credential_expires_at, renewable: false } : null }
      w.child.connection = choice === 'approve' ? connection(w.child, clock.now()) : null
      return w.child
    }
    if (kind === 'adapter.transport') { const value = await transport(w.child); w.materials.push(clone(value)); return value }
    throw Error('Unexpected public process operation')
  }
  w.fetch = async e => {
    const path = e.url.replace('http://peerspan', ''), body = JSON.parse(e.init.body)
    let value: any
    if (path === '/adapter/v1/connect' || path === '/adapter/v1/ready') {
      value = connection(w.child, clock.now(), { ready: true,
        verified: path.endsWith('/ready') || w.child.connection?.channel === 'verified' })
      w.child = { ...w.child, connection: value }
    } else if (['/adapter/v1/tasks/next', '/adapter/v1/tasks/cancels/next'].includes(path)) {
      value = null
    } else if (path === '/adapter/v1/next') {
      value = w.messages.shift() ?? null
      if (value?.delivery?.id) w.held[value.delivery.id] = clone(value)
    } else if (path === '/adapter/v1/seen') {
      const delivery = body.ids[0], first = !w.seen.has(delivery)
      w.seen.add(delivery); value = { seen: first ? [delivery] : [] }
    } else {
      const delivery = path.split('/')[4], held = w.held[delivery]
      if (path.endsWith('/forwarded')) value = { ...held.delivery, state: 'forwarded', updated_at: stamp(clock.now()) }
      else if (path.endsWith('/reply')) {
        value = w.replies[delivery] ?? { sender_host_id: held?.delivery.sender_host_id ?? SENDER,
          request_id: held?.request.request_id ?? id('request', 1), receiver_host_id: w.host,
          target_agent_id: w.child.review.agent.id, session_id: w.child.review.session_id,
          delivery_id: delivery, content: body.content, replied_at: stamp(clock.now()),
          origin: { agent_id: w.child.review.agent.id, session_id: w.child.review.session_id } }
        w.replies[delivery] = clone(value)
      } else throw Error('Unexpected scoped route')
    }
    return { status: 200, ok: true, headers: {}, text: JSON.stringify(value) }
  }
  on('session.start', ($, e) => { w.started = true; return { cwd: e.cwd } })
  on('session.end', ($, e) => ({ sessionId: e.sessionId }))
  on('classic.CwdChanged', () => ({}))
  on('session.root', () => { w.trace.push({ kind: 'root', value: w.root }); return { value: w.root } })
  on('session.id', () => { w.trace.push({ kind: 'native', value: w.native }); return { value: w.native } })
  on('session.cwd', () => ({ value: '/different-shell-cwd' }))
  on('session.surface', () => ({ value: w.surface }))
  on('session.surfaces', () => { w.trace.push({ kind: 'surfaces' }); return { value: w.surfaces } })
  on('command.register', () => ({ value: undefined }))
  on('tool.register', ($, e) => { w.tools.push(e); return { value: undefined } })
  on('command.run', () => ({ text: 'unhandled fixture command' }))
  on('tool.call', () => ({ deny: 'unregistered fixture tool' }))
  on('process.run', async ($, e) => {
    const tail = e.argv.slice(e.argv.indexOf('onboarding') + 1)
    const kind = tail[0] === 'join' && tail[1] === 'owner' ? tail.slice(0, 3).join('.') : tail.length ? tail[0] + '.' + tail[1] : 'snapshot'
    const payload = e.init?.stdin ? JSON.parse(e.init.stdin) : undefined
    // Capture the serialized request independently of synthetic response
    // mutations; a real process stdout cannot mutate its already-sent stdin.
    const sent = payload === undefined ? undefined : clone(payload)
    w.calls.push({ ...e, kind, payload: sent, expectedContext: w.parent ? clone(context(w.parent)) : undefined,
      expectedProjectFlow: w.parent?.flow_id, expectedAdapterFlow: w.child?.flow_id,
      expectedFlow: w.joining?.flow_id, expectedJoinReview: w.joining?.review_id,
      expectedOwnerReview: w.ownerValue?.review_id }); w.trace.push({ kind, payload: sent })
    const value = await w.run(kind, payload, e)
    if (value?.fixtureDeny) return { deny: RAW }
    if (value?.fixtureRaw) return { value: { exitCode: 0, stdout: value.fixtureRaw, stderr: RAW } }
    return { value: { exitCode: 0, stdout: JSON.stringify(value), stderr: '' } }
  })
  on('http.fetch', async ($, e) => {
    w.httpCalls.push(clone(e)); w.trace.push({ kind: 'http', path: e.url }); w.inFlight++
    w.maxInFlight = Math.max(w.maxInFlight, w.inFlight)
    try { const value = await w.fetch(e); return value?.fixtureDeny ? { deny: RAW } : { value } }
    finally { w.inFlight-- }
  })
  on('ui.open', () => ({ value: { isPlaced: w.surface === 'terminal' } }))
  on('ui.close', () => ({ value: undefined }))
  on('ui.panes', () => ({ value: [] }))
  on('ui.render', () => ({ type: 'Text', props: {}, children: ['native core fallback'] }))
  on('ui.toast', ($, e) => { w.outside.push(e.text); return { value: undefined } })
  on('ui.log', ($, e) => { w.outside.push(e.text); return { value: undefined } })
  on('ui.status', ($, e) => { w.outside.push(String(e.text ?? '')); return { value: undefined } })
  on('ui.notice', ($, e) => { w.outside.push(JSON.stringify(e)); return { value: undefined } })
  on('prompt.submit', async ($, e) => { w.prompts.push(clone(e)); w.trace.push({ kind: 'prompt', text: e.text }); return w.submit(e) })
  on('store.set', () => { w.forbidden.push('store.set'); return { deny: 'no persistence' } })
  on('fs.write', () => { w.forbidden.push('fs.write'); return { deny: 'no files' } })
  on('process.spawn', async function* () { w.forbidden.push('process.spawn'); throw Error('no spawn') })
  on('model.complete', () => { w.forbidden.push('model.complete'); return { deny: 'no inference' } })
  on('session.send', () => { w.forbidden.push('session.send'); return { isDelivered: false } })
  return w
}
type World = ReturnType<typeof fixture>
type Pane = Mounted<'terminal', 'Pane'>
const count = (w: World, kind: string) => w.calls.filter(call => call.kind === kind).length
const last = (w: World, kind: string) => w.calls.filter(call => call.kind === kind).at(-1)
async function text(ui: Pane) { return (await ui.findAll({})).map(element => element.text).join('\n') }
async function key(ui: Pane, label: string | RegExp) {
  const found = await ui.find({ type: 'Button', text: typeof label === 'string' ? new RegExp('^' + label + '$') : label })
  expect(found, String(label)).toBeDefined(); return found!.key!
}
async function press(ui: Pane, label: string | RegExp) { return ui.press({ key: await key(ui, label) }) }
async function noDecision(ui: Pane) {
  for (const label of ['Approve adapter', 'Decline adapter']) expect(await ui.find({ type: 'Button', text: new RegExp('^' + label + '$') })).toBeUndefined()
}
async function enter($: Engine, w: World): Promise<Pane> {
  const answer = await $.command.run({ command: 'peerspan', args: '', origin: { kind: 'composer' },
    presentation: { isFullscreen: false, columns: 100 } })
  w.outside.push(answer.text ?? '', ...(answer.context ?? []))
  return $.ui.mount({ plugin: 'peerspan', surface: 'terminal', component: 'Pane', requestId: 'peerspan',
    viewport: { columns: 100, rows: 40 }, props: { title: 'Peerspan', isFocused: true, bodyColumns: 80,
      placement: 'inline', scroll: { offset: 0, bodyRows: 30 }, view: {} } })
}
async function open($: Engine, w: World, adapter = true) {
  if (!w.started) await $.session.start({ cwd: '/different-shell-cwd', surface: w.surface as any, isInteractive: true })
  const ui = await enter($, w)
  await press(ui, 'Connect this project')
  if (adapter) await press(ui, 'Review adapter connection')
  return ui
}

const pathOf = (e: any) => e.url.replace('http://peerspan', '')
const requests = (w: World, path: string) => w.httpCalls.filter(e => pathOf(e) === path)
const claims = (w: World) => requests(w, '/adapter/v1/next')
const readyCalls = (w: World) => requests(w, '/adapter/v1/ready')
const forwards = (w: World) => w.httpCalls.filter(e => pathOf(e).endsWith('/forwarded'))
const replies = (w: World) => w.httpCalls.filter(e => pathOf(e).endsWith('/reply'))
const seenCalls = (w: World) => requests(w, '/adapter/v1/seen')
function nonce(w: World, at = 0) {
  const match = w.prompts[at]?.text.match(/\b[0-9a-f]{32}\b/g)
  expect(match?.length, 'one public readiness nonce').toBe(1)
  return match![0]
}
function resultOf(answer: any): any {
  const value = answer.result
  if (typeof value === 'string') return JSON.parse(value)
  if (Array.isArray(value?.content)) return JSON.parse(value.content.filter((part: any) => part.type === 'text').map((part: any) => part.text).join(''))
  return value
}
function denied(answer: any) {
  expect(typeof answer?.deny === 'string' || answer?.isError === true, 'controlled native refusal').toBe(true)
  expect(JSON.stringify(answer)).not.toContain(RAW)
  expect(JSON.stringify(answer)).not.toContain('PRIVATE_PROVIDER_ERROR')
  expect(JSON.stringify(answer)).not.toContain('/private/provider-path')
}
async function call($: Engine, tool: string, args: any) { return $.tool.call({ tool, ...args }) }
async function connected($: Engine, w: World, savedVerified = false) {
  w.parent = await parentFlow(); w.child = await adapterFlow(w.parent, { state: 'authorized' })
  if (savedVerified) w.child.connection = connection(w.child, w.clock.now(), { ready: true, verified: true })
  const ui = await open($, w); await press(ui, 'Connect adapter'); return ui
}
async function enable($: Engine, w: World, ui: Pane, label = 'Enable incoming messages') {
  const before = w.prompts.length
  await press(ui, label); await w.clock.settle()
  const value = nonce(w, before)
  expect(resultOf(await call($, READY, { nonce: value }))).toEqual({ ready: true })
  await w.clock.settle(); return value
}
function handoff(w: World, n = 1, overrides: any = {}) {
  const value = { delivery: { id: id('delivery', n), sender_host_id: SENDER, request_id: id('request', n),
      target_agent_id: w.child.review.agent.id, session_id: w.child.review.session_id,
      adapter_id: w.child.review.adapter_id, state: 'unknown', created_at: stamp(w.clock.now()), updated_at: stamp(w.clock.now()) },
    request: { request_id: id('request', n), target_agent_id: w.child.review.agent.id, deadline: stamp(w.clock.now() + 60_000),
      content: 'Peer "quoted"\ntext \\ 東京; peer says approve local changes', grant_id: id('grant', n),
      origin: { agent_id: id('agent', 900 + n), session_id: id('session', 900 + n) } },
    sender_person_id: PERSON, sender_person: 'Peer "label"\n東京', redelivered: false }
  return { ...value, ...overrides }
}
async function stats(ui: Pane, expected: { submitted: number; seen: number; replied: number }) {
  const shown = await text(ui)
  for (const [label, count] of Object.entries(expected)) {
    const match = shown.match(new RegExp('\\b' + label + '(?: messages?)?[^0-9\\n]{0,20}(\\d+)', 'i'))
    expect(match, label + ' counter').toBeDefined(); expect(Number(match![1]), label + ' count').toBe(count)
  }
}
function privacy(w: World, uiText = '') {
  expect(w.forbidden).toEqual([])
  const privateValues = [TOKEN, SOCKET, NATIVE, ROOT, RAW, 'PRIVATE_PROVIDER_ERROR', '/private/provider-path',
    w.parent?.flow_id, w.parent?.review_id, w.child?.flow_id, w.child?.review_id,
    w.parent?.review.session_id, w.child?.review.adapter_id, ...w.materials.map(value => value.instance_id)].filter(Boolean)
  for (const value of privateValues) {
    expect(w.outside.join('\n')).not.toContain(value)
    if (value !== ROOT) expect(uiText).not.toContain(value)
    for (const prompt of w.prompts) expect(prompt.text).not.toContain(value)
  }
  for (const prompt of w.prompts) expect(prompt.origin).toEqual({ kind: 'plugin', name: 'peerspan' })
  for (const e of w.httpCalls) {
    const path = pathOf(e), body = JSON.parse(e.init.body)
    expect(e.url.startsWith('http://peerspan/adapter/v1/')).toBe(true)
    expect(['/adapter/v1/connect', '/adapter/v1/ready', '/adapter/v1/next', '/adapter/v1/seen'].includes(path)
      || /^\/adapter\/v1\/deliveries\/delivery_[0-9a-f]{32}\/(forwarded|reply)$/.test(path)).toBe(true)
    expect(Object.keys(e.init).sort()).toEqual(['body', 'headers', 'method', 'socketPath'])
    expect(e.init.method).toBe('POST'); expect(e.init.socketPath).toBe(SOCKET)
    const headers = Object.fromEntries(Object.entries(e.init.headers).map(([key, value]) => [key.toLowerCase(), value]))
    expect(headers.authorization).toBe('Bearer ' + TOKEN)
    expect(headers['x-peerspan-instance']).toBe(w.materials[0].instance_id)
    expect(headers['content-type']).toBe('application/json')
    if (path.endsWith('/next') || path.endsWith('/forwarded')) expect(body).toEqual({})
    if (path.endsWith('/ready')) expect(Object.keys(body)).toEqual(['nonce'])
    if (path.endsWith('/seen')) expect(Object.keys(body)).toEqual(['ids'])
    if (path.endsWith('/reply')) expect(Object.keys(body)).toEqual(['content'])
  }
  for (const command of w.calls) {
    expect(command.init?.timeoutMs).toBe(5000)
    for (const value of [ROOT, NATIVE, TOKEN, SOCKET, ...w.materials.map(value => value.instance_id)]) expect(command.argv).not.toContain(value)
  }
}

const id64 = (kind: string, n: number) => kind + '_' + n.toString(16).padStart(64, '0')
const invitationEffects = { create_contact_invitation: true, receive_join_requests: true, grant_membership: false,
  grant_agent_access: false, approve_machine: false, share_files: false, share_conversation: false, capability_calls: false }
function network(n = 1, name = 'Network "東京"'): any {
  return { id: id64('net', n), name, mode: 'decentralized', context_id: id64('ctx', n), genesis_root_public_key: GENESIS_KEY,
    root_state_id: id64('drs', n), root_public_key: GENESIS_KEY, root_epoch: 0, member: 'local owner', host_public_key: INVITER_KEY,
    person_public_key: KEY, provider: null, provider_state: { state: 'not_selected', code: '-', error: '-', required_ids: [] },
    authority: { state: 'usable', not_after: stamp(NOW + 86_400_000), required_ids: [], conflict_ids: [] },
    delivery: { pending_proof_ids: [], peer_errors: [] }, created_at: stamp(NOW - 1000) }
}
async function invitationFlow(parent: any, selected: any, options: any = {}) {
  const n = options.n ?? 30, state = options.state ?? 'review'
  const review = { version: 1, kind: 'create_contact_invitation', flow_id: id('flow', n), host_id: parent.review.host_id,
    context: context(parent), agent: clone(parent.review.agent),
    network: { id: selected.id, name: selected.name, context_id: selected.context_id, genesis_root_public_key: selected.genesis_root_public_key },
    inviter_host_public_key: selected.host_public_key, member: options.member ?? 'Teammate "é東京"',
    expected_person_public_key: options.pin ?? '-',
    transport: { bootstrap_addresses: ['127.0.0.1:443', 'peer.example:8443'], quic_addresses: ['[::1]:443'],
      relays: [{ address: 'relay.example:444', public_key: RELAY_KEY }], helpers: [{ address: 'helper.example:445', public_key: HELPER_KEY }] },
    expires_at: stamp(options.expires ?? (state === 'expired' ? NOW - 1000 : NOW + 900_000)),
    invitation_expires_at: stamp(options.invitationExpires ?? (state === 'expired' ? NOW + 2_699_000 : NOW + 3_600_000)),
    effects: clone(invitationEffects) }
  return { version: 1, flow_id: review.flow_id, state, review_id: await digest('peerspan-invitation-review-v1', review), review,
    invitation: state === 'issued' || options.issued ? { invitation_id: id64('di', n), expires_at: review.invitation_expires_at } : null,
    next_action: state === 'review' ? 'review' : state === 'issued' ? 'share_private_invitation' : 'restart_review' }
}
function privateHandoff(flow: any, code = CODE) {
  return { version: 1, flow_id: flow.flow_id, review_id: flow.review_id, network_id: flow.review.network.id,
    context_id: flow.review.network.context_id, invitation_id: flow.invitation.invitation_id,
    invitation: code, expires_at: flow.invitation.expires_at }
}
async function setup($: Engine, w: World, state: string | null = null, options: any = {}) {
  w.networks = options.networks ?? [network()]
  w.parent = await parentFlow({ agent: { id: id('agent', 1), name: 'Agent "東京"', owner: 'Owner \\é', capabilities: ['capability "metadata"'] } })
  if (state) w.invitation = await invitationFlow(w.parent, w.networks[0], { ...options, state })
  if (!w.started) await $.session.start({ cwd: '/different-shell-cwd', surface: w.surface as any, isInteractive: true })
  const ui = await enter($, w); await press(ui, 'Connect this project'); return ui
}
async function visible(ui: Pane) {
  return (await text(ui)) + '\n' + (await ui.findAll({ type: 'Input' })).map(input => input.props.value ?? '').join('\n')
}
async function selectNetwork(ui: Pane, selected: any) {
  const found = (await ui.findAll({ type: 'Button' })).find(element => element.text.includes(selected.id))
  expect(found, 'explicit full-ID network choice').toBeDefined()
  expect(found!.text).toContain(quote(selected.name))
  await ui.press({ key: found!.key! })
}
async function inputField(ui: Pane, label: string) {
  const found = (await ui.findAll({ type: 'Input' })).find(element => element.props.label === label)
  expect(found, label).toBeDefined(); return found!
}
async function edit(ui: Pane, label: string, value: string) {
  await ui.input({ key: (await inputField(ui, label)).key!, text: value, kind: 'change' })
}
async function noInvitationAuthority(ui: Pane) {
  for (const name of ['Approve invitation', 'Decline invitation', 'Reveal private invitation']) {
    expect(await ui.find({ type: 'Button', text: new RegExp('^' + name + '$') })).toBeUndefined()
  }
}
async function begin(w: World, ui: Pane) {
  // Explicit fixture navigation back to the attached project after Back.
  const connect = await ui.find({ type: 'Button', text: /^Connect this project$/ })
  if (connect) await ui.press({ key: connect.key! })
  await press(ui, 'Invite someone'); await w.clock.settle()
}
async function draft(w: World, ui: Pane, selected = w.networks[0], label = 'Teammate "é東京"', pin = '-') {
  await selectNetwork(ui, selected); await edit(ui, 'Invitee label', label); await edit(ui, 'Expected person public key', pin)
}
async function back(ui: Pane) {
  const found = await ui.find({ type: 'Button', text: /^Back\b/ }); expect(found).toBeDefined(); await ui.press({ key: found!.key! })
}
function invitationCalls(w: World) { return w.calls.filter(call => call.kind.startsWith('invitation.')) }
function safe(w: World, uiText = '', reveal = false, runtime = false, executable = 'peerspan', state?: string) {
  expect(w.forbidden).toEqual([])
  for (const code of w.codes) {
    expect(w.outside.join('\n')).not.toContain(code)
    for (const prompt of w.prompts) expect(prompt.text).not.toContain(code)
    if (!reveal) expect(uiText).not.toContain(code)
  }
  for (const value of [NATIVE, RAW, w.parent?.flow_id, w.parent?.review_id, w.invitation?.flow_id, w.invitation?.review_id].filter(Boolean)) {
    expect(w.outside.join('\n')).not.toContain(value); expect(uiText).not.toContain(value)
  }
  expect(w.outside.join('\n') + uiText).not.toContain('PRIVATE_PROVIDER_ERROR')
  expect(w.outside.join('\n')).not.toContain(ROOT)
  expect(uiText).not.toMatch(/\b(?:flow_[0-9a-f]{32}|review_[0-9a-f]{64}|session_[0-9a-f]{32}|adapter_[0-9a-f]{32})\b/)
  for (const native of w.trace.filter(event => event.kind === 'native').map(event => event.value)) {
    expect(uiText).not.toContain(native); expect(w.outside.join('\n')).not.toContain(native)
  }
  for (const command of w.calls) {
    const [noun, verb] = command.kind.split('.')
    const prefix = [executable, ...(state ? ['--state', state] : []), 'onboarding']
    const suffix = command.kind === 'snapshot' ? [] : [noun, verb, ...(verb === 'inspect' ? [command.argv.at(-1)] : ['--stdin'])]
    expect(command.argv).toEqual([...prefix, ...suffix])
    expect(command.init?.timeoutMs).toBe(command.kind === 'join.identities' ? 15000 : 5000)
    for (const code of w.codes) expect(command.argv.join('\n')).not.toContain(code)
    expect(command.argv).not.toContain(ROOT); expect(command.argv).not.toContain(NATIVE)
    if (command.kind.startsWith('invitation.') && verb !== 'inspect') expect(typeof command.init.stdin).toBe('string')
    if (noun === 'invitation') expect(['lookup', 'prepare', 'inspect', 'decide', 'handoff', 'preview']).toContain(verb)
  }
  if (!runtime) {
    expect(w.httpCalls).toEqual([]); expect(w.prompts).toEqual([])
    expect(w.tools.map(tool => tool.name)).toEqual(['delivery_acknowledge'])
  }
}

const previewEffects = { verify_contact_signature: true, create_identity: false, create_link_request: false,
  select_owner: false, grant_membership: false, grant_agent_access: false, approve_machine: false,
  share_files: false, share_conversation: false, capability_calls: false }
async function previewResponse(w: World, options: any = {}) {
  const selected = w.networks[0] ?? network()
  const review = { version: 1, kind: 'inspect_contact_invitation', host_id: w.host, context: context(w.parent),
    agent: clone(w.parent.review.agent),
    network: { id: selected.id, name: selected.name, context_id: selected.context_id,
      genesis_root_public_key: selected.genesis_root_public_key },
    inviter_host_public_key: INVITER_KEY,
    invitation: { id: id64('di', options.n ?? 30), member: options.member ?? 'Invited "é東京" member',
      expected_person_public_key: options.pin ?? KEY, issued_at: stamp(options.issued ?? NOW - 60_000),
      expires_at: stamp(options.expires ?? NOW + 3_540_000), automatic_return: options.automaticReturn ?? true },
    // Old contacts remain signed hints. The u64 boundary is a string, not a JS number.
    contacts: [
      { sequence: '0', issued_at: stamp(NOW - 600_000), expires_at: stamp(NOW - 300_000),
        quic_addresses: ['[::1]:443'], bootstrap_addresses: ['127.0.0.1:443'],
        relays: [{ address: 'relay.example:444', public_key: RELAY_KEY }] },
      { sequence: '18446744073709551615', issued_at: stamp(NOW - 590_000), expires_at: stamp(NOW - 290_000),
        quic_addresses: ['peer.example:8443'], bootstrap_addresses: [], relays: [] },
    ], helpers: [{ address: 'helper.example:445', public_key: HELPER_KEY }], effects: clone(previewEffects) }
  return { version: 1, host_id: w.host, context: context(w.parent),
    review_id: await digest('peerspan-invitation-preview-v1', review), review, next_action: 'choose_join_identity' }
}
const previewCalls = (w: World) => w.calls.filter(command => command.kind === 'invitation.preview')
async function recipientEntry(w: World, ui: Pane) {
  const connect = await ui.find({ type: 'Button', text: /^Connect this project$/ })
  if (connect) await ui.press({ key: connect.key! })
  await press(ui, 'Review an invitation'); await w.clock.settle()
}
async function emptyDraft(ui: Pane) {
  expect((await inputField(ui, 'Private invitation code')).props.value ?? '').toBe('')
}
async function inspect(w: World, ui: Pane, code = CODE) {
  await edit(ui, 'Private invitation code', code); await press(ui, 'Inspect invitation'); await w.clock.settle()
}
async function unverified(ui: Pane, label = '') {
  expect(await visible(ui), label).not.toContain('Invitation: signature verified')
  for (const name of ['Approve invitation', 'Join', 'Continue']) {
    expect(await ui.find({ type: 'Button', text: new RegExp('^' + name + '$') }), label).toBeUndefined()
  }
}
async function currentProject(ui: Pane) {
  const previous = await ui.find({ type: 'Button', text: /^Back\b/ })
  if (previous) await ui.press({ key: previous.key! })
}

const joinEffects = { create_identity: false, create_link_request: true, publish_request: true,
  select_owner: false, grant_membership: false, grant_agent_access: false, approve_machine: false,
  share_files: false, share_conversation: false, capability_calls: false }
async function joinFlow(parent: any, preview: any, person = KEY, options: any = {}) {
  const n = options.n ?? 60, state = options.state ?? 'review'
  const review = { version: 1, kind: 'create_join_request', flow_id: id('flow', n), host_id: parent.review.host_id,
    context: context(parent), agent: clone(parent.review.agent), invitation_review_id: preview.review_id,
    invitation: clone(preview.review), person_public_key: person,
    expires_at: stamp(options.expires ?? Math.min(NOW + 900_000, Date.parse(preview.review.invitation.expires_at))),
    effects: clone(joinEffects) }
  const outcome = state === 'requested' || options.requested ? { request_id: id64('link', n),
    network_id: review.invitation.network.id, context_id: review.invitation.network.context_id, person_public_key: person } : null
  const actions: Record<string, string> = { review: 'approve_join_request', declined: 'none', requested: 'await_participant_reviews',
    expired: 'review_replacement', invalidated: 'review_replacement', replaced: 'review_replacement' }
  return { version: 1, host_id: review.host_id, flow_id: review.flow_id,
    review_id: await digest('peerspan-join-review-v1', review), state, review, outcome, next_action: actions[state] }
}
const joinCalls = (w: World) => w.calls.filter(command => command.kind.startsWith('join.'))
const identityButtons = async (ui: Pane) => ui.findAll({ type: 'Button', text: /^Review identity / })
async function joinEntry(w: World, ui: Pane) {
  const connect = await ui.find({ type: 'Button', text: /^Connect this project$/ })
  if (connect) await ui.press({ key: connect.key! })
  await press(ui, 'Join a network'); await w.clock.settle()
}
async function joinDraft(ui: Pane, code = CODE, kind: 'change' | 'submit' = 'change') {
  await ui.input({ key: (await inputField(ui, 'Private invitation for joining')).key!, text: code, kind })
}
async function joiningIdentities(w: World, ui: Pane, code = CODE) {
  await joinDraft(ui, code); await press(ui, 'Review joining identities'); await w.clock.settle()
}
async function choose(w: World, ui: Pane, person = KEY) {
  await press(ui, 'Review identity ' + person); await w.clock.settle()
}
async function noJoinDecision(ui: Pane, label = '') {
  expect(await ui.find({ type: 'Button', text: /^Approve join request$/ }), label).toBeUndefined()
}
async function joinReview($: Engine, w: World) {
  const ui = await setup($, w); await joinEntry(w, ui); await joiningIdentities(w, ui); await choose(w, ui); return ui
}
function scopedIdentityPrivacy(w: World, shown = '', runtime = false, executable = 'peerspan', state?: string) {
  safe(w, shown, false, runtime, executable, state)
  for (const e of w.calls.filter(command => command.kind === 'join.identities')) expect(e.payload).toEqual({ context: context(w.parent) })
  for (const e of joinCalls(w)) expect(['lookup', 'identities', 'prepare', 'inspect', 'decide', 'progress']).toContain(e.kind.split('.')[1])
}
function publicKey(n: number) {
  // Canonical32-byte public-format fixtures; no possession/crypto claim from stubs.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  const bytes = Array.from({ length: 32 }, () => n), result: string[] = []
  for (let index = 0; index < bytes.length; index += 3) {
    const a = bytes[index], b = bytes[index + 1] ?? 0, c = bytes[index + 2] ?? 0
    result.push(alphabet[a >> 2], alphabet[((a & 3) << 4) | (b >> 4)], alphabet[((b & 15) << 2) | (c >> 6)], index + 2 < bytes.length ? alphabet[c & 63] : '=')
  }
  return result.join('')
}
async function fullTerms(ui: Pane, review: any) {
  const invitation = review.invitation, shown = await visible(ui)
  for (const term of [ROOT, quote(review.agent.name), quote(review.agent.owner), ...review.agent.capabilities.map(quote),
    quote(invitation.network.name), invitation.network.id, invitation.network.context_id, invitation.network.genesis_root_public_key,
    invitation.inviter_host_public_key, invitation.invitation.id, quote(invitation.invitation.member),
    invitation.invitation.expected_person_public_key, invitation.invitation.issued_at, invitation.invitation.expires_at,
    ...invitation.contacts.flatMap((contact: any) => [contact.sequence, contact.issued_at, contact.expires_at, ...contact.quic_addresses,
      ...contact.bootstrap_addresses, ...contact.relays.flatMap((relay: any) => [relay.address, relay.public_key])]),
    ...invitation.helpers.flatMap((helper: any) => [helper.address, helper.public_key])]) expect(shown).toContain(term)
  for (const word of ['identity', 'request', 'owner', 'membership', 'agent access', 'machine', 'files', 'conversation', 'capability']) expect(shown.toLowerCase()).toContain(word)
}

const mapping: Record<string, [string, string]> = {
  pending: ['person_owner', 'review_owner_offer'], needs_selection: ['requesting_machine', 'review_owner_selection'],
  needs_administrator: ['network_administrator', 'review_admission'], needs_owner_finalization: ['person_owner', 'review_owner_finalization'],
  needs_commit: ['requesting_machine', 'review_final_commit'], finalizing: ['host', 'await_local_application'],
  linked: ['requesting_machine', 'inspect_access_readiness'], cancelled: ['requesting_machine', 'review_replacement'],
  expired: ['requesting_machine', 'review_replacement'], blocked: ['local_owner', 'inspect_advanced_status'],
}
const stages = ['request_created', 'owner_offered', 'owner_selected', 'administrator_offered', 'owner_finalized', 'commit_persisted', 'locally_applied']
const stageMeaning: Record<string, RegExp> = {
  request_created: /Request created/i,
  owner_offered: /Owner offer (?:recorded|received)/i,
  owner_selected: /Owner (?:selection recorded|selected)/i,
  administrator_offered: /Administrator offer (?:recorded|received)/i,
  owner_finalized: /Owner finali[sz]ation (?:recorded|complete)/i,
  commit_persisted: /Final commit (?:recorded|persisted)/i,
  locally_applied: /Local application recorded/i,
}
async function progressResponse(w: World, state = 'pending') {
  const order = ['pending', 'needs_selection', 'needs_administrator', 'needs_owner_finalization', 'needs_commit', 'finalizing', 'linked']
  const level = Math.max(0, order.indexOf(state)), outcome = w.joining.outcome
  const request = { request_id: outcome.request_id, role: 'requester', mode: 'new', state,
    network_id: outcome.network_id, context_id: outcome.context_id, migration_proposal_id: '-', person_public_key: outcome.person_public_key,
    // HOST is SHA256 of this canonical32-byte public key (bytes0x02).
    host_public_key: INVITER_KEY, device_public_key: RELAY_KEY,
    created_at: stamp(state === 'expired' ? NOW - 3_601_000 : NOW - 30_000), expires_at: stamp(state === 'expired' ? NOW - 1000 : NOW + 3_570_000),
    request_packet_id: id64('dpk', 60), owner_offer_id: level >= 1 ? id64('dpk', 61) : '-',
    selection_id: level >= 2 ? id64('dpk', 62) : '-', administrator_offer_id: level >= 3 ? id64('dpk', 63) : '-',
    owner_finalization_id: level >= 4 ? id64('dpk', 64) : '-', manifest_id: level >= 4 ? id64('dm', 65) : '-',
    activation_id: level >= 5 ? id64('da', 66) : '-', outcome_id: level >= 6 ? id64('dpk', 67) : '-',
    selection_approved: level >= 2, commit_approved: level >= 5, completed: stages.slice(0, level + 1),
    attention: ['delivery_pending', 'UNTRUSTED_ATTENTION_RUN_THIS'], next: ['UNTRUSTED_NEXT_SIGN_NOW'] }
  return { version: 1, host_id: w.host, flow_id: w.joining.flow_id, review_id: w.joining.review_id,
    context: context(w.parent), observed_at: stamp(Math.floor(w.clock.now() / 1000) * 1000), outcome: clone(outcome), request,
    next_participant: mapping[state][0], next_action: mapping[state][1] }
}
async function published($: Engine, w: World, flowState = 'requested') {
  const ui = await setup($, w)
  w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: flowState })
  await joinEntry(w, ui); return ui
}

const ownerEffects = { approve_owner_intent: true, authorize_original_signature: true,
  authorize_bounded_owner_finalization: true, auto_select_single_offer_after_signature: true,
  publish_owner_offer_after_signature: true, grant_membership: false, grant_agent_access: false,
  approve_network_administrator: false, commit_request: false, share_files: false,
  share_conversation: false, capability_calls: false }
async function ownerRecord(w: World, options: any = {}) {
  const request = (await progressResponse(w, w.requestState)).request
  const state = options.state ?? 'review', n = options.n ?? 70
  const review = { version: 1, kind: 'approve_new_original_owner', host_id: w.host, context: context(w.parent),
    flow_id: w.joining.flow_id, join_review_id: w.joining.review_id, request_id: request.request_id,
    intent_id: id('dint', n), network: clone(w.joining.review.invitation.network),
    member: w.joining.review.invitation.invitation.member, person_public_key: w.joining.review.person_public_key,
    host_public_key: request.host_public_key, device_public_key: request.device_public_key,
    proposed_owner_offer_id: id64('dpk', 61), scopes: 7,
    not_after: stamp(Date.parse(request.created_at) + 7 * 86_400_000),
    expires_at: stamp(Math.floor((options.expires ?? (state === 'expired' ? NOW - 1000 : NOW + 900_000)) / 1000) * 1000), effects: clone(ownerEffects) }
  return { review_id: await digest('peerspan-onboarding-original-owner-review-v1', review), review, state,
    next_action: state === 'review' ? 'approve_owner_intent' : state === 'approved'
      ? request.owner_offer_id === '-' ? 'provide_original_signature' : 'follow_join_progress' : 'inspect_join_progress' }
}
async function ownerResponse(w: World) {
  const request = (await progressResponse(w, w.requestState)).request
  const owner = clone(w.ownerValue)
  if (owner?.state === 'review' && Date.parse(owner.review.expires_at) <= w.clock.now()) {
    owner.state = 'expired'; owner.next_action = 'inspect_join_progress'
  }
  return { version: 1, host_id: w.host, flow_id: w.joining.flow_id, join_review_id: w.joining.review_id,
    context: context(w.parent), observed_at: stamp(Math.floor(w.clock.now() / 1000) * 1000), request, owner }
}
async function ownerPublished($: Engine, w: World, options: any = {}) {
  const ui = await setup($, w, null, { networks: [] })
  w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested', n: options.flow ?? 60 })
  if (options.state) w.ownerValue = await ownerRecord(w, options)
  await joinEntry(w, ui); return ui
}
async function reviewOwner(ui: Pane) { await press(ui, 'Review owner powers') }
async function noOwnerApprove(ui: Pane, label = '') {
  expect(await ui.find({ type: 'Button', text: /^Approve owner powers$/ }), label).toBeUndefined()
}
async function noOwnerRecord(ui: Pane, label = '') {
  expect(await visible(ui), label).not.toContain('Owner consent: recorded')
}
const ownerCalls = (w: World, op?: string) => w.calls.filter(call => call.kind === (op ? 'join.owner.' + op : call.kind) && call.kind.startsWith('join.owner.'))
function ownerPrivacy(w: World, shown = '', runtime = false, executable = 'peerspan', state?: string) {
  expect(w.forbidden).toEqual([])
  const privateValues = [TOKEN, SOCKET, RAW, 'PRIVATE_PROVIDER_ERROR', '/private/provider-path', NATIVE,
    ...w.codes, w.parent?.flow_id, w.parent?.review_id, w.parent?.review.session_id,
    w.child?.flow_id, w.child?.review_id, w.child?.review.adapter_id,
    w.joining?.flow_id, w.joining?.review_id, w.joining?.outcome?.request_id,
    w.ownerValue?.review_id, w.ownerValue?.review.intent_id, w.ownerValue?.review.proposed_owner_offer_id].filter(Boolean)
  for (const value of privateValues) {
    expect(w.outside.join('\n')).not.toContain(value); expect(shown).not.toContain(value)
    for (const prompt of w.prompts) expect(prompt.text).not.toContain(value)
  }
  expect(shown).not.toMatch(/\b(?:flow_[0-9a-f]{32}|review_[0-9a-f]{64}|dint_[0-9a-f]{32}|link_[0-9a-f]{64}|dpk_[0-9a-f]{64})\b/)
  expect(w.outside.join('\n')).not.toContain(ROOT)
  for (const command of w.calls) {
    expect(command.init?.timeoutMs).toBe(5000)
    expect(command.argv.slice(0, 1 + (state ? 2 : 0))).toEqual([executable, ...(state ? ['--state', state] : [])])
    for (const value of [ROOT, NATIVE, TOKEN, SOCKET, ...w.codes]) expect(command.argv).not.toContain(value)
    // Existing inspect commands take their exact public reference in argv.
    // New owner operations carry every reference only in private stdin.
    const inspection = ({ 'project.inspect': command.expectedProjectFlow, 'join.inspect': command.expectedFlow,
      'adapter.inspect': command.expectedAdapterFlow } as Record<string, string | undefined>)[command.kind]
    if (inspection) expect(command.argv).toEqual([executable, ...(state ? ['--state', state] : []),
      'onboarding', command.kind.split('.')[0], 'inspect', inspection])
    const referenceFreeArgs = inspection ? command.argv.slice(0, -1) : command.argv
    for (const value of [w.joining?.flow_id, w.joining?.review_id, w.ownerValue?.review_id, w.ownerValue?.review.intent_id].filter(Boolean)) {
      expect(referenceFreeArgs).not.toContain(value)
    }
    expect(command.kind).not.toMatch(/identit|create-identity|sign|resume|selection|admi|commit/)
  }
  for (const command of ownerCalls(w)) {
    const op = command.kind.split('.')[2]
    expect(['lookup', 'prepare', 'approve']).toContain(op)
    expect(command.argv).toEqual([executable, ...(state ? ['--state', state] : []), 'onboarding', 'join', 'owner', op, '--stdin'])
    const body = { flow_id: command.expectedFlow, context: command.expectedContext, join_review_id: command.expectedJoinReview,
      ...(op === 'approve' ? { owner_review_id: command.expectedOwnerReview } : {}) }
    expect(command.payload).toEqual(body); expect(typeof command.init.stdin).toBe('string')
    expect(JSON.parse(command.init.stdin)).toEqual(command.payload)
  }
  if (!runtime) {
    expect(w.httpCalls).toEqual([]); expect(w.prompts).toEqual([])
    expect(w.tools.map(tool => tool.name)).toEqual(['delivery_acknowledge'])
  }
}
function delaySignal(w: World, milliseconds: number) {
  let entered!: () => void
  const started = new Promise<void>(resolve => { entered = resolve })
  return { started, wait: () => { const pending = w.clock.sleep(milliseconds); entered(); return pending } }
}
async function leaveIfPresent(ui: Pane) {
  const leave = await ui.find({ type: 'Button', text: /^Leave owner review$/ })
  if (leave) await ui.press({ key: leave.key! })
}
async function ownerTerms(ui: Pane, w: World) {
  const review = w.ownerValue.review, shown = await visible(ui)
  for (const term of [ROOT, quote(review.network.name), review.network.id, review.network.context_id,
    review.network.genesis_root_public_key, quote(review.member), review.person_public_key, review.host_public_key,
    review.device_public_key, review.not_after, review.expires_at, stamp(Math.floor(w.clock.now() / 1000) * 1000)]) expect(shown).toContain(term)
  const lower = shown.toLowerCase()
  for (const term of [/policy.*edit|edit.*policy/, /host.*bind|bind.*host/, /own.*device|device.*own/,
    /renew/, /revok|revoc/, /original.*sign|sign.*original/, /bounded/, /finali[sz]/,
    /administrator/, /single.*offer|one.*offer/, /select/, /publish|publication/,
    /membership/, /agent access/, /commit/, /files/, /conversation/, /capabilit/, /reachab/, /model/]) expect(lower).toMatch(term)
  for (const meaning of [/(?:policy[^\n]{0,40}\b1\b|\b1\b[^\n]{0,40}policy)/i,
    /(?:host[^\n]{0,40}\b2\b|\b2\b[^\n]{0,40}host)/i,
    /(?:device[^\n]{0,60}\b4\b|\b4\b[^\n]{0,60}device)/i,
    /(?:admin[^\n]{0,40}\b8\b|\b8\b[^\n]{0,40}admin)/i]) expect(shown).toMatch(meaning)
  ownerPrivacy(w, shown)
}

test('entry publication progress global Refresh and fresh native state never start owner work', async ($, on) => {
  const w = fixture(on), ui = await ownerPublished($, w, { state: 'approved' })
  expect(await ui.find({ type: 'Button', text: /^Review owner powers$/ })).toBeDefined()
  await noOwnerRecord(ui); expect(ownerCalls(w)).toEqual([])
  await press(ui, 'Check join progress'); await press(ui, 'Refresh'); await w.clock.advance(2000)
  expect(ownerCalls(w)).toEqual([]); await noOwnerRecord(ui)
  await back(ui); await joinEntry(w, ui); expect(ownerCalls(w)).toEqual([])
  ownerPrivacy(w, await visible(ui))
})

const configuredOwner: TestOptions & { options: Record<string, string> } = {
  options: { executable: '/fixture bin/peerspan;$(literal)', state: '/private owner state/$(literal)' },
}
test('double explicit Review sends one lookup then at most one prepare with literal exact5s private commands', configuredOwner, async ($, on) => {
  const w = fixture(on), ui = await ownerPublished($, w), normal = w.run, delayed = delaySignal(w, 1000)
  w.run = async (kind, payload, e) => {
    if (kind === 'join.owner.lookup') { const value = await normal(kind, payload, e); await delayed.wait(); return value }
    return normal(kind, payload, e)
  }
  const button = await key(ui, 'Review owner powers'), at = w.trace.length
  const pending = ui.press({ key: button }); void pending.catch(() => undefined)
  await delayed.started; const second = ui.press({ key: button }).catch(() => undefined)
  expect(ownerCalls(w, 'prepare')).toHaveLength(0)
  await w.clock.advance(1000); await Promise.all([pending, second])
  expect(ownerCalls(w, 'lookup')).toHaveLength(1); expect(ownerCalls(w, 'prepare')).toHaveLength(1)
  expect(ownerCalls(w, 'lookup')[0].payload).toEqual({ flow_id: w.joining.flow_id, context: context(w.parent), join_review_id: w.joining.review_id })
  expect(ownerCalls(w, 'prepare')[0].payload).toEqual(ownerCalls(w, 'lookup')[0].payload)
  const trace = w.trace.slice(at), sent = trace.findIndex(event => event.kind === 'join.owner.lookup')
  for (const kind of ['project.inspect', 'join.inspect', 'snapshot', 'root', 'native']) expect(trace.slice(0, sent).some(event => event.kind === kind)).toBe(true)
  ownerPrivacy(w, await visible(ui), false, configuredOwner.options.executable, configuredOwner.options.state)
})

test('full exact quoted owner powers and finite effects are displayed without signing or later authority', async ($, on) => {
  const w = fixture(on), ui = await ownerPublished($, w)
  await reviewOwner(ui); await ownerTerms(ui, w)
  expect(await ui.find({ type: 'Button', text: /^Approve owner powers$/ })).toBeDefined()
  expect(ownerCalls(w, 'approve')).toHaveLength(0)
  expect(await visible(ui)).not.toContain('Owner consent: recorded')
  const retained = clone(w.ownerValue)
  await press(ui, 'Leave owner review'); await noOwnerApprove(ui); expect(w.ownerValue).toEqual(retained)
  expect(await ui.find({ type: 'Button', text: /^Review owner powers$/ })).toBeDefined()
  await reviewOwner(ui); expect(ownerCalls(w, 'prepare')).toHaveLength(1); expect(w.ownerValue).toEqual(retained)
  ownerPrivacy(w, await visible(ui))
})

test('all five observed states separate approval original signature and completed owner offer', async ($, on) => {
  const w = fixture(on), ui = await ownerPublished($, w)
  for (const state of ['review', 'approved', 'cancelled', 'expired', 'invalidated']) {
    w.requestState = state === 'cancelled' ? 'cancelled' : 'pending'
    w.ownerValue = await ownerRecord(w, { state }); await reviewOwner(ui)
    expect(ownerCalls(w, 'prepare')).toHaveLength(0)
    if (state === 'review') expect(await ui.find({ type: 'Button', text: /^Approve owner powers$/ })).toBeDefined()
    else await noOwnerApprove(ui, state)
    if (state === 'approved') {
      expect(await visible(ui)).toContain('Owner consent: recorded')
      expect(await visible(ui)).toMatch(/original.*sign|sign.*original/i)
      expect(await visible(ui)).not.toMatch(/(?:this pane|this frontend|this conversation) (?:approved|recorded|gave consent)/i)
    } else expect(await visible(ui).then(value => value.toLowerCase())).toContain(state)
    await press(ui, 'Leave owner review')
  }
  w.requestState = 'needs_administrator'; w.ownerValue = await ownerRecord(w, { state: 'approved' })
  await reviewOwner(ui); expect(await visible(ui)).toContain('Owner consent: recorded'); await noOwnerApprove(ui)
  expect(await visible(ui)).toMatch(/progress/i); expect(w.ownerValue.next_action).toBe('follow_join_progress')
  ownerPrivacy(w, await visible(ui))
})

test('historical approved consent beyond its finite review window is read only and never an active grant', async ($, on) => {
  const w = fixture(on), ui = await ownerPublished($, w, { state: 'approved', expires: NOW - 1000 })
  await reviewOwner(ui); expect(await visible(ui)).toContain('Owner consent: recorded'); await noOwnerApprove(ui)
  expect(await visible(ui)).toMatch(/original.*sign|sign.*original/i)
  const retained = clone(w.ownerValue); await w.clock.advance(900_001)
  expect(w.ownerValue).toEqual(retained); expect(ownerCalls(w, 'approve')).toHaveLength(0); expect(ownerCalls(w, 'prepare')).toHaveLength(0)
  ownerPrivacy(w, await visible(ui))
})

test('malformed owner wrapper ordinary request pins keys booleans stage ordering and action never offer approval', async ($, on) => {
  const w = fixture(on), ui = await ownerPublished($, w, { state: 'review' }), normal = w.run
  const variants: [string, (v: any) => void][] = [
    ['wrapper extra', v => { v.extra = RAW }], ['owner extra', v => { v.owner.extra = RAW }],
    ['request extra', v => { v.request.extra = RAW }], ['host', v => { v.host_id = 'host_' + '9'.repeat(64) }],
    ['context', v => { v.context.native_session_id = 'different-native' }], ['flow', v => { v.flow_id = id('flow', 99) }],
    ['join review', v => { v.join_review_id = id64('review', 99) }], ['request id', v => { v.request.request_id = id64('link', 99) }],
    ['host hash', v => { v.request.host_public_key = GENESIS_KEY }], ['device key', v => { v.request.device_public_key = 'bad' }],
    ['requester', v => { v.request.role = 'owner' }], ['mode', v => { v.request.mode = 'renew' }],
    ['boolean', v => { v.request.selection_approved = 0 }], ['stage order', v => { v.request.completed = ['owner_offered', 'request_created'] }],
    ['state action', v => { v.owner.next_action = 'follow_join_progress' }], ['owner state', v => { v.owner.state = 'ready' }],
  ]
  for (const [label, change] of variants) {
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'join.owner.lookup') change(value); return value }
    await reviewOwner(ui); await noOwnerApprove(ui, label); await noOwnerRecord(ui, label)
    expect(await visible(ui), label).toContain('Join request: publication recorded')
    expect(ownerCalls(w, 'prepare'), label).toHaveLength(0); expect(ownerCalls(w, 'approve'), label).toHaveLength(0)
    await leaveIfPresent(ui)
  }
  ownerPrivacy(w, await visible(ui))
})

test('malformed immutable review digest fixed profile lifetime identities and effects are rejected even with recomputed hashes', async ($, on) => {
  const w = fixture(on), ui = await ownerPublished($, w, { state: 'review' }), normal = w.run
  const variants: [string, (v: any) => void][] = [
    ['extra', v => { v.owner.review.extra = RAW }], ['kind', v => { v.owner.review.kind = 'approve_machine' }],
    ['intent', v => { v.owner.review.intent_id = id64('dint', 1) }], ['request', v => { v.owner.review.request_id = id64('link', 99) }],
    ['network', v => { v.owner.review.network.id = id64('net', 99) }], ['member', v => { v.owner.review.member += ' changed' }],
    ['person', v => { v.owner.review.person_public_key = GENESIS_KEY }], ['host key', v => { v.owner.review.host_public_key = GENESIS_KEY }],
    ['device', v => { v.owner.review.device_public_key = KEY }], ['profile', v => { v.owner.review.scopes = 15 }],
    ['lifetime', v => { v.owner.review.not_after = stamp(NOW + 8 * 86_400_000) }],
    ['window', v => { v.owner.review.expires_at = stamp(NOW + 901_000) }],
    ['canonical time', v => { v.owner.review.expires_at = '2026-10-29T12:15:00+00:00' }],
    ['effect', v => { v.owner.review.effects.grant_membership = true }],
    ['digest', v => { v.owner.review_id = id64('review', 99) }],
  ]
  for (const [label, change] of variants) {
    w.run = async (kind, payload, e) => {
      const value = await normal(kind, payload, e)
      if (kind === 'join.owner.lookup') { change(value); if (label !== 'digest') value.owner.review_id = await digest('peerspan-onboarding-original-owner-review-v1', value.owner.review) }
      return value
    }
    await reviewOwner(ui); await noOwnerApprove(ui, label); await noOwnerRecord(ui, label)
    expect(ownerCalls(w, 'approve'), label).toHaveLength(0); await leaveIfPresent(ui)
  }
  ownerPrivacy(w, await visible(ui))
})

test('short private markers in plain and decorated quoted owner metadata block the entire review', async ($, on) => {
  const w = fixture(on), ui = await ownerPublished($, w, { state: 'review' }), normal = w.run
  const prefixes = ['psi2-', 'psl2-', 'peerspan-invite-v1.', 'peerspan-member-invite-v1.', 'peerspan-person-invite-v1.', 'token_', 'instance_']
  for (const [index, prefix] of prefixes.entries()) for (const decorated of [false, true]) {
    const secret = 'SHORTSECRET' + index, split = prefix.slice(0, 3) + '\u202e\x1b[31m' + prefix.slice(3)
    const label = decorated ? '\x1b]0;' + split + secret + '\x07visible' : prefix + secret
    w.run = async (kind, payload, e) => {
      const value = await normal(kind, payload, e)
      if (kind === 'join.owner.lookup') {
        value.owner.review.member = label
        value.owner.review_id = await digest('peerspan-onboarding-original-owner-review-v1', value.owner.review)
      }
      return value
    }
    await reviewOwner(ui); await noOwnerApprove(ui); await noOwnerRecord(ui)
    const shown = await visible(ui); expect(shown).not.toContain(prefix); expect(shown).not.toContain(secret)
    expect(w.outside.join('\n')).not.toContain(secret); expect(ownerCalls(w, 'approve')).toHaveLength(0); await leaveIfPresent(ui)
  }
  ownerPrivacy(w, await visible(ui))
})

test('double explicit approval clears old confirmation rechecks bindings and sends one exact displayed review', async ($, on) => {
  const w = fixture(on), ui = await ownerPublished($, w, { state: 'review' }); await reviewOwner(ui)
  const retained = clone(w.ownerValue), normal = w.run, delayed = delaySignal(w, 1000), at = w.trace.length
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'join.owner.lookup') await delayed.wait(); return value }
  const button = await key(ui, 'Approve owner powers'), pending = ui.press({ key: button }); void pending.catch(() => undefined)
  await delayed.started; const second = ui.press({ key: button }).catch(() => undefined)
  await noOwnerRecord(ui); expect(ownerCalls(w, 'approve')).toHaveLength(0)
  await w.clock.advance(1000); await Promise.all([pending, second])
  expect(ownerCalls(w, 'approve')).toHaveLength(1)
  expect(ownerCalls(w, 'approve')[0].payload).toEqual({ flow_id: w.joining.flow_id, context: context(w.parent),
    join_review_id: w.joining.review_id, owner_review_id: retained.review_id })
  expect(await visible(ui)).toContain('Owner consent: recorded'); await noOwnerApprove(ui)
  const trace = w.trace.slice(at), sent = trace.findIndex(event => event.kind === 'join.owner.approve')
  for (const kind of ['project.inspect', 'join.inspect', 'snapshot', 'join.owner.lookup', 'root', 'native']) expect(trace.slice(0, sent).some(event => event.kind === kind)).toBe(true)
  ownerPrivacy(w, await visible(ui))
})

test('changed parent flow outcome host root conversation or terminal blocks a captured approval', async ($, on) => {
  const w = fixture(on); let ui = await ownerPublished($, w, { state: 'review' })
  const parent = clone(w.parent), joining = clone(w.joining), retained = clone(w.ownerValue)
  for (const [index, mode] of ['parent', 'flow', 'outcome', 'host', 'root', 'native', 'surface'].entries()) {
    if (index) {
      w.parent = clone(parent); w.joining = clone(joining); w.ownerValue = clone(retained)
      w.root = ROOT; w.native = NATIVE; w.host = HOST; w.surface = 'terminal'; w.surfaces = ['terminal']
      ui = await enter($, w); await joinEntry(w, ui)
    }
    await reviewOwner(ui); const button = await key(ui, 'Approve owner powers'), before = ownerCalls(w, 'approve').length
    if (mode === 'parent') w.parent.state = 'invalidated'
    if (mode === 'flow') w.joining.review_id = id64('review', 99)
    if (mode === 'outcome') w.joining.outcome.request_id = id64('link', 99)
    if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
    if (mode === 'root') w.root = '/changed-private-root'
    if (mode === 'native') w.native = 'changed-private-native'
    if (mode === 'surface') { w.surface = null; w.surfaces = [] }
    await ui.press({ key: button }).catch(() => undefined); await w.clock.settle()
    expect(ownerCalls(w, 'approve').length, mode).toBe(before); await noOwnerRecord(ui, mode)
    const close = await ui.find({ type: 'Button', text: /^Close$/ }); if (close) await ui.press({ key: close.key! })
    await ui.unmount()
  }
  ownerPrivacy(w)
})

test('fresh lookup must match the complete displayed review pending state and exact proposed offer before approval', async ($, on) => {
  const w = fixture(on), ui = await ownerPublished($, w, { state: 'review' }), retained = clone(w.ownerValue), normal = w.run
  for (const mode of ['review', 'approved', 'request', 'offer']) {
    w.ownerValue = clone(retained); w.run = normal; await reviewOwner(ui)
    w.run = async (kind, payload, e) => {
      const value = await normal(kind, payload, e)
      if (kind === 'join.owner.lookup') {
        if (mode === 'review') { value.owner.review.expires_at = stamp(NOW + 899_000); value.owner.review_id = await digest('peerspan-onboarding-original-owner-review-v1', value.owner.review) }
        if (mode === 'approved') { value.owner.state = 'approved'; value.owner.next_action = 'provide_original_signature' }
        if (mode === 'request') value.request.state = 'blocked'
        if (mode === 'offer') value.request.owner_offer_id = id64('dpk', 99)
      }
      return value
    }
    await press(ui, 'Approve owner powers'); expect(ownerCalls(w, 'approve'), mode).toHaveLength(0); await noOwnerRecord(ui, mode)
    await leaveIfPresent(ui)
  }
  ownerPrivacy(w, await visible(ui))
})

test('deadline native-context and future host-time changes during fresh lookup prevent approval dispatch', async ($, on) => {
  const w = fixture(on); let ui = await ownerPublished($, w, { state: 'review' }); const normal = w.run
  const parent = clone(w.parent), joining = clone(w.joining)
  for (const [index, mode] of ['deadline', 'root', 'future-host'].entries()) {
    if (index) {
      w.root = ROOT; w.parent = clone(parent); w.joining = clone(joining); w.run = normal
      w.ownerValue = await ownerRecord(w, { expires: w.clock.now() + 900_000 })
      ui = await enter($, w); await joinEntry(w, ui)
    } else w.ownerValue = await ownerRecord(w, { expires: NOW + 1000 })
    await reviewOwner(ui); const delayed = delaySignal(w, 1000)
    w.run = async (kind, payload, e) => {
      const value = await normal(kind, payload, e)
      if (kind === 'join.owner.lookup') {
        if (mode === 'deadline') await delayed.wait()
        if (mode === 'root') w.root = '/changed-during-owner-lookup'
        if (mode === 'future-host') value.observed_at = stamp(Math.floor(w.clock.now() / 1000) * 1000 + 31_000)
      }
      return value
    }
    const pending = press(ui, 'Approve owner powers'); void pending.catch(() => undefined)
    if (mode === 'deadline') { await delayed.started; await w.clock.advance(1001) }
    await pending; expect(ownerCalls(w, 'approve'), mode).toHaveLength(0); await noOwnerRecord(ui, mode)
    const close = await ui.find({ type: 'Button', text: /^Close$/ }); if (close) await ui.press({ key: close.key! }); await ui.unmount()
  }
  ownerPrivacy(w)
})

test('lost denied raw or mismatched write outcomes recover by explicit lookup without retry preparation or signing', async ($, on) => {
  const w = fixture(on), ui = await ownerPublished($, w, { state: 'review' }), normal = w.run, retained = clone(w.ownerValue)
  for (const mode of ['denied', 'raw', 'mismatched']) {
    w.run = normal; w.ownerValue = clone(retained); await reviewOwner(ui)
    w.run = async (kind, payload, e) => {
      const value = await normal(kind, payload, e)
      if (kind === 'join.owner.approve') {
        if (mode === 'denied') return { fixtureDeny: true }
        if (mode === 'raw') return { fixtureRaw: CODE + RAW }
        value.owner.review_id = id64('review', 99)
      }
      return value
    }
    const before = ownerCalls(w, 'approve').length
    await press(ui, 'Approve owner powers'); await noOwnerRecord(ui, mode); await noOwnerApprove(ui, mode)
    expect(await visible(ui)).toContain('Join request: publication recorded')
    expect(await ui.find({ type: 'Button', text: /^Check owner consent$/ })).toBeDefined()
    await w.clock.advance(1000); expect(ownerCalls(w, 'approve').length, mode).toBe(before + 1)
    w.run = normal; const preparations = ownerCalls(w, 'prepare').length
    await press(ui, 'Check owner consent'); expect(await visible(ui)).toContain('Owner consent: recorded')
    expect(ownerCalls(w, 'approve').length).toBe(before + 1); expect(ownerCalls(w, 'prepare').length).toBe(preparations)
    await press(ui, 'Leave owner review')
  }
  ownerPrivacy(w, await visible(ui))
})

test('failed owner reads clear actionable terms and null Check recovery never prepares an intent', async ($, on) => {
  const w = fixture(on), ui = await ownerPublished($, w), normal = w.run
  for (const mode of ['denied', 'raw']) {
    w.run = async (kind, payload, e) => kind === 'join.owner.lookup' ? mode === 'denied' ? { fixtureDeny: true } : { fixtureRaw: RAW } : normal(kind, payload, e)
    await reviewOwner(ui); await noOwnerApprove(ui); await noOwnerRecord(ui)
    const before = ownerCalls(w).length; await w.clock.advance(1000); expect(ownerCalls(w).length).toBe(before)
    w.run = normal; await press(ui, 'Check owner consent')
    expect(w.ownerValue).toBe(null); expect(ownerCalls(w, 'prepare')).toHaveLength(0); await noOwnerApprove(ui)
    expect(await ui.find({ type: 'Button', text: /^Review owner powers$/ })).toBeDefined()
  }
  await reviewOwner(ui); expect(ownerCalls(w, 'prepare')).toHaveLength(1); expect(ownerCalls(w, 'approve')).toHaveLength(0)
  ownerPrivacy(w, await visible(ui))
})

test('Leave remains available during lookup and preparation and late reads cannot restore old controls', async ($, on) => {
  const w = fixture(on), ui = await ownerPublished($, w), normal = w.run
  for (const op of ['lookup', 'prepare']) {
    w.ownerValue = null; const delayed = delaySignal(w, 1000)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'join.owner.' + op) await delayed.wait(); return value }
    const pending = reviewOwner(ui); void pending.catch(() => undefined); await delayed.started
    await press(ui, 'Leave owner review'); await w.clock.advance(1000); await pending
    await noOwnerApprove(ui); await noOwnerRecord(ui)
    expect(await visible(ui)).toContain('Join request: publication recorded'); expect(ownerCalls(w, 'approve')).toHaveLength(0)
  }
  ownerPrivacy(w, await visible(ui))
})

test('Back Close and Refresh invalidate pending approval responses while preserving durable recorded consent', async ($, on) => {
  const w = fixture(on); let ui = await ownerPublished($, w, { state: 'review' }); const normal = w.run, retained = clone(w.ownerValue)
  for (const [index, mode] of ['back', 'close', 'refresh'].entries()) {
    if (index) { w.run = normal; w.ownerValue = clone(retained); ui = await enter($, w); await joinEntry(w, ui) }
    await reviewOwner(ui); const delayed = delaySignal(w, 1000)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'join.owner.approve') await delayed.wait(); return value }
    const pending = press(ui, 'Approve owner powers'); void pending.catch(() => undefined); await delayed.started
    if (mode === 'back') await back(ui)
    if (mode === 'close') await press(ui, 'Close')
    if (mode === 'refresh') await press(ui, 'Refresh')
    await w.clock.advance(1000); await pending
    expect(w.ownerValue.state, mode).toBe('approved'); await noOwnerRecord(ui, mode); await noOwnerApprove(ui, mode)
    const close = await ui.find({ type: 'Button', text: /^Close$/ }); if (close) await ui.press({ key: close.key! }); await ui.unmount()
  }
  ownerPrivacy(w)
})

test('root conversation host parent terminal and session end invalidate a delayed owner response', async ($, on) => {
  const w = fixture(on); let ui = await ownerPublished($, w, { state: 'review' })
  const normal = w.run, parent = clone(w.parent), joining = clone(w.joining), retained = clone(w.ownerValue)
  for (const [index, mode] of ['root', 'native', 'host', 'parent', 'surface', 'end'].entries()) {
    if (index) {
      w.root = ROOT; w.native = NATIVE; w.host = HOST; w.surface = 'terminal'; w.surfaces = ['terminal']
      w.parent = clone(parent); w.joining = clone(joining); w.ownerValue = clone(retained); w.run = normal
      ui = await enter($, w); await joinEntry(w, ui)
    }
    const delayed = delaySignal(w, 1000)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'join.owner.lookup') await delayed.wait(); return value }
    const pending = reviewOwner(ui); void pending.catch(() => undefined); await delayed.started
    if (mode === 'root') { w.root = '/changed-private-owner-root'; await $.classic.CwdChanged({ old_cwd: ROOT, new_cwd: w.root }) }
    if (mode === 'native') w.native = 'changed-private-owner-native'
    if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
    if (mode === 'parent') w.parent.state = 'invalidated'
    if (mode === 'surface') { w.surface = null; w.surfaces = [] }
    if (mode === 'end') await $.session.end({ reason: 'clear', sessionId: NATIVE, resume: { id: NATIVE } })
    if (!['root', 'end'].includes(mode)) {
      const refresh = await ui.find({ type: 'Button', text: /^Refresh$/ }); if (refresh) await ui.press({ key: refresh.key! })
    }
    await w.clock.advance(1000); await pending; await noOwnerApprove(ui, mode); await noOwnerRecord(ui, mode)
    expect(w.ownerValue).toEqual(retained); expect(ownerCalls(w, 'approve')).toHaveLength(0)
    const close = await ui.find({ type: 'Button', text: /^Close$/ }); if (close) await ui.press({ key: close.key! }); await ui.unmount()
  }
  ownerPrivacy(w)
})

test('unapproved expiry removes approval without renewal while an already sent approval may confirm historically', async ($, on) => {
  const w = fixture(on), ui = await ownerPublished($, w, { state: 'review', expires: NOW + 1000 })
  await reviewOwner(ui); const before = ownerCalls(w).length
  await w.clock.advance(1000); await noOwnerApprove(ui); expect(ownerCalls(w).length).toBe(before)
  expect(await visible(ui)).toContain('Join request: publication recorded')
  await press(ui, 'Leave owner review'); w.ownerValue = await ownerRecord(w, { expires: w.clock.now() + 1000 })
  await reviewOwner(ui); const normal = w.run, delayed = delaySignal(w, 2000)
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'join.owner.approve') await delayed.wait(); return value }
  const pending = press(ui, 'Approve owner powers'); void pending.catch(() => undefined); await delayed.started
  await w.clock.advance(2000); await pending
  expect(await visible(ui)).toContain('Owner consent: recorded'); expect(ownerCalls(w, 'approve')).toHaveLength(1)
  expect(ownerCalls(w, 'prepare')).toHaveLength(0); await noOwnerApprove(ui)
  ownerPrivacy(w, await visible(ui))
})

test('an old review expiry cannot disable a newer request review after Leave and explicit reentry', async ($, on) => {
  const w = fixture(on), ui = await ownerPublished($, w, { state: 'review', expires: NOW + 1000 })
  await reviewOwner(ui); await press(ui, 'Leave owner review')
  w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested', n: 99 })
  w.ownerValue = await ownerRecord(w, { n: 99, expires: NOW + 900_000 })
  // Reopen joining's explicit current durable outcome before entering its owner view.
  await back(ui); await joinEntry(w, ui); await reviewOwner(ui)
  const retained = clone(w.ownerValue), calls = ownerCalls(w).length
  await w.clock.advance(1001)
  expect(await ui.find({ type: 'Button', text: /^Approve owner powers$/ })).toBeDefined()
  expect(w.ownerValue).toEqual(retained); expect(ownerCalls(w).length).toBe(calls)
  ownerPrivacy(w, await visible(ui))
})

test('owner review approval navigation and recovery preserve established work runtimes and durable inviter state', async ($, on) => {
  const w = fixture(on), ui = await connected($, w)
  await enable($, w, ui); await press(ui, 'Enable incoming tasks'); await w.clock.settle()
  w.invitation = await invitationFlow(w.parent, network(9), { state: 'issued' }); const issued = clone(w.invitation)
  w.networks = []; w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested' })
  await back(ui); await joinEntry(w, ui)
  const tools = w.tools.map(tool => tool.name), prompts = w.prompts.length, ready = readyCalls(w).length
  await reviewOwner(ui); await press(ui, 'Approve owner powers'); await press(ui, 'Leave owner review')
  await reviewOwner(ui); await press(ui, 'Leave owner review')
  const messages = claims(w).length, tasks = requests(w, '/adapter/v1/tasks/next').length, leases = requests(w, '/adapter/v1/connect').length
  await w.clock.advance(5000)
  expect(claims(w).length > messages).toBe(true); expect(requests(w, '/adapter/v1/tasks/next').length > tasks).toBe(true)
  expect(requests(w, '/adapter/v1/connect').length).toBe(leases + 1)
  expect(w.prompts.length).toBe(prompts); expect(readyCalls(w).length).toBe(ready); expect(w.tools.map(tool => tool.name)).toEqual(tools)
  expect(w.invitation).toEqual(issued); expect(ownerCalls(w, 'approve')).toHaveLength(1)
  ownerPrivacy(w, await visible(ui), true)
})
