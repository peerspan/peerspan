/**
 * Independent section34 native access inspection/consent fixtures, pinned303.
 * Public effects only, based on sections30/31 and runtime member/provider/policy
 * contracts; no production imports, real processes, transport, keys or model.
 * All312 prior native files and28 host suites remain unchanged. Delays signal
 * actual dispatch plus registered virtual sleep before navigation/time stimuli.
 * Daemon crypto/evaluator/persistence are separate host evidence. Obsolete
 * rendered closures, final-check/dispatch micro-races, actual reload/installed/
 * terminal/physical/model/readiness acceptance remain source/manual limits.
 */
import { expect, mock, test } from 'claude-code/testing'
import type { Engine, Mounted, TestOptions } from 'claude-code/testing'
import type { On } from 'claude-code'

const NOW = Date.parse('2026-10-29T12:00:00Z')
const ROOT = '/private project/Access $(literal)'
const NATIVE = 'private-access-conversation'
const RAW = 'PRIVATE_PROVIDER_ERROR token_SHORTERROR /private/access-path'
const TOKEN = 'token_' + 'b'.repeat(64)
const SOCKET = '/private host state/adapter.sock'
const HOST_KEY = '/FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU='
const HOST = 'host_dac073e0123bdea59dd9b3bda9cf6037f63aca82627d7abcd5c4ac29dd74003e'
const OWNER = '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='
const PERSON = 'PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw='
const DEVICE = 'WGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY='
const id = (kind: string, n: number, size = 32) => kind + '_' + n.toString(16).padStart(size, '0')
const ds = (n: number) => id('ds', n, 64)
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value))
const stamp = (milliseconds: number) => new Date(milliseconds).toISOString().replace('.000Z', 'Z')
const observed = (w: World) => stamp(Math.floor(w.clock.now() / 1000) * 1000)
const quoted = (value: string) => JSON.stringify(value).replace(/[\u200b\u202a-\u202e]/g,
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

const INSPECT = 'access.inspect', LOOKUP = 'access.lookup', PREPARE = 'access.prepare', APPROVE = 'access.approve'
const inspectEffects = { inspect_current_membership: true, inspect_current_policy: true,
  prepare_access: false, approve_access: false, sign_policy: false, publish_policy: false,
  grant_agent_access: false, share_files: false, share_conversation: false, capability_calls: false }
const consentEffects = { approve_policy_intent: true, authorize_policy_signature: true,
  authorize_policy_publication: true, grant_agent_access_after_signatures: true,
  grant_membership: false, delegate_tasks: false, share_files: false, share_conversation: false,
  capability_calls: false, allow_disconnected: false }
function network(n = 1): any {
  return { id: id('net', n, 64), name: 'Network "東京" ' + n, mode: 'decentralized', context_id: id('ctx', n, 64),
    genesis_root_public_key: OWNER, root_state_id: ds(2), root_public_key: OWNER, root_epoch: 0,
    member: 'Owner "é"', host_public_key: HOST_KEY, person_public_key: OWNER, provider: null,
    provider_state: { state: 'not_selected', code: '-', error: '-', required_ids: [] },
    authority: { state: 'usable', not_after: stamp(NOW + 604_800_000), required_ids: [], conflict_ids: [] },
    delivery: { pending_proof_ids: [], peer_errors: [] }, created_at: stamp(NOW - 60_000) }
}
function member(person = PERSON, key = DEVICE, n = 20, label = 'Participant "é東京"') {
  return { host_public_key: key, member: label, person_public_key: person,
    host_lease_id: ds(n + 1), binding_lease_id: ds(n + 2), device_lease_id: ds(n + 3), not_after: stamp(NOW + 259_200_000) }
}
function baseline(w: World) {
  return { format: 2, network_id: w.selected.id, person_public_key: OWNER, version: 4,
    issued_at: stamp(NOW - 600_000), valid_until: stamp(w.policyEnd),
    rules: [{ agent: w.parent.review.agent.name, principals: ['network'], actions: ['message.append', 'task.submit'],
      max_message_bytes: 65536, max_artifact_bytes: 0, allow_disconnected: false },
    { agent: 'Other "retained" agent', principals: ['network'], actions: ['message.append'],
      max_message_bytes: 4096, allow_disconnected: false },
    { agent: w.parent.review.agent.name, principals: ['group:retained'], actions: ['task.delegate'],
      max_message_bytes: 2048, max_artifact_bytes: 12345, allow_disconnected: true }],
    capability_rules: [{ host: HOST, capability: 'retained-operation', principals: ['network'],
      max_input_bytes: 1234, allow_disconnected: true, max_calls_per_hour: 17 }], trusted_hosts: [HOST],
    edits: [{ host: HOST, seq: 2 }] }
}
async function inspection(w: World) {
  const mine = member(OWNER, HOST_KEY, 10, 'Owner machine "alias"')
  mine.not_after = stamp(w.ownerEnd)
  if (!w.uniqueDevice) mine.device_lease_id = '-'
  const hosts = w.members.filter(row => row.person_public_key === w.person).map(clone)
    .sort((a, b) => a.host_public_key < b.host_public_key ? -1 : a.host_public_key > b.host_public_key ? 1 : 0)
  const body = baseline(w)
  const review = { version: 1, kind: 'inspect_project_agent_access', host_id: w.host, context: context(w.parent),
    agent: clone(w.parent.review.agent), network: { id: w.selected.id, name: w.selected.name, context_id: w.selected.context_id },
    root_state_id: w.selected.root_state_id,
    owner: { person_public_key: OWNER, member: 'Owner "é"', person_lease_id: ds(10), host: mine },
    participant: { person_public_key: w.person, member: w.person === OWNER ? 'Owner "é"' : 'Participant "é東京"',
      person_lease_id: w.person === OWNER ? ds(10) : ds(20), not_after: stamp(w.personEnd), hosts },
    policy: w.noPolicy ? null : { statement_id: ds(50), proof_id: id('dp', 50, 64), body,
      enforced_content: w.enforced ?? { rules: clone(body.rules), capability_rules: clone(body.capability_rules), trusted_hosts: clone(body.trusted_hosts) },
      valid_until: stamp(w.policyEnd) }, effects: clone(inspectEffects) }
  const value = { version: 1, host_id: w.host, context: context(w.parent), observed_at: observed(w),
    review_id: await digest('peerspan-project-access-inspection-v1', review), review, next_action: 'review_agent_access' }
  w.lastInspection = clone(value); return value
}
async function principal(key: string) {
  // Decode canonical public Base64 using ordinary byte arithmetic; no signer.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  let bits = 0, accumulator = 0; const bytes: number[] = []
  for (const char of key.replace(/=+$/, '')) { accumulator = (accumulator << 6) | alphabet.indexOf(char); bits += 6
    if (bits >= 8) { bits -= 8; bytes.push((accumulator >>> bits) & 255) } }
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes)))
  return 'person:person_' + Array.from(hash, b => b.toString(16).padStart(2, '0')).join('')
}
async function receipt(w: World, options: any = {}) {
  const inspected = options.inspected ?? await inspection(w), frozen = clone(inspected.review)
  const created = options.created ?? Math.floor(w.clock.now() / 1000) * 1000
  const end = Math.min(created + 86_400_000, w.providerEnd, Date.parse(frozen.participant.not_after))
  const provider = { kind: options.provider ?? 'device', person_public_key: OWNER, host_public_key: HOST_KEY,
    device_public_key: options.provider === 'original_person' ? '-' : DEVICE,
    lease_id: options.provider === 'original_person' ? frozen.owner.person_lease_id : ds(13),
    root_state_id: frozen.root_state_id, scopes: 7, not_after: stamp(w.providerEnd) }
  const grant = { policy_scope: 'owner_agent_name', agent_id: frozen.agent.id, agent_name: frozen.agent.name,
    principal: await principal(w.person), actions: ['message.append', 'task.submit'], max_message_bytes: 65536,
    max_artifact_bytes: 0, allow_disconnected: false }
  const body: any = clone(frozen.policy?.body ?? { format: 2, network_id: frozen.network.id, person_public_key: OWNER,
    version: 0, rules: [], capability_rules: [], trusted_hosts: [], edits: [] })
  body.version++; body.issued_at = stamp(created); body.valid_until = stamp(end)
  body.edits = [{ host: HOST, seq: 3 }]
  const matching = body.rules.find((rule: any) => rule.agent === grant.agent_name && rule.max_message_bytes === 65536 &&
    (rule.max_artifact_bytes ?? 0) === 0 && rule.allow_disconnected === false &&
    JSON.stringify(rule.actions) === JSON.stringify(grant.actions))
  if (matching) { if (!matching.principals.includes(grant.principal)) matching.principals.push(grant.principal) }
  else body.rules.push({ agent: grant.agent_name, principals: [grant.principal], actions: clone(grant.actions),
    max_message_bytes: 65536, max_artifact_bytes: 0, allow_disconnected: false })
  const parents = [{ role: 'issuer_person', id: frozen.owner.person_lease_id }]
  if (provider.kind === 'device') parents.unshift({ role: 'issuer_device', id: provider.lease_id })
  const review = { version: 1, kind: 'approve_project_agent_access', access_id: id('dint', options.n ?? 81), host_id: w.host,
    context: context(w.parent), inspection_review_id: inspected.review_id, inspection: frozen, replaces_access_id: options.replaces ?? '-',
    grant, action_id: id('act', 70, 64), intent_id: id('dint', 80), provider,
    statement: { id: ds(60), payload_sha256: '9'.repeat(64), payload: { root_state_id: frozen.root_state_id,
      operation_id: '-', sequence: body.version, predecessors: frozen.policy ? [frozen.policy.statement_id] : [], resolves: [],
      issuer: { kind: provider.kind === 'device' ? 'device' : 'person', person_public_key: OWNER }, parents,
      issued_at: stamp(created), not_before: stamp(created), not_after: stamp(end), body } },
    created_at: stamp(created), expires_at: stamp(Math.min(created + 300_000, end)), effects: clone(consentEffects) }
  const state = options.state ?? 'review'
  return { access_id: review.access_id, review_id: await digest('peerspan-project-access-consent-v1', review), review, state,
    next_action: state === 'review' ? 'approve_policy_intent' : state === 'approved' ? 'follow_policy_action' : 'inspect_agent_access' }
}
function accessResponse(w: World) {
  const access = clone(w.access)
  if (access?.state === 'review' && Date.parse(access.review.expires_at) <= w.clock.now()) {
    access.state = 'expired'; access.next_action = 'inspect_agent_access'
  }
  return { version: 1, host_id: w.host, context: context(w.parent), observed_at: observed(w), access }
}

function fixture(on: On) {
  const clock = mock.clock(on, { now: NOW })
  const w = { clock, started: false, root: ROOT, native: NATIVE, host: HOST, surface: 'terminal' as string | null,
    surfaces: ['terminal'], parent: null as any, child: null as any, selected: network(), person: PERSON,
    networks: [network()] as any[], members: [{ ...member(OWNER, HOST_KEY, 10, 'Owner machine "alias"'),
      not_after: stamp(NOW + 604_800_000) }, member()] as any[],
    noPolicy: false, uniqueDevice: true, enforced: null as any, ownerEnd: NOW + 604_800_000, personEnd: NOW + 259_200_000,
    providerEnd: NOW + 604_800_000, policyEnd: NOW + 3_600_000, access: null as any, lastInspection: null as any,
    calls: [] as any[], trace: [] as any[], outside: [] as string[], tools: [] as any[], prompts: [] as any[],
    forbidden: [] as string[], http: [] as any[], materials: [] as any[],
    read: async (_kind: string, _payload: any, _event: any): Promise<any> => undefined }
  w.read = async (kind, payload, e) => {
    if (kind === 'snapshot') return { version: 1, host_id: w.host, observed_at: observed(w), networks: clone(w.networks), agents: [], requests: [], attention: [] }
    if (kind === 'project.lookup') return { version: 1, host_id: w.host, context: payload, flow: clone(w.parent),
      agents: w.parent ? [{ ...clone(w.parent.review.agent), created_at: stamp(NOW - 1000) }] : [] }
    if (kind === 'project.inspect') return clone(w.parent)
    if (kind === 'members') return { context_id: w.selected.context_id,
      members: clone(w.members).sort((a, b) => a.host_public_key < b.host_public_key ? -1 : 1) }
    if (kind === INSPECT) return inspection(w)
    if (kind === LOOKUP) return accessResponse(w)
    if (kind === PREPARE) { w.access ??= await receipt(w); return accessResponse(w) }
    if (kind === APPROVE) { w.access = { ...w.access, state: 'approved', next_action: 'follow_policy_action' }; return accessResponse(w) }
    if (kind === 'adapter.lookup') return { version: 1, host_id: w.host, context: payload, flow: clone(w.child) }
    if (kind === 'adapter.inspect') return clone(w.child)
    if (kind === 'adapter.prepare') { w.child ??= await adapterFlow(w.parent); return clone(w.child) }
    if (kind === 'adapter.decide') {
      w.child = await adapterFlow(w.parent, { state: 'authorized' }); return clone(w.child)
    }
    if (kind === 'adapter.transport') { const value = await transport(w.child); w.materials.push(clone(value)); return value }
    throw Error('Unexpected public fixture operation')
  }
  on('session.start', ($, e) => { w.started = true; return { cwd: e.cwd } })
  on('session.end', ($, e) => ({ sessionId: e.sessionId }))
  on('classic.CwdChanged', () => ({}))
  on('session.root', () => { w.trace.push('root'); return { value: w.root } })
  on('session.id', () => { w.trace.push('native'); return { value: w.native } })
  on('session.cwd', () => ({ value: '/different-shell-cwd' }))
  on('session.surface', () => ({ value: w.surface }))
  on('session.surfaces', () => ({ value: w.surfaces }))
  on('command.register', () => ({ value: undefined }))
  on('tool.register', ($, e) => { w.tools.push(e); return { value: undefined } })
  on('command.run', () => ({ text: 'unhandled fixture command' }))
  on('tool.call', () => ({ deny: 'unregistered fixture tool' }))
  on('process.run', async ($, e) => {
    const at = e.argv.indexOf('onboarding'), tail = at < 0 ? [] : e.argv.slice(at + 1)
    const kind = at < 0 ? 'members' : tail.length ? tail.slice(0, 2).join('.') : 'snapshot'
    const payload = e.init?.stdin ? JSON.parse(e.init.stdin) : undefined
    w.calls.push({ ...e, kind, payload: payload === undefined ? undefined : clone(payload), expectedContext: w.parent ? clone(context(w.parent)) : null,
      expectedProject: w.parent?.flow_id, expectedAdapter: w.child?.flow_id, expectedNetwork: w.selected.id, expectedPerson: w.person,
      expectedInspection: w.lastInspection?.review_id, expectedAccess: w.access?.access_id, expectedReview: w.access?.review_id })
    w.trace.push(kind)
    const value = await w.read(kind, payload, e)
    if (value?.fixtureDeny) return { deny: RAW }
    if (value?.fixtureExit) return { value: { exitCode: 124, stdout: '', stderr: RAW } }
    if (value?.fixtureRaw) return { value: { exitCode: 0, stdout: value.fixtureRaw, stderr: RAW } }
    return { value: { exitCode: 0, stdout: JSON.stringify(value), stderr: '' } }
  })
  on('http.fetch', async ($, e) => {
    w.http.push(clone(e))
    expect(e.init?.socketPath).toBe(SOCKET)
    expect(e.url).toBe('http://peerspan/adapter/v1/connect')
    expect(JSON.parse(e.init.body)).toEqual({ adapter_id: w.child.review.adapter_id, session_id: w.child.review.session_id,
      instance_id: w.materials.at(-1).instance_id, protocol_version: 'claude-mod-v1' })
    expect(Object.fromEntries(Object.entries(e.init.headers).map(([k, v]) => [k.toLowerCase(), v])))
      .toEqual({ authorization: 'Bearer ' + TOKEN, 'x-peerspan-instance': w.materials.at(-1).instance_id, 'content-type': 'application/json' })
    const value = connection(w.child, clock.now(), { ready: true }); w.child.connection = clone(value)
    return { value: { status: 200, ok: true, headers: {}, text: JSON.stringify(value) } }
  })
  on('ui.open', () => ({ value: { isPlaced: w.surface === 'terminal' } }))
  on('ui.close', () => ({ value: undefined }))
  on('ui.panes', () => ({ value: [] }))
  on('ui.render', () => ({ type: 'Text', props: {}, children: ['native core fallback'] }))
  for (const kind of ['ui.toast', 'ui.log', 'ui.status', 'ui.notice'] as const)
    on(kind, ($, e) => { w.outside.push(JSON.stringify(e)); return { value: undefined } })
  on('prompt.submit', ($, e) => { w.prompts.push(clone(e)); return { text: e.text, origin: e.origin } })
  on('store.set', () => { w.forbidden.push('store.set'); return { deny: 'no persistence' } })
  on('fs.read', () => { w.forbidden.push('fs.read'); return { deny: 'no key reads' } })
  on('fs.write', () => { w.forbidden.push('fs.write'); return { deny: 'no files' } })
  on('process.spawn', async function* () { w.forbidden.push('process.spawn'); throw Error('no spawn') })
  on('model.complete', () => { w.forbidden.push('model.complete'); return { deny: 'no inference' } })
  on('session.send', () => { w.forbidden.push('session.send'); return { isDelivered: false } })
  return w
}
type World = ReturnType<typeof fixture>
type Pane = Mounted<'terminal', 'Pane'>
const calls = (w: World, kind?: string) => w.calls.filter(e => kind ? e.kind === kind : e.kind.startsWith('access.'))
const last = (w: World, kind: string) => calls(w, kind).at(-1)
async function shown(ui: Pane) { return (await ui.findAll({})).map(e => e.text).join('\n') }
async function button(ui: Pane, label: string | RegExp) {
  return ui.find({ type: 'Button', text: typeof label === 'string' ? new RegExp('^' + label + '$') : label })
}
async function press(ui: Pane, label: string | RegExp) {
  const found = await button(ui, label); expect(found, String(label)).toBeDefined(); return ui.press({ key: found!.key! })
}
async function enter($: Engine, w: World): Promise<Pane> {
  const answer = await $.command.run({ command: 'peerspan', args: '', origin: { kind: 'composer' },
    presentation: { isFullscreen: false, columns: 100 } })
  w.outside.push(answer.text ?? '', ...(answer.context ?? []))
  return $.ui.mount({ plugin: 'peerspan', surface: 'terminal', component: 'Pane', requestId: 'peerspan',
    viewport: { columns: 100, rows: 40 }, props: { title: 'Peerspan', isFocused: true, bodyColumns: 80,
      placement: 'inline', scroll: { offset: 0, bodyRows: 30 }, view: {} } })
}
async function attached($: Engine, w: World) {
  w.parent ??= await parentFlow({ agent: { id: id('agent', 1), name: 'Agent "東京"', owner: 'Owner \\é', capabilities: ['public metadata'] } })
  if (!w.started) await $.session.start({ cwd: '/different-shell-cwd', surface: w.surface as any, isInteractive: true })
  const ui = await enter($, w); await press(ui, 'Connect this project'); return ui
}
async function choose(ui: Pane, value: string) {
  const matches = (await ui.findAll({ type: 'Button' })).filter(e => e.text.includes(value))
  expect(matches.length, 'one full public identity choice').toBe(1); await ui.press({ key: matches[0].key! })
}
async function inspectPerson(ui: Pane, w: World) {
  await press(ui, 'Review agent access'); await choose(ui, w.selected.id); await choose(ui, w.person)
}
async function prepared($: Engine, w: World) {
  const ui = await attached($, w); await inspectPerson(ui, w); await press(ui, 'Review proposed grant'); return ui
}
async function leave(ui: Pane) { await press(ui, 'Leave agent access') }
async function reenter(ui: Pane, w: World) { await leave(ui); await inspectPerson(ui, w); await press(ui, 'Review proposed grant') }
async function noApprove(ui: Pane, reason = '') { expect(await button(ui, 'Approve agent access'), reason).toBeUndefined() }
async function recorded(ui: Pane) {
  expect(await shown(ui)).toContain('Agent-access consent: recorded'); await noApprove(ui)
  expect(await shown(ui)).toMatch(/sign(?:ing|ature)[\s\S]*publish|publish[\s\S]*sign(?:ing|ature)/i)
  expect(await shown(ui)).toMatch(/unverified|not verified|not establish/i)
  expect(await shown(ui)).not.toMatch(/access (?:is |now )?granted|connection ready|delivery verified/i)
}
function delaySignal(w: World, milliseconds = 1000) {
  let enter!: () => void; const started = new Promise<void>(resolve => { enter = resolve })
  return { started, wait: () => { const pending = w.clock.sleep(milliseconds); enter(); return pending } }
}
async function unknown(ui: Pane) {
  await noApprove(ui); expect(await shown(ui)).toMatch(/unknown|unavailable|not confirmed/i)
  expect(await button(ui, 'Check agent access')).toBeDefined()
  expect(await shown(ui)).not.toContain('Agent-access consent: recorded')
}
async function checkPure(ui: Pane, w: World, mode = 'consent') {
  const at = w.calls.length; await press(ui, 'Check agent access')
  expect(w.calls.slice(at).filter(e => e.kind.startsWith('access.')).map(e => e.kind)).toEqual([mode === 'consent' ? LOOKUP : INSPECT])
}
function privacy(w: World, text = '', runtime = false, executable = 'peerspan', state?: string) {
  expect(w.forbidden).toEqual([]); expect(w.prompts).toEqual([])
  expect(w.tools.map(tool => tool.name)).toEqual(['delivery_acknowledge'])
  if (!runtime) expect(w.http).toEqual([])
  expect(w.outside.join('\n')).not.toContain(ROOT)
  for (const value of [NATIVE, RAW, TOKEN, SOCKET, '/private/access-path', 'PRIVATE_PROVIDER_ERROR', state,
    w.parent?.flow_id, w.parent?.review_id, w.parent?.review.session_id, w.access?.access_id, w.access?.review_id,
    w.access?.review.intent_id].filter(Boolean)) {
    expect(text).not.toContain(value); expect(w.outside.join('\n')).not.toContain(value)
  }
  for (const e of w.calls) {
    const prefix = [executable, ...(state ? ['--state', state] : [])]
    expect(e.init?.timeoutMs, e.kind).toBe(5000)
    if (e.kind === 'members') expect(e.argv).toEqual([...prefix, 'network', 'members', e.expectedNetwork])
    else if (e.kind === 'snapshot') expect(e.argv).toEqual([...prefix, 'onboarding'])
    else if (e.kind.endsWith('.inspect') && !e.kind.startsWith('access.'))
      expect(e.argv).toEqual([...prefix, 'onboarding', e.kind.split('.')[0], 'inspect', e.kind === 'project.inspect' ? e.expectedProject : e.expectedAdapter])
    else expect(e.argv).toEqual([...prefix, 'onboarding', ...e.kind.split('.'), '--stdin'])
    for (const privateValue of [ROOT, NATIVE, RAW, TOKEN, SOCKET]) expect(e.argv).not.toContain(privateValue)
    expect(e.kind).not.toMatch(/sign|apply|action|provider|identit|resume|invitation|join/)
    if (e.kind.startsWith('access.')) expect(e.payload).toEqual({ context: e.expectedContext, network_id: e.expectedNetwork,
      person_public_key: e.expectedPerson,
      ...(e.kind === PREPARE ? { inspection_review_id: e.expectedInspection } : {}),
      ...(e.kind === APPROVE ? { access_id: e.expectedAccess, access_review_id: e.expectedReview } : {}) })
  }
}

async function inspectionTerms(ui: Pane, w: World) {
  const text = await shown(ui), review = w.lastInspection.review
  for (const value of [quoted(review.network.name), review.network.id, review.network.context_id, review.root_state_id,
    quoted(review.agent.name), review.agent.id, review.owner.person_public_key, quoted(review.owner.member),
    review.owner.person_lease_id, quoted(review.owner.host.member), review.owner.host.host_public_key, review.owner.host.host_lease_id,
    review.owner.host.binding_lease_id, review.participant.person_public_key, quoted(review.participant.member),
    review.participant.person_lease_id, review.participant.not_after]) expect(text).toContain(value)
  if (review.policy) {
    for (const value of [review.policy.statement_id, review.policy.proof_id, review.policy.valid_until,
      'rules', 'principals', 'actions', 'max_message_bytes', 'max_artifact_bytes', 'allow_disconnected',
      'capability_rules', 'trusted_hosts', 'edits', 'retained-operation', 'Other', '12345', '1234', '4096'])
      expect(text).toContain(value)
    expect(text).toMatch(/signed[\s\S]*enforced|enforced[\s\S]*signed/i)
  } else expect(text).toMatch(/(?:policy[^\n]*(?:none|absent|null)|no (?:retained |current )?policy)/i)
  expect(text).not.toMatch(/access (?:is |now )?granted|delivery (?:is )?allowed|connection ready/i)
  expect(await button(ui, 'Approve agent access')).toBeUndefined()
  expect(await button(ui, 'Review proposed grant')).toBeDefined()
}
async function consentTerms(ui: Pane, w: World) {
  const text = await shown(ui), review = w.access.review
  for (const value of [review.grant.agent_id, quoted(review.grant.agent_name), review.inspection.network.id,
    review.inspection.participant.person_public_key, review.grant.principal, 'message.append', 'task.submit', '65536',
    review.statement.id, review.provider.person_public_key, review.provider.host_public_key, review.provider.lease_id,
    review.provider.root_state_id, review.created_at, review.expires_at, review.statement.payload.not_after]) expect(text).toContain(value)
  expect(text).toMatch(/(?:name[\s\S]*(?:owner|machines)|(?:owner|machines)[\s\S]*name)/i)
  expect(text).toMatch(/0[^\n]*artifact|artifact[^\n]*0|"max_artifact_bytes"\s*:\s*0/i)
  expect(text).toMatch(/(?:unrelated|broader|existing)[\s\S]*(?:policy|rule)|(?:policy|rule)[\s\S]*(?:unrelated|broader|existing)/i)
  for (const word of ['membership', 'delegat', 'files', 'conversation', 'capabilit', 'disconnected']) expect(text.toLowerCase()).toContain(word)
  expect(text).not.toMatch(/access (?:is |now )?granted|delivery verified|connection ready/i)
}

// Canonical public basepoint multiples for bounded inventory paging.
const PUBLIC_KEYS = ["WGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY=", "yaP4aq5GXw5WUThkUQ85l1YfosnoXqIdwikjCfPNYCI=", "1LT1eEhowwIEAyRnF+wWn/eeJmCOoSahq2nud9GxZxI=", "LxEyymGrON/wDy/qMijyTGxx1YCFuA5H4ZUVyyfo0Ec=", "7ch21oMf0hBdC0OJyi4oMWZGkokUbizgb67+mLIlSN8=", "9H5J+dB60sFga02UBnxB+Xd9T/2nCbcdodiGKPzjTYU=", "uGJAn7XExBI98qv3RiuI8EGtNt1oZM6HL9VHK+NjxbE=", "tLk3/KlbLx6T5B5i/Dx4gY/zimYJb61ueXPlyQAG0yE=", "wPEiVYRETscwRG4jE5B4H/3S8lbp/L6y9A3dwsIjPX8=", "LHvoarB0iLpD6OA9haZ2Jc+/mMhUTeTIdyQbeqr8f+M=", "EzcDasMtjzDUWJw8HFlYEs4P/0DjfG9al6shPzGCkK0=", "+eQtLtyB0jNnlnNStH5IVrgleGNObB3nIoDOi2DOcMA=", "gB9A6q7h74cjJ5ooss9AN7iJ2tIiYEZ4dItT7Q2w25I=", "OSiciZj9aYNcJrYZ6JhIp78Ct8t60boVgcvEUG8lUM4=", "31wurcRMbZShmpqhGK/lrDGT0mQB92JR9SL/BC37y5I=", "6ydnwTeretgnnAeO/xFqsHhurTouD5ifcsN/gvKWlnA=", "BL6X7Jv+bM0B+TQ7coixF7efkcxFwkry+T4AYMorbW8=", "SrB14JA+TjWwltTWTg6BvKXDlorq6Oh9mNgLfoQmES4="]

test('entry Refresh and fresh native reentry are access-inert until explicit attached-project selection', async ($, on) => {
  const w = fixture(on), ui = await attached($, w)
  expect(await button(ui, 'Review agent access')).toBeDefined(); expect(calls(w)).toEqual([])
  await press(ui, 'Refresh'); expect(calls(w)).toEqual([])
  await press(ui, 'Close'); await ui.unmount()
  const again = await enter($, w); await press(again, 'Connect this project'); expect(calls(w)).toEqual([])
  await press(again, 'Review agent access'); expect(calls(w)).toEqual([])
  await choose(again, w.selected.id); expect(calls(w)).toEqual([])
  await choose(again, w.person); expect(calls(w).map(e => e.kind)).toEqual([INSPECT])
  expect(last(w, INSPECT).payload).toEqual({ context: context(w.parent), network_id: w.selected.id, person_public_key: PERSON })
  privacy(w, await shown(again))
})

test('network and grouped-person paging use full sorted public identities quoted labels and no implicit choice', async ($, on) => {
  const w = fixture(on); w.networks = Array.from({ length: 12 }, (_, n) => network(n + 1))
  const ui = await attached($, w); await press(ui, 'Review agent access')
  let choices = (await ui.findAll({ type: 'Button' })).filter(e => /net_[0-9a-f]{64}/.test(e.text))
  expect(choices).toHaveLength(10)
  expect(choices.map(e => e.text.match(/net_[0-9a-f]{64}/)![0])).toEqual(w.networks.slice(0, 10).map(n => n.id))
  for (let n = 0; n < 10; n++) expect(choices[n].text).toContain(quoted(w.networks[n].name))
  await press(ui, /^(?:More|Next).*networks/i)
  choices = (await ui.findAll({ type: 'Button' })).filter(e => /net_[0-9a-f]{64}/.test(e.text))
  expect(choices).toHaveLength(2); await press(ui, /^Previous.*networks/i)
  w.members = PUBLIC_KEYS.slice(0, 12).map((key, n) => member(key, PUBLIC_KEYS[n + 1], 100 + n * 4, 'Same "label"'))
  // A second host for one person is one choice; an unbound host is no person.
  w.members.push(member(PUBLIC_KEYS[0], PUBLIC_KEYS[16], 200, 'Other "machine alias"'))
  w.members.push({ ...member('-', PUBLIC_KEYS[17], 204, 'unbound only'), binding_lease_id: '-', device_lease_id: '-' })
  w.selected = w.networks[0]; await choose(ui, w.selected.id)
  const sorted = w.members.filter(m => m.person_public_key !== '-').map(m => m.person_public_key).filter((v, i, a) => a.indexOf(v) === i).sort()
  choices = (await ui.findAll({ type: 'Button' })).filter(e => sorted.some(key => e.text.includes(key)))
  expect(choices).toHaveLength(10)
  expect(choices.map(e => sorted.find(key => e.text.includes(key)))).toEqual(sorted.slice(0, 10))
  for (const choice of choices) expect(choice.text).toContain(quoted('Same "label"'))
  expect(await shown(ui)).not.toContain('unbound only'); expect(calls(w)).toEqual([])
  await press(ui, /^(?:More|Next).*(?:people|persons|participants|identities)/i)
  choices = (await ui.findAll({ type: 'Button' })).filter(e => sorted.some(key => e.text.includes(key)))
  expect(choices).toHaveLength(2); await press(ui, /^Previous.*(?:people|persons|participants|identities)/i)
  w.person = PUBLIC_KEYS[0]
  const alias = (await ui.findAll({ type: 'Button' })).find(e => e.text.includes(w.person))
  if (!alias) await press(ui, /^(?:More|Next).*(?:people|persons|participants|identities)/i)
  const selected = (await ui.findAll({ type: 'Button' })).find(e => e.text.includes(w.person))!
  expect(selected.text).toContain(quoted('Other "machine alias"')); expect(selected.text).toContain(quoted('Same "label"'))
  await choose(ui, w.person); expect(calls(w).map(e => e.kind)).toEqual([INSPECT])
  expect(last(w, INSPECT).payload.person_public_key).toBe(w.person)
  expect(await shown(ui)).toContain(quoted('Participant "é東京"')); privacy(w, await shown(ui))
})

test('closed member inventory refuses duplicate hosts wrong context and malformed bound rows', async ($, on) => {
  const w = fixture(on), ui = await attached($, w), normal = w.read
  const variants: [string, (v: any) => void][] = [
    ['null', v => { v.members = null }], ['extra', v => { v.extra = true }], ['context', v => { v.context_id = id('ctx', 999, 64) }],
    ['duplicate-host', v => { v.members.push(clone(v.members[0])) }],
    ['label-type', v => { v.members[1].member = 17 }],
    ['member-extra', v => { v.members[0].extra = true }], ['key', v => { v.members[0].person_public_key = 'not-a-key' }],
    ['lease', v => { v.members[0].binding_lease_id = 'drs_' + '1'.repeat(64) }],
    ['time', v => { v.members[0].not_after = stamp(NOW - 1000) }],
  ]
  for (const [label, change] of variants) {
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'members') change(value); return value }
    await press(ui, 'Review agent access'); await choose(ui, w.selected.id)
    expect(calls(w), label).toEqual([]); await noApprove(ui, label)
    expect((await ui.findAll({ type: 'Button' })).filter(e => e.text.includes(PERSON)), label).toEqual([])
    await leave(ui)
  }
  privacy(w, await shown(ui))
})

test('complete inspection preserves signed and enforced policy separately with optional zeros and no access inference', async ($, on) => {
  const w = fixture(on), ui = await attached($, w)
  const body = baseline(w); w.enforced = { rules: clone(body.rules.slice(0, 2)), capability_rules: clone(body.capability_rules), trusted_hosts: clone(body.trusted_hosts) }
  await inspectPerson(ui, w); await inspectionTerms(ui, w)
  expect(w.lastInspection.review.policy.body.rules).toHaveLength(3)
  expect(w.lastInspection.review.policy.enforced_content.rules).toHaveLength(2)
  expect(Object.hasOwn(w.lastInspection.review.policy.body.rules[0], 'max_artifact_bytes')).toBe(true)
  expect(Object.hasOwn(w.lastInspection.review.policy.body.rules[1], 'max_artifact_bytes')).toBe(false)
  await checkPure(ui, w, 'inspection'); expect(calls(w, PREPARE)).toEqual([]); expect(calls(w, APPROVE)).toEqual([])
  privacy(w, await shown(ui))
})

test('self-selection null policy and no unique displayed device remain valid read-only terms', async ($, on) => {
  const w = fixture(on); w.person = OWNER; w.noPolicy = true; w.uniqueDevice = false
  w.personEnd = w.ownerEnd
  w.members[0].device_lease_id = '-'
  const ui = await attached($, w); await inspectPerson(ui, w)
  await inspectionTerms(ui, w); expect(calls(w, PREPARE)).toEqual([])
  await press(ui, 'Review proposed grant'); expect(w.access.review.inspection.policy).toBeNull()
  expect(w.access.review.statement.payload.body.rules).toHaveLength(1)
  expect(w.access.review.statement.payload.body.rules[0].max_artifact_bytes).toBe(0)
  expect(await button(ui, 'Approve agent access')).toBeDefined(); privacy(w, await shown(ui))
})

test('inspection closed nested identities dates safe numbers and digest corpus refuses before preparation', async ($, on) => {
  const w = fixture(on), ui = await attached($, w), normal = w.read
  const variants: [string, (v: any) => void, boolean?][] = [
    ['wrapper-extra', v => { v.extra = true }], ['version', v => { v.version = 2 }], ['context', v => { v.context.native_session_id = 'different-conversation' }],
    ['agent', v => { v.review.agent.owner = 'different owner' }], ['owner-host', v => { v.review.owner.host.host_public_key = PERSON }],
    ['person', v => { v.review.participant.person_public_key = OWNER }], ['root', v => { v.review.root_state_id = id('drs', 2, 64) }],
    ['null-policy-content', v => { v.review.policy.enforced_content = null }], ['extra-member', v => { v.review.participant.hosts[0].extra = true }],
    ['fractional-time', v => { v.review.participant.not_after = '2026-11-01T12:00:00.000Z' }],
    ['expired', v => { v.review.owner.host.not_after = stamp(NOW) }], ['future', v => { v.observed_at = stamp(NOW + 31_000) }],
    ['unsafe-integer', v => { v.review.policy.body.version = Number.MAX_SAFE_INTEGER + 1 }],
    ['digest', v => { v.review_id = id('review', 999, 64) }, true],
  ]
  for (const [label, change, keepDigest] of variants) {
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === INSPECT) { change(value); if (!keepDigest) value.review_id = await digest('peerspan-project-access-inspection-v1', value.review) }
      return value }
    await inspectPerson(ui, w); await noApprove(ui, label)
    expect(await button(ui, 'Review proposed grant'), label).toBeUndefined(); expect(calls(w, PREPARE), label).toEqual([])
    await leave(ui)
  }
  privacy(w, await shown(ui))
})

test('all seven short private prefixes in values and decorated object keys are refused without echo or clipped payload', async ($, on) => {
  const w = fixture(on), ui = await attached($, w), normal = w.read
  const prefixes = ['psi2-', 'psl2-', 'peerspan-invite-v1.', 'peerspan-member-invite-v1.', 'peerspan-person-invite-v1.', 'token_', 'instance_']
  for (const [index, prefix] of prefixes.entries()) for (const decorated of [false, true]) {
    const secret = 'SHORTSECRET' + index, token = prefix + secret
    const dirty = decorated ? '\x1b]0;' + prefix.slice(0, 2) + '\u202e\x1b[31m' + prefix.slice(2) + secret + '\x07visible' : token
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === INSPECT) {
        if (decorated) value.review.policy.body[dirty] = 'safe'
        else value.review.policy.body.rules[0].agent = dirty
        value.review_id = await digest('peerspan-project-access-inspection-v1', value.review)
      } return value }
    await inspectPerson(ui, w); expect(await button(ui, 'Review proposed grant')).toBeUndefined(); await noApprove(ui)
    const text = await shown(ui); expect(text).not.toContain(prefix); expect(text).not.toContain(secret)
    expect(w.outside.join('\n')).not.toContain(secret); expect(calls(w, PREPARE)).toEqual([]); await leave(ui)
  }
  privacy(w, await shown(ui))
})

test('explicit Review performs pure lookup first and one fresh inspection-pinned preparation while Check stays lookup-only', async ($, on) => {
  const w = fixture(on), ui = await attached($, w)
  await inspectPerson(ui, w); const at = calls(w).length
  await press(ui, 'Review proposed grant')
  const steps = calls(w).slice(at).map(e => e.kind)
  expect(steps[0]).toBe(LOOKUP); expect(steps.filter(k => k === PREPARE)).toHaveLength(1)
  expect(steps.indexOf(INSPECT) < steps.indexOf(PREPARE)).toBe(true)
  expect(last(w, PREPARE).payload.inspection_review_id).toBe(w.access.review.inspection_review_id)
  const immutable = clone(w.access); await checkPure(ui, w); expect(w.access).toEqual(immutable)
  expect(calls(w, APPROVE)).toEqual([]); expect(calls(w, PREPARE)).toHaveLength(1); privacy(w, await shown(ui))
})

test('existing live approved expired and invalidated receipts recover unchanged without preparation replacement or renewal', async ($, on) => {
  const w = fixture(on), ui = await attached($, w)
  for (const state of ['review', 'approved', 'expired', 'invalidated']) {
    w.access = await receipt(w, { state, ...(state === 'expired' ? { created: NOW - 301_000 } : {}),
      replaces: state === 'invalidated' ? id('dint', 79) : '-' })
    const original = clone(w.access); await inspectPerson(ui, w); const at = calls(w).length
    await press(ui, 'Review proposed grant'); expect(calls(w).slice(at).map(e => e.kind)).toEqual([LOOKUP])
    await checkPure(ui, w); expect(w.access).toEqual(original)
    if (state === 'approved') await recorded(ui)
    else if (state !== 'review') await noApprove(ui, state)
    await leave(ui)
  }
  w.access = null; await inspectPerson(ui, w); await press(ui, 'Review proposed grant')
  const preparedCount = calls(w, PREPARE).length; w.access = null
  await checkPure(ui, w); await noApprove(ui); expect(calls(w, PREPARE)).toHaveLength(preparedCount)
  privacy(w, await shown(ui))
})

test('complete narrow name-wide grant preserves unrelated body defaults and actual original or device provider powers', async ($, on) => {
  const w = fixture(on), ui = await attached($, w)
  for (const provider of ['original_person', 'device']) {
    w.access = await receipt(w, { provider }); await inspectPerson(ui, w); await press(ui, 'Review proposed grant')
    await consentTerms(ui, w); expect(await button(ui, 'Approve agent access')).toBeDefined()
    const review = w.access.review, body = review.statement.payload.body
    expect(review.provider.scopes).toBe(7); expect(review.grant.principal).toBe(await principal(PERSON))
    expect(body.rules[0].principals).toEqual(['network', review.grant.principal]); expect(body.rules[0].max_artifact_bytes).toBe(0)
    expect(Object.hasOwn(body.rules[1], 'max_artifact_bytes')).toBe(false)
    expect(body.rules.slice(1)).toEqual(baseline(w).rules.slice(1)); expect(body.capability_rules).toEqual(baseline(w).capability_rules)
    expect(body.trusted_hosts).toEqual([HOST]); expect(calls(w, APPROVE)).toEqual([]); await leave(ui)
  }
  privacy(w, await shown(ui))
})

test('double Approve shares the in-flight gate and sends one configured5s exact private-stdin mutation after fresh guards', async ($, on) => {
  const w = fixture(on), ui = await prepared($, w), normal = w.read, original = clone(w.access), delayed = delaySignal(w)
  let gated = false
  w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e)
    if (kind === LOOKUP && !gated) { gated = true; await delayed.wait() } return value }
  const oldKey = (await button(ui, 'Approve agent access'))!.key!, at = w.trace.length
  const first = ui.press({ key: oldKey }); void first.catch(() => undefined); await delayed.started
  // The kit dispatches current drawing, not a retained obsolete callback.
  await ui.press({ key: oldKey }).catch(() => undefined)
  await w.clock.advance(1000); await first; await recorded(ui)
  expect(calls(w, APPROVE)).toHaveLength(1); expect(w.access.review).toEqual(original.review)
  const trace = w.trace.slice(at), sent = trace.indexOf(APPROVE)
  for (const kind of ['root', 'native', 'snapshot', 'project.inspect', LOOKUP, INSPECT]) expect(trace.slice(0, sent)).toContain(kind)
  privacy(w, await shown(ui), false, '/fixture bin/peerspan;$(literal)', '/private access state/$(literal)')
}, { options: { executable: '/fixture bin/peerspan;$(literal)', state: '/private access state/$(literal)' } } as TestOptions)

test('matching already-approved preflight recovers recorded global consent with zero approval calls', async ($, on) => {
  const w = fixture(on), ui = await prepared($, w), original = clone(w.access.review)
  w.access = { ...w.access, state: 'approved', next_action: 'follow_policy_action' }
  await press(ui, 'Approve agent access'); await recorded(ui)
  expect(calls(w, APPROVE)).toEqual([]); expect(w.access.review).toEqual(original)
  await checkPure(ui, w); expect(calls(w, PREPARE)).toHaveLength(1); privacy(w, await shown(ui))
})

test('closed consent nested grant provider policy payload parent and digest substitutions cannot become approval authority', async ($, on) => {
  const w = fixture(on), ui = await attached($, w), normal = w.read
  const variants: [string, (v: any) => void, boolean?][] = [
    ['extra', v => { v.access.extra = true }], ['wrong-access', v => { v.access.access_id = id('dint', 999) }],
    ['wrong-agent', v => { v.access.review.grant.agent_id = id('agent', 999) }],
    ['principal', v => { v.access.review.grant.principal = 'network' }],
    ['artifact', v => { v.access.review.grant.max_artifact_bytes = 1 }],
    ['scope', v => { v.access.review.grant.policy_scope = 'host_agent_id' }],
    ['root-provider', v => { v.access.review.provider.kind = 'network_root' }],
    ['device', v => { v.access.review.provider.lease_id = ds(999) }],
    ['provider-scope', v => { v.access.review.provider.scopes = 2 }],
    ['issuer', v => { v.access.review.statement.payload.issuer.person_public_key = PERSON }],
    ['parent', v => { v.access.review.statement.payload.parents[0].id = ds(999) }],
    ['predecessor', v => { v.access.review.statement.payload.predecessors = [] }],
    ['body-version', v => { v.access.review.statement.payload.body.version++ }],
    ['body-artifact', v => { v.access.review.statement.payload.body.rules[0].max_artifact_bytes = 1 }],
    ['creation', v => { v.access.review.created_at = stamp(NOW - 1000) }],
    ['future-created', v => { const r = v.access.review; r.created_at = stamp(NOW + 1000); r.expires_at = stamp(NOW + 301_000)
      r.statement.payload.issued_at = r.created_at; r.statement.payload.not_before = r.created_at; r.statement.payload.body.issued_at = r.created_at }],
    ['too-long-policy', v => { v.access.review.statement.payload.not_after = stamp(NOW + 86_401_000) }],
    ['unsafe-sequence', v => { v.access.review.statement.payload.sequence = Number.MAX_SAFE_INTEGER + 1 }],
    ['embedded-digest', v => { v.access.review.inspection_review_id = id('review', 999, 64) }],
    ['digest', v => { v.access.review_id = id('review', 999, 64) }, true],
    ['oversize', v => { v.access.review.statement.payload.body.rules[0].agent = 'x'.repeat(1024 * 1024 + 1) }],
  ]
  for (const [label, change, keepDigest] of variants) {
    w.access = await receipt(w); w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === LOOKUP) { change(value)
        if (!keepDigest) value.access.review_id = await digest('peerspan-project-access-consent-v1', value.access.review) }
      return value }
    await inspectPerson(ui, w); await press(ui, 'Review proposed grant'); await noApprove(ui, label)
    expect(calls(w, APPROVE), label).toEqual([]); expect(calls(w, PREPARE), label).toEqual([]); await leave(ui)
  }
  privacy(w, await shown(ui))
})

test('changed exact lookup fresh inspection parent host and native preflight terms send zero approval mutation', async ($, on) => {
  const w = fixture(on), normal = w.read; let ui: Pane
  for (const mode of ['review', 'provider', 'inspection', 'expired', 'parent', 'host', 'root', 'native']) {
    w.read = normal; w.access = null; if (w.parent) w.parent.state = 'attached'
    w.host = HOST; w.root = ROOT; w.native = NATIVE; ui = await prepared($, w)
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === LOOKUP) {
        if (mode === 'review') value.access.review.statement.payload.body.rules[0].principals.push('group:changed')
        if (mode === 'provider') value.access.review.provider.not_after = stamp(NOW + 600_000)
        if (mode === 'expired') { value.access.state = 'expired'; value.access.next_action = 'inspect_agent_access' }
        if (['review', 'provider'].includes(mode)) value.access.review_id = await digest('peerspan-project-access-consent-v1', value.access.review)
        if (mode === 'parent') w.parent.state = 'invalidated'
        if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
        if (mode === 'root') w.root = '/changed-access-root'
        if (mode === 'native') w.native = 'changed-access-conversation'
      }
      if (kind === INSPECT && mode === 'inspection') {
        value.review.policy.enforced_content.rules.pop()
        value.review_id = await digest('peerspan-project-access-inspection-v1', value.review)
      }
      return value }
    await press(ui, 'Approve agent access'); await noApprove(ui, mode); expect(calls(w, APPROVE), mode).toEqual([])
    const close = await button(ui, 'Close'); if (close) await press(ui, 'Close'); await ui.unmount()
  }
  privacy(w)
})

test('earliest live bound removes approval at its exact timer boundary with no read mutation or renewal', async ($, on) => {
  const w = fixture(on), ui = await prepared($, w)
  const end = Date.parse(w.access.review.expires_at), before = w.calls.length
  await w.clock.advance(end - w.clock.now() - 1); expect(await button(ui, 'Approve agent access')).toBeDefined()
  await w.clock.advance(1); await noApprove(ui)
  expect(w.calls).toHaveLength(before); expect(await button(ui, 'Check agent access')).toBeDefined()
  w.access = { ...w.access, state: 'approved', next_action: 'follow_policy_action' }
  await checkPure(ui, w); await recorded(ui); expect(calls(w, APPROVE)).toEqual([])
  privacy(w, await shown(ui))
})

test('registered async preflight expiry blocks dispatch while exact post-dispatch approval can show durable history', async ($, on) => {
  const w = fixture(on), normal = w.read; let ui: Pane
  for (const phase of ['preflight', 'dispatched']) {
    w.read = normal; w.access = await receipt(w, { created: w.clock.now() - 299_000 })
    ui = await attached($, w); await inspectPerson(ui, w); await press(ui, 'Review proposed grant')
    const delayed = delaySignal(w, 2000), before = calls(w, APPROVE).length
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === (phase === 'preflight' ? LOOKUP : APPROVE)) await delayed.wait(); return value }
    const pending = press(ui, 'Approve agent access'); void pending.catch(() => undefined); await delayed.started
    await w.clock.advance(2000); await pending
    expect(calls(w, APPROVE)).toHaveLength(before + (phase === 'dispatched' ? 1 : 0))
    if (phase === 'dispatched') await recorded(ui); else await noApprove(ui)
    await press(ui, 'Close'); await ui.unmount()
  }
  privacy(w)
})

test('denied nonzero timeout raw null and changed approval results remain unknown until pure explicit Check', async ($, on) => {
  const w = fixture(on), ui = await prepared($, w), normal = w.read
  for (const mode of ['deny', 'timeout', 'raw', 'null', 'changed', 'unapproved']) {
    w.read = normal; w.access = await receipt(w); if (mode !== 'deny') await reenter(ui, w)
    w.read = async (kind, payload, e) => {
      if (kind === APPROVE && mode === 'deny') return { fixtureDeny: true }
      if (kind === APPROVE && mode === 'timeout') return { fixtureExit: true }
      if (kind === APPROVE && mode === 'raw') return { fixtureRaw: RAW }
      const value = await normal(kind, payload, e)
      if (kind === APPROVE) {
        if (mode === 'null') return null
        if (mode === 'changed') { value.access.review.statement.id = ds(999); value.access.review_id = await digest('peerspan-project-access-consent-v1', value.access.review) }
        if (mode === 'unapproved') { value.access.state = 'review'; value.access.next_action = 'approve_policy_intent' }
      } return value }
    const before = calls(w, APPROVE).length; await press(ui, 'Approve agent access'); await unknown(ui)
    await w.clock.advance(1000); expect(calls(w, APPROVE)).toHaveLength(before + 1)
    w.read = normal; w.access = { ...w.access, state: 'approved', next_action: 'follow_policy_action' }
    await checkPure(ui, w); await recorded(ui); expect(calls(w, APPROVE)).toHaveLength(before + 1)
  }
  privacy(w, await shown(ui))
})

test('post-IO authoritative project host and current clock guards discard reads before installing actionable private terms', async ($, on) => {
  const w = fixture(on), normal = w.read; let ui: Pane
  for (const mode of ['parent', 'host', 'root', 'native', 'future', 'malformed-time']) {
    if (w.parent) w.parent.state = 'attached'
    w.host = HOST; w.root = ROOT; w.native = NATIVE; w.access = null; w.read = normal
    ui = await attached($, w)
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === INSPECT) {
        if (mode === 'parent') w.parent.state = 'invalidated'
        if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
        if (mode === 'root') w.root = '/different-access-root'
        if (mode === 'native') w.native = 'different-access-conversation'
        if (mode === 'future') value.observed_at = stamp(w.clock.now() + 31_000)
        if (mode === 'malformed-time') value.observed_at = 'not-a-time'
      } return value }
    await inspectPerson(ui, w); expect(await button(ui, 'Review proposed grant'), mode).toBeUndefined(); await noApprove(ui, mode)
    expect(calls(w, PREPARE), mode).toEqual([])
    const close = await button(ui, 'Close'); if (close) await press(ui, 'Close')
    await ui.unmount()
  }
  privacy(w)
})

test('Leave navigation context and end invalidate registered pending approval without revocation or late pane resurrection', async ($, on) => {
  const w = fixture(on), normal = w.read; let ui: Pane
  ui = await attached($, w); w.access = await receipt(w, { created: NOW - 299_000 })
  await inspectPerson(ui, w); await press(ui, 'Review proposed grant')
  const oldRead = delaySignal(w, 2000)
  w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === LOOKUP) await oldRead.wait(); return value }
  const oldPress = press(ui, 'Approve agent access'); void oldPress.catch(() => undefined); await oldRead.started
  await leave(ui); w.read = normal
  // A distinct explicit selection gets independent work; no live replacement.
  w.networks = [network(), network(2)]; w.selected = w.networks[1]
  w.access = await receipt(w, { n: 82 })
  await inspectPerson(ui, w); await press(ui, 'Review proposed grant'); const fresh = clone(w.access)
  await w.clock.advance(1000); expect(await button(ui, 'Approve agent access')).toBeDefined()
  await w.clock.advance(1000); await oldPress
  expect(await button(ui, 'Approve agent access')).toBeDefined(); expect(w.access).toEqual(fresh)
  expect(calls(w, APPROVE)).toEqual([]); await press(ui, 'Close'); await ui.unmount()
  for (const mode of ['leave', 'back', 'close', 'refresh', 'root', 'native', 'host', 'parent', 'surface', 'end']) {
    w.read = normal; w.host = HOST; w.root = ROOT; w.native = NATIVE; w.surface = 'terminal'; w.surfaces = ['terminal']
    if (w.parent) w.parent.state = 'attached'; w.access = null
    ui = await prepared($, w); const delayed = delaySignal(w), before = calls(w, APPROVE).length
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === APPROVE) await delayed.wait(); return value }
    const pending = press(ui, 'Approve agent access'); void pending.catch(() => undefined); await delayed.started
    const retained = clone(w.access)
    if (mode === 'leave') await leave(ui)
    if (mode === 'back') await press(ui, /^Back\b/)
    if (mode === 'close') await press(ui, 'Close')
    if (mode === 'refresh') await press(ui, 'Refresh')
    if (mode === 'root') { w.root = '/departed-access-root'; await $.classic.CwdChanged({ old_cwd: ROOT, new_cwd: w.root }) }
    if (mode === 'native') w.native = 'departed-access-conversation'
    if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
    if (mode === 'parent') w.parent.state = 'invalidated'
    if (mode === 'surface') { w.surface = null; w.surfaces = [] }
    if (mode === 'end') await $.session.end({ reason: 'clear', sessionId: NATIVE, resume: { id: NATIVE } })
    await w.clock.advance(1000); await pending; await noApprove(ui, mode)
    expect(await shown(ui), mode).not.toContain('Agent-access consent: recorded')
    expect(w.access, mode).toEqual(retained); expect(calls(w, APPROVE)).toHaveLength(before + 1)
    const close = await button(ui, 'Close'); if (close) await press(ui, 'Close'); await ui.unmount()
  }
  privacy(w)
})

test('access review preserves established authorized lease through Leave Close and reentry without new transport or tools', async ($, on) => {
  const w = fixture(on), ui = await attached($, w)
  await press(ui, 'Review adapter connection'); await press(ui, 'Approve adapter'); await press(ui, 'Connect adapter')
  expect(w.http).toHaveLength(1); await press(ui, /^Back to project$/)
  const tools = w.tools.map(tool => tool.name), material = clone(w.materials[0]), normal = w.read
  await inspectPerson(ui, w); await press(ui, 'Review proposed grant'); await press(ui, 'Approve agent access'); await recorded(ui)
  await leave(ui); expect(w.http).toHaveLength(1); await press(ui, 'Close'); await ui.unmount()
  await w.clock.advance(5000); expect(w.http).toHaveLength(2)
  expect(w.materials).toEqual([material]); expect(w.tools.map(tool => tool.name)).toEqual(tools)
  w.read = normal; const again = await enter($, w); await press(again, 'Connect this project'); await inspectPerson(again, w)
  await press(again, 'Review proposed grant'); await recorded(again)
  expect(calls(w, PREPARE)).toHaveLength(1); expect(calls(w, APPROVE)).toHaveLength(1)
  privacy(w, await shown(again), true)
})
