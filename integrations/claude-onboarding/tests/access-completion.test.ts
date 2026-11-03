/**
 * Independent section35 native access-completion fixtures, pinned303.
 * Copied public fixture foundation from independent section34 tests; no product
 * imports, hooks/Rust reads, real processes, transport, keys or model inference.
 * Sections31/32/33 define closed consent/signature/application projections.
 * Preserve all333 existing native files and28 host suites byte-for-byte.
 * Delays signal actual dispatch plus virtual sleep registration. Daemon crypto,
 * storage, ordinary authority/evaluator behavior are separate host evidence.
 * Obsolete rendered closures and microscopic dispatch races remain source-only;
 * actual reload/installed/terminal/physical/model/readiness remain open gates.
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
const APPLICATION = 'access.application', SIGN = 'access.sign', APPLY = 'access.apply'
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
    rules: [{ agent: w.parent.review.agent.name, principals: ['network'], actions: clone(w.ruleActions),
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
    JSON.stringify([...new Set(rule.actions)].sort()) === JSON.stringify([...new Set(grant.actions)].sort()))
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
function applicationResponse(w: World) {
  const review = w.access?.review
  return { ...accessResponse(w), application: w.access?.state !== 'approved' ? null : {
    state: w.applicationState, action_id: review.action_id, intent_id: review.intent_id, statement_id: review.statement.id,
    proof_id: w.applicationState === 'unsigned' ? '-' : w.proof,
    peer_delivery: 'not_verified', connection_readiness: 'not_verified' } }
}
function signingResponse(w: World) {
  const review = w.access?.review, signed = w.applicationState !== 'unsigned'
  return { ...accessResponse(w), signing: w.access?.state !== 'approved' ? null : {
    state: signed ? 'signed' : 'unsigned', action_id: review.action_id, intent_id: review.intent_id,
    statement_id: review.statement.id, signature_count: signed ? 1 : 0, required_signatures: 1,
    policy_application: 'not_verified', peer_delivery: 'not_verified', connection_readiness: 'not_verified' } }
}

function fixture(on: On) {
  const clock = mock.clock(on, { now: NOW })
  const w = { clock, started: false, root: ROOT, native: NATIVE, host: HOST, surface: 'terminal' as string | null,
    surfaces: ['terminal'], parent: null as any, child: null as any, selected: network(), person: PERSON,
    networks: [network()] as any[], members: [{ ...member(OWNER, HOST_KEY, 10, 'Owner machine "alias"'),
      not_after: stamp(NOW + 604_800_000) }, member()] as any[],
    noPolicy: false, uniqueDevice: true, ruleActions: ['message.append', 'task.submit'], enforced: null as any,
    ownerEnd: NOW + 604_800_000, personEnd: NOW + 259_200_000,
    providerEnd: NOW + 604_800_000, policyEnd: NOW + 3_600_000, access: null as any, lastInspection: null as any,
    applicationState: 'unsigned', proof: id('dp', 88, 64),
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
    if (kind === APPLICATION) return applicationResponse(w)
    if (kind === SIGN) { w.applicationState = 'signed'; return signingResponse(w) }
    if (kind === APPLY) { w.applicationState = 'locally_applied'; return applicationResponse(w) }
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
    expect(e.init?.timeoutMs, e.kind).toBe([SIGN, APPLY].includes(e.kind) ? 95000 : 5000)
    if (e.kind === 'members') expect(e.argv).toEqual([...prefix, 'network', 'members', e.expectedNetwork])
    else if (e.kind === 'snapshot') expect(e.argv).toEqual([...prefix, 'onboarding'])
    else if (e.kind.endsWith('.inspect') && !e.kind.startsWith('access.'))
      expect(e.argv).toEqual([...prefix, 'onboarding', e.kind.split('.')[0], 'inspect', e.kind === 'project.inspect' ? e.expectedProject : e.expectedAdapter])
    else expect(e.argv).toEqual([...prefix, 'onboarding', ...e.kind.split('.'), '--stdin'])
    for (const privateValue of [ROOT, NATIVE, RAW, TOKEN, SOCKET]) expect(e.argv).not.toContain(privateValue)
    if (![SIGN, APPLY].includes(e.kind)) expect(e.kind).not.toMatch(/sign|apply|action|provider|identit|resume|invitation|join/)
    if (e.kind.startsWith('access.')) expect(e.payload).toEqual({ context: e.expectedContext, network_id: e.expectedNetwork,
      person_public_key: e.expectedPerson,
      ...(e.kind === PREPARE ? { inspection_review_id: e.expectedInspection } : {}),
      ...([APPROVE, APPLICATION, SIGN, APPLY].includes(e.kind) ? { access_id: e.expectedAccess, access_review_id: e.expectedReview } : {}),
      ...(e.kind === SIGN ? { decision: 'sign_project_agent_access' } : {}),
      ...(e.kind === APPLY ? { decision: 'apply_project_agent_access' } : {}) })
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

const mutations = (w: World) => calls(w).filter(e => [SIGN, APPLY].includes(e.kind))
async function approved($: Engine, w: World, options: any = {}) {
  const ui = await attached($, w)
  w.access = await receipt(w, { ...options, state: 'approved' })
  await inspectPerson(ui, w); await press(ui, 'Review proposed grant'); return ui
}
async function noFinish(ui: Pane, reason = '') { expect(await button(ui, 'Finish agent access'), reason).toBeUndefined() }
async function checkApplication(ui: Pane, w: World) {
  const at = w.calls.length; await press(ui, 'Check application')
  expect(w.calls.slice(at).filter(e => e.kind.startsWith('access.')).map(e => e.kind)).toEqual([LOOKUP, APPLICATION])
}
async function signedRecorded(ui: Pane, w: World, proof = false) {
  const text = await shown(ui)
  expect(text).toMatch(/signature[^\n]*(?:recorded|stored)|(?:recorded|stored)[^\n]*signature/i)
  expect(text).toContain(w.access.review.statement.id)
  if (proof) expect(text).toContain(w.proof)
  expect(text).toMatch(/(?:not verified|unverified)[\s\S]*(?:deliver|readiness|connection)|(?:deliver|readiness|connection)[\s\S]*(?:not verified|unverified)/i)
  expect(text).not.toMatch(/(?:permission|delivery|connection|model receipt) (?:is )?(?:verified|ready|allowed)/i)
}
async function appliedRecorded(ui: Pane, w: World) {
  await signedRecorded(ui, w, true)
  const text = await shown(ui); expect(text).toContain('Local application: recorded')
  expect(text).not.toMatch(/(?:signature|application)[^\n]*(?:is |are )?absent|no (?:signature|application)[^\n]*recorded/i)
  await consentTerms(ui, w)
}
async function uncertain(ui: Pane, w: World, reason = '') {
  await noFinish(ui, reason)
  const text = await shown(ui)
  expect(text, reason).toMatch(/unknown|unavailable|not confirmed/i)
  expect(await button(ui, 'Check application'), reason).toBeDefined()
  expect(text, reason).not.toContain('Local application: recorded')
  privacy(w, text)
}
async function closePane(ui: Pane) {
  const close = await button(ui, 'Close')
  if (close) {
    const label = 'Close'
    expect(close, String(label)).toBeDefined()
    await ui.press({ key: close.key! })
  }
  await ui.unmount()
}

test('entry nonsigning approval lookup Check and fresh reentry never implicitly continue the approved policy action', async ($, on) => {
  const w = fixture(on), ui = await prepared($, w)
  await noFinish(ui); await press(ui, 'Approve agent access'); await recorded(ui)
  expect(await button(ui, 'Finish agent access')).toBeDefined(); expect(await button(ui, 'Check application')).toBeDefined()
  expect(calls(w, APPLICATION)).toEqual([]); expect(mutations(w)).toEqual([])
  await checkPure(ui, w); expect(mutations(w)).toEqual([]); expect(calls(w, APPLICATION)).toEqual([])
  await press(ui, 'Refresh'); expect(mutations(w)).toEqual([])
  await closePane(ui); const again = await enter($, w); await press(again, 'Connect this project')
  await inspectPerson(again, w); await press(again, 'Review proposed grant'); await recorded(again)
  expect(mutations(w)).toEqual([]); expect(calls(w, APPLICATION)).toEqual([])
  privacy(w, await shown(again))
})

test('explicit configured Finish signs once then freshly observes and applies once with separate95s bounds and exact private decisions',
  { options: { executable: '/fixture bin/peerspan;$(literal)', state: '/private completion state/$(literal)' } } as TestOptions, async ($, on) => {
  const w = fixture(on), ui = await approved($, w), original = clone(w.access.review), at = w.calls.length
  expect(await button(ui, 'Finish agent access')).toBeDefined()
  expect(await shown(ui)).toMatch(/sign[\s\S]*appl|appl[\s\S]*sign/i)
  await press(ui, 'Finish agent access'); await appliedRecorded(ui, w)
  expect(mutations(w).map(e => e.kind)).toEqual([SIGN, APPLY])
  const sequence = w.calls.slice(at).filter(e => e.kind.startsWith('access.')).map(e => e.kind)
  expect(sequence.slice(0, 2)).toEqual([LOOKUP, APPLICATION])
  const sign = sequence.indexOf(SIGN), apply = sequence.indexOf(APPLY)
  expect(sequence.slice(2, sign)).toContain(LOOKUP); expect(sequence.slice(2, sign)).toContain(INSPECT)
  expect(sequence.slice(sign + 1, apply)).toContain(LOOKUP); expect(sequence.slice(sign + 1, apply)).toContain(APPLICATION)
  expect(sequence.slice(sign + 1, apply)).toContain(INSPECT)
  expect(w.access.review).toEqual(original); expect(calls(w, PREPARE)).toEqual([]); expect(calls(w, APPROVE)).toEqual([])
  privacy(w, await shown(ui), false, '/fixture bin/peerspan;$(literal)', '/private completion state/$(literal)')
})

test('actual dispatched completion preflight is single-flight under a second Finish press', async ($, on) => {
  const w = fixture(on), ui = await approved($, w), normal = w.read, delayed = delaySignal(w)
  let held = false
  w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e)
    if (kind === APPLICATION && !held) { held = true; await delayed.wait() } return value }
  const key = (await button(ui, 'Finish agent access'))!.key!, pending = ui.press({ key })
  void pending.catch(() => undefined); await delayed.started
  expect(await button(ui, 'Leave agent access')).toBeDefined()
  // Public kit dispatches the current drawing, not an obsolete handler closure.
  await ui.press({ key }).catch(() => undefined)
  await w.clock.advance(1000); await pending; await appliedRecorded(ui, w)
  expect(calls(w, SIGN)).toHaveLength(1); expect(calls(w, APPLY)).toHaveLength(1); privacy(w, await shown(ui))
})

test('already signed state skips signer while an already applied first observation finishes through pure recovery', async ($, on) => {
  const w = fixture(on); w.applicationState = 'signed'
  let ui = await approved($, w); await press(ui, 'Finish agent access'); await appliedRecorded(ui, w)
  expect(calls(w, SIGN)).toEqual([]); expect(calls(w, APPLY)).toHaveLength(1)
  await closePane(ui); ui = await approved($, w)
  const at = w.calls.length; await press(ui, 'Finish agent access'); await appliedRecorded(ui, w)
  expect(w.calls.slice(at).filter(e => e.kind.startsWith('access.')).map(e => e.kind)).toEqual([LOOKUP, APPLICATION])
  expect(calls(w, APPLY)).toHaveLength(1); expect(calls(w, SIGN)).toEqual([]); privacy(w, await shown(ui))
})

test('Check application advances only verified global unsigned signed applied history and stays pure after the fixed deadline', async ($, on) => {
  const w = fixture(on), ui = await approved($, w)
  await checkApplication(ui, w); expect(await shown(ui)).not.toContain('Local application: recorded')
  w.applicationState = 'signed'; await checkApplication(ui, w); await signedRecorded(ui, w, true)
  w.applicationState = 'locally_applied'; await checkApplication(ui, w); await appliedRecorded(ui, w)
  const immutable = clone(w.access); await w.clock.advance(Date.parse(w.access.review.expires_at) - w.clock.now() + 1)
  await noFinish(ui); await checkApplication(ui, w); await appliedRecorded(ui, w)
  expect(w.access).toEqual(immutable); expect(mutations(w)).toEqual([])
  await leave(ui); await inspectPerson(ui, w); await press(ui, 'Review proposed grant')
  await checkApplication(ui, w); await appliedRecorded(ui, w); expect(mutations(w)).toEqual([])
  privacy(w, await shown(ui))
})

test('closed signed-result count reference state date and private-value faults stop before any apply or confirmed signing', async ($, on) => {
  const w = fixture(on), normal = w.read; let ui: Pane
  const variants: [string, (v: any) => void][] = [
    ['bare', v => { delete v.signing }], ['null', v => { v.signing = null }], ['extra', v => { v.signing.extra = true }],
    ['unsigned', v => { v.signing.state = 'unsigned'; v.signing.signature_count = 0 }],
    ['count', v => { v.signing.signature_count = Number.MAX_SAFE_INTEGER + 1 }],
    ['reference', v => { v.signing.statement_id = ds(999) }], ['overclaim', v => { v.signing.policy_application = 'verified' }],
    ['future', v => { v.observed_at = stamp(NOW + 31_000) }], ['private', v => { v.signing.intent_id = 'token_SHORTSIGNSECRET' }],
  ]
  for (const [label, change] of variants) {
    w.read = normal; w.applicationState = 'unsigned'; ui = await approved($, w)
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === SIGN) change(value); return value }
    const before = calls(w, APPLY).length; await press(ui, 'Finish agent access'); await uncertain(ui, w, label)
    expect(calls(w, APPLY), label).toHaveLength(before); expect(await shown(ui)).not.toContain('SHORTSIGNSECRET')
    expect(w.outside.join('\n')).not.toContain('SHORTSIGNSECRET')
    expect(await shown(ui)).not.toMatch(/signature[^\n]*(?:recorded|stored)/i); await closePane(ui)
  }
  privacy(w)
})

test('closed application observation rejects null bare extra proof identity readiness and malformed-date terms without mutation', async ($, on) => {
  const w = fixture(on), normal = w.read; let ui: Pane
  const variants: [string, (v: any) => void][] = [
    ['bare', v => { delete v.application }], ['null', v => { v.application = null }], ['extra', v => { v.application.extra = true }],
    ['proof-on-unsigned', v => { v.application.proof_id = id('dp', 99, 64) }],
    ['missing-signed-proof', v => { v.application.state = 'signed'; v.application.proof_id = '-' }],
    ['intent', v => { v.application.intent_id = id('dint', 999) }], ['state', v => { v.application.state = 'approved' }],
    ['readiness', v => { v.application.connection_readiness = 'ready' }],
    ['date', v => { v.observed_at = '2026-10-29T12:00:00.000Z' }],
  ]
  for (const [label, change] of variants) {
    w.read = normal; w.applicationState = 'unsigned'; ui = await approved($, w)
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === APPLICATION) change(value); return value }
    const before = mutations(w).length; await press(ui, 'Finish agent access'); await uncertain(ui, w, label)
    expect(mutations(w), label).toHaveLength(before); await closePane(ui)
  }
  privacy(w)
})

test('Apply must return exact locally-applied evidence with the observed proof while bare changed or partial replies stay unknown', async ($, on) => {
  const w = fixture(on), normal = w.read; let ui: Pane
  const variants: [string, (v: any) => void][] = [
    ['bare', v => { delete v.application }], ['null', v => { v.application = null }],
    ['signed-only', v => { v.application.state = 'signed' }], ['proof', v => { v.application.proof_id = id('dp', 999, 64) }],
    ['action', v => { v.application.action_id = id('act', 999, 64) }], ['delivery', v => { v.application.peer_delivery = 'verified' }],
    ['review', v => { v.access.review.provider.not_after = stamp(NOW + 600_000) }],
  ]
  for (const [label, change] of variants) {
    w.read = normal; w.applicationState = 'signed'; ui = await approved($, w)
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === APPLY) change(value); return value }
    const before = calls(w, APPLY).length; await press(ui, 'Finish agent access'); await uncertain(ui, w, label)
    expect(calls(w, APPLY)).toHaveLength(before + 1); expect(calls(w, SIGN)).toEqual([])
    w.read = normal; await checkApplication(ui, w); await appliedRecorded(ui, w); await closePane(ui)
  }
  privacy(w)
})

test('observed public proof and monotone state survive unknown Check replies within one captured completion view', async ($, on) => {
  const w = fixture(on); w.applicationState = 'signed'; const ui = await approved($, w), normal = w.read
  await checkApplication(ui, w); await signedRecorded(ui, w, true)
  for (const mode of ['proof', 'regress', 'null']) {
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === APPLICATION) {
        if (mode === 'proof') value.application.proof_id = id('dp', 999, 64)
        if (mode === 'regress') { value.application.state = 'unsigned'; value.application.proof_id = '-' }
        if (mode === 'null') value.application = null
      } return value }
    await checkApplication(ui, w); await uncertain(ui, w, mode); expect(mutations(w)).toEqual([])
  }
  w.read = normal; w.applicationState = 'locally_applied'; await checkApplication(ui, w); await appliedRecorded(ui, w)
  w.applicationState = 'signed'; await checkApplication(ui, w); await uncertain(ui, w, 'applied-to-signed')
  await leave(ui); w.networks = [network(), network(2)]; w.selected = w.networks[1]; w.proof = id('dp', 89, 64)
  w.access = await receipt(w, { state: 'approved', n: 82 })
  await inspectPerson(ui, w); await press(ui, 'Review proposed grant')
  await checkApplication(ui, w); await signedRecorded(ui, w, true); expect(mutations(w)).toEqual([])
  privacy(w, await shown(ui))
})

test('changed immutable consent fresh inspection or authoritative context stops the next captured mutation without rebind', async ($, on) => {
  const w = fixture(on), normal = w.read; let ui: Pane
  for (const mode of ['review', 'inspection', 'parent', 'host', 'native', 'provider-after-sign']) {
    w.read = normal; w.root = ROOT; w.native = NATIVE; w.host = HOST; if (w.parent) w.parent.state = 'attached'
    w.applicationState = 'unsigned'; ui = await approved($, w)
    let signed = false
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === SIGN) signed = true
      if (kind === LOOKUP && (mode === 'review' || (mode === 'provider-after-sign' && signed))) {
        if (mode === 'review') value.access.review.statement.payload.body.rules[0].principals.push('group:changed')
        else value.access.review.provider.not_after = stamp(NOW + 600_000)
        value.access.review_id = await digest('peerspan-project-access-consent-v1', value.access.review)
      }
      if (kind === INSPECT && mode === 'inspection') {
        value.review.policy.enforced_content.rules.pop(); value.review_id = await digest('peerspan-project-access-inspection-v1', value.review)
      }
      if (kind === APPLICATION) {
        if (mode === 'parent') w.parent.state = 'invalidated'
        if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
        if (mode === 'native') w.native = 'different-completion-conversation'
      } return value }
    const before = mutations(w).length; await press(ui, 'Finish agent access'); await noFinish(ui, mode)
    expect(mutations(w).slice(before).map(e => e.kind), mode).toEqual(mode === 'provider-after-sign' ? [SIGN] : [])
    expect(await shown(ui)).not.toContain('Local application: recorded'); await closePane(ui)
  }
  privacy(w)
})

test('the exact earliest fixed deadline removes Finish without IO while retained applied history stays readable', async ($, on) => {
  const w = fixture(on), ui = await approved($, w, { created: NOW - 299_000 })
  const before = w.calls.length, end = Date.parse(w.access.review.expires_at)
  await w.clock.advance(end - w.clock.now() - 1); expect(await button(ui, 'Finish agent access')).toBeDefined()
  await w.clock.advance(1); await noFinish(ui); expect(w.calls).toHaveLength(before); expect(mutations(w)).toEqual([])
  w.applicationState = 'locally_applied'; await checkApplication(ui, w); await appliedRecorded(ui, w)
  expect(mutations(w)).toEqual([]); privacy(w, await shown(ui))
})

test('actual registered preflight clock crossing blocks signing or the next apply after a recorded signature', async ($, on) => {
  const w = fixture(on), normal = w.read; let ui: Pane
  for (const phase of ['sign', 'apply']) {
    w.read = normal; w.applicationState = 'unsigned'; ui = await approved($, w, { created: w.clock.now() - 299_000 })
    const delayed = delaySignal(w, 2000), before = mutations(w).length; let signed = false, held = false
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === SIGN) signed = true
      if (!held && ((phase === 'sign' && kind === LOOKUP) || (phase === 'apply' && signed && kind === INSPECT))) {
        held = true; await delayed.wait()
      } return value }
    const pending = press(ui, 'Finish agent access'); void pending.catch(() => undefined); await delayed.started
    await w.clock.advance(2000); await pending; await noFinish(ui, phase)
    expect(mutations(w).slice(before).map(e => e.kind)).toEqual(phase === 'apply' ? [SIGN] : [])
    expect(await shown(ui)).not.toContain('Local application: recorded'); await closePane(ui)
  }
  privacy(w)
})

test('signing and apply uncertainty stop the pipeline then pure Check recovers before one explicit remaining operation', async ($, on) => {
  const w = fixture(on), normal = w.read; let ui: Pane
  const variants = [[SIGN, 'deny'], [SIGN, 'timeout'], [SIGN, 'raw-lost'], [APPLY, 'timeout-lost'], [APPLY, 'null-lost']]
  for (const [fault, mode] of variants) {
    w.read = normal; w.applicationState = fault === SIGN ? 'unsigned' : 'signed'; ui = await approved($, w)
    w.read = async (kind, payload, e) => {
      if (kind === fault && mode === 'deny') return { fixtureDeny: true }
      if (kind === fault && mode === 'timeout') return { fixtureExit: true }
      const value = await normal(kind, payload, e)
      if (kind === fault) {
        if (mode === 'raw-lost') return { fixtureRaw: RAW }
        if (mode === 'timeout-lost') return { fixtureExit: true }
        if (mode === 'null-lost') return null
      } return value }
    const at = mutations(w).length; await press(ui, 'Finish agent access'); await uncertain(ui, w, mode)
    expect(mutations(w).slice(at).map(e => e.kind)).toEqual([fault])
    await w.clock.advance(1000); expect(mutations(w)).toHaveLength(at + 1)
    w.read = normal; await checkApplication(ui, w)
    expect(mutations(w)).toHaveLength(at + 1)
    if (fault === APPLY) await appliedRecorded(ui, w)
    if (mode === 'raw-lost') {
      await signedRecorded(ui, w, true); await press(ui, 'Finish agent access'); await appliedRecorded(ui, w)
      expect(mutations(w).slice(at).map(e => e.kind)).toEqual([SIGN, APPLY])
    }
    await closePane(ui)
  }
  privacy(w)
})

test('post-sign dispatch expiry preserves signature history without apply and post-apply expiry permits exact historical application', async ($, on) => {
  const w = fixture(on), normal = w.read; let ui: Pane
  for (const phase of [SIGN, APPLY]) {
    w.read = normal; w.applicationState = phase === SIGN ? 'unsigned' : 'signed'
    ui = await approved($, w, { created: w.clock.now() - 299_000 })
    const delayed = delaySignal(w, 2000), at = mutations(w).length
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === phase) await delayed.wait(); return value }
    const pending = press(ui, 'Finish agent access'); void pending.catch(() => undefined); await delayed.started
    await w.clock.advance(2000); await pending
    expect(mutations(w).slice(at).map(e => e.kind)).toEqual([phase]); await noFinish(ui)
    if (phase === SIGN) {
      if (/signature[^\n]*(?:recorded|stored)|(?:recorded|stored)[^\n]*signature/i.test(await shown(ui))) await signedRecorded(ui, w)
      else expect(await shown(ui)).toMatch(/unknown|unavailable|not confirmed/i)
      expect(await button(ui, 'Check application')).toBeDefined()
      expect(await shown(ui)).not.toContain('Local application: recorded')
    }
    else await appliedRecorded(ui, w)
    await closePane(ui)
  }
  privacy(w)
})

test('late preflight signer application and old timers cannot resurrect a departed or newer selected completion view', async ($, on) => {
  const w = fixture(on), normal = w.read; let ui = await approved($, w, { created: NOW - 299_000 })
  const oldRead = delaySignal(w, 2000)
  w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === LOOKUP) await oldRead.wait(); return value }
  const oldPress = press(ui, 'Finish agent access'); void oldPress.catch(() => undefined); await oldRead.started
  await leave(ui); w.read = normal; w.selected = network(2); w.networks = [network(), w.selected]
  w.access = await receipt(w, { state: 'approved', n: 82 }); const newReceipt = clone(w.access)
  await inspectPerson(ui, w); await press(ui, 'Review proposed grant')
  await w.clock.advance(1000); expect(await button(ui, 'Finish agent access')).toBeDefined()
  await w.clock.advance(1000); await oldPress
  expect(await button(ui, 'Finish agent access')).toBeDefined(); expect(w.access).toEqual(newReceipt)
  expect(mutations(w)).toEqual([]); await closePane(ui)
  const variants: [string, string][] = [[SIGN, 'leave'], [SIGN, 'back'], [SIGN, 'root'], [SIGN, 'native'],
    [APPLY, 'close'], [APPLY, 'refresh'], [APPLY, 'host'], [APPLY, 'parent'], [APPLY, 'surface'], [APPLY, 'end']]
  for (const [phase, mode] of variants) {
    w.read = normal; w.root = ROOT; w.native = NATIVE; w.host = HOST; w.parent.state = 'attached'; w.surface = 'terminal'; w.surfaces = ['terminal']
    w.applicationState = phase === SIGN ? 'unsigned' : 'signed'; ui = await approved($, w)
    const delayed = delaySignal(w), at = mutations(w).length
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === phase) await delayed.wait(); return value }
    const pending = press(ui, 'Finish agent access'); void pending.catch(() => undefined); await delayed.started
    const retained = clone(w.access)
    if (mode === 'leave') await leave(ui)
    if (mode === 'back') await press(ui, /^Back\b/)
    if (mode === 'close') await press(ui, 'Close')
    if (mode === 'refresh') await press(ui, 'Refresh')
    if (mode === 'root') { w.root = '/departed-completion-root'; await $.classic.CwdChanged({ old_cwd: ROOT, new_cwd: w.root }) }
    if (mode === 'native') w.native = 'departed-completion-conversation'
    if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
    if (mode === 'parent') w.parent.state = 'invalidated'
    if (mode === 'surface') { w.surface = null; w.surfaces = [] }
    if (mode === 'end') await $.session.end({ reason: 'clear', sessionId: NATIVE, resume: { id: NATIVE } })
    await w.clock.advance(1000); await pending; await noFinish(ui, mode)
    expect(await shown(ui), mode).not.toContain('Local application: recorded')
    expect(mutations(w).slice(at).map(e => e.kind)).toEqual([phase]); expect(w.access).toEqual(retained)
    await closePane(ui)
  }
  privacy(w)
})

test('Finish pure Check and leaving preserve the established authorized lease with no new tools prompts keys or direct transport', async ($, on) => {
  const w = fixture(on), ui = await attached($, w)
  await press(ui, 'Review adapter connection'); await press(ui, 'Approve adapter'); await press(ui, 'Connect adapter')
  expect(w.http).toHaveLength(1); await press(ui, /^Back to project$/)
  w.access = await receipt(w, { state: 'approved' }); await inspectPerson(ui, w); await press(ui, 'Review proposed grant')
  const tools = w.tools.map(tool => tool.name), material = clone(w.materials[0]), original = clone(w.access.review)
  await press(ui, 'Finish agent access'); await appliedRecorded(ui, w); await checkApplication(ui, w)
  expect(w.http).toHaveLength(1); expect(w.access.review).toEqual(original)
  await leave(ui); await closePane(ui); await w.clock.advance(5000)
  expect(w.http).toHaveLength(2); expect(w.tools.map(tool => tool.name)).toEqual(tools); expect(w.materials).toEqual([material])
  expect(calls(w, SIGN)).toHaveLength(1); expect(calls(w, APPLY)).toHaveLength(1)
  privacy(w, '', true)
})
