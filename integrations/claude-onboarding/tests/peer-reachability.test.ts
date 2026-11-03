/**
 * Independent section39 native selected-machine outbound fixtures, pinned303.
 * Public sections30/36/38/39 plus copied independent native fixture foundation.
 * No product imports/reads, real processes/hosts/network/keys/model inference.
 * All365 old native cases and30 host/helper files remain byte-for-byte exact.
 * Delays acknowledge actual command/guard dispatch and registered virtual sleep.
 * Cryptographic/evaluator/transport behavior is covered separately by real hosts;
 * obsolete rendered closures and microscopic digest-await/final-dispatch races
 * remain source-only. No actual terminal/reload/installed/physical/model/peer
 * acceptance is inferred from runtime effects or the preserved adapter lease.
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
const APPLICATION = 'access.application', SIGN = 'access.sign', APPLY = 'access.apply', STATUS = 'readiness', OUT = 'reachability'
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
  const w = { clock, started: false, sessionStarts: 0, root: ROOT, native: NATIVE, host: HOST, surface: 'terminal' as string | null,
    surfaces: ['terminal'], parent: null as any, child: null as any, selected: network(), person: PERSON,
    networks: [network()] as any[], members: [{ ...member(OWNER, HOST_KEY, 10, 'Owner machine "alias"'),
      not_after: stamp(NOW + 604_800_000) }, member()] as any[],
    noPolicy: false, uniqueDevice: true, ruleActions: ['message.append', 'task.submit'], enforced: null as any,
    ownerEnd: NOW + 604_800_000, personEnd: NOW + 259_200_000,
    providerEnd: NOW + 604_800_000, policyEnd: NOW + 3_600_000, access: null as any, lastInspection: null as any,
    applicationState: 'unsigned', proof: id('dp', 88, 64),
    targetKey: DEVICE, targetId: '', outboundStatus: 200 as number | null, outboundTag: 'authenticated_response',
    outboundObserved: null as number | null, lastOutbound: null as any,
    statusConnections: [] as any[], statusAuthorizations: [] as any[], statusObserved: null as number | null, lastStatus: null as any,
    expectedMutations: [] as string[], calls: [] as any[], trace: [] as any[], outside: [] as string[], tools: [] as any[], prompts: [] as any[],
    forbidden: [] as string[], http: [] as any[], materials: [] as any[],
    read: async (_kind: string, _payload: any, _event: any): Promise<any> => undefined }
  w.read = async (kind, payload, e) => {
    if (kind === 'snapshot') return { version: 1, host_id: w.host, observed_at: observed(w), networks: clone(w.networks), agents: [], requests: [], attention: [] }
    if (kind === 'project.lookup') return { version: 1, host_id: w.host, context: payload, flow: clone(w.parent),
      agents: w.parent ? [{ ...clone(w.parent.review.agent), created_at: stamp(NOW - 1000) }] : [] }
    if (kind === 'project.inspect') return clone(w.parent)
    if (kind === 'members') return { context_id: w.selected.context_id,
      members: clone(w.members).sort((a, b) => a.host_public_key < b.host_public_key ? -1 : 1) }
    if (kind === OUT) return outboundResponse(w)
    if (kind === STATUS) return statusResponse(w)
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
  on('session.start', ($, e) => { w.started = true; w.sessionStarts++; return { cwd: e.cwd } })
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
    const kind = at < 0 ? 'members' : tail[0] === 'reachability' ? OUT : tail[0] === 'readiness' ? STATUS : tail.length ? tail.slice(0, 2).join('.') : 'snapshot'
    const payload = e.init?.stdin ? JSON.parse(e.init.stdin) : undefined
    w.calls.push({ ...e, kind, payload: payload === undefined ? undefined : clone(payload), expectedContext: w.parent ? clone(context(w.parent)) : null,
      expectedPeer: w.targetId, expectedProject: w.parent?.flow_id, expectedAdapter: w.child?.flow_id, expectedNetwork: w.selected.id, expectedPerson: w.person,
      expectedInspection: w.lastInspection?.review_id, expectedAccess: w.access?.access_id, expectedReview: w.access?.review_id })
    w.trace.push(kind)
    const value = await w.read(kind, payload, e)
    if (value?.fixtureDeny) return { deny: RAW }
    if (value?.fixtureExit) return { value: { exitCode: 124, stdout: '', stderr: RAW } }
    if (typeof value?.fixtureRaw === 'string') return { value: { exitCode: 0, stdout: value.fixtureRaw, stderr: RAW } }
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
function privacy(w: World, text = '', runtime = false, executable = 'peerspan', state?: string) {
  expect(w.forbidden).toEqual([]); expect(w.prompts).toEqual([])
  expect(w.calls.filter(e => [PREPARE, APPROVE, SIGN, APPLY].includes(e.kind)).map(e => e.kind)).toEqual(w.expectedMutations)
  expect(w.tools.map(tool => tool.name)).toEqual(Array(w.sessionStarts).fill('delivery_acknowledge'))
  if (!runtime) expect(w.http).toEqual([])
  expect(w.outside.join('\n')).not.toContain(ROOT)
  for (const value of [NATIVE, RAW, TOKEN, SOCKET, '/private/access-path', 'PRIVATE_PROVIDER_ERROR', state,
    w.parent?.flow_id, w.parent?.review_id, w.parent?.review.session_id, w.access?.access_id, w.access?.review_id,
    w.access?.review.intent_id, w.child?.flow_id, w.child?.review_id, w.child?.review.adapter_id,
    ...w.statusConnections.map(value => value.adapter_id), ...w.materials.map(value => value.instance_id)].filter(Boolean)) {
    expect(text).not.toContain(value); expect(w.outside.join('\n')).not.toContain(value)
  }
  for (const e of w.calls) {
    const prefix = [executable, ...(state ? ['--state', state] : [])]
    expect(e.init?.timeoutMs, e.kind).toBe(e.kind === OUT ? 15000 : [SIGN, APPLY].includes(e.kind) ? 95000 : 5000)
    if (e.kind === 'members') expect(e.argv).toEqual([...prefix, 'network', 'members', e.expectedNetwork])
    else if (e.kind === 'snapshot') expect(e.argv).toEqual([...prefix, 'onboarding'])
    else if (e.kind.endsWith('.inspect') && !e.kind.startsWith('access.'))
      expect(e.argv).toEqual([...prefix, 'onboarding', e.kind.split('.')[0], 'inspect', e.kind === 'project.inspect' ? e.expectedProject : e.expectedAdapter])
    else expect(e.argv).toEqual([...prefix, 'onboarding', ...e.kind.split('.'), '--stdin'])
    if (e.kind === STATUS) expect(e.payload).toEqual({ context: e.expectedContext, network_id: e.expectedNetwork, person_public_key: e.expectedPerson })
    if (e.kind === OUT) expect(e.payload).toEqual({ context: e.expectedContext, network_id: e.expectedNetwork, person_public_key: e.expectedPerson, peer_host_id: e.expectedPeer })
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


// Host IDs hash the canonical decoded32-byte key, independently of person labels.
async function hostId(key: string) { return 'host_' + (await principal(key)).slice('person:person_'.length) }
async function statusResponse(w: World) {
  const inspected = await inspection(w)
  const peers = await Promise.all(inspected.review.participant.hosts
    .filter((row: any) => row.host_public_key !== HOST_KEY)
    .map(async (row: any) => ({ host_id: await hostId(row.host_public_key), host_public_key: row.host_public_key,
      authorizations: clone(w.statusAuthorizations) })))
  peers.sort((a, b) => a.host_id < b.host_id ? -1 : a.host_id > b.host_id ? 1 : 0)
  const value = { version: 1, host_id: w.host, context: context(w.parent),
    observed_at: w.statusObserved === null ? observed(w) : stamp(w.statusObserved),
    inspection: { review_id: inspected.review_id, review: inspected.review },
    readiness: { direction: 'participant_hosts_to_project_agent', session_id: w.parent.review.session_id,
      adapter_connections: clone(w.statusConnections), peers,
      peer_reachability: 'not_verified', model_receipt: 'not_verified', connection_readiness: 'not_verified' } }
  w.lastStatus = clone(value); return value
}
function grant(n = 1, now = NOW) {
  return { kind: 'grant', grant_id: id('grant', n), actions: ['task.submit'], max_message_bytes: 3210,
    max_artifact_bytes: 12345, expires_at: stamp(now + 25_000), from_agent: id('agent', 77) }
}
function policy(actions = ['task.submit', 'message.append', 'task.submit']) {
  return { kind: 'policy', actions, max_message_bytes: 23456, max_artifact_bytes: 54321, from_agent: id('agent', 76) }
}
function statusConnection(w: World, state = 'registered', verified = false, n = 10) {
  const now = w.clock.now(), ready = state === 'ready', past = state === 'offline'
  return { adapter_id: id('adapter', n), session_id: w.parent.review.session_id, state, recoverable: state !== 'registered',
    lease_expires_at: ready ? stamp(now + 12_345) : past ? stamp(now - 1000) : null,
    last_seen_at: state === 'registered' ? null : stamp(now - 2000), channel: ready ? verified ? 'verified' : 'unverified' : null,
    channel_verified_at: verified ? stamp(now - 3000) : null, protocol_version: state === 'registered' ? null : 'public-status-v1' }
}
async function selected($: Engine, w: World) {
  const ui = await attached($, w); await inspectPerson(ui, w); return ui
}
async function openStatus($: Engine, w: World) {
  const ui = await selected($, w); await press(ui, 'Check connection status'); return ui
}
async function closePane(ui: Pane) { if (await button(ui, 'Close')) await press(ui, 'Close'); await ui.unmount() }
async function details(ui: Pane) {
  if (await button(ui, 'Show connection details')) await press(ui, 'Show connection details')
  else expect(await button(ui, 'Hide connection details')).toBeDefined()
}
function delaySignal(w: World, milliseconds = 1000) {
  let enter!: () => void; const started = new Promise<void>(resolve => { enter = resolve })
  return { started, wait: () => { const pending = w.clock.sleep(milliseconds); enter(); return pending } }
}
const statusCalls = (w: World) => w.calls.filter(e => e.kind === STATUS)

async function outboundResponse(w: World) {
  const inspected = await inspection(w)
  const value = { version: 1, host_id: w.host, context: context(w.parent),
    observed_at: w.outboundObserved === null ? observed(w) : stamp(w.outboundObserved),
    inspection: { review_id: inspected.review_id, review: inspected.review },
    reachability: { direction: 'project_host_to_participant_host', peer_host_id: w.targetId, peer_host_public_key: w.targetKey,
      result: w.outboundTag, http_status: w.outboundStatus,
      incoming_delivery: 'not_verified', model_receipt: 'not_verified', connection_readiness: 'not_verified' } }
  w.lastOutbound = clone(value); return value
}
const outboundCalls = (w: World) => w.calls.filter(e => e.kind === OUT)
async function machineButtons(ui: Pane) { return (await ui.findAll({ type: 'Button' })).filter(e => /^Choose machine\b/.test(e.text)) }
async function chooseMachine(ui: Pane, w: World, key = DEVICE) {
  w.targetKey = key; w.targetId = await hostId(key)
  const choices = (await machineButtons(ui)).filter(e => e.text.includes(w.targetId))
  expect(choices, 'one explicit full selected-machine identity').toHaveLength(1)
  await ui.press({ key: choices[0].key! })
}
async function machinePane($: Engine, w: World, key = DEVICE) {
  const ui = await openStatus($, w); await press(ui, 'Check a machine connection'); await chooseMachine(ui, w, key); return ui
}
async function outboundDetails(ui: Pane) {
  if (await button(ui, 'Show outbound connection details')) await press(ui, 'Show outbound connection details')
  else expect(await button(ui, 'Hide outbound connection details')).toBeDefined()
}
function outboundReadsOnly(w: World, at: number) {
  expect(w.calls.slice(at).filter(e => !['snapshot', 'project.inspect', OUT].includes(e.kind))).toEqual([])
}
async function outboundTerms(ui: Pane, w: World, status = w.outboundStatus) {
  const text = await shown(ui), value = w.lastOutbound, review = value.inspection.review
  for (const term of ['Outbound connection', quoted(ROOT), quoted(review.agent.name), review.network.id,
    quoted(review.network.name), review.participant.person_public_key, w.targetId, w.targetKey, value.observed_at]) expect(text).toContain(term)
  expect(text).toMatch(/from this project's host to (?:the )?selected person's machine/i)
  expect(text).toMatch(/incoming(?: agent)? delivery: not verified/i)
  expect(text).toContain('Model receipt from this observation: not verified')
  expect(text).toContain('Overall connection readiness: not verified')
  if (status === null) {
    expect(text).toContain('Outbound connection: not verified')
    expect(text).not.toContain('Outbound connection unavailable')
    expect(text).not.toContain('Outbound authenticated response observed')
  } else {
    expect(text).toContain('Outbound authenticated response observed'); expect(text).toContain(String(status))
    expect(text).toMatch(/(?:not|does not|doesn't)[^\n]*(?:permission|authoriz)|(?:permission|authoriz)[^\n]*(?:not|unverified)/i)
  }
  expect(await button(ui, 'Choose another machine')).toBeDefined()
  expect(await button(ui, 'Check outbound connection')).toBeDefined()
  expect(await button(ui, 'Leave machine connection')).toBeDefined()
  expect(await button(ui, 'Approve agent access')).toBeUndefined(); expect(await button(ui, 'Finish agent access')).toBeUndefined()
}
async function outboundUnavailable(ui: Pane, label = '') {
  expect(await shown(ui), label).toContain('Outbound connection unavailable')
  expect(await shown(ui), label).not.toContain('Outbound authenticated response observed')
  expect(await shown(ui), label).not.toContain('Outbound connection: not verified')
  expect(await button(ui, 'Check outbound connection'), label).toBeDefined()
  expect(await button(ui, 'Choose another machine'), label).toBeDefined()
  expect(await button(ui, 'Show outbound connection details'), label).toBeUndefined()
}
async function machineExpired(ui: Pane) {
  expect(await shown(ui)).toContain('Machine connection observation expired. Check connection status again.')
  expect(await shown(ui)).not.toContain('Outbound authenticated response observed')
  expect(await machineButtons(ui)).toEqual([])
  expect(await button(ui, 'Check outbound connection')).toBeUndefined()
  expect(await button(ui, 'Show outbound connection details')).toBeUndefined()
  expect(await button(ui, 'Choose another machine')).toBeUndefined()
  expect(await button(ui, 'Check connection status')).toBeDefined()
  expect(await button(ui, 'Leave machine connection')).toBeDefined()
}
async function changedReply(w: World, normal: World['read'], change: (v: any) => void | Promise<void>, kind: string, payload: any, e: any) {
  const value = await normal(kind, payload, e)
  if (kind === OUT) await change(value)
  return value
}

// Canonical public basepoint multiples, copied only from independent fixture source.
const MACHINE_KEYS = ['WGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY=', 'yaP4aq5GXw5WUThkUQ85l1YfosnoXqIdwikjCfPNYCI=',
  '1LT1eEhowwIEAyRnF+wWn/eeJmCOoSahq2nud9GxZxI=', 'LxEyymGrON/wDy/qMijyTGxx1YCFuA5H4ZUVyyfo0Ec=',
  '7ch21oMf0hBdC0OJyi4oMWZGkokUbizgb67+mLIlSN8=', '9H5J+dB60sFga02UBnxB+Xd9T/2nCbcdodiGKPzjTYU=',
  'uGJAn7XExBI98qv3RiuI8EGtNt1oZM6HL9VHK+NjxbE=', 'tLk3/KlbLx6T5B5i/Dx4gY/zimYJb61ueXPlyQAG0yE=',
  'wPEiVYRETscwRG4jE5B4H/3S8lbp/L6y9A3dwsIjPX8=', 'LHvoarB0iLpD6OA9haZ2Jc+/mMhUTeTIdyQbeqr8f+M=',
  'EzcDasMtjzDUWJw8HFlYEs4P/0DjfG9al6shPzGCkK0=', '+eQtLtyB0jNnlnNStH5IVrgleGNObB3nIoDOi2DOcMA=']

// 1. Only the explicit configured outbound action dispatches section38.
test('entry consent Finish local status details and explicit choice are outbound-inert until exact private15s Check',
  { options: { executable: '/fixture bin/peerspan;$(literal)', state: '/private outbound state/$(literal)' } } as TestOptions, async ($, on) => {
  const w = fixture(on), ui = await attached($, w)
  expect(await button(ui, 'Check a machine connection')).toBeUndefined(); expect(outboundCalls(w)).toEqual([])
  await inspectPerson(ui, w); w.expectedMutations = [PREPARE, APPROVE, SIGN, APPLY]
  await press(ui, 'Review proposed grant'); await press(ui, 'Approve agent access')
  await press(ui, 'Finish agent access'); await press(ui, 'Check application'); expect(outboundCalls(w)).toEqual([])
  await press(ui, 'Check connection status'); await press(ui, 'Show connection details'); await press(ui, 'Hide connection details')
  expect(outboundCalls(w)).toEqual([])
  const localAt = w.calls.length; await press(ui, 'Check a machine connection'); await chooseMachine(ui, w)
  expect(w.calls).toHaveLength(localAt); expect(outboundCalls(w)).toEqual([])
  const original = clone(w.access), at = w.calls.length
  await press(ui, 'Check outbound connection'); await outboundTerms(ui, w)
  expect(outboundCalls(w)).toHaveLength(1); outboundReadsOnly(w, at); expect(w.access).toEqual(original)
  privacy(w, await shown(ui), false, '/fixture bin/peerspan;$(literal)', '/private outbound state/$(literal)')
})

// 2. No cardinality permits an implicit target, and every picker action is local.
test('one many and empty remote rosters require explicit full-ID quoted machine choice with ten-item paging and self exclusion', async ($, on) => {
  const w = fixture(on), ui = await openStatus($, w)
  let at = w.calls.length; await press(ui, 'Check a machine connection')
  expect(await shown(ui)).toContain('Choose a remote machine'); expect(await machineButtons(ui)).toHaveLength(1)
  expect(await button(ui, 'Check outbound connection')).toBeUndefined(); await chooseMachine(ui, w)
  expect(await shown(ui)).toMatch(/no outbound check|not (?:yet )?(?:been )?(?:performed|checked)/i)
  await press(ui, 'Choose another machine'); expect(w.calls).toHaveLength(at); expect(outboundCalls(w)).toEqual([])
  await press(ui, 'Leave machine connection')
  w.person = OWNER; w.personEnd = w.ownerEnd
  w.members = [w.members[0], ...MACHINE_KEYS.map((key, n) => member(OWNER, key, 100 + n * 4, 'Same "machine"'))]
  await inspectPerson(ui, w); await press(ui, 'Check connection status'); at = w.calls.length
  await press(ui, 'Check a machine connection')
  const sorted = (await Promise.all(MACHINE_KEYS.map(hostId))).sort()
  let choices = await machineButtons(ui); expect(choices).toHaveLength(10)
  expect(choices.map(e => e.text.match(/host_[0-9a-f]{64}/)![0])).toEqual(sorted.slice(0, 10))
  for (const choice of choices) expect(choice.text).toContain(quoted('Same "machine"'))
  expect(choices.some(e => e.text.includes(HOST))).toBe(false)
  await press(ui, 'More machines'); choices = await machineButtons(ui); expect(choices).toHaveLength(2)
  expect(choices.map(e => e.text.match(/host_[0-9a-f]{64}/)![0])).toEqual(sorted.slice(10))
  await press(ui, 'Previous machines'); expect(await machineButtons(ui)).toHaveLength(10)
  expect(w.calls).toHaveLength(at); expect(outboundCalls(w)).toEqual([])
  await press(ui, 'Leave machine connection'); w.members = [w.members[0]]
  await inspectPerson(ui, w); await press(ui, 'Check connection status'); at = w.calls.length
  await press(ui, 'Check a machine connection')
  expect(await shown(ui)).toMatch(/no remote machines.*observed/i); expect(await machineButtons(ui)).toEqual([])
  expect(await button(ui, 'Check outbound connection')).toBeUndefined()
  expect(await button(ui, 'Check connection status')).toBeDefined(); expect(w.calls).toHaveLength(at)
  privacy(w, await shown(ui))
})

// 3. Outbound authenticated exchange is not a permission or incoming/model proof.
test('authenticated200 without adapter or authorization displays only exact outbound selected-key evidence', async ($, on) => {
  const w = fixture(on), ui = await machinePane($, w)
  expect(w.statusConnections).toEqual([]); expect(w.statusAuthorizations).toEqual([])
  await press(ui, 'Check outbound connection'); await outboundTerms(ui, w, 200)
  expect(await shown(ui)).not.toContain('Peer reachability: not verified')
  expect(await shown(ui)).not.toMatch(/live verified|adapter[^\n]*ready|incoming(?: agent)? delivery: verified|overall connection readiness: ready/i)
  expect(w.lastOutbound.reachability.peer_host_id).toBe(await hostId(DEVICE))
  expect(w.lastOutbound.reachability.peer_host_public_key).toBe(DEVICE)
  privacy(w, await shown(ui))
})

// 4. Every complete authenticated error status is transport evidence; null is honest.
test('403 404 and500 are authenticated responses while a valid negative is neither unavailable nor authorization', async ($, on) => {
  const w = fixture(on), ui = await machinePane($, w)
  for (const status of [403, 404, 500, null]) {
    w.outboundStatus = status; w.outboundTag = status === null ? 'not_verified' : 'authenticated_response'
    const at = outboundCalls(w).length; await press(ui, 'Check outbound connection'); await outboundTerms(ui, w, status)
    expect(outboundCalls(w)).toHaveLength(at + 1)
  }
  privacy(w, await shown(ui))
})

// 5. Current complete public terms stay inspectable and details remain local.
test('outbound details preserve complete signed and enforced policy action order and public finite references without consent footer', async ($, on) => {
  const w = fixture(on); w.ruleActions = ['task.submit', 'message.append', 'task.submit']
  const ui = await machinePane($, w)
  const body = baseline(w); w.enforced = { rules: clone(body.rules.slice(0, 2)), capability_rules: clone(body.capability_rules), trusted_hosts: clone(body.trusted_hosts) }
  await press(ui, 'Check outbound connection'); await outboundTerms(ui, w)
  const at = w.calls.length; await outboundDetails(ui)
  const text = await shown(ui), review = w.lastOutbound.inspection.review
  for (const value of [review.root_state_id, review.owner.person_public_key, quoted(review.owner.member),
    review.owner.person_lease_id, review.owner.host.host_public_key, review.owner.host.host_lease_id, review.owner.host.binding_lease_id,
    review.participant.person_lease_id, review.participant.not_after, review.participant.hosts[0].not_after,
    review.policy.statement_id, review.policy.proof_id, review.policy.valid_until, 'max_message_bytes', 'max_artifact_bytes',
    'capability_rules', 'trusted_hosts', 'edits', 'retained-operation']) expect(text).toContain(value)
  expect(text).toMatch(/signed[\s\S]*enforced|enforced[\s\S]*signed/i)
  expect(text).toMatch(/task\.submit[\s,\[\]"]+message\.append[\s,\[\]"]+task\.submit/)
  expect(text).not.toMatch(/no signature|signature[^\n]*absent|application[^\n]*absent/i)
  await press(ui, 'Hide outbound connection details'); expect(w.calls).toHaveLength(at)
  privacy(w, await shown(ui))
})

// 6. A supported current-drawing press cannot start another in-flight operation.
test('recheck clears previous facts immediately and shares one genuinely dispatched delayed command with no automatic retry', async ($, on) => {
  const w = fixture(on), ui = await machinePane($, w), normal = w.read
  await press(ui, 'Check outbound connection'); await outboundTerms(ui, w); await outboundDetails(ui)
  const delayed = delaySignal(w), at = outboundCalls(w).length
  w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === OUT) await delayed.wait(); return value }
  const key = (await button(ui, 'Check outbound connection'))!.key!
  const pending = ui.press({ key }); void pending.catch(() => undefined); await delayed.started
  expect(await shown(ui)).not.toContain('Outbound authenticated response observed')
  expect(await button(ui, 'Show outbound connection details')).toBeUndefined()
  expect(await button(ui, 'Leave machine connection')).toBeDefined()
  await ui.press({ key }).catch(() => undefined)
  await w.clock.advance(1000); await pending; await outboundTerms(ui, w)
  expect(outboundCalls(w)).toHaveLength(at + 1)
  const count = w.calls.length; await w.clock.advance(1000); expect(w.calls).toHaveLength(count)
  privacy(w, await shown(ui))
})

// 7. Compact closed-result corpus exercises independent wrapper and evidence gates.
test('closed wrapper version direction flags and unsafe HTTP status refuse without fabricated negative success', async ($, on) => {
  const w = fixture(on), ui = await machinePane($, w), normal = w.read
  const variants: [string, (v: any) => void][] = [
    ['extra', v => { v.extra = true }], ['version', v => { v.version = '1' }],
    ['direction', v => { v.reachability.direction = 'participant_hosts_to_project_agent' }],
    ['flag', v => { v.reachability.incoming_delivery = 'verified' }],
    ['unsafe-status', v => { v.reachability.http_status = Number.MAX_SAFE_INTEGER + 1 }]]
  for (const [label, change] of variants) {
    w.read = (kind, payload, e) => changedReply(w, normal, change, kind, payload, e)
    await press(ui, 'Check outbound connection'); await outboundUnavailable(ui, label)
  }
  privacy(w, await shown(ui))
})

// 8. Metadata can become fresh; identity/authority/context cannot silently rebind.
test('exact target key digest and nested parent reject while current changed labels and policy for the same key replace old terms', async ($, on) => {
  const w = fixture(on), ui = await machinePane($, w), normal = w.read
  const variants: [string, (v: any) => void | Promise<void>][] = [
    ['other-target', v => { v.reachability.peer_host_id = HOST }],
    ['other-key', v => { v.reachability.peer_host_public_key = OWNER }],
    ['digest', v => { v.inspection.review_id = id('review', 999, 64) }],
    ['nested-context', async v => { v.inspection.review.context.native_session_id = 'other-outbound-conversation'
      v.inspection.review_id = await digest('peerspan-project-access-inspection-v1', v.inspection.review) }]]
  for (const [label, change] of variants) {
    w.read = (kind, payload, e) => changedReply(w, normal, change, kind, payload, e)
    await press(ui, 'Check outbound connection'); await outboundUnavailable(ui, label)
  }
  w.read = (kind, payload, e) => changedReply(w, normal, async v => {
    v.inspection.review.participant.member = 'Fresh "participant"'
    v.inspection.review.participant.hosts[0].member = 'Fresh "machine"'
    v.inspection.review.policy.statement_id = ds(51); v.inspection.review.policy.proof_id = id('dp', 51, 64)
    v.inspection.review.policy.body.version = 5
    v.inspection.review.policy.body.rules[0].max_message_bytes = 12345
    v.inspection.review.policy.enforced_content.rules[0].max_message_bytes = 12345
    v.inspection.review_id = await digest('peerspan-project-access-inspection-v1', v.inspection.review)
    w.lastOutbound = clone(v)
  }, kind, payload, e)
  await press(ui, 'Check outbound connection'); await outboundTerms(ui, w)
  expect(await shown(ui)).toContain(quoted('Fresh "machine"')); await outboundDetails(ui)
  expect(await shown(ui)).toContain(ds(51)); expect(await shown(ui)).toContain('12345')
  expect(outboundCalls(w).every(e => e.payload.peer_host_id === w.targetId)).toBe(true)
  privacy(w, await shown(ui))
})

// 9. Raw/decorated aggregate metadata and oversized JSON stay behind private IO.
test('plain and decorated private metadata controls and oversized public response never become outbound evidence', async ($, on) => {
  const w = fixture(on), ui = await machinePane($, w), normal = w.read
  const variants: [string, (v: any) => void | Promise<void>][] = [
    ['private', async v => { v.inspection.review.participant.hosts[0].member = 'token_SHORTPEER'
      v.inspection.review_id = await digest('peerspan-project-access-inspection-v1', v.inspection.review) }],
    ['decorated', async v => { v.inspection.review.participant.member = '\x1b]0;to\u202eken_SHORTOSC\x07visible'
      v.inspection.review_id = await digest('peerspan-project-access-inspection-v1', v.inspection.review) }],
    ['control', async v => { v.inspection.review.participant.hosts[0].member = 'machine\nSHORTCONTROL'
      v.inspection.review_id = await digest('peerspan-project-access-inspection-v1', v.inspection.review) }],
    ['oversize', v => { v.fixtureRaw = ' '.repeat(2 * 1024 * 1024 + 1) + JSON.stringify(v) }]]
  for (const [label, change] of variants) {
    w.read = (kind, payload, e) => changedReply(w, normal, change, kind, payload, e)
    await press(ui, 'Check outbound connection'); await outboundUnavailable(ui, label)
    expect(await shown(ui)).not.toMatch(/SHORTPEER|SHORTOSC|SHORTCONTROL|PRIVATE_PROVIDER_ERROR/)
  }
  expect(w.outside.join('\n')).not.toMatch(/SHORTPEER|SHORTOSC|SHORTCONTROL/); privacy(w, await shown(ui))
})

// 10. Roster membership replaces old lease/grant facts without extending any fact.
test('captured roster ignores cleared old adapter grant timers and result deadlines never extend original30s or returned finite bounds', async ($, on) => {
  const w = fixture(on); w.parent = await parentFlow()
  w.statusConnections = [{ ...statusConnection(w, 'ready'), lease_expires_at: stamp(NOW + 2000) }]
  w.statusAuthorizations = [{ ...grant(), expires_at: stamp(NOW + 2000) }]
  let ui = await machinePane($, w); await w.clock.advance(3000)
  expect(await button(ui, 'Check outbound connection')).toBeDefined()
  await press(ui, 'Check outbound connection'); await outboundTerms(ui, w)
  // A fresh explicit check clears the prior result's shorter expiry, while
  // the original roster remains authoritative throughout its real dispatch.
  w.personEnd = w.clock.now() + 2000; await press(ui, 'Check outbound connection')
  w.personEnd = w.clock.now() + 259_200_000
  const normal = w.read, delayed = delaySignal(w, 3000)
  w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === OUT) await delayed.wait(); return value }
  const pending = press(ui, 'Check outbound connection'); void pending.catch(() => undefined); await delayed.started
  await w.clock.advance(2000)
  expect(await shown(ui)).not.toContain('Machine connection observation expired. Check connection status again.')
  expect(await button(ui, 'Leave machine connection')).toBeDefined()
  await w.clock.advance(1000); await pending; await outboundTerms(ui, w)
  w.read = normal; await closePane(ui)
  for (const bound of ['original', 'returned-membership', 'returned-policy']) {
    w.statusConnections = []; w.statusAuthorizations = []; w.statusObserved = null
    w.personEnd = w.clock.now() + 259_200_000; w.policyEnd = w.clock.now() + 3_600_000
    const start = w.clock.now(); ui = await machinePane($, w)
    let duration = 2000
    if (bound === 'original') { await w.clock.advance(10_000); duration = 20_000 }
    if (bound === 'returned-membership') w.personEnd = w.clock.now() + duration
    if (bound === 'returned-policy') w.policyEnd = w.clock.now() + duration
    await press(ui, 'Check outbound connection'); await outboundTerms(ui, w); await outboundDetails(ui)
    const at = w.calls.length; await w.clock.advance(duration - 1)
    expect(await shown(ui), bound).toContain('Outbound authenticated response observed')
    await w.clock.advance(1); await machineExpired(ui); expect(w.calls).toHaveLength(at)
    if (bound === 'original') expect(w.clock.now()).toBe(start + 30_000)
    await closePane(ui)
  }
  privacy(w)
})

// 11. Real async boundaries are synchronized before advancing across roster expiry.
test('original roster deadline during actual preflight prevents send and delayed outbound response cannot resurrect elapsed selection', async ($, on) => {
  const w = fixture(on), normal = w.read
  for (const phase of ['project.inspect', OUT]) {
    w.read = normal; w.statusObserved = w.clock.now() - 29_000
    const ui = await machinePane($, w), delayed = delaySignal(w, 2000), at = outboundCalls(w).length
    let gated = false
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === phase && !gated) { gated = true; await delayed.wait() } return value }
    const pending = press(ui, 'Check outbound connection'); void pending.catch(() => undefined); await delayed.started
    await w.clock.advance(2000); await pending; await machineExpired(ui)
    expect(outboundCalls(w).length - at, phase).toBe(phase === OUT ? 1 : 0)
    await closePane(ui)
  }
  privacy(w)
})

// 12. Supported navigation replaces generations without pretending to invoke old closures.
test('changing choice clears facts and old result plus roster timer cannot replace a fresh local status and different selected machine', async ($, on) => {
  const w = fixture(on); w.members.push(member(PERSON, OWNER, 30, 'Second "machine"'))
  let ui = await machinePane($, w)
  w.personEnd = w.clock.now() + 2000; await press(ui, 'Check outbound connection'); await outboundTerms(ui, w)
  const at = w.calls.length; await press(ui, 'Choose another machine'); await chooseMachine(ui, w, OWNER)
  expect(w.calls).toHaveLength(at); expect(await shown(ui)).not.toContain('Outbound authenticated response observed')
  w.personEnd = w.clock.now() + 259_200_000
  await w.clock.advance(2000)
  expect(await button(ui, 'Check outbound connection')).toBeDefined()
  expect(await shown(ui)).not.toContain('Machine connection observation expired. Check connection status again.')
  await closePane(ui)
  w.statusObserved = w.clock.now() - 29_000; ui = await machinePane($, w)
  const normal = w.read, delayed = delaySignal(w, 2000); let first = true
  w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e)
    if (kind === OUT && first) { first = false; await delayed.wait() } return value }
  const old = press(ui, 'Check outbound connection'); void old.catch(() => undefined); await delayed.started
  await press(ui, 'Leave machine connection'); w.statusObserved = null
  await inspectPerson(ui, w); await press(ui, 'Check connection status'); await press(ui, 'Check a machine connection'); await chooseMachine(ui, w, OWNER)
  await w.clock.advance(1000); expect(await button(ui, 'Check outbound connection')).toBeDefined()
  await w.clock.advance(1000); await old
  expect(await shown(ui)).toContain(await hostId(OWNER)); expect(await shown(ui)).not.toContain('Outbound authenticated response observed')
  await press(ui, 'Check outbound connection'); await outboundTerms(ui, w)
  expect(outboundCalls(w).at(-1).payload.peer_host_id).toBe(await hostId(OWNER)); privacy(w, await shown(ui))
})

// 13. Current authoritative pins and native context are rechecked around real IO.
test('root native host network context and authoritative parent changes at registered preflight or IO discard old evidence', async ($, on) => {
  const w = fixture(on), normal = w.read
  for (const mode of ['preflight-root', 'io-native', 'io-host', 'io-network', 'post-io-parent']) {
    w.read = normal; w.root = ROOT; w.native = NATIVE; w.host = HOST; w.selected = network(); w.networks = [clone(w.selected)]
    w.parent = await parentFlow(); const ui = await machinePane($, w), delayed = delaySignal(w), at = outboundCalls(w).length
    let once = false
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (mode === 'post-io-parent' && kind === 'project.inspect' && outboundCalls(w).length > at) {
        value.review.native_session_id = 'other-authoritative-native'
        value.review_id = await digest('peerspan-project-review-v1', value.review)
      }
      if (!once && kind === (mode === 'preflight-root' ? 'project.inspect' : OUT)) { once = true; await delayed.wait() }
      return value }
    const pending = press(ui, 'Check outbound connection'); void pending.catch(() => undefined); await delayed.started
    if (mode === 'preflight-root') w.root = '/other-outbound-root'
    if (mode === 'io-native') w.native = 'other-native-conversation'
    if (mode === 'io-host') w.host = 'host_' + '9'.repeat(64)
    if (mode === 'io-network') { w.selected.context_id = id('ctx', 999, 64); w.networks = [clone(w.selected)] }
    await w.clock.advance(1000); await pending
    expect(await shown(ui), mode).not.toContain('Outbound authenticated response observed')
    expect(outboundCalls(w).length - at, mode).toBe(mode === 'preflight-root' ? 0 : 1)
    await closePane(ui)
  }
  privacy(w)
})

// 14. No persistence or automatically selected target survives navigation/reentry.
test('Leave Back Close Refresh end and lost terminal during dispatched work invalidate late callbacks and fresh entry has no target', async ($, on) => {
  const w = fixture(on), normal = w.read
  for (const mode of ['leave', 'back', 'close', 'refresh', 'end', 'surface']) {
    w.read = normal; w.surface = 'terminal'; w.surfaces = ['terminal']; w.parent = await parentFlow()
    const ui = await machinePane($, w), delayed = delaySignal(w), at = outboundCalls(w).length
    w.read = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === OUT) await delayed.wait(); return value }
    const pending = press(ui, 'Check outbound connection'); void pending.catch(() => undefined); await delayed.started
    if (mode === 'leave') await press(ui, 'Leave machine connection')
    if (mode === 'back') await press(ui, /^Back\b/)
    if (mode === 'close') await press(ui, 'Close')
    if (mode === 'refresh') await press(ui, 'Refresh')
    if (mode === 'end') { await $.session.end({ reason: 'clear', sessionId: NATIVE, resume: { id: NATIVE } }); w.started = false }
    if (mode === 'surface') { w.surface = null; w.surfaces = [] }
    await w.clock.advance(1000); await pending
    expect(await shown(ui), mode).not.toContain('Outbound authenticated response observed')
    expect(outboundCalls(w).length - at).toBe(1); await closePane(ui)
  }
  w.read = normal; w.surface = 'terminal'; w.surfaces = ['terminal']
  const count = outboundCalls(w).length, fresh = await openStatus($, w)
  expect(await button(fresh, 'Check outbound connection')).toBeUndefined()
  await press(fresh, 'Check a machine connection'); expect(await machineButtons(fresh)).toHaveLength(1)
  expect(await button(fresh, 'Check outbound connection')).toBeUndefined(); expect(outboundCalls(w)).toHaveLength(count)
  privacy(w, await shown(fresh))
})

// 15. Uncertainty and local-read recovery never imply an automatic outbound action.
test('denied timeout raw and missing replies clear old facts and only explicit checks recover or return through local status', async ($, on) => {
  const w = fixture(on), ui = await machinePane($, w), normal = w.read
  await press(ui, 'Check outbound connection'); await outboundTerms(ui, w)
  for (const fault of [{ fixtureDeny: true }, { fixtureExit: true }, { fixtureRaw: RAW }, null]) {
    w.read = async (kind, payload, e) => kind === OUT ? clone(fault) : normal(kind, payload, e)
    const at = outboundCalls(w).length; await press(ui, 'Check outbound connection'); await outboundUnavailable(ui)
    const count = w.calls.length; await w.clock.advance(1000)
    expect(outboundCalls(w)).toHaveLength(at + 1); expect(w.calls).toHaveLength(count)
  }
  w.read = normal; const at = w.calls.length, outboundCount = outboundCalls(w).length
  await press(ui, 'Check connection status')
  expect(w.calls.slice(at).filter(e => [STATUS, OUT].includes(e.kind)).map(e => e.kind)).toEqual([STATUS])
  expect(await button(ui, 'Check a machine connection')).toBeDefined()
  await press(ui, 'Check a machine connection'); expect(await button(ui, 'Check outbound connection')).toBeUndefined()
  expect(outboundCalls(w)).toHaveLength(outboundCount); privacy(w, await shown(ui))
})

// 16. An existing authorized runtime is separate from this optional observation.
test('authorized lease survives choice positive negative unavailable details and Leave without new tools prompts or direct peer transport', async ($, on) => {
  const w = fixture(on), ui = await attached($, w), normal = w.read
  await press(ui, 'Review adapter connection'); await press(ui, 'Approve adapter'); await press(ui, 'Connect adapter')
  expect(w.http).toHaveLength(1); await press(ui, /^Back to project$/)
  const material = clone(w.materials[0]), child = clone(w.child.review), tools = w.tools.map(tool => tool.name)
  w.statusConnections = [clone(w.child.connection)]
  await inspectPerson(ui, w); await press(ui, 'Check connection status'); await press(ui, 'Check a machine connection'); await chooseMachine(ui, w)
  const at = w.calls.length; await press(ui, 'Check outbound connection'); await outboundTerms(ui, w)
  await outboundDetails(ui); await press(ui, 'Hide outbound connection details')
  w.outboundStatus = null; w.outboundTag = 'not_verified'; await press(ui, 'Check outbound connection'); await outboundTerms(ui, w, null)
  w.read = async (kind, payload, e) => kind === OUT ? { fixtureDeny: true } : normal(kind, payload, e)
  await press(ui, 'Check outbound connection'); await outboundUnavailable(ui)
  await press(ui, 'Leave machine connection'); await closePane(ui); await w.clock.advance(5000)
  expect(w.http).toHaveLength(2); expect(w.materials).toEqual([material]); expect(w.child.review).toEqual(child)
  expect(w.tools.map(tool => tool.name)).toEqual(tools); expect(w.prompts).toEqual([])
  expect(w.calls.slice(at).filter(e => !['snapshot', 'project.inspect', 'adapter.inspect', OUT].includes(e.kind))).toEqual([])
  privacy(w, '', true)
})
