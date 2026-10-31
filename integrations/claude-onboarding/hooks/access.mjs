// Public presentation only. The daemon verifies authority and enforces policy.
import { same, bytes, quoted } from './project.mjs';
import { context } from './adapter.mjs';
import { privateValue } from './observation.mjs';
import { publicKey, publicLabel, canonical, freeze, networks } from './invitation.mjs';

const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v, keys) => object(v) && Object.keys(v).sort().join(',') === keys.split(' ').sort().join(',');
const id = (v, kind, n = 64) => typeof v === 'string' && new RegExp(`^${kind}_[0-9a-f]{${n}}$`).test(v);
const time = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v) &&
  Number.isFinite(Date.parse(v)) && new Date(v).toISOString().replace('.000Z', 'Z') === v;
const integer = v => Number.isSafeInteger(v) && v >= 0;
const list = (v, check) => Array.isArray(v) && v.every(check);
const ordered = (v, key = x => x) => v.every((x, i) => !i || key(v[i - 1]) < key(x));
function safe(v, depth = 0) {
  if (depth > 64) return false;
  if (typeof v === 'string') return Number.isFinite(bytes(v)) && !/[\u0000-\u001f\u007f-\u009f]/u.test(v) && !privateValue(v) &&
    !privateValue(v.replace(/[\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/gu, ''));
  if (typeof v === 'number') return integer(v);
  return v === null || typeof v === 'boolean' || (Array.isArray(v) ? v.every(x => safe(x, depth + 1))
    : object(v) && Object.entries(v).every(([k, x]) => safe(k, depth + 1) && safe(x, depth + 1)));
}
function decode(raw, limit) {
  if (typeof raw !== 'string' || bytes(raw) > limit) throw new Error('Unavailable access view');
  const value = JSON.parse(raw);
  if (!safe(value)) throw new Error('Unavailable public access terms');
  return value;
}
async function hash(raw) {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', raw)), x => x.toString(16).padStart(2, '0')).join('');
}
async function digest(domain, review) { return 'review_' + await hash(new TextEncoder().encode(domain + '\n' + canonical(review))); }
async function personId(key) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', out = [];
  let bits = 0, value = 0;
  for (const c of key.replace(/=+$/, '')) {
    value = (value << 6) | alphabet.indexOf(c); bits += 6;
    if (bits >= 8) { bits -= 8; out.push((value >>> bits) & 255); }
  }
  return 'person_' + await hash(new Uint8Array(out));
}
const inspectionEffects = { inspect_current_membership: true, inspect_current_policy: true,
  prepare_access: false, approve_access: false, sign_policy: false, publish_policy: false,
  grant_agent_access: false, share_files: false, share_conversation: false, capability_calls: false };
const consentEffects = { approve_policy_intent: true, authorize_policy_signature: true,
  authorize_policy_publication: true, grant_agent_access_after_signatures: true, grant_membership: false,
  delegate_tasks: false, share_files: false, share_conversation: false, capability_calls: false, allow_disconnected: false };
function member(v) {
  return exact(v, 'host_public_key member person_public_key host_lease_id binding_lease_id device_lease_id not_after') &&
    publicKey(v.host_public_key) && publicLabel(v.member) && (v.person_public_key === '-' || publicKey(v.person_public_key)) &&
    id(v.host_lease_id, 'ds') && (v.binding_lease_id === '-' || id(v.binding_lease_id, 'ds')) &&
    (v.device_lease_id === '-' || id(v.device_lease_id, 'ds')) && time(v.not_after) &&
    (v.person_public_key === '-' ? v.binding_lease_id === '-' && v.device_lease_id === '-' : id(v.binding_lease_id, 'ds'));
}
export function inventory(raw, host) {
  const v = decode(raw, 2 << 20);
  networks(raw, host);
  const selected = v.networks.filter(n => n.mode === 'decentralized');
  if (selected.some(n => !id(n.context_id, 'ctx'))) throw new Error('Unavailable network context');
  return freeze(selected.map(({ id, name, context_id }) => ({ id, name, context_id })).sort((a, b) => a.id < b.id ? -1 : 1));
}
export function people(raw, now, network) {
  const v = decode(raw, 2 << 20);
  if (!exact(v, 'context_id members') || v.context_id !== network.context_id || !id(v.context_id, 'ctx') || !list(v.members, member) ||
      v.members.length > 4096 || !ordered(v.members, x => x.host_public_key) || !Number.isFinite(now) ||
      v.members.some(m => Date.parse(m.not_after) <= now)) throw new Error('Unavailable current people');
  const groups = new Map();
  for (const m of v.members.filter(m => m.person_public_key !== '-')) {
    const old = groups.get(m.person_public_key);
    const labels = [...new Set([...(old?.labels ?? []), m.member])].sort();
    groups.set(m.person_public_key, { person_public_key: m.person_public_key, labels, context_id: v.context_id });
  }
  return freeze([...groups.values()].sort((a, b) => a.person_public_key < b.person_public_key ? -1 : 1));
}
function rule(v) {
  return exact(v, 'agent principals actions max_message_bytes allow_disconnected' + (Object.hasOwn(v ?? {}, 'max_artifact_bytes') ? ' max_artifact_bytes' : '')) &&
    typeof v.agent === 'string' && list(v.principals, x => typeof x === 'string') && list(v.actions, x => typeof x === 'string') &&
    integer(v.max_message_bytes) && (!Object.hasOwn(v, 'max_artifact_bytes') || integer(v.max_artifact_bytes)) && typeof v.allow_disconnected === 'boolean';
}
function content(v) {
  return exact(v, 'rules capability_rules trusted_hosts') && list(v.rules, rule) && list(v.trusted_hosts, x => id(x, 'host')) &&
    list(v.capability_rules, r => exact(r, 'host capability principals max_input_bytes allow_disconnected max_calls_per_hour') &&
      id(r.host, 'host') && typeof r.capability === 'string' && list(r.principals, x => typeof x === 'string') &&
      integer(r.max_input_bytes) && typeof r.allow_disconnected === 'boolean' && integer(r.max_calls_per_hour));
}
function body(v, net, person) {
  return exact(v, 'network_id person_public_key version issued_at valid_until rules' +
    (Object.hasOwn(v ?? {}, 'format') ? ' format capability_rules trusted_hosts edits' : '')) &&
    v.network_id === net && v.person_public_key === person && integer(v.version) && v.version > 0 &&
    time(v.issued_at) && time(v.valid_until) && Date.parse(v.issued_at) < Date.parse(v.valid_until) && list(v.rules, rule) &&
    (!Object.hasOwn(v, 'format') || v.format === 2 && content({ rules: v.rules, capability_rules: v.capability_rules, trusted_hosts: v.trusted_hosts }) &&
      list(v.edits, e => exact(e, 'host seq') && id(e.host, 'host') && integer(e.seq) && e.seq > 0));
}
async function review(r, parent, host, network, selected) {
  if (!exact(r, 'version kind host_id context agent network root_state_id owner participant policy effects') || r.version !== 1 ||
      r.kind !== 'inspect_project_agent_access' || r.host_id !== host || !id(host, 'host') || !same(r.context, context(parent)) ||
      !same(r.agent, parent.review.agent) || !exact(r.network, 'id name context_id') ||
      r.network.id !== network.id || r.network.name !== network.name || !id(r.network.id, 'net') || !publicLabel(r.network.name) ||
      r.network.context_id !== selected.context_id || !id(r.network.context_id, 'ctx') || !id(r.root_state_id, 'ds') ||
      !exact(r.owner, 'person_public_key member person_lease_id host') || !publicKey(r.owner.person_public_key) ||
      !publicLabel(r.owner.member) || !id(r.owner.person_lease_id, 'ds') || !member(r.owner.host) ||
      r.owner.host.person_public_key !== r.owner.person_public_key ||
      !exact(r.participant, 'person_public_key member person_lease_id not_after hosts') ||
      r.participant.person_public_key !== selected.person_public_key || !publicLabel(r.participant.member) ||
      !id(r.participant.person_lease_id, 'ds') || !time(r.participant.not_after) || !list(r.participant.hosts, member) ||
      !ordered(r.participant.hosts, x => x.host_public_key) ||
      r.participant.hosts.some(h => h.person_public_key !== r.participant.person_public_key) ||
      !same(r.effects, inspectionEffects)) throw new Error('Changed access inspection');
  if ('host_' + (await personId(r.owner.host.host_public_key)).slice(7) !== host) throw new Error('Changed owner host');
  const p = r.policy;
  if (p !== null && (!exact(p, 'statement_id proof_id body enforced_content valid_until') || !id(p.statement_id, 'ds') ||
      !id(p.proof_id, 'dp') || !body(p.body, network.id, r.owner.person_public_key) || !content(p.enforced_content) || !time(p.valid_until) ||
      Date.parse(p.valid_until) > Date.parse(p.body.valid_until))) throw new Error('Unavailable full policy');
  return r;
}
export function liveInspection(v, now) {
  const r = v.review, bounds = [r.owner.host.not_after, r.participant.not_after,
    ...r.participant.hosts.map(h => h.not_after), ...(r.policy ? [r.policy.valid_until] : [])].map(Date.parse);
  return Number.isFinite(now) && Date.parse(v.observed_at) <= now + 30000 &&
    Math.max(now, Date.parse(v.observed_at)) < Math.min(...bounds) &&
    (!r.policy || Date.parse(v.observed_at) >= Date.parse(r.policy.body.issued_at) && now >= Date.parse(r.policy.body.issued_at));
}
export async function inspection(raw, parent, host, network, selected, now) {
  const v = decode(raw, 2 << 20);
  if (!exact(v, 'version host_id context observed_at review_id review next_action') || v.version !== 1 || v.host_id !== host ||
      !same(v.context, context(parent)) || !time(v.observed_at) || v.next_action !== 'review_agent_access') throw new Error('Unavailable access inspection');
  await review(v.review, parent, host, network, selected);
  if (v.review_id !== await digest('peerspan-project-access-inspection-v1', v.review) || !liveInspection(v, now)) throw new Error('Elapsed access inspection');
  return freeze(v);
}
export async function consent(raw, parent, host, network, selected) {
  const v = decode(raw, 1 << 20), a = v.access;
  if (!exact(v, 'version host_id context observed_at access') || v.version !== 1 || v.host_id !== host ||
      !same(v.context, context(parent)) || !time(v.observed_at)) throw new Error('Unavailable access consent');
  if (a === null) return freeze(v);
  const r = a?.review, p = r?.statement?.payload, provider = r?.provider;
  if (!exact(a, 'access_id review_id review state next_action') || !id(a.access_id, 'dint', 32) ||
      !exact(r, 'version kind access_id host_id context inspection_review_id inspection replaces_access_id grant action_id intent_id provider statement created_at expires_at effects') ||
      r.version !== 1 || r.kind !== 'approve_project_agent_access' || r.access_id !== a.access_id || r.host_id !== host ||
      !same(r.context, context(parent)) || !(r.replaces_access_id === '-' || id(r.replaces_access_id, 'dint', 32)) ||
      !id(r.action_id, 'act') || !id(r.intent_id, 'dint', 32) || r.intent_id === r.access_id ||
      !time(r.created_at) || !time(r.expires_at) || Date.parse(v.observed_at) < Date.parse(r.created_at) ||
      !same(r.effects, consentEffects)) throw new Error('Changed access consent');
  await review(r.inspection, parent, host, network, selected);
  const i = r.inspection;
  if (!liveInspection({ review: i, observed_at: r.created_at }, Date.parse(r.created_at)) ||
      r.inspection_review_id !== await digest('peerspan-project-access-inspection-v1', i) ||
      !same(r.grant, { policy_scope: 'owner_agent_name', agent_id: i.agent.id, agent_name: i.agent.name,
        principal: 'person:' + await personId(selected.person_public_key), actions: ['message.append', 'task.submit'],
        max_message_bytes: 65536, max_artifact_bytes: 0, allow_disconnected: false }) ||
      !exact(provider, 'kind person_public_key host_public_key device_public_key lease_id root_state_id scopes not_after') ||
      !['original_person', 'device'].includes(provider.kind) || provider.person_public_key !== i.owner.person_public_key ||
      provider.host_public_key !== i.owner.host.host_public_key || provider.root_state_id !== i.root_state_id ||
      !integer(provider.scopes) || provider.scopes > 15 || (provider.scopes & 1) !== 1 || !time(provider.not_after) ||
      (provider.kind === 'original_person' ? provider.device_public_key !== '-' || provider.lease_id !== i.owner.person_lease_id
        : !publicKey(provider.device_public_key) || !id(provider.lease_id, 'ds') ||
          i.owner.host.device_lease_id !== '-' && provider.lease_id !== i.owner.host.device_lease_id) ||
      !exact(r.statement, 'id payload_sha256 payload') || !id(r.statement.id, 'ds') || !/^[0-9a-f]{64}$/.test(r.statement.payload_sha256) ||
      !exact(p, 'root_state_id operation_id sequence predecessors resolves issuer parents issued_at not_before not_after body') ||
      p.root_state_id !== i.root_state_id || p.operation_id !== '-' || !integer(p.sequence) || p.sequence < 1 ||
      !same(p.predecessors, i.policy ? [i.policy.statement_id] : []) || !same(p.resolves, []) ||
      !same(p.issuer, { kind: provider.kind === 'device' ? 'device' : 'person', person_public_key: i.owner.person_public_key }) ||
      !same(p.parents, [{ role: 'issuer_person', id: i.owner.person_lease_id },
        ...(provider.kind === 'device' ? [{ role: 'issuer_device', id: provider.lease_id }] : [])].sort((a, b) => a.role < b.role ? -1 : 1)) ||
      !time(p.issued_at) || p.issued_at !== r.created_at || p.not_before !== p.issued_at || !time(p.not_after) ||
      !body(p.body, network.id, i.owner.person_public_key) || p.body.version !== p.sequence ||
      p.body.issued_at !== p.issued_at || p.body.valid_until !== p.not_after ||
      Date.parse(p.not_after) > Math.min(Date.parse(p.issued_at) + 86400000, Date.parse(provider.not_after), Date.parse(i.participant.not_after)) ||
      Date.parse(r.expires_at) !== Math.min(Date.parse(r.created_at) + 300000, Date.parse(p.not_after)) ||
      Date.parse(r.expires_at) <= Date.parse(r.created_at) || !p.body.rules.some(rule => rule.agent === r.grant.agent_name &&
        same(rule.actions, r.grant.actions) && rule.principals.includes(r.grant.principal) && rule.max_message_bytes === 65536 &&
        (rule.max_artifact_bytes ?? 0) === 0 && rule.allow_disconnected === false) ||
      a.review_id !== await digest('peerspan-project-access-consent-v1', r)) throw new Error('Unavailable exact grant');
  const actions = { review: 'approve_policy_intent', approved: 'follow_policy_action', expired: 'inspect_agent_access', invalidated: 'inspect_agent_access' };
  if (!Object.hasOwn(actions, a.state) || a.next_action !== actions[a.state] ||
      a.state === 'review' && Date.parse(v.observed_at) >= Date.parse(r.expires_at)) throw new Error('Changed access state');
  return freeze(v);
}
export function deadline(v) {
  const r = v.access.review, i = r.inspection;
  return Math.min(Date.parse(r.expires_at), Date.parse(r.statement.payload.not_after), Date.parse(i.owner.host.not_after),
    Date.parse(i.participant.not_after), ...i.participant.hosts.map(h => Date.parse(h.not_after)),
    ...(i.policy ? [Date.parse(i.policy.valid_until)] : []));
}
export function approvable(v, now) {
  return v?.access?.state === 'review' && Number.isFinite(now) && now >= Date.parse(v.access.review.created_at) &&
    Date.parse(v.observed_at) <= now + 30000 && Math.max(now, Date.parse(v.observed_at)) < deadline(v);
}
export function inspectionLines(v) {
  const r = v.review;
  const machine = h => `${quoted(h.member)} ${quoted(h.host_public_key)}; host lease: ${h.host_lease_id}; binding: ${h.binding_lease_id}; device: ${h.device_lease_id}; ends: ${h.not_after}`;
  return [`Project: ${quoted(r.context.project_root)}`, 'Conversation: current conversation',
    `Agent: ${quoted(r.agent.name)} (${r.agent.id})`, `Owner label: ${quoted(r.agent.owner)}`,
    `Network: ${quoted(r.network.name)} (${r.network.id})`, `Context ID: ${r.network.context_id}`, `Current root: ${r.root_state_id}`,
    `Owner person: ${quoted(r.owner.member)} ${quoted(r.owner.person_public_key)}`, `Person lease: ${r.owner.person_lease_id}`,
    `Owner machine: ${machine(r.owner.host)}`, `Selected person: ${quoted(r.participant.member)} ${quoted(r.participant.person_public_key)}`,
    `Selected person lease: ${r.participant.person_lease_id}; ends: ${r.participant.not_after}`,
    `Selected machines: ${r.participant.hosts.length ? r.participant.hosts.map(machine).join('; ') : 'none'}`,
    `Signed baseline policy: ${r.policy ? quoted(canonical(r.policy.body)) : 'none retained'}`,
    `Enforced content: ${r.policy ? quoted(canonical(r.policy.enforced_content)) : 'none retained'}`,
    ...(r.policy ? [`Policy statement: ${r.policy.statement_id}; proof: ${r.policy.proof_id}; effective end: ${r.policy.valid_until}`] : []),
    'Inspection grants no access. Membership and policy presence do not prove delivery permission.',
    'Files and conversation sharing: none. Capability calls: none. Peer delivery and connection readiness: not verified.'].join('\n');
}
export function consentLines(v) {
  if (!v.access) return 'Agent-access consent: none recorded. Review proposed grant explicitly to prepare terms.';
  const a = v.access, r = a.review;
  return [inspectionLines({ review: r.inspection }), `Agent-access consent: ${a.state === 'approved' ? 'recorded' : a.state}`,
    'Policy scope: owner_agent_name — this exact agent name across the owner’s machines; not exclusive to this host or agent ID.',
    `Exact proposed grant: ${quoted(canonical(r.grant))}`, `Provider: ${quoted(canonical(r.provider))}`,
    `Policy statement: ${r.statement.id}; payload SHA256: ${r.statement.payload_sha256}`,
    `Proposed unsigned policy: ${quoted(canonical(r.statement.payload))}`, `Review created: ${r.created_at}; expires: ${r.expires_at}`,
    'Approve authorizes the existing policy intent and later policy signing/publication. It does not sign or apply here.',
    'Other broader baseline permissions remain. Membership, delegation, files, conversation, capabilities and disconnected access: no new permission.',
    'Signing, local application, peer delivery and connection readiness: not verified here.',
    'Historical consent does not establish current access. Leaving does not revoke consent or retract prior or dispatched work.'].join('\n');
}
