// Pure owner-response validation. Private codes are never review text.
import { same, bytes, quoted } from './project.mjs';
import { context } from './adapter.mjs';
import { observation, privateValue } from './observation.mjs';

const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v, keys) => object(v) && Object.keys(v).sort().join(',') === keys.split(' ').sort().join(',');
const id = (v, prefix, n = 64) => typeof v === 'string' && new RegExp(`^${prefix}_[0-9a-f]{${n}}$`).test(v);
const time = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(v) && Number.isFinite(Date.parse(v));
const label = v => typeof v === 'string' && v.trim().length > 0 && bytes(v) <= 128 && !/[\u0000-\u001f\u007f-\u009f]/u.test(v) && !privateValue(v);
// Last Base64 sextet must have its two padding bits clear.
const key = v => typeof v === 'string' && /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(v);
function freeze(v) {
  if (object(v) || Array.isArray(v)) { Object.values(v).forEach(freeze); Object.freeze(v); }
  return v;
}
function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (object(v)) return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  return JSON.stringify(v);
}
function ipv6(host) {
  const raw = host.slice(1, -1), parts = raw.split('::');
  if (parts.length > 2) return false;
  const words = s => s ? s.split(':') : [];
  const left = words(parts[0]), right = parts.length === 2 ? words(parts[1]) : [];
  const all = [...left, ...right];
  if (!all.every(w => /^[0-9a-f]{1,4}$/.test(w)) || (parts.length === 1 ? all.length !== 8 : all.length >= 8)) return false;
  const groups = [...left.map(w => parseInt(w, 16)), ...Array(8 - all.length).fill(0), ...right.map(w => parseInt(w, 16))];
  if (groups.every(n => n === 0) || (groups.slice(0, 5).every(n => n === 0) && groups[5] === 65535)) return false;
  let best = -1, length = 1;
  for (let i = 0; i < 8; i++) {
    if (groups[i] !== 0) continue;
    let end = i;
    while (end < 8 && groups[end] === 0) end++;
    if (end - i > length) { best = i; length = end - i; }
    i = end - 1;
  }
  const strings = groups.map(n => n.toString(16));
  const canonical = best === -1 ? strings.join(':') : strings.slice(0, best).join(':') + '::' + strings.slice(best + length).join(':');
  return raw === canonical;
}
function endpoint(v) {
  if (typeof v !== 'string' || v.length > 260 || privateValue(v)) return false;
  const m = /^(\[[0-9a-f:]+\]|[a-z0-9.-]+):([1-9][0-9]{0,4})$/.exec(v);
  if (!m || Number(m[2]) > 65535) return false;
  const h = m[1];
  if (h.startsWith('[')) return ipv6(h);
  if (/^[0-9.]+$/.test(h)) return h.split('.').length === 4 && h.split('.').every(x => /^(0|[1-9][0-9]{0,2})$/.test(x) && Number(x) <= 255) && h !== '0.0.0.0';
  return h.length <= 253 && h.split('.').every(x => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x));
}
const ordered = (a, bound, validate, sortKey = x => x) => Array.isArray(a) && a.length <= bound &&
  a.every(validate) && a.every((v, i) => i === 0 || sortKey(a[i - 1]) < sortKey(v));
function transport(v) {
  const hint = h => exact(h, 'address public_key') && endpoint(h.address) && key(h.public_key);
  return exact(v, 'bootstrap_addresses quic_addresses relays helpers') &&
    ordered(v.bootstrap_addresses, 8, endpoint) && ordered(v.quic_addresses, 8, endpoint) &&
    ordered(v.relays, 4, hint, h => h.address + '\n' + h.public_key) &&
    ordered(v.helpers, 4, hint, h => h.address + '\n' + h.public_key);
}
export function proposal(member, pin) {
  if (typeof member !== 'string' || !label(member.trim()) || !(pin === '-' || key(pin))) throw new Error('Invalid invitation draft');
  return { member: member.trim(), expected_person_public_key: pin };
}
export function networks(raw, host) {
  observation(raw);
  const v = JSON.parse(raw);
  if (v.host_id !== host || !Array.isArray(v.networks) || v.networks.length > 4096 ||
      !v.networks.every(n => id(n.id, 'net') && label(n.name)) || new Set(v.networks.map(n => n.id)).size !== v.networks.length) {
    throw new Error('Unavailable invitation networks');
  }
  return freeze(v.networks.map(n => ({ id: n.id, name: n.name })));
}
export async function flow(v, parent, host) {
  if (!exact(v, 'version flow_id state review_id review invitation next_action') || v.version !== 1 ||
      !id(v.flow_id, 'flow', 32) || !id(v.review_id, 'review') || parent.state !== 'attached') throw new Error('Unavailable invitation review');
  const r = v.review;
  if (!exact(r, 'version kind flow_id host_id context agent network inviter_host_public_key member expected_person_public_key transport expires_at invitation_expires_at effects') ||
      r.version !== 1 || r.kind !== 'create_contact_invitation' || r.flow_id !== v.flow_id || r.host_id !== host || !id(host, 'host') ||
      !same(r.context, context(parent)) || !same(r.agent, parent.review.agent) ||
      !exact(r.network, 'id name context_id genesis_root_public_key') || !id(r.network.id, 'net') || !label(r.network.name) ||
      !id(r.network.context_id, 'ctx') || !key(r.network.genesis_root_public_key) || !key(r.inviter_host_public_key) ||
      !label(r.member) || r.member !== r.member.trim() || !(r.expected_person_public_key === '-' || key(r.expected_person_public_key)) ||
      !transport(r.transport) || !time(r.expires_at) || !time(r.invitation_expires_at) ||
      Date.parse(r.invitation_expires_at) - Date.parse(r.expires_at) !== 2_700_000 ||
      !same(r.effects, { create_contact_invitation: true, receive_join_requests: true, grant_membership: false,
        grant_agent_access: false, approve_machine: false, share_files: false, share_conversation: false, capability_calls: false })) {
    throw new Error('Unavailable invitation review');
  }
  const actions = { review: 'review', issued: 'share_private_invitation', declined: 'restart_review', expired: 'restart_review', invalidated: 'restart_review' };
  if (!Object.hasOwn(actions, v.state) || v.next_action !== actions[v.state] ||
      (v.invitation === null ? v.state === 'issued' : !exact(v.invitation, 'invitation_id expires_at') ||
        !id(v.invitation.invitation_id, 'di') || v.invitation.expires_at !== r.invitation_expires_at || ['review', 'declined'].includes(v.state))) {
    throw new Error('Unavailable invitation outcome');
  }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('peerspan-invitation-review-v1\n' + canonical(r))));
  if (v.review_id !== 'review_' + Array.from(digest, b => b.toString(16).padStart(2, '0')).join('')) throw new Error('Changed invitation digest');
  return freeze(v);
}
export async function lookup(raw, parent, host) {
  const v = JSON.parse(raw);
  if (!exact(v, 'version host_id context flow') || v.version !== 1 || v.host_id !== host || !same(v.context, context(parent))) throw new Error('Unavailable invitation lookup');
  if (v.flow !== null) await flow(v.flow, parent, host);
  return freeze(v);
}
export function handoff(raw, captured) {
  const v = JSON.parse(raw), r = captured.review;
  if (!exact(v, 'version flow_id review_id network_id context_id invitation_id invitation expires_at') || v.version !== 1 ||
      captured.state !== 'issued' || v.flow_id !== captured.flow_id || v.review_id !== captured.review_id ||
      v.network_id !== r.network.id || v.context_id !== r.network.context_id || v.invitation_id !== captured.invitation.invitation_id ||
      v.expires_at !== r.invitation_expires_at || typeof v.invitation !== 'string' || bytes(v.invitation) > 32768 ||
      !/^psi2-[A-Za-z0-9_-]+$/.test(v.invitation)) throw new Error('Unavailable private invitation');
  return v.invitation;
}
export function reviewLines(v) {
  const r = v.review;
  const addresses = a => a.length ? a.map(quoted).join(', ') : 'none';
  const hints = a => a.length ? a.map(h => `${quoted(h.address)} key ${quoted(h.public_key)}`).join(', ') : 'none';
  return [`Project: ${quoted(r.context.project_root)}`, 'Conversation: current conversation',
    `Agent: ${quoted(r.agent.name)}`, `Owner label: ${quoted(r.agent.owner)}`,
    `Capability metadata: ${addresses(r.agent.capabilities)}`, `Network: ${quoted(r.network.name)}`,
    `Network ID: ${r.network.id}`, `Context ID: ${r.network.context_id}`,
    `Genesis root public key: ${quoted(r.network.genesis_root_public_key)}`, `Inviter host public key: ${quoted(r.inviter_host_public_key)}`,
    `Invitee label: ${quoted(r.member)}`, `Expected person: ${r.expected_person_public_key === '-' ? 'unpinned' : quoted(r.expected_person_public_key)}`,
    `Bootstrap addresses: ${addresses(r.transport.bootstrap_addresses)}`, `QUIC addresses: ${addresses(r.transport.quic_addresses)}`,
    `Relays: ${hints(r.transport.relays)}`, `Helpers: ${hints(r.transport.helpers)}`,
    `Review expires: ${r.expires_at}`, `Invitation expires: ${r.invitation_expires_at}`,
    'Create one private contact invitation', 'Receive join requests', 'Membership grants: none', 'Agent access grants: none',
    'Machine approval: none', 'Files shared: none', 'Conversation sharing: none', 'Capability calls: none',
    'Peer reachability and model receipt: not verified'].join('\n');
}

// Shared pure public-term validation; no private transport or native effects.
export { key as publicKey, endpoint as publicEndpoint, label as publicLabel, freeze, canonical };
