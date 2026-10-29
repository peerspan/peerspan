// Pure presentation of a host-verified incoming introduction; never parses codes.
import { same, bytes, quoted } from './project.mjs';
import { context } from './adapter.mjs';
import { privateValue } from './observation.mjs';
import { publicKey, publicEndpoint, publicLabel, freeze, canonical } from './invitation.mjs';
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v, keys) => object(v) && Object.keys(v).sort().join(',') === keys.split(' ').sort().join(',');
const id = (v, prefix) => typeof v === 'string' && new RegExp(`^${prefix}_[0-9a-f]{64}$`).test(v);
const time = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v) &&
  Number.isFinite(Date.parse(v)) && new Date(v).toISOString().replace('.000Z', 'Z') === v;
const uint = v => typeof v === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(v) && (v.length < 20 || v <= '18446744073709551615');
const ascending = (a, n, valid, key = x => x) => Array.isArray(a) && a.length <= n && a.every(valid) && a.every((v, i) => !i || key(a[i - 1]) < key(v));
const hint = h => exact(h, 'address public_key') && publicEndpoint(h.address) && publicKey(h.public_key);
const hints = (a, n) => ascending(a, n, hint, h => h.address + '\n' + h.public_key);
function contact(c) {
  return exact(c, 'sequence issued_at expires_at quic_addresses bootstrap_addresses relays') && uint(c.sequence) &&
    time(c.issued_at) && time(c.expires_at) && Date.parse(c.expires_at) > Date.parse(c.issued_at) &&
    Date.parse(c.expires_at) - Date.parse(c.issued_at) <= 300_000 &&
    ascending(c.quic_addresses, 8, publicEndpoint) && ascending(c.bootstrap_addresses, 8, publicEndpoint) &&
    hints(c.relays, 8) && c.quic_addresses.length + c.bootstrap_addresses.length + c.relays.length <= 16;
}
export const validCode = v => typeof v === 'string' && bytes(v) <= 32768 && /^psi2-[A-Za-z0-9_-]+$/.test(v);
export async function preview(raw, parent, host) {
  const v = JSON.parse(raw), r = v.review;
  if (!exact(v, 'version host_id context review_id review next_action') || v.version !== 1 || v.host_id !== host || !id(host, 'host') ||
      !same(v.context, context(parent)) || parent.state !== 'attached' || !id(v.review_id, 'review') || v.next_action !== 'choose_join_identity' ||
      !exact(r, 'version kind host_id context agent network inviter_host_public_key invitation contacts helpers effects') ||
      r.version !== 1 || r.kind !== 'inspect_contact_invitation' || r.host_id !== host || !same(r.context, context(parent)) ||
      !same(r.agent, parent.review.agent) || !exact(r.network, 'id name context_id genesis_root_public_key') ||
      !id(r.network.id, 'net') || !id(r.network.context_id, 'ctx') || !publicLabel(r.network.name) ||
      r.network.name !== r.network.name.trim() || !publicKey(r.network.genesis_root_public_key) || !publicKey(r.inviter_host_public_key) ||
      !exact(r.invitation, 'id member expected_person_public_key issued_at expires_at automatic_return') ||
      !id(r.invitation.id, 'di') || !publicLabel(r.invitation.member) || r.invitation.member !== r.invitation.member.trim() ||
      !(r.invitation.expected_person_public_key === '-' || publicKey(r.invitation.expected_person_public_key)) ||
      !time(r.invitation.issued_at) || !time(r.invitation.expires_at) || typeof r.invitation.automatic_return !== 'boolean' ||
      Date.parse(r.invitation.expires_at) - Date.parse(r.invitation.issued_at) < 60_000 ||
      Date.parse(r.invitation.expires_at) - Date.parse(r.invitation.issued_at) > 86_400_000 ||
      !Array.isArray(r.contacts) || r.contacts.length > 4 || !r.contacts.every(contact) ||
      r.contacts.some((c, n) => n > 0 && (r.contacts[n - 1].sequence.length > c.sequence.length ||
        (r.contacts[n - 1].sequence.length === c.sequence.length && r.contacts[n - 1].sequence > c.sequence))) || !hints(r.helpers, 4) ||
      !same(r.effects, { verify_contact_signature: true, create_identity: false, create_link_request: false, select_owner: false,
        grant_membership: false, grant_agent_access: false, approve_machine: false, share_files: false, share_conversation: false, capability_calls: false }) ||
      [r.context.project_root, r.context.native_session_id, r.agent.name, r.agent.owner, ...r.agent.capabilities].some(privateValue)) {
    throw new Error('Unavailable invitation preview');
  }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('peerspan-invitation-preview-v1\n' + canonical(r))));
  if (v.review_id !== 'review_' + Array.from(digest, b => b.toString(16).padStart(2, '0')).join('')) throw new Error('Changed invitation preview');
  return freeze(v);
}
export function reviewLines(v) {
  const r = v.review, i = r.invitation;
  const addresses = a => a.length ? a.map(quoted).join(', ') : 'none';
  const pairs = a => a.length ? a.map(h => `${quoted(h.address)} key ${quoted(h.public_key)}`).join(', ') : 'none';
  return [`Project: ${quoted(r.context.project_root)}`, 'Conversation: current conversation', `Agent: ${quoted(r.agent.name)}`,
    `Owner label: ${quoted(r.agent.owner)}`, `Capability metadata: ${addresses(r.agent.capabilities)}`,
    `Network: ${quoted(r.network.name)}`, `Network ID: ${r.network.id}`, `Context ID: ${r.network.context_id}`,
    `Genesis root public key: ${quoted(r.network.genesis_root_public_key)}`, `Inviter host public key: ${quoted(r.inviter_host_public_key)}`,
    `Invitation ID: ${i.id}`, `Invitee label: ${quoted(i.member)}`, `Expected person: ${i.expected_person_public_key === '-' ? 'unpinned' : quoted(i.expected_person_public_key)}`,
    `Invitation issued: ${i.issued_at}`, `Invitation expires: ${i.expires_at}`, `Automatic return: ${i.automatic_return ? 'available' : 'unavailable (legacy invitation)'}`,
    ...(r.contacts.length ? r.contacts.flatMap((c, n) => [`Contact ${n + 1} sequence: ${c.sequence}`, `Contact issued: ${c.issued_at}`, `Contact expires: ${c.expires_at}`,
      `QUIC addresses: ${addresses(c.quic_addresses)}`, `Bootstrap addresses: ${addresses(c.bootstrap_addresses)}`, `Relays: ${pairs(c.relays)}`]) : ['Contacts: none']),
    `Helpers: ${pairs(r.helpers)}`, 'Contact signature: verified', 'New identities: none', 'Link requests created: none', 'Owner selected: none',
    'Membership grants: none', 'Agent access grants: none', 'Machine approval: none', 'Files shared: none', 'Conversation sharing: none', 'Capability calls: none',
    'Signer membership and authority: not established', 'Admission and agent access: not established', 'Peer reachability and model receipt: not verified',
    'Identity selection and joining are subsequent steps; this preview records no consent.'].join('\n');
}
