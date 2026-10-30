// Public local identities and exact host reviews; no native effects or key IO.
import { same, quoted } from './project.mjs';
import { context } from './adapter.mjs';
import { publicKey, freeze, canonical } from './invitation.mjs';
import { preview, terms } from './recipient.mjs';
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v, keys) => object(v) && Object.keys(v).sort().join(',') === keys.split(' ').sort().join(',');
const id = (v, prefix, n = 64) => typeof v === 'string' && new RegExp(`^${prefix}_[0-9a-f]{${n}}$`).test(v);
const time = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v) &&
  Number.isFinite(Date.parse(v)) && new Date(v).toISOString().replace('.000Z', 'Z') === v;
export function identities(raw, parent, host) {
  const v = JSON.parse(raw), sources = ['generated', 'ssh_agent'];
  if (!exact(v, 'version host_id context identities') || v.version !== 1 || v.host_id !== host || !id(host, 'host') ||
      !same(v.context, context(parent)) || !Array.isArray(v.identities) || v.identities.length > 64 ||
      !v.identities.every((i, n) => exact(i, 'public_key sources') && publicKey(i.public_key) &&
        (!n || v.identities[n - 1].public_key < i.public_key) && Array.isArray(i.sources) && i.sources.length > 0 && i.sources.length <= 2 &&
        i.sources.every((s, j) => sources.includes(s) && (!j || sources.indexOf(i.sources[j - 1]) < sources.indexOf(s))))) {
    throw new Error('Unavailable local identities');
  }
  return freeze(v.identities);
}
export function createdIdentity(raw, parent, host) {
  const v = JSON.parse(raw);
  if (!exact(v, 'version host_id context identity') || v.version !== 1 || v.host_id !== host || !id(host, 'host') ||
      !same(v.context, context(parent)) || !exact(v.identity, 'public_key sources') || !publicKey(v.identity.public_key) ||
      !same(v.identity.sources, ['generated'])) throw new Error('Unavailable saved identity');
  return freeze(v.identity);
}
export async function flow(raw, parent, host) {
  const v = typeof raw === 'string' ? JSON.parse(raw) : raw, r = v?.review;
  const actions = { review: 'approve_join_request', declined: 'none', requested: 'await_participant_reviews',
    expired: 'review_replacement', invalidated: 'review_replacement', replaced: 'review_replacement' };
  if (!exact(v, 'version host_id flow_id review_id state review outcome next_action') || v.version !== 1 || v.host_id !== host ||
      !id(v.flow_id, 'flow', 32) || !id(v.review_id, 'review') || !Object.hasOwn(actions, v.state) || v.next_action !== actions[v.state] ||
      !exact(r, 'version kind flow_id host_id context agent invitation_review_id invitation person_public_key expires_at effects') ||
      r.version !== 1 || r.kind !== 'create_join_request' || r.flow_id !== v.flow_id || r.host_id !== host ||
      !same(r.context, context(parent)) || !same(r.agent, parent.review.agent) || !id(r.invitation_review_id, 'review') ||
      !publicKey(r.person_public_key) || !time(r.expires_at) ||
      !same(r.effects, { create_identity: false, create_link_request: true, publish_request: true, select_owner: false,
        grant_membership: false, grant_agent_access: false, approve_machine: false, share_files: false, share_conversation: false, capability_calls: false })) {
    throw new Error('Unavailable join review');
  }
  await preview(JSON.stringify({ version: 1, host_id: host, context: r.context, review_id: r.invitation_review_id,
    review: r.invitation, next_action: 'choose_join_identity' }), parent, host);
  if (Date.parse(r.expires_at) > Date.parse(r.invitation.invitation.expires_at) ||
      Date.parse(r.expires_at) <= Date.parse(r.invitation.invitation.issued_at) ||
      (r.invitation.invitation.expected_person_public_key !== '-' && r.person_public_key !== r.invitation.invitation.expected_person_public_key) ||
      ((v.state === 'requested') !== (v.outcome !== null)) ||
      (v.outcome !== null && (!exact(v.outcome, 'request_id network_id context_id person_public_key') ||
        !id(v.outcome.request_id, 'link') || v.outcome.network_id !== r.invitation.network.id ||
        v.outcome.context_id !== r.invitation.network.context_id || v.outcome.person_public_key !== r.person_public_key))) {
    throw new Error('Changed join terms');
  }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('peerspan-join-review-v1\n' + canonical(r))));
  if (v.review_id !== 'review_' + Array.from(digest, b => b.toString(16).padStart(2, '0')).join('')) throw new Error('Changed join digest');
  return freeze(v);
}
export async function lookup(raw, parent, host) {
  const v = JSON.parse(raw);
  if (!exact(v, 'version host_id context flow') || v.version !== 1 || v.host_id !== host || !id(host, 'host') ||
      !same(v.context, context(parent))) throw new Error('Unavailable join lookup');
  if (v.flow !== null) await flow(v.flow, parent, host);
  return freeze(v);
}
export const provenance = i => i.sources.map(s => s === 'generated' ? 'local generated original' : 'SSH agent').join(', ');
export function reviewLines(v, selected) {
  const r = v.review;
  return [...terms({ review: r.invitation }), `Selected original person: ${quoted(r.person_public_key)}`,
    ...(selected ? [`Identity source: ${provenance(selected)}`] : []), `Join review expires: ${r.expires_at}`,
    'New original person identities: none', 'Create or reuse one ordinary join request', 'Publish the encrypted request through ordinary transport',
    'Owner selection: none', 'Membership grants: none', 'Agent access grants: none', 'Machine approval: none', 'Files shared: none',
    'Conversation sharing: none', 'Capability calls: none', 'Public key selection: not possession proof',
    'Participant approvals and current link state: not verified', 'Access, reachability and model receipt: not verified'].join('\n');
}
