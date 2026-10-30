// Exact public requester consent/application evidence; keys stay in the daemon.
import { same, quoted } from './project.mjs';
import { context } from './adapter.mjs';
import { canonical, freeze } from './invitation.mjs';
import { requestView } from './join-progress.mjs';
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v, keys) => object(v) && Object.keys(v).sort().join(',') === keys.split(' ').sort().join(',');
const id = (v, prefix, n = 64) => typeof v === 'string' && new RegExp(`^${prefix}_[0-9a-f]{${n}}$`).test(v);
const time = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v) &&
  Number.isFinite(Date.parse(v)) && new Date(v).toISOString().replace('.000Z', 'Z') === v;
const stages = ['request_created', 'owner_offered', 'owner_selected', 'administrator_offered',
  'owner_finalized', 'commit_persisted', 'locally_applied'];
const effects = { approve_commit_intent: true, authorize_binding_host_signature: true,
  authorize_requester_commit_signatures: true, authorize_commit_publication: true,
  authorize_local_application: true, grant_agent_access: false, share_files: false,
  share_conversation: false, capability_calls: false };
const pins = ['request_id', 'network_id', 'context_id', 'person_public_key', 'host_public_key', 'device_public_key',
  'created_at', 'expires_at', 'request_packet_id', 'owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id'];
export function applied(v) {
  return v?.commit?.state === 'approved' && v.request.state === 'linked' && same(v.request.completed, stages);
}
export function sameConsent(a, b) {
  return a?.commit?.review_id === b?.commit?.review_id && same(a?.commit?.review, b?.commit?.review) &&
    pins.every(k => a.request[k] === b.request[k]);
}
export function deadline(v) {
  if (!v?.commit || !['review', 'approved'].includes(v.commit.state) || applied(v)) return null;
  return Math.min(Date.parse(v.request.expires_at), Date.parse(v.commit.review.not_after),
    v.commit.state === 'review' ? Date.parse(v.commit.review.expires_at) : Infinity);
}
export function eligible(v, now, approve = false) {
  if (!v?.commit || v.commit.state !== (approve ? 'review' : 'approved') || applied(v) ||
      !['needs_commit', 'finalizing'].includes(v.request.state) ||
      !same(v.request.completed, stages.slice(0, v.request.completed.length)) ||
      v.request.completed.length < 5 || v.request.completed.length > (approve ? 5 : 6)) return false;
  const r = v.commit.review, observed = Date.parse(v.observed_at);
  return Number.isFinite(now) && now >= Date.parse(v.request.created_at) && now >= Date.parse(r.created_at) &&
    observed >= Date.parse(r.created_at) &&
    observed <= now + 30000 && Math.max(now, observed) < deadline(v);
}
export function canPrepare(original, now) {
  const r = original?.request;
  if (original?.owner?.state !== 'approved' || r.state !== 'needs_commit' || !r.selection_approved || r.commit_approved ||
      !same(r.completed, stages.slice(0, 5)) || !['manifest_id', 'activation_id', 'outcome_id'].every(k => r[k] === '-')) return false;
  const observed = Date.parse(original.observed_at);
  return Number.isFinite(now) && now >= Date.parse(r.created_at) && observed <= now + 30000 &&
    Math.max(now, observed) < Math.min(Date.parse(r.expires_at), Date.parse(original.owner.review.not_after));
}
export async function snapshot(raw, flow, parent, host, original) {
  const v = JSON.parse(raw), c = v?.commit, r = c?.review;
  if (!exact(v, 'version host_id flow_id join_review_id context observed_at request commit') || v.version !== 1 ||
      v.host_id !== host || v.flow_id !== flow.flow_id || v.join_review_id !== flow.review_id ||
      !same(v.context, context(parent)) || !time(v.observed_at) || original?.owner?.state !== 'approved' ||
      Date.parse(v.observed_at) < Date.parse(original.observed_at)) throw new Error('Unavailable requester consent');
  await requestView(v.request, flow, host);
  if (Date.parse(v.observed_at) < Date.parse(v.request.created_at) ||
      !pins.filter(k => original.request[k] !== '-').every(k => v.request[k] === original.request[k])) throw new Error('Changed requester original');
  if (c === null) {
    if (v.request.commit_approved) throw new Error('Missing approved requester intent');
    return freeze(v);
  }
  if (!exact(c, 'review_id review state next_action') || !id(c.review_id, 'review') ||
      !exact(r, 'version kind host_id context flow_id join_review_id owner_review_id request_id intent_id network member person_public_key host_public_key device_public_key request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id root_state_id person_lease_id host_lease_id binding_lease_id device_lease_id scopes binding_scopes not_after provider created_at expires_at effects') ||
      r.version !== 1 || r.kind !== 'approve_new_original_requester_commit' || r.scopes !== 7 || r.binding_scopes !== 2 ||
      !same(r.effects, effects) || !['host_id', 'context', 'flow_id', 'join_review_id'].every(k => same(r[k], v[k])) ||
      r.owner_review_id !== original.owner.review_id || !id(r.intent_id, 'dint', 32) ||
      !['network', 'member', 'person_public_key', 'host_public_key', 'device_public_key', 'not_after']
        .every(k => same(r[k], original.owner.review[k])) ||
      !['request_id', 'person_public_key', 'host_public_key', 'device_public_key', 'request_packet_id',
        'owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id'].every(k => r[k] === v.request[k]) ||
      !pins.every(k => original.request[k] === v.request[k]) ||
      !['owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id'].every(k => id(r[k], 'dpk')) ||
      !['root_state_id', 'person_lease_id', 'host_lease_id', 'binding_lease_id', 'device_lease_id'].every(k => id(r[k], 'ds')) ||
      new Set([r.root_state_id, r.person_lease_id, r.host_lease_id, r.binding_lease_id, r.device_lease_id]).size !== 5 ||
      !exact(r.provider, 'kind host_public_key device_public_key signature_format') || r.provider.kind !== 'requester' ||
      r.provider.host_public_key !== r.host_public_key || r.provider.device_public_key !== r.device_public_key ||
      r.provider.signature_format !== 'ed25519' || !['created_at', 'expires_at', 'not_after'].every(k => time(r[k])) ||
      Date.parse(r.created_at) < Date.parse(v.request.created_at) ||
      Date.parse(v.observed_at) < Date.parse(r.created_at) ||
      Date.parse(r.not_after) !== Date.parse(v.request.created_at) + 7 * 86400000 ||
      Date.parse(r.expires_at) !== Math.min(Date.parse(r.created_at) + 900000, Date.parse(v.request.expires_at), Date.parse(r.not_after)) ||
      Date.parse(r.expires_at) <= Date.parse(r.created_at) ||
      !v.request.selection_approved || v.request.completed.length < 5 ||
      !same(v.request.completed, stages.slice(0, v.request.completed.length))) throw new Error('Changed requester terms');
  const approved = c.state === 'approved';
  const action = approved ? 'follow_join_progress' : c.state === 'review' ? 'approve_requester_commit'
    : ['expired', 'cancelled', 'invalidated'].includes(c.state) ? 'inspect_join_progress' : null;
  if (!action || c.next_action !== action || v.request.commit_approved !== approved ||
      !approved && (v.request.completed.length !== 5 || !['manifest_id', 'activation_id', 'outcome_id'].every(k => v.request[k] === '-')) ||
      c.state === 'review' && (v.request.state !== 'needs_commit' || Date.parse(v.observed_at) >= Date.parse(r.expires_at)) ||
      v.request.completed.length === 5 && v.request.manifest_id !== '-' ||
      v.request.state === 'finalizing' && v.request.completed.length !== 6 ||
      v.request.state === 'needs_commit' && v.request.completed.length !== 5) throw new Error('Changed requester state');
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(
    'peerspan-requester-commit-review-v1\n' + canonical(r))));
  if (c.review_id !== 'review_' + Array.from(digest, b => b.toString(16).padStart(2, '0')).join('')) throw new Error('Changed requester digest');
  return freeze(v);
}
export async function result(raw, flow, parent, host, original, captured) {
  const v = JSON.parse(raw), marker = v?.completion;
  if (!exact(v, 'version host_id flow_id join_review_id context observed_at request commit completion') ||
      !exact(marker, 'state review_id manifest_id activation_id outcome_id participant_delivery agent_access connection_readiness') ||
      marker.state !== 'locally_applied' || marker.review_id !== captured.commit.review_id ||
      !['participant_delivery', 'agent_access', 'connection_readiness'].every(k => marker[k] === 'not_verified') ||
      !id(marker.manifest_id, 'dm') || !id(marker.activation_id, 'da') || !id(marker.outcome_id, 'dpk')) throw new Error('Unavailable requester completion');
  const { completion, ...publicSnapshot } = v;
  const checked = await snapshot(JSON.stringify(publicSnapshot), flow, parent, host, original);
  if (!applied(checked) || !sameConsent(captured, checked) ||
      !['manifest_id', 'activation_id', 'outcome_id'].every(k => marker[k] === checked.request[k]) ||
      Date.parse(checked.observed_at) < Date.parse(captured.observed_at)) throw new Error('Changed requester completion');
  return freeze(v);
}
export function reviewLines(v, parent, expired = false) {
  if (!v?.commit) return 'Requester consent: none recorded. Review requester commit explicitly to prepare eligible terms.';
  const c = v.commit, r = c.review;
  return [`Requester consent: ${c.state === 'approved' ? 'recorded' : expired && c.state === 'review' ? 'expired' : c.state}`,
    `Observed at: ${v.observed_at}`, `Project: ${quoted(parent.review.project_root)}`, 'Conversation: current conversation',
    `Network: ${quoted(r.network.name)}`, `Network ID: ${r.network.id}`, `Context ID: ${r.network.context_id}`,
    `Genesis root public key: ${quoted(r.network.genesis_root_public_key)}`, `Invitee label: ${quoted(r.member)}`,
    `Original person public key: ${quoted(r.person_public_key)}`, `Host public key: ${quoted(r.host_public_key)}`,
    `Device public key: ${quoted(r.device_public_key)}`, 'Original consent and finalization: recorded for this exact person, machine and fixed powers.',
    `Original offer: ${r.owner_offer_id}`, `Requester selection: ${r.selection_id}`, `Administrator offer: ${r.administrator_offer_id}`,
    `Original finalization: ${r.owner_finalization_id}`, `Current root: ${r.root_state_id}`, `Person lease: ${r.person_lease_id}`,
    `Host lease: ${r.host_lease_id}`, `Binding lease: ${r.binding_lease_id}`, `Device lease: ${r.device_lease_id}`,
    'Machine powers profile: 7; binding scope: 2',
    'Policy editing (1); host binding (2); approval, renewal and revocation of eligible own devices (4). Network administrator (8): not approved.',
    `Powers end: ${r.not_after}`, `Requester review expires: ${r.expires_at}`, `Request expires: ${v.request.expires_at}`,
    'Provider: this requester host and device; signature format: ed25519.',
    'Approve authorizes the existing intent, binding-host and requester signatures, commit publication and local application.',
    'Complete is a separate bounded action using owned host/device keys. No original key is selected, created, copied or imported.',
    ...(applied(v) ? ['Local application: recorded', `Manifest: ${v.request.manifest_id}`, `Activation: ${v.request.activation_id}`,
      `Outcome: ${v.request.outcome_id}`, 'Global public evidence; the approving/completing interface is not identified.']
      : ['Local application: not confirmed. Earlier valid signatures or publication may already exist.']),
    'Participant delivery: not verified. Agent access: not verified. Connection readiness and model receipt: not verified.',
    'Files shared: none. Conversation sharing: none. Capability calls: none. Agent-access grants: none.',
    'Historical consent or application does not establish current powers. Leaving does not cancel or revoke recorded consent.',
    'Leaving cannot retract valid prior work or dispatched signatures/publication/application. Check reads evidence without preparing, approving, completing or retrying.'].join('\n');
}
