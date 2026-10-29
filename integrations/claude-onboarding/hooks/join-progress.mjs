// An exact public ordinary-request snapshot, never a ceremony driver.
import { same, bytes, quoted } from './project.mjs';
import { context } from './adapter.mjs';
import { publicKey, freeze } from './invitation.mjs';
import { privateValue } from './observation.mjs';
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v, keys) => object(v) && Object.keys(v).sort().join(',') === keys.split(' ').sort().join(',');
const id = (v, prefix, n = 64) => typeof v === 'string' && new RegExp(`^${prefix}_[0-9a-f]{${n}}$`).test(v);
const time = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v) &&
  Number.isFinite(Date.parse(v)) && new Date(v).toISOString().replace('.000Z', 'Z') === v;
const stages = ['request_created', 'owner_offered', 'owner_selected', 'administrator_offered', 'owner_finalized', 'commit_persisted', 'locally_applied'];
const next = {
  pending: ['person_owner', 'review_owner_offer', 'Person owner: review identity and machine powers.'],
  needs_selection: ['requesting_machine', 'review_owner_selection', 'This computer: review the exact owner offer.'],
  needs_administrator: ['network_administrator', 'review_admission', 'Network administrator: review person and machine admission.'],
  needs_owner_finalization: ['person_owner', 'review_owner_finalization', 'Person owner: review the final machine binding and powers.'],
  needs_commit: ['requesting_machine', 'review_final_commit', 'This computer: review and commit the exact complete link.'],
  finalizing: ['host', 'await_local_application', 'Host: finish the already approved local application.'],
  linked: ['requesting_machine', 'inspect_access_readiness', 'This computer: inspect agent access and connection readiness separately.'],
  cancelled: ['requesting_machine', 'review_replacement', 'This computer: explicitly review a replacement request if needed.'],
  expired: ['requesting_machine', 'review_replacement', 'This computer: explicitly review a replacement request if needed.'],
  blocked: ['local_owner', 'inspect_advanced_status', 'Local owner: inspect advanced linking status.'],
};
const publicStrings = v => Array.isArray(v) && v.length <= 32 && v.every(s => typeof s === 'string' && s.length > 0 && bytes(s) <= 1024 &&
  !/[\u0000-\u001f\u007f-\u009f]/u.test(s) && !privateValue(s));
async function hostFor(key) {
  // Canonical32-byte Base64 was validated above. No atob/Buffer dependency in
  // the pinned native runtime, which exposes digest but not key import/signing.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', raw = [];
  let accumulator = 0, bits = 0;
  for (const c of key.slice(0, -1)) {
    accumulator = accumulator << 6 | alphabet.indexOf(c); bits += 6;
    if (bits >= 8) { bits -= 8; raw.push(accumulator >> bits & 255); accumulator &= (1 << bits) - 1; }
  }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(raw)));
  return 'host_' + Array.from(digest, b => b.toString(16).padStart(2, '0')).join('');
}
// Shared public LINK_VIEW validation for observation and exact owner consent.
export async function requestView(r, flow, host) {
  if (!exact(r, 'request_id role mode state network_id context_id migration_proposal_id person_public_key host_public_key device_public_key created_at expires_at request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id manifest_id activation_id outcome_id selection_approved commit_approved completed attention next') ||
      r.request_id !== flow.outcome.request_id || r.role !== 'requester' || r.mode !== 'new' || r.migration_proposal_id !== '-' ||
      typeof r.state !== 'string' || !Object.hasOwn(next, r.state) || r.network_id !== flow.outcome.network_id || r.context_id !== flow.outcome.context_id ||
      r.person_public_key !== flow.outcome.person_public_key || !publicKey(r.host_public_key) || !publicKey(r.device_public_key) ||
      !time(r.created_at) || !time(r.expires_at) || Date.parse(r.expires_at) <= Date.parse(r.created_at) ||
      !id(r.request_packet_id, 'dpk') ||
      !['owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id', 'outcome_id']
        .every(k => r[k] === '-' || id(r[k], 'dpk')) || !(r.manifest_id === '-' || id(r.manifest_id, 'dm')) ||
      !(r.activation_id === '-' || id(r.activation_id, 'da')) || typeof r.selection_approved !== 'boolean' ||
      typeof r.commit_approved !== 'boolean' || r.commit_approved && !r.selection_approved ||
      !Array.isArray(r.completed) || r.completed.length === 0 || r.completed.length > 7 || r.completed[0] !== 'request_created' ||
      !r.completed.every((s, i) => stages.includes(s) && (!i || stages.indexOf(r.completed[i - 1]) < stages.indexOf(s))) ||
      !publicStrings(r.attention) || !publicStrings(r.next)) throw new Error('Unavailable ordinary join request');
  for (const [stage, field] of [['owner_offered', 'owner_offer_id'], ['owner_selected', 'selection_id'],
    ['administrator_offered', 'administrator_offer_id'], ['owner_finalized', 'owner_finalization_id']]) {
    if (r.completed.includes(stage) !== (r[field] !== '-')) throw new Error('Changed recorded join stages');
  }
  if (r.completed.includes('owner_selected') && !r.selection_approved ||
      r.completed.includes('commit_persisted') && (!r.commit_approved || r.manifest_id === '-') ||
      r.completed.includes('locally_applied') !== (r.state === 'linked') ||
      r.state === 'linked' && (!r.completed.includes('commit_persisted') || r.activation_id === '-' || r.outcome_id === '-') ||
      await hostFor(r.host_public_key) !== host) throw new Error('Changed join request binding');
  return freeze(r);
}
export async function progress(raw, flow, parent, host) {
  const v = JSON.parse(raw), r = v?.request;
  if (!exact(v, 'version host_id flow_id review_id context observed_at outcome request next_participant next_action') ||
      v.version !== 1 || v.host_id !== host || !id(host, 'host') || flow.state !== 'requested' ||
      v.flow_id !== flow.flow_id || v.review_id !== flow.review_id || !same(v.context, context(parent)) ||
      !same(v.outcome, flow.outcome) || !time(v.observed_at)) throw new Error('Unavailable join progress');
  await requestView(r, flow, host);
  if (v.next_participant !== next[r.state][0] || v.next_action !== next[r.state][1]) throw new Error('Changed join progress mapping');
  return freeze(v);
}
export function progressLines(v) {
  const r = v.request, names = ['Request created', 'Owner offer recorded', 'Owner selected', 'Administrator offer recorded',
    'Owner finalization recorded', 'Final commit persisted', 'Local application recorded'];
  return [`Join progress: ${r.state === 'linked' ? 'Local application recorded' : r.state}`,
    `Observed at: ${v.observed_at}`, `Network ID: ${r.network_id}`, `Person public key: ${quoted(r.person_public_key)}`,
    `Host public key: ${quoted(r.host_public_key)}`, `Device public key: ${quoted(r.device_public_key)}`,
    `Recorded stages: ${r.completed.map(s => names[stages.indexOf(s)]).join(', ')}`,
    `Requester owner selection approved: ${r.selection_approved ? 'yes' : 'no'}`,
    `Requester final commit approved: ${r.commit_approved ? 'yes' : 'no'}`, next[r.state][2],
    ...(r.attention.includes('delivery_pending') ? ['Transport: delivery pending. Arrival is not verified.'] : []),
    'Remaining approvals use advanced linking in this preview.',
    'Snapshot only. Current authority, agent access, reachability and model receipt are not verified.'].join('\n');
}
