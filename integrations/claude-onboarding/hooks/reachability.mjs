// Public outbound transport evidence only; the host owns authority and peer IO.
import { quoted } from './project.mjs';
import { inspection, liveInspection, decodePublic, personId } from './access.mjs';
import { canonical, freeze } from './invitation.mjs';

const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v, keys) => object(v) && Object.keys(v).sort().join(',') === keys.split(' ').sort().join(',');
const json = v => canonical(v).replace(/[\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/gu,
  c => '\\u' + c.codePointAt(0).toString(16).padStart(4, '0'));

export function deadline(v) {
  const r = v.inspection.review;
  return Math.min(Date.parse(v.observed_at) + 30000, Date.parse(r.owner.host.not_after),
    Date.parse(r.participant.not_after), ...r.participant.hosts.map(h => Date.parse(h.not_after)),
    ...(r.policy ? [Date.parse(r.policy.valid_until)] : []));
}
export function live(v, now) {
  return Number.isFinite(now) && now < deadline(v) &&
    liveInspection({ review: v.inspection.review, observed_at: v.observed_at }, now);
}
export function machines(v) {
  // Section37 has already checked the exact derived remote roster and ordering.
  return freeze(v.readiness.peers.map(p => ({
    host_id: p.host_id, host_public_key: p.host_public_key,
    member: v.inspection.review.participant.hosts.find(h => h.host_public_key === p.host_public_key).member,
  })));
}
export async function snapshot(raw, parent, host, network, selected, target, now) {
  const v = decodePublic(raw, 2 << 20), r = v.reachability;
  if (!exact(v, 'version host_id context observed_at inspection reachability') ||
      !exact(v.inspection, 'review_id review') || parent.state !== 'attached' ||
      !exact(r, 'direction peer_host_id peer_host_public_key result http_status incoming_delivery model_receipt connection_readiness') ||
      r.direction !== 'project_host_to_participant_host' ||
      !['incoming_delivery', 'model_receipt', 'connection_readiness'].every(k => r[k] === 'not_verified') ||
      r.peer_host_id !== target.host_id || r.peer_host_public_key !== target.host_public_key || r.peer_host_id === host ||
      !(r.result === 'authenticated_response' && Number.isSafeInteger(r.http_status) && r.http_status >= 200 && r.http_status <= 599 ||
        r.result === 'not_verified' && r.http_status === null)) throw new Error('Unavailable outbound wrapper');
  await inspection(JSON.stringify({ version: v.version, host_id: v.host_id, context: v.context, observed_at: v.observed_at,
    ...v.inspection, next_action: 'review_agent_access' }), parent, host, network, selected, now);
  const current = v.inspection.review.participant.hosts.filter(h => h.host_public_key === target.host_public_key);
  if (current.length !== 1 || 'host_' + (await personId(target.host_public_key)).slice(7) !== target.host_id ||
      !live(v, now)) throw new Error('Changed outbound machine');
  return freeze(v);
}
export function lines(source, parent, target, value = null, attempted = false) {
  const observed = value ?? source, r = observed.inspection.review;
  const machine = target && (value
    ? r.participant.hosts.find(h => h.host_public_key === target.host_public_key) : target);
  return ['Outbound connection', 'Project: ' + quoted(parent.review.project_root),
    'Agent: ' + quoted(r.agent.name) + ' (' + r.agent.id + ')',
    'Network: ' + quoted(r.network.name) + ' (' + r.network.id + ')',
    'Selected person: ' + quoted(r.participant.member) + ' ' + quoted(r.participant.person_public_key),
    'Project host: ' + observed.host_id,
    ...(target ? ['Machine: ' + quoted(machine.member) + ' (' + target.host_id + ')',
      'Machine public key: ' + quoted(target.host_public_key)] : ['Choose a remote machine. No machine is selected.']),
    ...(value ? ['Observed at: ' + value.observed_at, value.reachability.result === 'authenticated_response'
      ? 'Outbound authenticated response observed (HTTP ' + value.reachability.http_status + ').'
      : 'Outbound connection: not verified'] : [attempted
      ? 'No outbound result is available for this check.' : 'No outbound check has been performed.']),
    'Direction: from this project’s host to the selected person’s machine.',
    'Incoming agent delivery: not verified', 'Model receipt from this observation: not verified',
    'Overall connection readiness: not verified',
    'An authenticated HTTP response does not establish permission or incoming delivery.',
    'Existing adapter and model checks remain separate.'].join('\n');
}
export function details(v, displayDeadline) {
  const r = v.inspection.review;
  return ['Outbound connection details (as observed)', 'Agent metadata: ' + json(r.agent),
    'Network: ' + json(r.network) + '; current root at observation: ' + r.root_state_id,
    'Owner membership: ' + json(r.owner), 'Selected membership: ' + json(r.participant),
    'Signed baseline body: ' + (r.policy ? json(r.policy.body) : 'none retained'),
    'Separately enforced content: ' + (r.policy ? json(r.policy.enforced_content) : 'none retained'),
    ...(r.policy ? ['Policy statement: ' + r.policy.statement_id + '; proof: ' + r.policy.proof_id +
      '; effective end: ' + r.policy.valid_until] : []),
    'Inspection effects: ' + json(r.effects), 'Selected outbound observation: ' + json(v.reachability),
    'Observation display ends: ' + new Date(displayDeadline).toISOString()].join('\n');
}
