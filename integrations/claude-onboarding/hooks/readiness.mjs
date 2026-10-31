// Current public projections only. The host evaluates permissions and channels.
import { same, quoted } from './project.mjs';
import { connection as adapterConnection } from './adapter.mjs';
import { inspection, liveInspection, decodePublic, personId } from './access.mjs';
import { canonical, freeze } from './invitation.mjs';

const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v, keys) => object(v) && Object.keys(v).sort().join(',') === keys.split(' ').sort().join(',');
const id = (v, kind) => typeof v === 'string' && new RegExp(`^${kind}_[0-9a-f]{32}$`).test(v);
const actions = ['message.append', 'task.submit', 'task.delegate'];
const integer = (v, min, max) => Number.isSafeInteger(v) && v >= min && v <= max;
function time(v, utc = false) {
  if (typeof v !== 'string') return false;
  const m = /^(\d{4}-\d{2}-\d{2})[Tt](\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?([Zz]|[+-]\d{2}:\d{2})$/.exec(v);
  if (!m || utc && m[4] !== 'Z' || !Number.isFinite(Date.parse(v))) return false;
  if (!/^[Zz]$/.test(m[4]) && (+m[4].slice(1, 3) > 23 || +m[4].slice(4) > 59)) return false;
  const base = m[1] + 'T' + m[2], ms = Date.parse(base + 'Z');
  return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 19) === base;
}
function authorization(a) {
  if (!object(a) || !['self', 'policy', 'grant'].includes(a.kind) ||
      !Array.isArray(a.actions) || !a.actions.length || !a.actions.every(x => actions.includes(x)) ||
      !integer(a.max_message_bytes, 1, 65536) || !integer(a.max_artifact_bytes, 0, 1073741824)) return false;
  const base = 'kind actions max_message_bytes max_artifact_bytes';
  if (a.kind === 'self') return exact(a, base) && same(a.actions, actions) &&
    a.max_message_bytes === 65536 && a.max_artifact_bytes === 1073741824;
  if (!(a.from_agent === null || id(a.from_agent, 'agent'))) return false;
  return a.kind === 'policy' ? exact(a, base + ' from_agent') :
    exact(a, base + ' from_agent grant_id expires_at') && id(a.grant_id, 'grant') && a.actions.length === 1 && time(a.expires_at);
}
function entries(list) {
  if (!Array.isArray(list)) return false;
  let previous = -1, self = 0, grant = '';
  for (const a of list) {
    if (!authorization(a)) return false;
    const rank = ['self', 'policy', 'grant'].indexOf(a.kind);
    if (rank < previous || a.kind === 'self' && ++self > 1 || a.kind === 'grant' && a.grant_id <= grant) return false;
    previous = rank;
    if (a.kind === 'grant') grant = a.grant_id;
  }
  return true;
}
export function deadline(v) {
  const r = v.inspection.review, ready = v.readiness;
  return Math.min(Date.parse(v.observed_at) + 30000, Date.parse(r.owner.host.not_after), Date.parse(r.participant.not_after),
    ...r.participant.hosts.map(h => Date.parse(h.not_after)), ...(r.policy ? [Date.parse(r.policy.valid_until)] : []),
    ...ready.peers.flatMap(p => p.authorizations.filter(a => a.kind === 'grant').map(a => Date.parse(a.expires_at))),
    ...ready.adapter_connections.filter(c => c.state === 'ready').map(c => Date.parse(c.lease_expires_at)));
}
export function live(v, now) {
  return Number.isFinite(now) && Date.parse(v.observed_at) <= now + 30000 && now < deadline(v) &&
    liveInspection({ review: v.inspection.review, observed_at: v.observed_at }, now);
}
export async function snapshot(raw, parent, host, network, selected, now) {
  const v = decodePublic(raw, 2 << 20), r = v.readiness;
  if (!exact(v, 'version host_id context observed_at inspection readiness') || parent.state !== 'attached' ||
      !exact(v.inspection, 'review_id review') || !exact(r, 'direction session_id adapter_connections peers peer_reachability model_receipt connection_readiness') ||
      r.direction !== 'participant_hosts_to_project_agent' || r.session_id !== parent.review.session_id ||
      !['peer_reachability', 'model_receipt', 'connection_readiness'].every(k => r[k] === 'not_verified')) throw new Error('Unavailable readiness wrapper');
  await inspection(JSON.stringify({ version: v.version, host_id: v.host_id, context: v.context, observed_at: v.observed_at,
    ...v.inspection, next_action: 'review_agent_access' }), parent, host, network, selected, now);
  if (!Array.isArray(r.peers)) throw new Error('Unavailable readiness machines');
  const expected = [];
  for (const h of v.inspection.review.participant.hosts) {
    const hostId = 'host_' + (await personId(h.host_public_key)).slice(7);
    if (hostId !== host) expected.push({ host_id: hostId, host_public_key: h.host_public_key });
  }
  expected.sort((a, b) => a.host_id < b.host_id ? -1 : 1);
  if (r.peers.length !== expected.length || r.peers.some((p, i) => !exact(p, 'host_id host_public_key authorizations') ||
      p.host_id !== expected[i].host_id || p.host_public_key !== expected[i].host_public_key || !entries(p.authorizations))) throw new Error('Changed readiness machines');
  if (!Array.isArray(r.adapter_connections)) throw new Error('Unavailable readiness connections');
  let previous = '';
  for (const c of r.adapter_connections) {
    if (!id(c?.adapter_id, 'adapter') || c.adapter_id <= previous || !['registered', 'ready', 'offline'].includes(c.state)) throw new Error('Changed readiness connection');
    adapterConnection(c, { review: { adapter_id: c.adapter_id, session_id: parent.review.session_id } });
    if (!['lease_expires_at', 'last_seen_at', 'channel_verified_at'].every(k => c[k] === null || time(c[k], true)) ||
        ['last_seen_at', 'channel_verified_at'].some(k => c[k] !== null && Date.parse(c[k]) > now + 30000) ||
        c.state === 'ready' && (!time(c.last_seen_at, true) || Date.parse(c.lease_expires_at) <= now)) throw new Error('Unavailable readiness time');
    previous = c.adapter_id;
  }
  if (!live(v, now)) throw new Error('Elapsed readiness observation');
  return freeze(v);
}
export function lines(v, parent) {
  const r = v.inspection.review, ready = v.readiness;
  const machines = new Map(r.participant.hosts.map(h => [h.host_public_key, h]));
  const connections = ready.adapter_connections;
  return ['Connection status', `Observed at: ${v.observed_at}`,
    `Project: ${quoted(parent.review.project_root)}`, `Agent: ${quoted(r.agent.name)}`,
    `Network: ${quoted(r.network.name)} (${r.network.id})`,
    `Selected person: ${quoted(r.participant.member)} ${quoted(r.participant.person_public_key)}`,
    'Direction: selected person’s remote machines → this project’s agent.', 'Membership: current at observation.',
    'Receiver-advertised permissions at observation:',
    ...(ready.peers.length ? ready.peers.flatMap(p => [
      `Machine: ${quoted(machines.get(p.host_public_key).member)} (${p.host_id})`,
      ...(p.authorizations.length ? p.authorizations.map(a =>
        `${a.kind}: ${a.actions.join(', ')}; message bytes: ${a.max_message_bytes}; artifact bytes: ${a.max_artifact_bytes}; ` +
        `requester agent: ${a.kind === 'self' || a.from_agent === null ? 'any under this entry' : a.from_agent}` +
        (a.kind === 'grant' ? `; grant: ${a.grant_id}; expires: ${a.expires_at}` : ''))
        : ['No permissions advertised to this machine in this network.']),
    ]) : ['No remote machines for this person in this observation.']),
    ...(connections.length ? connections.map((c, i) => `Local adapter ${i + 1}: ${c.state === 'registered'
      ? 'registered; no live connection observed' : c.state === 'offline' ? 'offline; no live lease observed'
        : c.channel === 'verified' ? 'connected; channel verification observed' : 'connected; incoming channel not verified'} (as observed).`)
      : ['Local adapter: no current credential for this project session.']),
    'Peer reachability: not verified', 'Model receipt from this observation: not verified', 'Overall connection readiness: not verified',
    'Advertised entries do not guarantee acceptance of future work, its body, origin or deadline.',
    'Check connection status refreshes local evidence only. Review agent access to change permissions.',
    'Leave to review the adapter connection and use its separate incoming-delivery check. Existing runtime checks remain separate.'].join('\n');
}
export function details(v) {
  const r = v.inspection.review;
  return ['Connection details (as observed)', `Agent metadata: ${quoted(canonical(r.agent))}`,
    `Network context: ${r.network.context_id}; current root at observation: ${r.root_state_id}`,
    `Owner membership: ${quoted(canonical(r.owner))}`, `Selected membership: ${quoted(canonical(r.participant))}`,
    `Signed baseline body: ${r.policy ? quoted(canonical(r.policy.body)) : 'none retained'}`,
    `Separately enforced content: ${r.policy ? quoted(canonical(r.policy.enforced_content)) : 'none retained'}`,
    ...(r.policy ? [`Policy statement: ${r.policy.statement_id}; proof: ${r.policy.proof_id}; effective end: ${r.policy.valid_until}`] : []),
    ...v.readiness.peers.map(p => `Exact entries for ${p.host_id}: ${quoted(canonical(p.authorizations))}`),
    ...v.readiness.adapter_connections.map((c, i) => `Adapter ${i + 1}: ${quoted(canonical(Object.fromEntries(
      Object.entries(c).filter(([k]) => !['adapter_id', 'session_id'].includes(k)))))}`),
    `Observation display ends: ${new Date(deadline(v)).toISOString()}`].join('\n');
}
