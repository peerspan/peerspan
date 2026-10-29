// Presentation accepts only the observation contract, never arbitrary CLI text.
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const optionalString = value => value === null || typeof value === 'string';

function session(value) {
  if (!record(value) || typeof value.id !== 'string' || typeof value.integration !== 'string' ||
      !optionalString(value.adapter_id) || !optionalString(value.expires_at) || typeof value.renewable !== 'boolean') return false;
  if (value.adapter_id === null) return value.connection === null && value.expires_at === null && !value.renewable;
  const c = value.connection;
  return record(c) && c.adapter_id === value.adapter_id && c.session_id === value.id &&
    ['registered', 'ready', 'offline', 'detached', 'revoked', 'expired'].includes(c.state) &&
    [null, 'verified', 'unverified'].includes(c.channel) && typeof c.recoverable === 'boolean' &&
    ['lease_expires_at', 'last_seen_at', 'channel_verified_at', 'protocol_version'].every(key => optionalString(c[key]));
}

export function safeName(value) {
  return value
    .replace(/(?:psi2-|psl2-|token_|instance_|peerspan-(?:member-)?invite-v1\.)[A-Za-z0-9_.-]*/g, '[private value]')
    .replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\|$)/g, '')
    .replace(/(?:\u001b\[|\u009b)[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '')
    .slice(0, 80);
}

export function observation(text) {
  const v = JSON.parse(text);
  if (!record(v) || v.version !== 1 || typeof v.host_id !== 'string' ||
      typeof v.observed_at !== 'string' || !Number.isFinite(Date.parse(v.observed_at)) ||
      !['networks', 'agents', 'requests', 'attention'].every(key => Array.isArray(v[key])) ||
      !v.networks.every(n => record(n) && typeof n.id === 'string' && typeof n.name === 'string') ||
      !v.requests.every(r => record(r) && typeof r.request_id === 'string' && typeof r.state === 'string') ||
      !v.agents.every(a => record(a) && typeof a.id === 'string' && typeof a.name === 'string' &&
        Array.isArray(a.sessions) && a.sessions.every(session))) {
    throw new Error('Invalid onboarding observation');
  }
  const connections = v.agents.flatMap(a => a.sessions).map(s => s.connection).filter(Boolean);
  return [
    'Host: running',
    `Networks: ${v.networks.length}`,
    ...v.networks.slice(0, 10).map(n => `  ${safeName(n.name)}`),
    `Local agents: ${v.agents.length}`,
    `Pending connections: ${v.requests.filter(r => r.state === 'pending').length}`,
    `Live adapters: ${connections.filter(c => c.state === 'ready').length}`,
    `Verified adapter channels: ${connections.filter(c => c.state === 'ready' && c.channel === 'verified').length}`,
  ];
}
