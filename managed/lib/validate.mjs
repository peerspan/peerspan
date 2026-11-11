// Request validation (contract sections 2, 9 and 10). Unknown fields and
// invalid values are refused with 400 before anything is stored.

const TEXT_LIMITS = { name: 100, instructions: 12_000 };
const INTEGER_RANGES = {
  intervalMinutes: [1, 10_080],
  maxRunsPerDay: [1, 1000],
  acceptanceMinutes: [1, 1440]
};
const EDITABLE = ['name', 'connectionId', 'instructions', 'intervalMinutes', 'maxRunsPerDay', 'acceptanceMinutes'];
const CREATABLE = [...EDITABLE, 'enabled'];
// The store decides whether an ID exists; this only bounds its shape.
const ID = /^[A-Za-z0-9_-]{1,64}$/;

export function invalid(message) {
  const error = new Error(message);
  error.status = 400;
  return error;
}

function checkFields(body, allowed, required) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw invalid('Expected a JSON object');
  const unknown = Object.keys(body).find(key => !allowed.includes(key));
  if (unknown !== undefined) throw invalid('Unexpected workflow fields');
  const fields = {};
  for (const key of allowed) {
    const value = body[key];
    if (value === undefined) {
      if (required.includes(key)) throw invalid('Invalid ' + key);
      continue;
    }
    if (key in TEXT_LIMITS) {
      if (typeof value !== 'string' || !value.trim() || value.length > TEXT_LIMITS[key]) throw invalid('Invalid ' + key);
      fields[key] = key === 'name' ? value.trim() : value;
    } else if (key in INTEGER_RANGES) {
      const [min, max] = INTEGER_RANGES[key];
      if (!Number.isInteger(value) || value < min || value > max) throw invalid('Invalid ' + key);
      fields[key] = value;
    } else if (key === 'connectionId') {
      if (typeof value !== 'string' || !ID.test(value)) throw invalid('Unknown worker connection');
      fields[key] = value;
    } else if (key === 'enabled') {
      if (typeof value !== 'boolean') throw invalid('Invalid enabled flag');
      fields[key] = value;
    }
  }
  return fields;
}

/** A complete workflow definition; paused unless `enabled` is true. */
export function newWorkflow(body) {
  const fields = checkFields(body, CREATABLE, EDITABLE);
  return { ...fields, enabled: fields.enabled ?? false };
}

/** At least one editable field; `enabled` is changed by pause and resume only. */
export function workflowPatch(body) {
  const fields = checkFields(body, EDITABLE, []);
  if (!Object.keys(fields).length) throw invalid('Nothing to change');
  return fields;
}

export function emptyBody(body) {
  if (Object.keys(body).length) throw invalid('Unexpected fields');
}

/** `?before=&limit=` and, for runs, `?workflowId=`. */
export function pageQuery(params, { allowWorkflow = false } = {}) {
  const allowed = allowWorkflow ? ['before', 'limit', 'workflowId'] : ['before', 'limit'];
  for (const key of params.keys()) if (!allowed.includes(key)) throw invalid('Unexpected query parameter');
  const query = { before: null, limit: 50, workflowId: null };
  if (params.has('limit')) {
    const limit = params.get('limit');
    if (!/^\d{1,3}$/.test(limit) || Number(limit) < 1 || Number(limit) > 200) throw invalid('Invalid limit');
    query.limit = Number(limit);
  }
  if (params.has('before')) {
    const before = params.get('before');
    if (!/^\d{1,15}$/.test(before)) throw invalid('Invalid before');
    query.before = Number(before);
  }
  if (params.has('workflowId')) {
    const workflowId = params.get('workflowId');
    if (!ID.test(workflowId)) throw invalid('Invalid workflowId');
    query.workflowId = workflowId;
  }
  return query;
}
