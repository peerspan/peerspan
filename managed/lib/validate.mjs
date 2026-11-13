// Request validation (contract sections 2, 9, 10, 14, 15 and 15.1 to 15.3).
// Unknown fields and invalid values are refused with 400 before anything is
// stored. Rules that depend on stored state, such as whether a reviewer is
// another agent than the worker, are the model's.
import { normalizeChecks } from './checks.mjs';
import { normalizeSchedule } from './schedule.mjs';

const TEXT_LIMITS = { name: 100, instructions: 12_000 };
const INTEGER_RANGES = {
  intervalMinutes: [1, 10_080],
  maxRunsPerDay: [1, 1000],
  acceptanceMinutes: [1, 1440],
  reworkLimit: [0, 3]
};
const REQUIRED = ['name', 'connectionId', 'instructions', 'maxRunsPerDay', 'acceptanceMinutes'];
const EDITABLE = [...REQUIRED, 'intervalMinutes', 'schedule', 'after', 'review', 'reviewerId', 'reviewCriteria',
  'reworkLimit', 'resultChecks', 'approval'];
// A workflow runs on exactly one of these (contract sections 14 and 14.1).
const WHEN = ['intervalMinutes', 'schedule', 'after'];
const CREATABLE = [...EDITABLE, 'enabled'];
const REVIEWS = ['none', 'operator', 'agent'];
const APPROVALS = ['none', 'operator'];
const VERDICTS = ['accepted', 'rejected'];
const NOTE_LIMIT = 2000;
const CRITERIA_LIMIT = 2000;
// The store decides whether an ID exists; this only bounds its shape.
const ID = /^[A-Za-z0-9_-]{1,64}$/;

/** Characters counted as Unicode code points, as agents' notes are cut (contract section 15.1). */
const characters = text => {
  let count = 0;
  for (const _ of text) count += 1;
  return count;
};

export function invalid(message) {
  const error = new Error(message);
  error.status = 400;
  return error;
}

function checkFields(body, allowed, required, { nullSchedule = false } = {}) {
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
      // Instructions travel as one command-line argument, which cannot carry NUL (contract section 2).
      if (key === 'instructions' && value.includes('\u0000')) throw invalid('Instructions cannot contain NUL characters');
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
    } else if (key === 'schedule') {
      // At creation a null schedule is no schedule. In an edit it is refused: setting
      // intervalMinutes is how a schedule is removed.
      if (value === null) {
        if (!nullSchedule) throw invalid('Give a schedule, or set intervalMinutes instead');
        continue;
      }
      fields[key] = normalizeSchedule(value);
    } else if (key === 'after') {
      // As for a schedule: null is no upstream at creation, and refused in an edit (section 14.1).
      if (value === null) {
        if (!nullSchedule) throw invalid('Set intervalMinutes or a schedule to stop running after another workflow');
        continue;
      }
      if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 1
        || typeof value.workflowId !== 'string' || !ID.test(value.workflowId)) {
        throw invalid('after is {"workflowId": ID}, the workflow this one runs after');
      }
      fields[key] = { workflowId: value.workflowId };
    } else if (key === 'review') {
      if (!REVIEWS.includes(value)) throw invalid('Invalid review; use none, operator or agent');
      fields[key] = value;
    } else if (key === 'reviewerId') {
      if (value !== null && (typeof value !== 'string' || !ID.test(value))) throw invalid('Unknown reviewer connection');
      fields[key] = value;
    } else if (key === 'reviewCriteria') {
      // Stored trimmed, with an empty text stored as no criteria (contract section 15.1).
      if (value !== null && (typeof value !== 'string' || characters(value) > CRITERIA_LIMIT)) {
        throw invalid('Review criteria are at most 2,000 characters');
      }
      if (value?.includes('\u0000')) throw invalid('Review criteria cannot contain NUL characters');
      fields[key] = value === null ? null : value.trim() || null;
    } else if (key === 'approval') {
      // Approval before each run (contract section 14.2).
      if (!APPROVALS.includes(value)) throw invalid('Invalid approval; use none or operator');
      fields[key] = value;
    } else if (key === 'resultChecks') {
      fields[key] = normalizeChecks(value);
    }
  }
  if (WHEN.filter(key => fields[key] !== undefined).length > 1) {
    throw invalid('Give one of intervalMinutes, schedule and after, not several');
  }
  return fields;
}

/** A complete workflow definition; paused unless `enabled` is true. */
export function newWorkflow(body) {
  const fields = checkFields(body, CREATABLE, REQUIRED, { nullSchedule: true });
  if (WHEN.every(key => fields[key] === undefined)) {
    throw invalid('Give intervalMinutes, a schedule, or the workflow this one runs after');
  }
  const workflow = { review: 'none', reviewerId: null, reviewCriteria: null, reworkLimit: 0, resultChecks: [], approval: 'none', ...fields };
  // A reviewer exactly when the review is an agent's (contract section 15.1).
  if (workflow.review === 'agent' && workflow.reviewerId === null) throw invalid('Choose the reviewer agent');
  if (workflow.review !== 'agent' && workflow.reviewerId !== null) {
    throw invalid('Only a workflow reviewed by an agent has a reviewer');
  }
  return { ...workflow, enabled: fields.enabled ?? false };
}

/** At least one editable field; `enabled` is changed by pause and resume only. */
export function workflowPatch(body) {
  const fields = checkFields(body, EDITABLE, []);
  if (!Object.keys(fields).length) throw invalid('Nothing to change');
  return fields;
}

/** `{verdict}` or `{verdict, note}`; the note is stored trimmed, an empty one as null. */
export function reviewVerdict(body) {
  if (Object.keys(body).some(key => key !== 'verdict' && key !== 'note')) throw invalid('Unexpected review fields');
  if (!VERDICTS.includes(body.verdict)) throw invalid('Verdict is accepted or rejected');
  let note = null;
  if (body.note !== undefined) {
    if (typeof body.note !== 'string' || characters(body.note) > NOTE_LIMIT) throw invalid('Note is at most 2,000 characters');
    // A note may be sent to the worker with a rework, as part of one command-line argument.
    if (body.note.includes('\u0000')) throw invalid('Note cannot contain NUL characters');
    note = body.note.trim() || null;
  }
  return { verdict: body.verdict, note };
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
