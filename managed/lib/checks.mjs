// Result checks (contract section 15.3, MGD-17): checks the controller applies
// to a succeeded result itself, before any review. Validation of a workflow's
// `resultChecks`, and the checks' outcomes with their exact messages. Pure
// functions only; the model decides when they apply.
import { reasonsNote, splitBranch } from './review.mjs';

function invalid(message) {
  const error = new Error(message);
  error.status = 400;
  return error;
}

const MAX_CHECKS = 8;
const TEXT_LIMIT = 500;
const CHARS_LIMIT = 262_144;
const MAX_KEYS = 16;
const KEY_LIMIT = 100;
const FIELDS = {
  contains: ['text'],
  excludes: ['text'],
  minLength: ['chars'],
  maxLength: ['chars'],
  branch: [],
  jsonKeys: ['keys']
};

/** Characters counted as Unicode code points (contract section 15.1). */
const length = text => {
  let count = 0;
  for (const _ of text) count += 1;
  return count;
};

const isText = value => typeof value === 'string' && length(value) >= 1 && length(value) <= TEXT_LIMIT
  && !value.includes('\u0000') && /\S/u.test(value);
const isKey = value => typeof value === 'string' && length(value) >= 1 && length(value) <= KEY_LIMIT
  && !value.includes('\u0000');

/** One check, rebuilt with its kind first and exactly its kind's fields; throws 400 otherwise. */
function normalizeCheck(check) {
  // The kind must be the string itself: an object key would also match ["contains"] (MGD-17 review).
  if (!check || typeof check !== 'object' || Array.isArray(check) || typeof check.kind !== 'string'
    || !Object.hasOwn(FIELDS, check.kind)) {
    throw invalid('Each result check needs a known kind: contains, excludes, minLength, maxLength, branch or jsonKeys');
  }
  const fields = FIELDS[check.kind];
  if (Object.keys(check).length !== fields.length + 1 || fields.some(field => !Object.hasOwn(check, field))) {
    throw invalid(`A ${check.kind} check has exactly the fields kind${fields.map(field => ', ' + field).join('')}`);
  }
  if (fields[0] === 'text' && !isText(check.text)) {
    throw invalid('A check text is 1 to 500 characters, not only whitespace, without NUL');
  }
  if (fields[0] === 'chars' && !(Number.isInteger(check.chars) && check.chars >= 1 && check.chars <= CHARS_LIMIT)) {
    throw invalid('A length check counts 1 to 262,144 characters');
  }
  if (fields[0] === 'keys') {
    const keys = check.keys;
    if (!Array.isArray(keys) || keys.length < 1 || keys.length > MAX_KEYS || !keys.every(isKey)
      || new Set(keys).size !== keys.length) {
      throw invalid('A jsonKeys check lists 1 to 16 distinct keys of 1 to 100 characters, without NUL');
    }
  }
  return Object.fromEntries([['kind', check.kind], ...fields.map(field => [field, field === 'keys' ? [...check.keys] : check[field]])]);
}

/** A workflow's `resultChecks`, validated (contract section 15.3). */
export function normalizeChecks(value) {
  if (!Array.isArray(value) || value.length > MAX_CHECKS) throw invalid('Result checks are an array of at most 8 checks');
  const checks = value.map(normalizeCheck);
  const longest = Math.min(...checks.filter(check => check.kind === 'maxLength').map(check => check.chars));
  if (checks.some(check => check.kind === 'minLength' && check.chars > longest)) {
    throw invalid('A minimum length above a maximum length can never pass');
  }
  return checks;
}

/** The text a jsonKeys check parses: no branch line, trimmed, out of a code fence. */
function jsonText(result, branch) {
  let text = (branch !== null ? splitBranch(result)?.rest ?? result : result).trim();
  const lines = text.split('\n');
  if (lines.length >= 2 && lines[0].startsWith('```') && lines.at(-1) === '```') {
    text = lines.slice(1, -1).join('\n').trim();
  }
  return text;
}

function parseObject(text) {
  try {
    const value = JSON.parse(text);
    return value !== null && typeof value === 'object' && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

/** The message of a check, or null when it passes. */
function outcome(check, result, branch) {
  switch (check.kind) {
    case 'contains':
      return result.includes(check.text) ? null : `The result does not contain ${JSON.stringify(check.text)}.`;
    case 'excludes':
      return result.includes(check.text) ? `The result contains ${JSON.stringify(check.text)}.` : null;
    case 'minLength': {
      const m = length(result);
      return m >= check.chars ? null : `The result has ${m} characters; at least ${check.chars} are required.`;
    }
    case 'maxLength': {
      const m = length(result);
      return m <= check.chars ? null : `The result has ${m} characters; at most ${check.chars} are allowed.`;
    }
    case 'branch':
      return branch?.outcome === 'committed' ? null : 'The result does not end with a branch line of a commit.';
    case 'jsonKeys': {
      const object = parseObject(jsonText(result, branch));
      if (!object) return 'The result is not a JSON object.';
      const missing = check.keys.filter(key => !Object.hasOwn(object, key));
      return missing.length ? `The result's JSON object lacks ${missing.map(key => JSON.stringify(key)).join(', ')}.` : null;
    }
    default:
      throw new Error('Unknown result check ' + check.kind);
  }
}

/**
 * Applies `checks` to a succeeded run's retained `output` with its `branch`
 * (section 10.1): `[{check, passed, message}]` in the checks' order.
 */
export function applyChecks(checks, output, branch) {
  const result = (output ?? '').replaceAll('\u0000', '');
  return checks.map(check => {
    const message = outcome(check, result, branch);
    return { check, passed: message === null, message };
  });
}

/** The review note of a rejection by checks: the failed messages, treated as a reviewer's reasons. */
export function checksNote(results) {
  return reasonsNote(results.filter(item => !item.passed).map(item => item.message).join('\n'));
}
