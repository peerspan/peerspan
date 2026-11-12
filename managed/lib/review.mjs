// Reviewer agents, rework and workspace branches (contract sections 10.1, 15.1
// and 15.2): the exact inputs the controller sends, the verdict it reads back,
// and the branch line upstream runtime agents end their output with. Pure
// functions only; the model decides when they apply.

// Upstream bounds a task's input to 65,536 bytes of UTF-8 (task contract).
export const INPUT_LIMIT = 65_536;
const NOTE_LIMIT = 2000;
const ELLIPSIS = '…';

const REVIEW_HEADER = [
  'Review the result below, which an agent produced for the assignment that follows it. Decide whether the result does what the assignment asks.',
  'Begin your answer with one line that says exactly VERDICT: ACCEPT or VERDICT: REJECT. Then give your reasons briefly: the operator reads them, and after a rejection the agent may receive them with the assignment.'
];
const REWORK_REQUEST = 'A reviewer rejected your previous result for this assignment. Do the assignment again in full, addressing the review.';
const NO_REASONS = 'The reviewer gave no reasons.';

/**
 * `prefix` followed by `body`, with `body` cut at a character boundary and ended
 * with an ellipsis when the whole would exceed the input limit.
 */
function fit(prefix, body) {
  const whole = prefix + body;
  if (Buffer.byteLength(whole) <= INPUT_LIMIT) return whole;
  const bytes = Buffer.from(body);
  let end = Math.max(0, INPUT_LIMIT - Buffer.byteLength(prefix) - Buffer.byteLength(ELLIPSIS));
  // Step back over UTF-8 continuation bytes (10xxxxxx) to the start of a character.
  while (end > 0 && (bytes[end] & 0xc0) === 0x80) end -= 1;
  return prefix + bytes.subarray(0, end).toString() + ELLIPSIS;
}

/** The review task's input for a result (section 15.1). */
export function reviewInput({ assignment, criteria, output }) {
  const lines = [...REVIEW_HEADER, '', 'ASSIGNMENT', assignment, ''];
  if (criteria !== null) lines.push('CRITERIA', criteria, '');
  lines.push('RESULT', '');
  return fit(lines.join('\n'), output);
}

/** A rework's input: the instructions, the review and the rejected result (section 15.2). */
export function reworkInput({ instructions, note, output }) {
  const prefix = [instructions, '', 'REVISION REQUESTED', REWORK_REQUEST, '', 'REVIEW', note ?? NO_REASONS, '',
    'PREVIOUS RESULT', ''].join('\n');
  return fit(prefix, output);
}

// Section 10.1. Names and errors are counted in characters, so the expressions use the `u` flag.
const NAME = String.raw`[^/\u0000-\u001f\u007f-\u009f]{1,255}`;
const ERROR = String.raw`[^\u0000-\u001f\u007f-\u009f]{1,1024}`;
const BRANCH_FORMS = [
  [/^Branch: none$/u, () => ({ name: null, outcome: 'none', commit: null, from: null, error: null })],
  [new RegExp(`^Branch: (${NAME}) at commit ([0-9a-f]{66})$`, 'u'),
    m => ({ name: m[1], outcome: 'committed', commit: m[2], from: null, error: null })],
  [new RegExp(`^Branch: (${NAME}), unchanged from (${NAME})$`, 'u'),
    m => ({ name: m[1], outcome: 'unchanged', commit: null, from: m[2], error: null })],
  [new RegExp(`^Branch: (${NAME}), not committed: (${ERROR})$`, 'u'),
    m => ({ name: m[1], outcome: 'not_committed', commit: null, from: null, error: m[2] })]
];

/**
 * The branch line that ends `output`, as `{branch, rest}` where `rest` is the
 * output before the empty line that precedes it; null when the output does not
 * end with one of the documented forms.
 */
function splitBranch(output) {
  const text = output.trimEnd();
  const lineStart = text.lastIndexOf('\n') + 1;
  if (lineStart < 2 || text[lineStart - 2] !== '\n') return null;
  const line = text.slice(lineStart);
  for (const [pattern, read] of BRANCH_FORMS) {
    const match = line.match(pattern);
    if (match) return { branch: read(match), rest: text.slice(0, lineStart - 2) };
  }
  return null;
}

/** A run's `branch` from its final output, or null (section 10.1). */
export function branchOf(state, output, truncated) {
  if ((state !== 'succeeded' && state !== 'failed') || truncated || typeof output !== 'string') return null;
  return splitBranch(output)?.branch ?? null;
}

const DECORATION = /^[\s*_#>`.]+|[\s*_#>`.]+$/g;
const VERDICT_LINE = /^verdict: *(accept|reject)$/i;
// Control characters other than LF and tab.
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;

/**
 * The verdict a reviewer agent's output gives, as `{verdict, note}`, or null
 * when its first non-blank line is not a verdict line (section 15.1).
 */
export function readVerdict(output) {
  const text = splitBranch(output)?.rest ?? output;
  const lines = text.split('\n');
  const index = lines.findIndex(line => /\S/.test(line));
  if (index < 0) return null;
  const match = lines[index].replace(DECORATION, '').match(VERDICT_LINE);
  if (!match) return null;
  let note = lines.slice(index + 1).join('\n').replace(CONTROL, '').trim();
  const characters = Array.from(note);
  if (characters.length > NOTE_LIMIT) note = characters.slice(0, NOTE_LIMIT - 1).join('') + ELLIPSIS;
  return { verdict: match[1].toLowerCase() === 'accept' ? 'accepted' : 'rejected', note: note || null };
}
