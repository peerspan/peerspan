// Line differences between two results, for "what changed since the previous
// result". Myers' algorithm, bounded: texts too long or too different to
// compare quickly give null instead of freezing the page.

const MAX_LINES = 20_000;
const MAX_EDITS = 1_000;

/**
 * The edit script from `before` to `after` as `[op, line]` pairs, where `op` is
 * `=`, `-` or `+`, in order; or null when the texts are too long or too
 * different to compare.
 */
export function diffLines(before, after) {
  const a = before.split('\n');
  const b = after.split('\n');
  const n = a.length;
  const m = b.length;
  if (n + m > MAX_LINES) return null;
  const max = n + m;
  const offset = max + 1;
  const v = new Int32Array(2 * max + 3);
  // trace[d] is v at the start of step d, for k from -d - 1 to d + 1.
  const trace = [];
  for (let d = 0; d <= Math.min(max, MAX_EDITS); d += 1) {
    trace.push(v.slice(offset - d - 1, offset + d + 2));
    for (let k = -d; k <= d; k += 2) {
      let x = k === -d || (k !== d && v[offset + k - 1] < v[offset + k + 1]) ? v[offset + k + 1] : v[offset + k - 1] + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) {
        x += 1;
        y += 1;
      }
      v[offset + k] = x;
      if (x >= n && y >= m) return backtrack(trace, a, b);
    }
  }
  return null;
}

function backtrack(trace, a, b) {
  const ops = [];
  let x = a.length;
  let y = b.length;
  for (let d = trace.length - 1; d >= 0; d -= 1) {
    const at = k => trace[d][k + d + 1];
    const k = x - y;
    const previousK = k === -d || (k !== d && at(k - 1) < at(k + 1)) ? k + 1 : k - 1;
    const previousX = at(previousK);
    const previousY = previousX - previousK;
    while (x > previousX && y > previousY) {
      ops.push(['=', a[x - 1]]);
      x -= 1;
      y -= 1;
    }
    if (d > 0) {
      if (x === previousX) ops.push(['+', b[y - 1]]);
      else ops.push(['-', a[x - 1]]);
    }
    x = previousX;
    y = previousY;
  }
  return ops.reverse();
}

/**
 * The script with long unchanged stretches folded: `context` lines are kept
 * around each change, and a fold is `['…', count]`.
 */
export function foldUnchanged(ops, context = 2) {
  const keep = ops.map(([op]) => op !== '=');
  const near = keep.map((_, index) => {
    for (let offset = -context; offset <= context; offset += 1) if (keep[index + offset]) return true;
    return false;
  });
  const folded = [];
  let hidden = 0;
  ops.forEach((op, index) => {
    if (near[index]) {
      if (hidden) folded.push(['…', hidden]);
      hidden = 0;
      folded.push(op);
    } else {
      hidden += 1;
    }
  });
  if (hidden) folded.push(['…', hidden]);
  return folded;
}
