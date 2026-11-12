// The controller's clock. Recorded times order runs and activity, so they must
// not run backwards when the system clock is stepped back by a time sync or a
// resumed virtual machine: the controller then keeps the newest time it has
// used until the system clock passes it. A step back of more than the tolerance
// is taken as a deliberate correction and followed, and its moment is kept, so
// that times recorded before it can be read as no later than the correction.
//
// For conformance only, MANAGED_CLOCK_FILE names a file holding a millisecond
// offset that is added to the system clock (contract section 1).
import { readFileSync } from 'node:fs';

const TOLERANCE_MS = 10 * 60 * 1000;
const OFFSET_REREAD_MS = 100;
const OFFSET = /^\s*-?\d{1,15}\s*$/;

let newest = 0;
// When the clock last followed a deliberate correction, in its new time, or null.
let correctedAt = null;
let offset = 0;
let offsetReadAt = -Infinity;

function systemMs() {
  const file = process.env.MANAGED_CLOCK_FILE;
  if (!file) return Date.now();
  const now = performance.now();
  if (now - offsetReadAt >= OFFSET_REREAD_MS) {
    offsetReadAt = now;
    try {
      const text = readFileSync(file, 'utf8');
      offset = OFFSET.test(text) ? Number(text.trim()) : 0;
    } catch {
      offset = 0;
    }
  }
  return Date.now() + offset;
}

export function nowMs() {
  const system = systemMs();
  if (newest - system > TOLERANCE_MS) correctedAt = system;
  newest = newest - system > TOLERANCE_MS ? system : Math.max(system, newest);
  return newest;
}

/** The moment of the latest deliberate correction this process followed, as an RFC 3339 time, or null. */
export const clockCorrectedAt = () => (correctedAt === null ? null : new Date(correctedAt).toISOString());

export const stamp = () => new Date(nowMs()).toISOString();

/** Continues from the newest time already recorded in the store, within the tolerance. */
export function seedClock(iso) {
  const recorded = typeof iso === 'string' ? Date.parse(iso) : NaN;
  if (!Number.isFinite(recorded)) return;
  const system = systemMs();
  // Recorded times further ahead than the tolerance came from before a deliberate correction.
  if (recorded - system <= TOLERANCE_MS) newest = Math.max(newest, recorded);
  else correctedAt = system;
}
