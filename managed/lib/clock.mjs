// The controller's clock. Recorded times order runs and activity, so they must
// not run backwards when the system clock is stepped back by a time sync or a
// resumed virtual machine: the controller then keeps the newest time it has
// used until the system clock passes it. A step back of more than the tolerance
// is taken as a deliberate correction and followed.

const TOLERANCE_MS = 10 * 60 * 1000;

let newest = 0;

export function nowMs() {
  const system = Date.now();
  newest = newest - system > TOLERANCE_MS ? system : Math.max(system, newest);
  return newest;
}

export const stamp = () => new Date(nowMs()).toISOString();

/** Continues from the newest time already recorded in the store, within the tolerance. */
export function seedClock(iso) {
  const recorded = typeof iso === 'string' ? Date.parse(iso) : NaN;
  if (Number.isFinite(recorded) && recorded - Date.now() <= TOLERANCE_MS) newest = Math.max(newest, recorded);
}
