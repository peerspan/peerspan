// Wall-clock schedules (contract section 14, MGD-8): weekdays and local times
// in one time zone. Pure functions, used on both threads.

export const DAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];
const TIME = /^([01]\d|2[0-3]):[0-5]\d$/;
const DAY_MS = 86_400_000;
const MINUTE_MS = 60_000;

const formats = new Map();

/** A cached formatter for `timeZone`; throws a RangeError for a zone the runtime does not know. */
function formatter(timeZone) {
  let format = formats.get(timeZone);
  if (!format) {
    format = new Intl.DateTimeFormat('en-US', {
      timeZone,
      hourCycle: 'h23',
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      second: 'numeric'
    });
    if (formats.size > 100) formats.clear();
    formats.set(timeZone, format);
  }
  return format;
}

/** The local wall-clock time at `ms` in `timeZone`, written as if it were UTC. */
function wallClock(ms, timeZone) {
  const parts = {};
  for (const { type, value } of formatter(timeZone).formatToParts(ms)) parts[type] = Number(value);
  return Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second);
}

const offsetAt = (ms, timeZone) => wallClock(ms, timeZone) - Math.floor(ms / 1000) * 1000;

/**
 * The instant at which the local time `wall` (written as UTC) occurs in
 * `timeZone`. A skipped local time moves later by the length of the change; a
 * repeated one takes its first occurrence.
 */
function instantOf(wall, timeZone) {
  const before = offsetAt(wall - DAY_MS, timeZone);
  const after = offsetAt(wall + DAY_MS, timeZone);
  const valid = [...new Set([before, after])]
    .map(offset => wall - offset)
    .filter(instant => wallClock(instant, timeZone) === wall)
    .sort((a, b) => a - b);
  // No valid instant: the clocks skipped this local time; keep the offset in force before the change.
  return valid.length ? valid[0] : wall - before;
}

function invalidSchedule(message) {
  const error = new Error(message);
  error.status = 400;
  return error;
}

/** Validates a schedule request value and returns it normalized: days in week order, times ascending. */
export function normalizeSchedule(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalidSchedule('Invalid schedule');
  const keys = Object.keys(value).sort();
  if (keys.join() !== 'days,timeZone,times') throw invalidSchedule('A schedule has exactly timeZone, days and times');
  const { timeZone, days, times } = value;
  // A name, such as Europe/London or Etc/GMT+12; the runtime also takes bare offsets like +05:30, which are not.
  if (typeof timeZone !== 'string' || timeZone.length < 1 || timeZone.length > 64 || !/^[A-Za-z]/.test(timeZone)) {
    throw invalidSchedule('Invalid schedule time zone');
  }
  try {
    formatter(timeZone);
  } catch {
    throw invalidSchedule('Unknown schedule time zone');
  }
  if (!Array.isArray(days) || days.length < 1 || days.length > 7 || new Set(days).size !== days.length
    || !days.every(day => DAYS.includes(day))) {
    throw invalidSchedule('Schedule days are 1 to 7 distinct names from mon to sun');
  }
  if (!Array.isArray(times) || times.length < 1 || times.length > 24 || new Set(times).size !== times.length
    || !times.every(time => typeof time === 'string' && TIME.test(time))) {
    throw invalidSchedule('Schedule times are 1 to 24 distinct HH:MM times');
  }
  return { timeZone, days: DAYS.filter(day => days.includes(day)), times: [...times].sort() };
}

/**
 * The first slot of `schedule` after `fromMs` (or at it, when `inclusive`), as
 * epoch milliseconds. Every schedule has at least one slot a week, so looking a
 * little over a week ahead always finds one.
 */
export function nextSlot(schedule, fromMs, { inclusive = false } = {}) {
  const { timeZone } = schedule;
  const minutes = schedule.times.map(time => Number(time.slice(0, 2)) * 60 + Number(time.slice(3)));
  const local = new Date(wallClock(fromMs, timeZone));
  let best = null;
  for (let offset = -1; offset <= 8; offset += 1) {
    const date = Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate() + offset);
    // getUTCDay: 0 is Sunday.
    // No time zone is a day away from UTC, so once a slot is known, dates a day past it hold only later ones.
    if (best !== null && date - DAY_MS > best) break;
    if (!schedule.days.includes(DAYS[(new Date(date).getUTCDay() + 6) % 7])) continue;
    for (const minute of minutes) {
      const instant = instantOf(date + minute * MINUTE_MS, timeZone);
      if ((inclusive ? instant >= fromMs : instant > fromMs) && (best === null || instant < best)) best = instant;
    }
  }
  return best;
}
