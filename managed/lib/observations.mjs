// Read-only bridge to external controllers (contract section 5). It reads two
// files of a registered directory and returns fixed summaries; it never writes
// there, and no path or unlisted field leaves this module.
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

const MAX_SOURCE_BYTES = 2 * 1024 * 1024;
const STALE_AFTER_MS = 180_000;

const count = value => (Array.isArray(value) ? value.length : Number.isFinite(value) ? value : 0);
// Summaries are short scalars; anything else in the source is not passed on.
const text = value => (typeof value === 'string' ? value.slice(0, 500) : Number.isFinite(value) ? String(value) : null);

async function readJson(directory, name) {
  const text = await readFile(join(directory, name), 'utf8');
  if (text.length > MAX_SOURCE_BYTES) throw new Error('Observation source is too large');
  return JSON.parse(text);
}

async function observe(source) {
  const [config, state] = await Promise.all([
    readJson(source.directory, 'config.json'),
    readJson(source.directory, 'state.json')
  ]);
  const tickedAt = Date.parse(state?.lastTickAt);
  if (typeof config?.enabled !== 'boolean' || typeof state.phase !== 'string' || !Number.isFinite(tickedAt)) {
    throw new Error('Invalid observation source');
  }
  const stale = Date.now() - tickedAt > STALE_AFTER_MS;
  const { task, lastBatch } = state;
  return {
    id: source.id,
    name: source.name,
    available: true,
    enabled: config.enabled,
    cycle: Number.isFinite(state.cycle) ? state.cycle : 0,
    phase: state.phase.slice(0, 500),
    lastTickAt: new Date(tickedAt).toISOString(),
    error: state.error ? 'Source controller reports an error'
      : stale ? 'Source heartbeat is older than three minutes' : null,
    task: task && typeof task === 'object' ? {
      id: text(task.id),
      key: text(task.key),
      state: text(task.status) || text(task.state),
      lane: text(task.lane)
    } : null,
    lastBatch: lastBatch && typeof lastBatch === 'object' ? {
      key: text(lastBatch.key),
      status: text(lastBatch.status),
      articlesAdded: count(lastBatch.articlesAdded),
      dossiersAdded: count(lastBatch.dossiersAdded)
    } : null
  };
}

const unavailable = source => ({
  id: source.id,
  name: source.name,
  available: false,
  enabled: false,
  cycle: 0,
  phase: 'unavailable',
  lastTickAt: null,
  error: 'Observation source is unavailable',
  task: null,
  lastBatch: null
});

/** Current summaries of every registered source; a failing one is unavailable, never healthy. */
export function readObservations(sources) {
  return Promise.all(sources.map(source => observe(source).catch(() => unavailable(source))));
}
