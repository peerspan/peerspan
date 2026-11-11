// Main-thread facade over the storage worker. Each method is one atomic model
// operation; see model.mjs for what they do.
import { Worker } from 'node:worker_threads';
import { join } from 'node:path';

export const DATABASE_NAME = 'managed.sqlite';

/**
 * Opens the store in `directory`. The listener given to `store.onChange` is
 * called after every operation that changed stored state.
 */
export async function openStore(directory) {
  let onChange = null;
  const worker = new Worker(new URL('./store-worker.mjs', import.meta.url), {
    workerData: { file: join(directory, DATABASE_NAME) }
  });
  const operations = await new Promise((resolve, reject) => {
    worker.once('error', reject);
    worker.once('message', message => {
      if (message.ready) resolve(message.operations);
      else reject(new Error(message.error));
    });
  }).catch(async error => {
    await worker.terminate();
    throw error;
  });

  const pending = new Map();
  let counter = 0;
  let closed = false;
  const failAll = error => {
    for (const request of pending.values()) request.reject(error);
    pending.clear();
  };
  worker.on('message', message => {
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    if (message.error) {
      const error = new Error(message.error.message);
      if (message.error.status) error.status = message.error.status;
      request.reject(error);
      return;
    }
    if (message.changed) onChange?.();
    request.resolve(message.value);
  });
  worker.on('error', failAll);
  worker.on('exit', () => failAll(new Error('Storage worker stopped')));

  const call = (op, args) => new Promise((resolve, reject) => {
    if (closed) {
      reject(new Error('Storage closed'));
      return;
    }
    const id = ++counter;
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, op, args });
  });

  const store = {
    onChange(listener) {
      onChange = listener;
    },
    async close() {
      if (closed) return;
      await call('close', []);
      closed = true;
      await worker.terminate();
    }
  };
  for (const op of operations) store[op] = (...args) => call(op, args);
  return store;
}
