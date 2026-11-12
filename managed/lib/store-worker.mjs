// Storage worker thread: owns the SQLite connection and runs each requested
// model operation synchronously inside one transaction.
import { parentPort, workerData } from 'node:worker_threads';
import { openDatabase } from './schema.mjs';
import { Model } from './model.mjs';

// Every operation the main thread may request, and whether it writes.
const OPERATIONS = new Map(Object.entries({
  listConnections: 'read',
  listObservations: 'read',
  listActivity: 'read',
  listRuns: 'read',
  openTasks: 'read',
  maySubmit: 'read',
  isOpen: 'read',
  runPreview: 'read',
  runDetail: 'read',
  workflowDetail: 'read',
  snapshot: 'read',
  dataVersion: 'read',
  latestTime: 'read',
  addConnection: 'write',
  removeConnection: 'write',
  addObservation: 'write',
  removeObservation: 'write',
  recordReadiness: 'write',
  createWorkflow: 'write',
  editWorkflow: 'write',
  workflowAction: 'write',
  planDispatch: 'write',
  markCancelSent: 'write',
  applyTask: 'write',
  taskProblem: 'write',
  requestCancel: 'write',
  abandonRun: 'write',
  reviewRun: 'write',
  requestReviewCancel: 'write',
  abandonReview: 'write'
}));

let db;
let model;
try {
  db = openDatabase(workerData.file);
  model = new Model(db);
} catch (error) {
  parentPort.postMessage({ ready: false, error: error.message });
}

if (db) {
  const totalChanges = db.prepare('SELECT total_changes() AS count');
  parentPort.on('message', ({ id, op, args }) => {
    try {
      if (op === 'close') {
        db.close();
        parentPort.postMessage({ id, value: true, changed: false });
        return;
      }
      const kind = OPERATIONS.get(op);
      if (!kind) throw new Error('Unknown storage operation');
      const before = totalChanges.get().count;
      db.exec(kind === 'write' ? 'BEGIN IMMEDIATE' : 'BEGIN');
      let value;
      try {
        value = model[op](...args);
        db.exec('COMMIT');
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
      parentPort.postMessage({ id, value, changed: totalChanges.get().count > before });
    } catch (error) {
      parentPort.postMessage({ id, error: { message: error.message, status: error.status ?? null } });
    }
  });
  parentPort.postMessage({ ready: true, operations: [...OPERATIONS.keys()] });
}
