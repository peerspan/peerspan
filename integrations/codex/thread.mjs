import { randomUUID } from 'node:crypto';
import { RPCError } from './connection.mjs';
export class ExistingThread {
  constructor(rpc, threadId, { emit = () => {}, onFatal = () => {}, pollMs = 500 } = {}) {
    this.rpc = rpc;
    this.threadId = threadId;
    this.emit = emit;
    this.onFatal = onFatal;
    this.pollMs = pollMs;
    this.pending = [];
    this.busy = false;
    this.pumping = false;
    this.completed = new Set();
    rpc.on('notification', ({ method, params }) => {
      if (params?.threadId !== threadId) return;
      if (method === 'thread/status/changed') this.busy = params.status.type === 'active';
      if (method === 'turn/started') this.busy = true;
      if (method === 'turn/completed') {
        this.completed.add(params.turn.id);
        if (this.completed.size > 100) this.completed.delete(this.completed.values().next().value);
        this.busy = false;
        this.emit({ type: 'turn_complete', turn_id: params.turn.id, status: params.turn.status });
      }
      if (method === 'item/agentMessage/delta')
        this.emit({ type: 'model_delta', text: params.delta });
      if (method === 'thread/closed' || method === 'thread/deleted' || method === 'thread/archived')
        this.onFatal(new Error('Selected Codex thread closed.'));
    });
  }
  async attach() {
    const read = await this.rpc.request('thread/read', {
      threadId: this.threadId,
      includeTurns: false
    });
    if (read.thread?.id !== this.threadId || !['idle', 'active'].includes(read.thread.status?.type))
      throw new Error('Select an already-running Codex thread.');
    // Rejoin the loaded thread with zero settings/history overrides. Native
    // approval requests continue to be handled by the existing desktop/TUI.
    const result = await this.rpc.request('thread/resume', {
      threadId: this.threadId,
      excludeTurns: true
    });
    if (result.thread?.id !== this.threadId)
      throw new Error('Codex attachment changed its thread identity.');
    this.busy = result.thread.status?.type === 'active';
    return result;
  }
  start() {
    this.timer = setInterval(() => {
      void this.pump().catch(this.onFatal);
    }, this.pollMs);
  }
  stop() {
    clearInterval(this.timer);
  }
  async submit(text) {
    const result = await this.rpc.request('thread/queue/add', {
      threadId: this.threadId,
      clientUserMessageId: randomUUID(),
      input: [{ type: 'text', text }]
    });
    const id = result.queuedSubmission?.id;
    if (typeof id !== 'string') throw new Error('Codex returned no queued input identity.');
    this.pending.push(id);
    // Acceptance is Codex's durable queue acknowledgement. Starting work is
    // separate; a busy turn is never interrupted or replaced to deliver input.
    return id;
  }
  async isQueued(id) {
    let cursor;
    do {
      const page = await this.rpc.request('thread/queue/list', {
        threadId: this.threadId,
        limit: 100,
        ...(cursor && { cursor })
      });
      if (!Array.isArray(page.data)) throw new Error('Invalid Codex queue response.');
      if (page.data.some((item) => item.id === id)) return true;
      cursor = page.nextCursor;
    } while (cursor);
    return false;
  }
  async pump() {
    if (this.pumping || this.busy || !this.pending.length) return;
    this.pumping = true;
    try {
      const id = this.pending[0];
      const head = await this.rpc.request('thread/queue/list', {
        threadId: this.threadId,
        limit: 1
      });
      if (!Array.isArray(head.data)) throw new Error('Invalid Codex queue response.');
      if (head.data[0]?.id !== id) {
        if (!(await this.isQueued(id))) this.pending.shift();
        return;
      }
      try {
        const result = await this.rpc.request('thread/queue/start', {
          threadId: this.threadId,
          queuedSubmissionId: id
        });
        if (!result.turn?.id) throw new Error('Codex returned no started turn identity.');
        this.pending.shift();
        this.busy = !this.completed.has(result.turn.id);
      } catch (error) {
        if (!(error instanceof RPCError) || error.code !== -32600) throw error;
        // The native client may have started this queue item, or a new owner
        // turn may have won the race. Never enqueue its content again.
        if (!(await this.isQueued(id))) this.pending.shift();
      }
    } finally {
      this.pumping = false;
    }
  }
}
