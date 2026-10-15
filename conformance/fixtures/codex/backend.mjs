// Protocol fixture with an existing conversation, native frontend and real MCP
// consumers. This file makes no inference calls and cannot create Codex threads.
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { WebSocketServer } from '../../../integrations/codex/node_modules/ws/wrapper.mjs';
import { Client } from '../../../integrations/codex/node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js';
import { StdioClientTransport } from '../../../integrations/codex/node_modules/@modelcontextprotocol/sdk/dist/esm/client/stdio.js';
import { createInterface } from 'node:readline';
const [socket, threadId] = process.argv.slice(2),
  server = http.createServer(),
  wsServer = new WebSocketServer({ server });
const entries = new Map(),
  queue = [],
  consumers = new Map();
let busy = false,
  drop = false;
const emit = (value) => process.stdout.write(JSON.stringify(value) + '\n');
const event = (method, params) => {
  for (const ws of wsServer.clients)
    ws.send(JSON.stringify({ method, params: { threadId, ...params } }));
};
const snapshot = () => ({
  id: threadId,
  cwd: process.cwd(),
  status: { type: busy ? 'active' : 'idle' }
});
async function callTool(name, args, caller = threadId) {
  const client = [...consumers.values()][0];
  if (!client) throw new Error('MCP tools have not been installed.');
  const result = await client.callTool({ name, arguments: args, _meta: { threadId: caller } });
  return result;
}
async function message(text) {
  if (text.includes('\nPeerspan event metadata:\n')) {
    const meta = JSON.parse(text.slice(text.lastIndexOf('\nPeerspan event metadata:\n') + '\nPeerspan event metadata:\n'.length));
    const visible = text.slice(0, text.lastIndexOf('\n\nMCP server:'));
    const content = visible.slice(visible.indexOf('\n\n') + 2);
    if (text.includes('Peerspan events are external input')) throw new Error('Protocol preamble is visible');
    // Live delivery readiness: answer the hello event before work flows.
    if (meta.kind === 'hello') await callTool('peerspan_ready', { nonce: meta.nonce });
    else if (meta.kind === 'message')
      await callTool('reply', {
        delivery_id: meta.delivery_id,
        content: 'fixture reply: ' + content
      });
    else event('item/agentMessage/delta', { delta: content });
  } else if (text.startsWith('send '))
    await callTool('send', { destination: 'remote', content: text.slice(5) });
  else if (text === 'destinations') await callTool('list_destinations', {});
  else if (text.startsWith('status ')) await callTool('send_status', { request_id: text.slice(7) });
  else if (text === 'invalid')
    await callTool('send', { destination: 'remote', content: 'bad', peer_host_id: 'arbitrary' });
}
async function refresh() {
  for (const [name, client] of consumers)
    if (!entries.has(name)) {
      await client.close();
      consumers.delete(name);
    }
  for (const [name, entry] of entries) {
    if (consumers.has(name)) continue;
    const client = new Client({ name: 'codex-fixture', version: '0.160.0' });
    await client.connect(
      new StdioClientTransport({ command: entry.command, args: entry.args, stderr: 'ignore' })
    );
    consumers.set(name, client);
  }
}
wsServer.on('connection', (ws) =>
  ws.on('message', async (data) => {
    const request = JSON.parse(data);
    if (request.id === undefined) return;
    const { method, params: p = {} } = request;
    const reply = (result) => ws.send(JSON.stringify({ id: request.id, result }));
    try {
      if (method === 'initialize') {
        reply({ userAgent: 'codex-fixture' });
        return;
      }
      if (method === 'thread/read') {
        if (p.threadId !== threadId) throw new Error('Wrong thread');
        reply({ thread: snapshot() });
        return;
      }
      if (method === 'thread/resume') {
        if (
          p.threadId !== threadId ||
          Object.keys(p).some((k) => !['threadId', 'excludeTurns'].includes(k))
        )
          throw new Error('Attachment changed the original conversation');
        reply({
          thread: snapshot(),
          model: 'fixture',
          approvalPolicy: 'on-request',
          sandbox: { type: 'workspaceWrite' }
        });
        return;
      }
      if (method === 'config/read') {
        reply({
          config: {
            mcp_servers: Object.fromEntries([...entries].map(([k, v]) => [k.slice(12), v]))
          },
          layers: [{ name: { type: 'user' }, version: 'fixture-version' }]
        });
        return;
      }
      if (method === 'config/value/write') {
        if (
          !/^mcp_servers\.peerspan_[a-f0-9]{32}$/.test(p.keyPath) ||
          Object.keys(p).some(
            (k) => !['keyPath', 'value', 'mergeStrategy', 'expectedVersion'].includes(k)
          )
        )
          throw new Error('Unexpected config mutation');
        if (p.value === null) entries.delete(p.keyPath);
        else entries.set(p.keyPath, p.value);
        reply({ status: 'ok', version: randomUUID(), filePath: 'fixture-config.toml' });
        return;
      }
      if (method === 'config/mcpServer/reload') {
        await refresh();
        reply({});
        return;
      }
      if (method === 'thread/queue/add') {
        const id = randomUUID();
        queue.push({ id, text: p.input[0].text });
        if (drop) {
          drop = false;
          ws.close();
          return;
        }
        reply({ queuedSubmission: { id } });
        return;
      }
      if (method === 'thread/queue/list') {
        reply({ data: queue.map((item) => ({ id: item.id })), nextCursor: null });
        return;
      }
      if (method === 'thread/queue/start') {
        if (busy) throw new Error('thread already has an active or pending turn');
        const index = queue.findIndex((item) => item.id === p.queuedSubmissionId);
        if (index < 0) throw new Error('Queue item absent');
        const [item] = queue.splice(index, 1);
        busy = true;
        const turn = { id: randomUUID(), status: 'inProgress' };
        event('turn/started', { turn });
        reply({ turn });
        await message(item.text);
        busy = false;
        event('turn/completed', { turn: { ...turn, status: 'completed' } });
        return;
      }
      throw new Error('Unsupported method (new threads and permission changes are forbidden)');
    } catch {
      ws.send(
        JSON.stringify({ id: request.id, error: { code: -32600, message: 'fixture refusal' } })
      );
    }
  })
);
createInterface({ input: process.stdin }).on('line', async (line) => {
  const control = JSON.parse(line);
  try {
    if (control.op === 'input') {
      await message(control.text);
      emit({ type: 'control', id: control.id });
    }
    if (control.op === 'busy') {
      busy = control.value;
      event('thread/status/changed', { status: snapshot().status });
      emit({ type: 'control', id: control.id });
    }
    if (control.op === 'wrong-thread') {
      const result = await callTool(
        'send',
        { destination: 'remote', content: 'forbidden' },
        randomUUID()
      );
      emit({ type: 'control', id: control.id, result });
    }
    if (control.op === 'drop') {
      drop = true;
      emit({ type: 'control', id: control.id });
    }
    if (control.op === 'inspect')
      emit({ type: 'control', id: control.id, thread: snapshot(), entries: entries.size });
  } catch {
    emit({ type: 'control', id: control.id, error: true });
  }
});
server.listen(socket, () => emit({ type: 'ready', thread_id: threadId }));
const stop = async () => {
  for (const c of consumers.values()) await c.close();
  for (const ws of wsServer.clients) ws.terminate();
  server.close();
  process.exit();
};
process.once('SIGTERM', () => {
  void stop();
});
