// Existing OpenCode HTTP backend fixture + actual Capsule plugin execution.
// No model inference: inputs are interpreted only by this explicit fixture.
import http from 'node:http';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import { Capsule } from '../../../integrations/opencode/plugin.mjs';
const [directory, bindings, plugin] = process.argv.slice(2);
const selected = 'ses_' + 'a'.repeat(26),
  foreign = 'ses_' + 'b'.repeat(26),
  messages = [];
let drop = false,
  busy = false,
  permissionDenied = false;
const sessions = new Map([
  [
    selected,
    {
      id: selected,
      directory,
      time: { created: 1 },
      permission: [
        { permission: '*', pattern: '*', action: 'deny' },
        { permission: 'capsule_*', pattern: '*', action: 'allow' }
      ]
    }
  ],
  [foreign, { id: foreign, directory, time: { created: 1 } }]
]);
const hooks = await Capsule({}, { bindings });
const emit = (value) => process.stdout.write(JSON.stringify(value) + '\n');
async function call(name, args, session = selected) {
  return hooks.tool['capsule_' + name].execute(args, {
    sessionID: session,
    ask: async () => {
      if (permissionDenied) throw new Error('permission denied');
    }
  });
}
async function input(text) {
  if (text.includes('External Capsule event:\n')) {
    const event = JSON.parse(text.split('External Capsule event:\n')[1]);
    if (event.meta.kind === 'message')
      await call('reply', {
        delivery_id: event.meta.delivery_id,
        content: 'fixture reply: ' + event.content
      });
    else emit({ type: 'model_output', text: event.content });
  } else if (text.startsWith('send '))
    return await call('send', { destination: 'remote', content: text.slice(5) });
  else if (text === 'destinations') return await call('list_destinations', {});
  else if (text.startsWith('status '))
    return await call('send_status', { request_id: text.slice(7) });
  else if (text === 'invalid')
    return await call('send', { destination: 'remote', content: 'bad', peer_host_id: 'arbitrary' });
}
async function processPending() {
  if (busy) return;
  for (const message of messages.filter((item) => !item.done)) {
    message.done = true;
    await input(message.parts[0].text);
  }
}
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://local'),
    path = url.pathname;
  const reply = (status, value) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(value === undefined ? '' : JSON.stringify(value));
  };
  const getBody = async () => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    return JSON.parse(Buffer.concat(chunks));
  };
  try {
    if (path === '/global/health') {
      reply(200, { healthy: true, version: '1.18.31' });
      return;
    }
    if (url.searchParams.get('directory') !== directory) {
      reply(400, {});
      return;
    }
    if (path === '/config') {
      reply(200, { plugin: [[pathToFileURL(plugin).href, { bindings }]] });
      return;
    }
    if (path === '/experimental/tool/ids') {
      reply(200, Object.keys(hooks.tool));
      return;
    }
    const match = /^\/session\/(ses_[a-z0-9]+)(.*)$/i.exec(path);
    if (!match || !sessions.has(match[1])) {
      reply(404, {});
      return;
    }
    const session = match[1],
      tail = match[2];
    if (!tail && req.method === 'GET') {
      reply(200, sessions.get(session));
      return;
    }
    if (tail === '/message' && req.method === 'GET') {
      reply(200, [
        {
          info: {
            agent: 'original-agent',
            model: { providerID: 'original', modelID: 'original-model' }
          },
          parts: []
        }
      ]);
      return;
    }
    if (tail.startsWith('/message/') && req.method === 'GET') {
      const value = messages.find((item) => item.info.id === tail.slice(9));
      reply(value ? 200 : 404, value);
      return;
    }
    if (tail === '/prompt_async' && req.method === 'POST') {
      const body = await getBody();
      if (body.agent !== 'original-agent' || body.model.providerID !== 'original') {
        reply(400, {});
        return;
      }
      messages.push({ info: { id: body.messageID, sessionID: session }, parts: body.parts });
      if (drop) {
        drop = false;
        req.socket.destroy();
        return;
      }
      reply(204);
      void processPending().catch((error) =>
        emit({ type: 'fixture_error', detail: error.message })
      );
      return;
    }
    // Capsule must not create a session, change settings, install plugins, or
    // answer native approval requests through this API.
    reply(400, {});
  } catch {
    reply(400, {});
  }
});
createInterface({ input: process.stdin }).on('line', async (line) => {
  const control = JSON.parse(line);
  try {
    let result;
    if (control.op === 'input') {
      try {
        result = await input(control.text);
      } catch {
        result = { tool_error: true };
      }
    }
    if (control.op === 'wrong-session') {
      try {
        await call('send', { destination: 'remote', content: 'forbidden' }, foreign);
      } catch {
        result = { blocked: true };
      }
    }
    if (control.op === 'deny') {
      permissionDenied = true;
      try {
        await input('send forbidden');
      } catch {
        result = { blocked: true };
      } finally {
        permissionDenied = false;
      }
    }
    if (control.op === 'busy') {
      busy = control.value;
      if (!busy) await processPending();
    }
    if (control.op === 'drop') drop = true;
    if (control.op === 'inspect')
      result = { session: sessions.get(selected), message_count: messages.length };
    emit({ type: 'control', id: control.id, result });
  } catch (error) {
    emit({ type: 'control', id: control.id, error: error.message });
  }
});
server.listen(0, '127.0.0.1', () =>
  emit({ type: 'ready', session_id: selected, server: 'http://127.0.0.1:' + server.address().port })
);
process.once('SIGTERM', () => {
  server.closeAllConnections();
  server.close(() => process.exit());
});
