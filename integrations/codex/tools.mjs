import http from 'node:http';
import { chmod, lstat } from 'node:fs/promises';
export async function toolGateway(socket, threadId, adapter, emit = () => {}) {
  // A previous crashed bridge's private socket may remain. Never unlink an
  // arbitrary file or another account's socket.
  try {
    const stat = await lstat(socket);
    if (!stat.isSocket() || stat.uid !== process.getuid())
      throw new Error('Unexpected Capsule tool socket.');
    throw new Error(
      'A Capsule tool socket already exists; inspect the previous bridge before removing it.'
    );
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const server = http.createServer(async (request, response) => {
    const reply = (status, value) => {
      response.writeHead(status, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify(value));
    };
    if (request.method !== 'POST' || request.url !== '/tool') {
      reply(404, {});
      return;
    }
    try {
      let size = 0;
      const chunks = [];
      for await (const chunk of request) {
        size += chunk.length;
        if (size > 1048576) throw new Error('Tool request too large.');
        chunks.push(chunk);
      }
      const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (value.thread_id !== threadId) {
        reply(403, {});
        return;
      }
      const result = await adapter.callTool(value.name, value.arguments);
      reply(200, result);
      emit({
        type: 'tool_result',
        tool: value.name,
        success: !result.isError,
        content: result.content
      });
    } catch {
      reply(400, {});
    }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 15000;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socket, resolve);
  });
  await chmod(socket, 0o600);
  return {
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(resolve);
      })
  };
}
export async function proxyTool(socket, threadId, name, args) {
  return new Promise((resolve, reject) => {
    const encoded = Buffer.from(JSON.stringify({ thread_id: threadId, name, arguments: args }));
    const request = http.request(
      {
        socketPath: socket,
        path: '/tool',
        method: 'POST',
        agent: false,
        headers: { 'Content-Type': 'application/json', 'Content-Length': encoded.length },
        signal: AbortSignal.timeout(15000)
      },
      (response) => {
        const chunks = [];
        let size = 0;
        response.on('data', (chunk) => {
          size += chunk.length;
          if (size > 1048576) response.destroy();
          else chunks.push(chunk);
        });
        response.on('error', () => reject(new Error('Capsule tool response unavailable.')));
        response.on('end', () => {
          if (response.statusCode !== 200) {
            reject(new Error('This Codex thread is not authorized for this Capsule attachment.'));
            return;
          }
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
          } catch {
            reject(new Error('Invalid Capsule tool response.'));
          }
        });
      }
    );
    request.on('error', () =>
      reject(
        new Error('Capsule bridge unavailable; an uncertain send must be checked with send_status.')
      )
    );
    request.end(encoded);
  });
}
