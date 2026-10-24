// Owner-controlled live-test frontend; never used by the Peerspan integration.
// Holds one app-server connection open, as a native client does, so threads it starts stay loaded. Reads one JSON
// request per line on stdin ({id, method, params}) and writes one JSON line per answer ({id, result} or
// {id, error}). Exits when stdin closes.
import { createInterface } from 'node:readline';
import { Connection } from '../../../integrations/codex/connection.mjs';
const rpc = new Connection(process.argv[2]);
await rpc.initialize();
console.log(JSON.stringify({ ready: true }));
for await (const line of createInterface({ input: process.stdin })) {
  if (!line.trim()) continue;
  const { id, method, params } = JSON.parse(line);
  try {
    console.log(JSON.stringify({ id, result: await rpc.request(method, params) }));
  } catch (error) {
    console.log(JSON.stringify({ id, error: { code: error.code ?? null, message: String(error.message ?? error) } }));
  }
}
rpc.close();
