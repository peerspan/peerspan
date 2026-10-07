// Owner-controlled live-test driver; never used by the Capsule integration.
import { Connection } from '../../../integrations/codex/connection.mjs';
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const { socket, requests } = JSON.parse(Buffer.concat(chunks).toString('utf8'));
const rpc = new Connection(socket);
try {
  await rpc.initialize();
  const results = [];
  for (const request of requests) results.push(await rpc.request(request.method, request.params));
  console.log(JSON.stringify(results));
} finally {
  rpc.close();
}
