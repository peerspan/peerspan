import { privateJSON } from '../shared/provider.mjs';
export class HTTPError extends Error {
  constructor(status) {
    super(`OpenCode request failed (HTTP ${status}).`);
    this.status = status;
  }
}
export function serverURL(value) {
  const url = new URL(value);
  if (
    url.protocol !== 'http:' ||
    !['127.0.0.1', '[::1]'].includes(url.hostname) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== '/'
  )
    throw new Error(
      'Select an existing loopback OpenCode HTTP server, without credentials in its URL.'
    );
  return url.origin;
}
export class Client {
  constructor({ server, directory, auth_file }) {
    this.server = serverURL(server);
    this.directory = directory;
    this.authFile = auth_file;
    this.stop = new AbortController();
  }
  close() {
    this.stop.abort();
  }
  async headers() {
    if (!this.authFile) return {};
    const auth = await privateJSON(this.authFile, 4096);
    if (
      typeof auth.username !== 'string' ||
      !auth.username.length ||
      auth.username.includes(':') ||
      typeof auth.password !== 'string' ||
      !auth.password.length
    )
      throw new Error('Invalid private OpenCode auth file.');
    return {
      Authorization: 'Basic ' + Buffer.from(auth.username + ':' + auth.password).toString('base64')
    };
  }
  async request(method, path, body) {
    const url = new URL(path, this.server);
    url.searchParams.set('directory', this.directory);
    let response;
    try {
      response = await fetch(url, {
        method,
        headers: {
          ...(await this.headers()),
          ...(body !== undefined && { 'Content-Type': 'application/json' })
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: 'error',
        signal: AbortSignal.any([this.stop.signal, AbortSignal.timeout(10000)])
      });
    } catch (error) {
      if (error instanceof HTTPError) throw error;
      throw new Error('Could not confirm the OpenCode request.');
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body ?? []) {
      size += chunk.length;
      if (size > 1048576) {
        await response.body.cancel().catch(() => {});
        throw new Error('OpenCode response exceeds 1 MiB.');
      }
      chunks.push(chunk);
    }
    if (!response.ok) throw new HTTPError(response.status);
    if (response.status === 204) return null;
    try {
      return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      throw new Error('Invalid OpenCode response.');
    }
  }
}
