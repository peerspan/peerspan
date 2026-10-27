// Independent, bounded relay4 FIXTURE OPERATOR from the public wire contract.
// It never terminates QUIC or reads inner HTTP/authority. Not a product helper.
// Inputs are fixture-owned operator PEM files and independently pinned PUBLIC
// participant keys; actual daemon private keys are never read or copied.
'use strict';
const fs = require('node:fs');
const tls = require('node:tls');
const crypto = require('node:crypto');

const [configuration] = process.argv.slice(2);
if (!configuration) throw new Error('owned fixture configuration required');
const config = JSON.parse(fs.readFileSync(configuration, 'utf8'));
const allowed = new Set(config.public_keys);
const prefix = Buffer.from('302a300506032b6570032100', 'hex');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const registrations = new Map(), connections = new Set();
let sequence = 0, stopping = false;
function event(value) {
  if (++sequence > 20000) throw new Error('owned fixture observation quota exhausted');
  fs.appendFileSync(config.observations, JSON.stringify({sequence, ...value}) + '\n', {mode:0o600});
}
function send(socket, kind, payload = Buffer.alloc(0), done) {
  if (socket.destroyed || socket.writableLength + payload.length + 3 > 1024 * 1024) { socket.destroy(); return; }
  const head = Buffer.alloc(3); head[0] = kind; head.writeUInt16BE(payload.length, 1);
  socket.write(Buffer.concat([head, payload]), done);
}
const server = tls.createServer({
  key: fs.readFileSync(config.key_file), cert: fs.readFileSync(config.certificate_file),
  requestCert:true, rejectUnauthorized:false, minVersion:'TLSv1.3', maxVersion:'TLSv1.3',
  ALPNProtocols:['peerspan-relay/4'], handshakeTimeout:5000,
}, socket => {
  // TLS CertificateVerify still establishes possession when CA validation is
  // intentionally replaced by the exact independently known Ed25519 pins.
  const certificate = socket.getPeerX509Certificate();
  if (!certificate || socket.alpnProtocol !== 'peerspan-relay/4' || connections.size >= 8) { socket.destroy(); return; }
  const spki = certificate.publicKey.export({type:'spki', format:'der'});
  if (spki.length !== 44 || !spki.subarray(0,12).equals(prefix)) { socket.destroy(); return; }
  const publicKey = spki.subarray(12).toString('base64');
  if (!allowed.has(publicKey)) { socket.destroy(); return; }
  const host = sha(spki.subarray(12));
  const certificatePath = config.certificate_directory + '/' + host + '.pem';
  fs.writeFileSync(certificatePath, certificate.toString(), {mode:0o600});
  event({kind:'actual_tls_host', host, public_key:publicKey, certificate_sha256:sha(certificate.raw)});
  connections.add(socket);socket.setTimeout(60000, () => socket.destroy());
  let buffered = Buffer.alloc(0), state = 'awaiting_auth', expires = 0, leaseTimer;
  const initial = setTimeout(() => socket.destroy(), 5000);
  function cleanup() {
    clearTimeout(initial);clearTimeout(leaseTimer);connections.delete(socket);
    if (registrations.get(host) === socket) registrations.delete(host);
  }
  socket.on('error', () => {});socket.on('close', cleanup);
  socket.on('data', data => {
    // A TLS chunk may contain many complete relay frames. Bound the pending
    // byte stream independently of the single-frame bound checked below.
    if (buffered.length + data.length > 128 * 1024) { socket.destroy(); return; }
    buffered = Buffer.concat([buffered, data]);
    while (buffered.length >= 3 && !socket.destroyed) {
      const kind=buffered[0], length=buffered.readUInt16BE(1);
      if (length > 1532) {socket.destroy();return;}
      if (buffered.length < length+3) return;
      const payload=buffered.subarray(3,length+3);buffered=buffered.subarray(length+3);
      if (state === 'auth_reply_pending' || (state !== 'registered' && kind !== 0)) {socket.destroy();return;}
      if (kind === 0) {
        if (length !== 0) {send(socket,8,Buffer.alloc(0), () => socket.destroy());return;}
        state='auth_reply_pending';
        send(socket,7,Buffer.alloc(0), () => {
          if (socket.destroyed) return;
          const previous=registrations.get(host);registrations.set(host,socket);
          if (previous && previous !== socket) previous.destroy();
          clearTimeout(initial);clearTimeout(leaseTimer);expires=Date.now()+300000;state='registered';
          leaseTimer=setTimeout(() => socket.destroy(),300000);
          event({kind:'auth_ok', host});
        });
      } else if (Date.now() >= expires || registrations.get(host) !== socket) {
        socket.destroy();return;
      } else if (kind === 1 && length >= 33) {
        const destination=payload.subarray(0,32).toString('hex'), datagram=payload.subarray(32);
        const target=registrations.get(destination);
        event({kind:'send', source:host, destination, bytes:datagram.length, opaque_sha256:sha(datagram)});
        if (!target || target.destroyed) send(socket,3,payload.subarray(0,32));
        else {
          send(target,2,Buffer.concat([Buffer.from(host,'hex'),datagram]));
          event({kind:'forward', source:host, destination, bytes:datagram.length, opaque_sha256:sha(datagram)});
        }
      } else if (kind !== 4 || length !== 0) {socket.destroy();return;}
    }
  });
});
server.on('tlsClientError', () => {});
server.on('error', error => { process.stderr.write('owned relay fixture listener failure\n'); process.exitCode=1; });
server.listen(0,'127.0.0.1', () => {
  const address=server.address();
  const publicKey=crypto.createPublicKey(fs.readFileSync(config.key_file)).export({type:'spki',format:'der'}).subarray(12).toString('base64');
  process.stdout.write(JSON.stringify({address:'127.0.0.1:'+address.port, public_key:publicKey})+'\n');
});
process.on('SIGTERM', () => {
  if (stopping) return;stopping=true;
  for (const socket of connections) socket.destroy();
  server.close(() => process.exit(0));
});
