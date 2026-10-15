#!/usr/bin/env python3
"""Test scoped adapter APIs and the real MCP subprocess across Go/Rust peers.

This deterministic MCP client does not run a model. The separate live experiment
uses the same adapter in an authenticated Claude Code session.
"""
import argparse
import concurrent.futures
from datetime import datetime
import hashlib
import json
from pathlib import Path
import queue
import secrets
import sqlite3
import stat
import subprocess
import tempfile
import threading
import time

from host_service import ARTIFACT_TABLES, DELEGATION_TABLES, POLICY_DELIVERY_TABLES, TASK_TABLES, UnixHTTPConnection
from peer_messaging import PeerHost, fixture_context, set_probe, timestamp, wire


def instance_for(host, token):
    if not hasattr(host, '_test_adapter_instances'):
        host._test_adapter_instances = {}
    if token not in host._test_adapter_instances:
        records = sql(host, 'SELECT record FROM adapter_credentials WHERE token_hash=?', (hashlib.sha256(token.encode()).hexdigest(),))
        adapter = json.loads(records[0][0]) if records else {'id':'adapter_'+'0'*32,'session_id':'session_'+'0'*32}
        host._test_adapter_instances[token]={'instance':'instance_'+secrets.token_hex(32),'pid':host.process.pid,'adapter':adapter}
    return host._test_adapter_instances[token]


# Work routes answer 409 until the authorization's channel is verified.
WORK_ROUTES = {'/adapter/v1/next', '/adapter/v1/tasks/next', '/adapter/v1/tasks/cancels/next',
               '/adapter/v1/task-updates/next', '/adapter/v1/replies/next'}


def adapter_call(host, token, method, path, body=None, raw=None, socket_name='adapter.sock',
                 instance=None, auto_connect=True, timeout=3):
    # Raw API calls and the deterministic MCP consumer simulate one test instance.
    # A daemon restart never automatically resumes this raw fixture client.
    owned = instance_for(host, token)
    key = owned['instance'] if instance is None else instance
    if (auto_connect and path.startswith('/adapter/v1/') and path != '/adapter/v1/connect'
            and socket_name == 'adapter.sock' and owned['pid'] == host.process.pid):
        connected = adapter_call(host, token, 'POST', '/adapter/v1/connect',
                                 {'instance_id': key}, instance=key, auto_connect=False)[0]
        # The raw fixture client verifies its channel once, as an adapter does
        # after the model calls peerspan_ready, before it first claims work.
        if connected == 200 and path in WORK_ROUTES and not owned.get('verified'):
            ready = adapter_call(host, token, 'POST', '/adapter/v1/ready', {'nonce': secrets.token_hex(16)},
                                 instance=key, auto_connect=False)[0]
            owned['verified'] = ready == 200
    if path == '/adapter/v1/connect' and body is not None:
        body = {'adapter_id':owned['adapter']['id'],'session_id':owned['adapter']['session_id'], **body}
    conn = UnixHTTPConnection(host.state / socket_name, timeout=timeout)
    try:
        payload = raw if raw is not None else (json.dumps(body) if body is not None else None)
        # Send headers and body in one write: http.client writes a str body
        # separately, and a server that answers early (e.g. 404) and closes can
        # then make the second write fail with a broken pipe.
        if isinstance(payload, str):
            payload = payload.encode()
        headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
        if key: headers['X-Peerspan-Instance'] = key
        conn.request(method, path, payload, headers)
        response = conn.getresponse()
        encoded = response.read()
        try:
            value = json.loads(encoded)
        except json.JSONDecodeError:
            value = encoded.decode()
        if path == '/adapter/v1/connect' and response.status == 200:
            owned['pid'] = host.process.pid
        return response.status, value
    finally:
        conn.close()


def sql(host, statement, args=()):
    # A write that must upgrade a stale read snapshot fails at once while the
    # running daemon commits, so retry briefly.
    for attempt in range(50):
        try:
            with sqlite3.connect(host.state / 'host.db', timeout=10) as conn:
                return conn.execute(statement, args).fetchall()
        except sqlite3.OperationalError as error:
            if 'locked' not in str(error) or attempt == 49:
                raise
            time.sleep(0.1)


def credential(host, session):
    return host.cli('adapter', 'create', '--session', session['id'], '--expires-at', timestamp(1200))


def check_v2_migration(original_binary, replacement_binary, label):
    with tempfile.TemporaryDirectory(prefix='peerspan-adapter-migration-') as directory:
        root = Path(directory)
        sender = PeerHost(original_binary, root / 'sender')
        receiver = PeerHost(original_binary, root / 'receiver')
        try:
            a, b = sender.start(), receiver.start()
            sender.configure(receiver, b)
            receiver.configure(sender, a)
            agent = receiver.cli('agent', 'register', '--name', 'migration', '--owner', 'test')
            grant = receiver.grant(a, agent)
            sent = sender.submit(b, agent, grant)
            messages = receiver.cli('message', 'list')
            activity = receiver.cli('activity')
            receiver.stop()
            for table in [*POLICY_DELIVERY_TABLES, *DELEGATION_TABLES, *ARTIFACT_TABLES, *TASK_TABLES, 'access_blocks', 'network_statements', 'adapter_connections', 'adapter_outbound', 'adapter_routes', 'outbound_replies', 'received_replies', 'deliveries', 'adapter_credentials']:
                sql(receiver, 'DROP TABLE ' + table)
            sql(receiver, 'PRAGMA user_version = 3')
            # Force failure after migration begins; no partial extension may persist.
            sql(receiver, 'CREATE TABLE deliveries (id TEXT PRIMARY KEY)')
            result = subprocess.run([str(replacement_binary), '--state', str(receiver.state), 'run'],
                                    capture_output=True, timeout=5)
            assert result.returncode != 0
            assert sql(receiver, 'PRAGMA user_version')[0][0] == 3
            assert not sql(receiver, "SELECT name FROM sqlite_master WHERE name = 'adapter_credentials'")
            sql(receiver, 'DROP TABLE deliveries')
            receiver.binary = str(replacement_binary)
            identity = receiver.start()
            assert identity['id'] == b['id'] and identity['public_key'] == b['public_key']
            assert sql(receiver, 'PRAGMA user_version')[0][0] == 15
            assert receiver.cli('message', 'list') == messages
            assert receiver.cli('activity') == activity
            assert receiver.cli('grant', 'list') == [grant]
            assert receiver.cli('adapter', 'list') == []
            assert receiver.cli('delivery', 'list') == []
            assert sender.cli('message', 'inspect', '--peer', b['id'], sent['request']['request_id']) == sent
        finally:
            sender.stop(); receiver.stop()
    print(label + ': v3→v11 migration/rollback passed', flush=True)


# Channel meta fields the Claude channel sends as JSON text.
JSON_META = {'cancel_requested', 'artifacts', 'chain_hosts', 'delegable', 'sequence'}


def decoded(params):
    """Check that meta holds only strings, as Claude Code requires, and decode
    the JSON-text fields; null fields are absent."""
    meta = params['meta']
    assert all(isinstance(value, str) for value in meta.values()), meta
    return {**params, 'meta': {key: json.loads(value) if key in JSON_META else value for key, value in meta.items()}}


class Channel:
    def __init__(self, node, script, receiver, secret, directory):
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / 'credential.json'
        self.credential_path = path
        path.write_text(json.dumps({**secret, 'test_instance': instance_for(receiver, secret['token'])['instance']}))
        path.chmod(0o600)
        self.logs = tempfile.TemporaryFile()
        # The launcher supplies the same synthetic instance used by raw fixtures;
        # the production entry point always generates a fresh key in memory.
        launcher = directory / 'test-channel.mjs'
        sdk = script.parent / 'node_modules/@modelcontextprotocol/sdk/dist/esm/server/stdio.js'
        launcher.write_text(
            'import { readCredential, configuredChannel } from ' + json.dumps(script.as_uri()) + ';\n'
            'import { StdioServerTransport } from ' + json.dumps(sdk.as_uri()) + ';\n'
            'const [socket,path] = process.argv.slice(2);\n'
            'const secret = await readCredential(path);\n'
            'const channel = await configuredChannel(socket,path,{instanceId:secret.test_instance,pollMs:50});\n'
            'process.stdin.once("end",()=>{void channel.stop()});\n'
            'await channel.server.connect(new StdioServerTransport());\n')
        self.process = subprocess.Popen([str(node), str(launcher), str(receiver.state / 'adapter.sock'), str(path)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.logs, text=True)
        self.events = queue.Queue()
        self.notifications = []
        self.count = 0
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()
        result = self.call('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
                                         'clientInfo': {'name': 'peerspan-conformance', 'version': '1'}})
        assert result['protocolVersion'] == '2025-11-25'
        assert result['capabilities']['experimental'] == {'claude/channel': {}}
        self.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        self.handshake()

    def handshake(self):
        # Live delivery readiness: answer the hello event with peerspan_ready
        # before any work flows, as a model receiving channel events would.
        hello = self.notification()
        assert hello['meta']['kind'] == 'hello', hello
        ready = self.call('tools/call', {'name': 'peerspan_ready', 'arguments': {'nonce': hello['meta']['nonce']}})
        assert not ready.get('isError') and json.loads(ready['content'][0]['text']) == {'ready': True}, ready

    def read(self):
        try:
            for line in self.process.stdout:
                self.events.put(json.loads(line))
        finally:
            self.events.put(None)

    def send(self, value):
        self.process.stdin.write(json.dumps(value) + '\n')
        self.process.stdin.flush()

    def call(self, method, params, *, seconds=8):
        self.count += 1
        rid = self.count
        self.send({'jsonrpc': '2.0', 'id': rid, 'method': method, 'params': params})
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            event = self.events.get(timeout=max(.01, deadline - time.monotonic()))
            assert event is not None, 'MCP subprocess exited'
            if event.get('id') == rid:
                assert 'error' not in event, event
                return event['result']
            self.notifications.append(event)
        raise AssertionError('MCP response timed out')

    def notification(self):
        for index, event in enumerate(self.notifications):
            if event.get('method') == 'notifications/claude/channel':
                return decoded(self.notifications.pop(index)['params'])
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            event = self.events.get(timeout=max(.01, deadline - time.monotonic()))
            assert event is not None
            if event.get('method') == 'notifications/claude/channel':
                return decoded(event['params'])
            self.notifications.append(event)
        raise AssertionError('channel notification timed out')

    def reply(self, delivery, content, **extra):
        return self.call('tools/call', {'name': 'reply', 'arguments': {
            'delivery_id': delivery, 'content': content, **extra}})

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                raise AssertionError('channel did not stop on stdin close')
        assert self.process.returncode == 0
        self.reader.join(timeout=1)
        self.logs.seek(0)
        output = self.logs.read().decode()
        assert 'token_' not in output
        self.logs.close()


def check(sender_binary, receiver_binary, node, script, label):
    with tempfile.TemporaryDirectory(prefix='peerspan-adapter-') as directory:
        root = Path(directory)
        sender = PeerHost(sender_binary, root / 'sender')
        receiver = PeerHost(receiver_binary, root / 'receiver')
        stranger = PeerHost(sender_binary, root / 'stranger')
        channel = None
        try:
            a, b, c = sender.start(), receiver.start(), stranger.start()
            sender.configure(receiver, b)
            receiver.configure(sender, a)
            receiver.configure(stranger, c)
            agent = receiver.cli('agent', 'register', '--name', 'alice', '--owner', 'alice')
            other = receiver.cli('agent', 'register', '--name', 'other', '--owner', 'alice')
            session = receiver.cli('session', 'attach', '--agent', agent['id'], '--integration', 'claude-channel')
            other_session = receiver.cli('session', 'attach', '--agent', other['id'], '--integration', 'test')
            secret = credential(receiver, session)
            other_secret = credential(receiver, other_session)
            token = secret['token']
            assert len(token) == 70
            assert receiver.cli('adapter', 'inspect', secret['adapter']['id']) == secret['adapter']
            assert all('token' not in item for item in receiver.cli('adapter', 'list'))
            assert sql(receiver, 'SELECT token_hash FROM adapter_credentials WHERE id = ?',
                       (secret['adapter']['id'],))[0][0] == hashlib.sha256(token.encode()).hexdigest()
            assert stat.S_IMODE((receiver.state / 'adapter.sock').stat().st_mode) == 0o600
            assert receiver.call('POST', '/v1/adapters', {'session_id': session['id'], 'expires_at': timestamp()})[0] == 409
            sibling = receiver.cli('session', 'attach', '--agent', agent['id'], '--integration', 'test')
            assert receiver.call('POST', '/v1/adapters', {'session_id': sibling['id'], 'expires_at': timestamp()})[0] == 409
            assert receiver.call('POST', '/v1/adapters', {'session_id': session['id'], 'expires_at': timestamp(-1)})[0] == 400
            assert adapter_call(receiver, '', 'POST', '/adapter/v1/next', {})[0] == 403
            assert adapter_call(receiver, 'token_' + '0' * 64, 'POST', '/adapter/v1/next', {})[0] == 403
            assert adapter_call(receiver, token, 'GET', '/v1/host')[0] == 404
            assert adapter_call(receiver, token, 'POST', '/v1/agents', {'name': 'bad', 'owner': 'bad'})[0] == 404
            assert adapter_call(receiver, token, 'POST', '/adapter/v1/next', {}, socket_name='admin.sock')[0] == 404
            for raw in ['null', '{} {}', '{"extra":true}', '{} trailing', b'{"bad":"\xff"}']:
                assert adapter_call(receiver, token, 'POST', '/adapter/v1/next', raw=raw)[0] == 400

            grant = receiver.grant(a, agent)
            first = sender.submit(b, agent, grant, content='hello from another host — こんにちは')
            rid = first['request']['request_id']
            assert sender.cli('message', 'reply', '--peer', b['id'], rid)['state'] == 'pending'
            channel = Channel(node, script, receiver, secret, root)
            tools = channel.call('tools/list', {})['tools']
            assert [tool['name'] for tool in tools] == ['peerspan_ready', 'mark_seen', 'pending_work', 'list_destinations', 'list_agents', 'send', 'send_status', 'reply', 'task_accept', 'task_reject', 'task_progress', 'task_complete', 'task_cancelled', 'delegate_task', 'task_status', 'artifact_save']
            event = channel.notification()
            assert event['content'] == first['request']['content']
            assert event['meta']['request_id'] == rid
            assert event['meta']['session_id'] == session['id']
            assert event['meta']['sender_host_id'] == a['id']
            # An owner send without --from-agent, from an unbound host.
            for field in ('origin_agent_id', 'origin_session_id', 'sender_person_id', 'sender_person'):
                assert field not in event['meta'], (field, event['meta'])
            delivery = event['meta']['delivery_id']
            deadline = time.monotonic() + 3
            while receiver.cli('delivery', 'inspect', delivery)['state'] == 'unknown':
                assert time.monotonic() < deadline
                time.sleep(.02)
            assert receiver.cli('delivery', 'inspect', delivery)['state'] == 'forwarded'
            assert adapter_call(receiver, other_secret['token'], 'POST', '/adapter/v1/deliveries/' + delivery + '/reply', {'content': 'wrong session'})[0] == 403
            assert channel.reply(delivery, 'response', recipient='arbitrary').get('isError')

            # A reply and its delivery/activity update roll back together.
            sql(receiver, "CREATE TRIGGER fail_reply_event BEFORE INSERT ON events WHEN NEW.kind = 'message.replied' BEGIN SELECT RAISE(ABORT, 'injected failure'); END")
            assert channel.reply(delivery, 'response').get('isError')
            assert sql(receiver, 'SELECT count(*) FROM received_replies')[0][0] == 0
            assert receiver.cli('delivery', 'inspect', delivery)['state'] == 'forwarded'
            sql(receiver, 'DROP TRIGGER fail_reply_event')
            assert not channel.reply(delivery, 'response').get('isError')
            assert not channel.reply(delivery, 'response').get('isError')
            assert channel.reply(delivery, 'changed response').get('isError')
            assert receiver.cli('delivery', 'inspect', delivery)['state'] == 'replied'

            # Persisted sender replies are atomic and restricted to the original sender.
            sql(sender, "CREATE TRIGGER fail_received_reply BEFORE INSERT ON events WHEN NEW.kind = 'reply.received' BEGIN SELECT RAISE(ABORT, 'injected failure'); END")
            sender.cli('message', 'reply', '--peer', b['id'], rid, success=False)
            assert sql(sender, 'SELECT count(*) FROM outbound_replies')[0][0] == 0
            sql(sender, 'DROP TRIGGER fail_received_reply')
            saved = sender.cli('message', 'reply', '--peer', b['id'], rid)
            assert saved['state'] == 'replied' and saved['reply']['content'] == 'response'
            assert saved['reply']['session_id'] == session['id']
            assert saved['reply']['origin'] == {'agent_id': agent['id'], 'session_id': session['id']}, saved
            context = fixture_context(stranger, root)
            assert wire(receiver, context, 'GET', '/peer/v1/replies/' + rid)[0] == 404
            assert wire(receiver, context, 'POST', '/adapter/v1/next', {})[0] == 404
            context = fixture_context(sender, root)
            assert wire(receiver, context, 'GET', '/peer/v1/replies/' + rid)[1] == saved['reply']

            # Concurrent polling must claim a message only once.
            channel.close(); channel = None
            author = sender.cli('agent', 'register', '--name', 'author', '--owner', 'bob')
            second = sender.cli('message', 'send', '--peer', b['id'], '--agent', agent['id'], '--grant', grant['id'],
                                '--deadline', timestamp(), '--content', 'from an agent', '--from-agent', author['id'])
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
                claims = list(executor.map(lambda _: adapter_call(receiver, token, 'POST', '/adapter/v1/next', {}), range(6)))
            assert all(status == 200 for status, _ in claims)
            handed = [value for _, value in claims if value is not None]
            assert len(handed) == 1
            assert handed[0]['request']['origin'] == {'agent_id': author['id']}, handed
            assert handed[0]['sender_person_id'] is None and handed[0]['sender_person'] is None, handed
            uncertain = handed[0]['delivery']
            assert uncertain['state'] == 'unknown'
            assert uncertain['request_id'] == second['request']['request_id']

            # Revocation between durable receipt and handoff blocks content.
            blocked = sender.submit(b, agent, grant)
            receiver.cli('grant', 'revoke', grant['id'])
            assert adapter_call(receiver, token, 'POST', '/adapter/v1/next', {}) == (200, None)
            records = receiver.cli('delivery', 'list')
            assert [r['delivery']['state'] for r in records] == ['replied', 'unknown', 'blocked']
            assert records[-1]['delivery']['request_id'] == blocked['request']['request_id']
            assert adapter_call(receiver, token, 'POST', '/adapter/v1/deliveries/' + uncertain['id'] + '/reply', {'content': 'late'})[0] == 403
            assert wire(receiver, context, 'GET', '/peer/v1/replies/' + rid)[1] == saved['reply']

            # Claim/activity failure must leave the message eligible for a later attempt.
            grant2 = receiver.grant(a, agent, size=10)
            third = sender.submit(b, agent, grant2, content='short')
            sql(receiver, "CREATE TRIGGER fail_handoff BEFORE INSERT ON events WHEN NEW.kind = 'message.handoff' BEGIN SELECT RAISE(ABORT, 'injected failure'); END")
            assert adapter_call(receiver, token, 'POST', '/adapter/v1/next', {})[0] == 500
            assert len(receiver.cli('delivery', 'list')) == 3
            sql(receiver, 'DROP TRIGGER fail_handoff')
            status, handoff = adapter_call(receiver, token, 'POST', '/adapter/v1/next', {})
            assert status == 200 and handoff['request']['request_id'] == third['request']['request_id']
            d3 = handoff['delivery']['id']
            assert adapter_call(receiver, token, 'POST', '/adapter/v1/deliveries/' + d3 + '/reply', {'content': 'x' * 11})[0] == 403
            assert adapter_call(receiver, token, 'POST', '/adapter/v1/deliveries/' + d3 + '/reply', {'content': 'x' * 65537})[0] == 400
            for raw in ['null', '{"content":null}', '{"content":"ok","recipient":"bad"}']:
                assert adapter_call(receiver, token, 'POST', '/adapter/v1/deliveries/' + d3 + '/reply', raw=raw)[0] == 400

            # Expired delivery deadlines are checked again, after wire acceptance.
            expiring = sender.submit(b, agent, grant2, content='short', deadline=timestamp(1))
            time.sleep(1.1)
            assert adapter_call(receiver, token, 'POST', '/adapter/v1/next', {}) == (200, None)
            assert receiver.cli('delivery', 'list')[-1]['delivery']['state'] == 'blocked'
            assert receiver.cli('delivery', 'list')[-1]['delivery']['request_id'] == expiring['request']['request_id']

            # A delivered request may reply after its delivery deadline, while its grant remains valid.
            after_deadline = sender.submit(b, agent, grant2, content='short', deadline=timestamp(1))
            status, handoff = adapter_call(receiver, token, 'POST', '/adapter/v1/next', {})
            assert status == 200 and handoff['request']['request_id'] == after_deadline['request']['request_id']
            time.sleep(1.1)
            assert adapter_call(receiver, token, 'POST', '/adapter/v1/deliveries/' + handoff['delivery']['id'] + '/reply', {'content': 'late'})[0] == 200

            # Credential expiry independently removes local adapter authority.
            expired_agent = receiver.cli('agent', 'register', '--name', 'expiry', '--owner', 'test')
            expired_session = receiver.cli('session', 'attach', '--agent', expired_agent['id'], '--integration', 'test')
            expiring_secret = receiver.cli('adapter', 'create', '--session', expired_session['id'], '--expires-at', timestamp(1))
            time.sleep(1.1)
            assert adapter_call(receiver, expiring_secret['token'], 'GET', '/adapter/v1/session')[0] == 403

            # Credential revocation and session detach each independently stop access.
            receiver.cli('adapter', 'revoke', other_secret['adapter']['id'])
            assert adapter_call(receiver, other_secret['token'], 'POST', '/adapter/v1/next', {})[0] == 403
            other_secret = credential(receiver, other_session)
            receiver.cli('session', 'detach', other_session['id'])
            assert adapter_call(receiver, other_secret['token'], 'POST', '/adapter/v1/next', {})[0] == 403
            pending = sender.submit(b, agent, grant2, content='short')

            # Swap daemon implementations on restart; preserve replies and unknowns.
            receiver.stop(crash=True); sender.stop(crash=True)
            receiver.binary = str(sender_binary)
            sender.binary = str(receiver_binary)
            for actual, expected in [(receiver.start(), b), (sender.start(), a)]:
                assert actual['id'] == expected['id'] and actual['public_key'] == expected['public_key']
                # Compare instants; state written before both used one spelling may differ.
                assert datetime.fromisoformat(actual['created_at'].replace('Z', '+00:00')) == datetime.fromisoformat(expected['created_at'].replace('Z', '+00:00'))
            assert sql(receiver, 'PRAGMA user_version')[0][0] == 15
            assert adapter_call(receiver, token, 'POST', '/adapter/v1/next', {})[0] == 503
            receiver.cli('session', 'detach', session['id'])
            assert receiver.cli('delivery', 'inspect', uncertain['id']) == uncertain
            assert sender.cli('message', 'reply', '--peer', b['id'], rid) == saved
            session2 = receiver.cli('session', 'attach', '--agent', agent['id'], '--integration', 'test')
            secret2 = credential(receiver, session2)
            # Live delivery slice 2: the detached session never saw `third`, so
            # session2 receives it again in place. `uncertain` was also unseen, but
            # its grant is revoked, so its return is blocked rather than redelivered.
            status, handoff = adapter_call(receiver, secret2['token'], 'POST', '/adapter/v1/next', {})
            assert status == 200 and handoff['redelivered'] is True, handoff
            assert handoff['request']['request_id'] == third['request']['request_id'], handoff
            assert handoff['delivery']['id'] == d3 and handoff['delivery']['session_id'] == session2['id']
            status, handoff = adapter_call(receiver, secret2['token'], 'POST', '/adapter/v1/next', {})
            assert status == 200 and handoff['request']['request_id'] == pending['request']['request_id'], handoff
            assert handoff['delivery']['session_id'] == session2['id'] and handoff['redelivered'] is False
            assert adapter_call(receiver, secret2['token'], 'POST', '/adapter/v1/next', {}) == (200, None)
            assert receiver.cli('delivery', 'inspect', uncertain['id'])['state'] == 'blocked'
            assert adapter_call(receiver, secret2['token'], 'POST', '/adapter/v1/deliveries/' + uncertain['id'] + '/forwarded', {})[0] == 403
            receiver.stop()
            # Saved reply inspection requires no live receiver.
            assert sender.cli('message', 'reply', '--peer', b['id'], rid) == saved
        finally:
            if channel: channel.close()
            sender.stop(); receiver.stop(); stranger.stop()
    print(label + ': adapter/MCP conformance passed', flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--node', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True, help='peerspan-peer-probe test client')
    args = parser.parse_args()
    set_probe(args.probe.resolve(strict=True))
    script = Path(__file__).resolve().parents[1] / 'integrations/claude-channel/channel.mjs'
    check_v2_migration(args.go.resolve(), args.rust.resolve(), 'Go→Rust')
    check_v2_migration(args.rust.resolve(), args.go.resolve(), 'Rust→Go')
    for sender, receiver, label in [(args.go, args.go, 'Go→Go'), (args.rust, args.rust, 'Rust→Rust'),
                                     (args.go, args.rust, 'Go→Rust'), (args.rust, args.go, 'Rust→Go')]:
        check(sender.resolve(), receiver.resolve(), args.node.resolve(), script, label)


if __name__ == '__main__':
    main()
