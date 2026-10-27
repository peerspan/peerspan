#!/usr/bin/env python3
"""Exercise task artifacts (milestone 6 slice 3) with real hosts.

Runs every Go/Rust submitter/receiver pairing with deterministic adapter
consumers and no model calls: raw adapter and local API calls, the CLI, and the
real MCP channel subprocess. Covers artifacts refused under a bound of 0 by
grant and by policy in both directions; inputs fetched, verified, and handed
off only once stored; results fetched by the submitter; the combined bound,
the per-artifact size limit, and manifest validation; a corrupted served file
rejected by digest with the task kept queued; non-party fetches returning 404
and fetches after revocation succeeding; quota refusal with a small
--artifact-quota, and artifact prune; MCP delegate_task, task_complete, and
artifact_save with files on both sides; a restart during pending fetches; a
policy with max_artifact_bytes signed and verified across implementations
with the capped default deadline; and migration from version 9 to 10.
Needs the Go coordinator and peerspan-peer-probe; policy cases need OpenSSH.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from agent_adapter import Channel, adapter_call, credential, instance_for, sql
from support import Coordinator, wait_for
from host_service import LINKING_TABLES, AGENT_CALL_TABLES, APPROVAL_TABLES, BUILTIN_TABLES, DEC_TABLES, OAUTH_TABLES, ARTIFACT_TABLES, CAPABILITY_TABLES, DELEGATION_TABLES, Host, POLICY_DELIVERY_TABLES, POLICY_EDIT_TABLES, SCHEMA_VERSION, UnixHTTPConnection, stop_all
from peer_messaging import PeerHost, fixture_context, set_probe, timestamp, wire
from tasks import (EVENT_KEYS, LOCAL_KEYS, STATUS_KEYS, act, adapter_for, channel_event, claim, events, inspect,
                   task_id, tool, until_state)

ENTRY_KEYS = {'name', 'size', 'sha256', 'media_type'}
LOCAL_ARTIFACT_KEYS = {'direction', 'name', 'size', 'sha256', 'media_type', 'state'}
MAX_SIZE = 104857600
# Fetches back off to a minute while a peer keeps failing.
FETCH = 75


def sha(data):
    return hashlib.sha256(data).hexdigest()


def local_raw(host, method, path, raw=None, timeout=60):
    """One local API call with a raw body; returns status, headers, and bytes."""
    connection = UnixHTTPConnection(host.state / 'admin.sock', timeout=timeout)
    try:
        connection.request(method, path, raw, {'Content-Type': 'application/octet-stream'} if raw is not None else {})
        response = connection.getresponse()
        return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
    finally:
        connection.close()


def oversized_upload(host, size):
    """Stream a body of `size` zero bytes and return the status, tolerating a
    server that answers before reading it all."""
    import socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(120)
    try:
        sock.connect(str(host.state / 'admin.sock'))
        sock.sendall(f'POST /v1/artifacts?name=huge HTTP/1.1\r\nHost: localhost\r\n'
                     f'Content-Type: application/octet-stream\r\nContent-Length: {size}\r\n\r\n'.encode())
        chunk, sent = b'\0' * (1 << 20), 0
        try:
            while sent < size:
                piece = chunk[:min(len(chunk), size - sent)]
                sock.sendall(piece)
                sent += len(piece)
        except (BrokenPipeError, ConnectionResetError):
            pass
        response = b''
        while b'\r\n' not in response:
            data = sock.recv(65536)
            if not data:
                break
            response += data
        return int(response.split(b' ', 2)[1])
    finally:
        sock.close()


def upload(host, name, data, media_type=None, expect=200):
    path = f'/v1/artifacts?name={name}' + (f'&media_type={media_type}' if media_type else '')
    status, _, body = local_raw(host, 'POST', path, data)
    assert status == expect, (path, status, body)
    value = json.loads(body)
    if expect == 200:
        assert set(value) == ENTRY_KEYS and value['size'] == len(data) and value['sha256'] == sha(data), value
        assert value['name'] == name and value['media_type'] == (media_type or 'application/octet-stream'), value
    return value


def adapter_upload(host, token, name, data, expect=200):
    status, value = adapter_call(host, token, 'POST', f'/adapter/v1/artifacts?name={name}', raw=data)
    assert status == expect, (status, value)
    return value


def task_grant(receiver, sender_identity, agent, bound=None):
    args = ['grant', 'create', '--peer', sender_identity['id'], '--agent', agent['id'], '--expires-at',
            timestamp(7200), '--allow-disconnected', '--action', 'task.submit']
    if bound is not None:
        args += ['--max-artifact-bytes', str(bound)]
    grant = receiver.cli(*args)
    assert grant['max_artifact_bytes'] == (bound or 0), grant
    return grant


def submit(sender, receiver_identity, agent, grant=None, files=(), types=(), text='work', tid=None):
    args = ['task', 'submit', '--peer', receiver_identity['id'], '--agent', agent['id'], '--input', text]
    if grant:
        args += ['--grant', grant['id']]
    if tid:
        args += ['--task', tid]
    for path in files:
        args += ['--artifact', str(path)]
    for media_type in types:
        args += ['--artifact-type', media_type]
    out = sender.cli(*args)
    assert set(out) == LOCAL_KEYS, out
    assert all(set(a) == LOCAL_ARTIFACT_KEYS for a in out['artifacts']), out
    return out


def write(directory, name, data):
    path = directory / name
    path.write_bytes(data)
    return path


def states(out):
    return [(a['direction'], a['name'], a['state']) for a in out['artifacts']]


def stored_states(sender, peer, tid, expected, seconds=FETCH):
    return wait_for(lambda: (out := inspect(sender, peer, tid)) and states(out) == expected and out,
                    timeout=seconds, message=f'{tid} artifacts {expected}')


def corrupt(host, digest):
    """Flip the bytes of a stored file, keeping its size; returns a restore function."""
    path = host.state / 'artifacts' / digest
    original = path.read_bytes()
    path.write_bytes(bytes(b ^ 0xff for b in original))
    return lambda: path.write_bytes(original)


def check(sender_binary, receiver_binary, node, script, label):
    with tempfile.TemporaryDirectory(prefix='peerspan-artifacts-') as directory:
        root = Path(directory)
        files = root / 'files'
        files.mkdir()
        sender, receiver = PeerHost(sender_binary, root / 'sender'), PeerHost(receiver_binary, root / 'receiver')
        stranger = PeerHost(sender_binary, root / 'stranger')
        tight = PeerHost(receiver_binary, root / 'tight')
        tight.daemon_args = (*tight.daemon_args, '--artifact-quota', '40')
        hosts = (sender, receiver, stranger, tight)
        channels = []
        try:
            a, b, c, t = sender.start(), receiver.start(), stranger.start(), tight.start()
            sender.configure(receiver, b)
            sender.configure(tight, t)
            sender.configure(stranger, c)
            receiver.configure(sender, a)
            receiver.configure(stranger, c)
            tight.configure(sender, a)
            worker = receiver.cli('agent', 'register', '--name', 'worker', '--owner', 'pat')
            session, secret = adapter_for(receiver, worker)
            token = secret['token']

            # Grants: the bound needs task.submit and is at most 1 GiB.
            receiver.cli('grant', 'create', '--peer', a['id'], '--agent', worker['id'], '--expires-at', timestamp(),
                         '--max-artifact-bytes', '10', success=False)
            receiver.cli('grant', 'create', '--peer', a['id'], '--agent', worker['id'], '--expires-at', timestamp(),
                         '--action', 'task.submit', '--max-artifact-bytes', str(2**30 + 1), success=False)
            assert receiver.call('POST', '/v1/grants', {'requester_host_id': a['id'], 'target_agent_id': worker['id'],
                                                        'expires_at': timestamp(), 'max_message_bytes': 10,
                                                        'allow_disconnected': True, 'max_artifact_bytes': 5})[0] == 400
            zero = task_grant(receiver, a, worker)
            bounded = task_grant(receiver, a, worker, 64)
            assert receiver.cli('grant', 'create', '--peer', a['id'], '--agent', worker['id'], '--expires-at',
                                timestamp(), '--action', 'task.submit', '--max-artifact-bytes',
                                str(2**30))['max_artifact_bytes'] == 2**30

            # Uploads: the manifest entry, and validation.
            entry = upload(sender, 'notes.txt', b'alpha input', 'text/plain')
            for query in ('', '?name=', '?name=a%2Fb', '?name=..', '?name=a&media_type=', '?name=a%00'):
                assert local_raw(sender, 'POST', '/v1/artifacts' + query, b'x')[0] == 400, query
            assert oversized_upload(sender, MAX_SIZE + 1) == 413

            # Artifacts are refused under a bound of 0, in both directions.
            path = write(files, 'notes.txt', b'alpha input')
            refused = submit(sender, b, worker, zero, [path])
            assert refused['submit_state'] == 'rejected' and 'HTTP 403' in refused['error'], refused
            assert refused['artifacts'] == [{'direction': 'input', 'name': 'notes.txt', 'size': 11,
                                             'sha256': entry['sha256'], 'media_type': 'application/octet-stream',
                                             'state': 'stored'}], refused
            assert refused['request']['artifacts'] == [{**entry, 'media_type': 'application/octet-stream'}], refused
            plain = submit(sender, b, worker, zero, text='no files')
            assert plain['artifacts'] == [] and 'artifacts' not in plain['request'], plain
            plain_id = plain['request']['task_id']
            assert claim(receiver, token)['task']['task_id'] == plain_id
            act(receiver, token, plain_id, 'accept')
            result = adapter_upload(receiver, token, 'r.txt', b'result under zero')
            act(receiver, token, plain_id, 'complete', {'status': 'succeeded', 'output': 'x', 'artifacts': [result]},
                expect=403)
            as_sender, as_stranger, as_receiver = fixture_context(sender), fixture_context(stranger), fixture_context(receiver)
            assert wire(receiver, as_sender, 'GET', f'/peer/v1/tasks/{plain_id}')[1]['state'] == 'running'
            done = act(receiver, token, plain_id, 'complete', {'status': 'succeeded', 'output': 'x', 'artifacts': []})
            assert done['state'] == 'succeeded', done
            final = until_state(sender, b, plain_id, 'succeeded')
            assert events(sender, b, plain_id)[-1]['artifacts'] is None and final['artifacts'] == []

            # Inputs are fetched, verified, and handed off only once stored.
            second = write(files, 'data.bin', b'beta data!')
            out = submit(sender, b, worker, bounded, [path, second], ['text/plain'], text='use the files')
            tid = out['request']['task_id']
            assert out['submit_state'] == 'accepted' and out['status']['state'] == 'queued', out
            manifest = out['request']['artifacts']
            assert [(e['name'], e['size'], e['media_type']) for e in manifest] == [
                ('notes.txt', 11, 'text/plain'), ('data.bin', 10, 'application/octet-stream')], manifest
            assert states(out) == [('input', 'notes.txt', 'stored'), ('input', 'data.bin', 'stored')], out
            handoff = wait_for(lambda: claim(receiver, token), timeout=FETCH, message='handoff after fetch')
            assert handoff['task']['task_id'] == tid and handoff['task']['artifacts'] == manifest, handoff
            fetched = [e for e in receiver.cli('activity', '--limit', '1000') if e['kind'] == 'task.artifact_fetched']
            assert {e['subject_id'] for e in fetched} >= {f"{a['id']}/{tid}/{m['sha256']}" for m in manifest}, fetched
            for m, data in zip(manifest, (b'alpha input', b'beta data!')):
                assert adapter_call(receiver, token, 'GET', f"/adapter/v1/tasks/{tid}/artifacts/{m['sha256']}") == (
                    200, data.decode())
            # Peer fetches: only the other party of the task; an unlisted digest is not found.
            status, served = wire(sender, as_receiver, 'GET', f"/peer/v1/tasks/{tid}/artifacts/{manifest[0]['sha256']}")
            assert (status, served) == (200, 'alpha input'), served
            for context, digest in ((as_stranger, manifest[0]['sha256']), (as_receiver, sha(b'unlisted'))):
                assert wire(sender, context, 'GET', f'/peer/v1/tasks/{tid}/artifacts/{digest}')[0] == 404
            assert wire(receiver, as_sender, 'GET', f"/peer/v1/tasks/{tid}/artifacts/{manifest[0]['sha256']}")[0] == 404

            # Results: the combined bound, identical repeats, then fetched by the submitter.
            act(receiver, token, tid, 'accept')
            big = adapter_upload(receiver, token, 'big.bin', b'b' * 44)  # 21 inputs + 44 > 64
            act(receiver, token, tid, 'complete', {'status': 'succeeded', 'output': 'done', 'artifacts': [big]},
                expect=403)
            unstored = {'name': 'u', 'size': 1, 'sha256': sha(b'never uploaded'), 'media_type': 'x/y'}
            act(receiver, token, tid, 'complete', {'status': 'succeeded', 'output': 'done', 'artifacts': [unstored]},
                expect=400)
            report = adapter_upload(receiver, token, 'report.txt', b'gamma result')
            # The submitter's first fetch meets a corrupted file and keeps it pending.
            restore = corrupt(receiver, report['sha256'])
            body = {'status': 'succeeded', 'output': 'done', 'artifacts': [report]}
            completed = act(receiver, token, tid, 'complete', body)
            assert act(receiver, token, tid, 'complete', body) == completed
            act(receiver, token, tid, 'complete', {'status': 'succeeded', 'output': 'done'}, expect=409)
            until_state(sender, b, tid, 'succeeded')
            stored = events(sender, b, tid)
            assert all(set(e) == EVENT_KEYS for e in stored), stored
            assert stored[-1]['artifacts'] == [report] and all(e['artifacts'] is None for e in stored[:-1]), stored
            out_file = root / 'report-copy.txt'
            pending = sender.cli('task', 'artifact', '--peer', b['id'], tid, report['sha256'], '--out', str(out_file),
                                 success=False)
            assert '409' in pending or 'conflict' in pending or 'fetched' in pending, pending
            assert not out_file.exists()
            assert ('result', 'report.txt', 'pending') in states(inspect(sender, b, tid))
            time.sleep(1)
            restore()
            stored_states(sender, b, tid, [('input', 'notes.txt', 'stored'), ('input', 'data.bin', 'stored'),
                                           ('result', 'report.txt', 'stored')])
            saved = sender.cli('task', 'artifact', '--peer', b['id'], tid, report['sha256'], '--out', str(out_file))
            assert saved == {'path': str(out_file), 'sha256': report['sha256'], 'size': 12}, saved
            assert out_file.read_bytes() == b'gamma result'
            sender.cli('task', 'artifact', '--peer', b['id'], tid, report['sha256'], '--out', str(out_file),
                       success=False)
            status, headers, data = local_raw(sender, 'GET', f"/v1/tasks/{b['id']}/{tid}/artifacts/{manifest[1]['sha256']}")
            assert (status, data) == (200, b'beta data!') and headers['content-type'] == 'application/octet-stream'
            assert headers['content-length'] == '10', headers
            assert local_raw(sender, 'GET', f"/v1/tasks/{b['id']}/{tid}/artifacts/{sha(b'x')}")[0] == 404
            # Fetches authorize no new work: they still succeed after revocation.
            receiver.cli('grant', 'revoke', bounded['id'])
            assert wire(receiver, as_sender, 'GET', f"/peer/v1/tasks/{tid}/artifacts/{report['sha256']}") == (
                200, 'gamma result')
            assert wire(receiver, as_stranger, 'GET', f"/peer/v1/tasks/{tid}/artifacts/{report['sha256']}")[0] == 404
            assert wire(sender, as_receiver, 'GET', f"/peer/v1/tasks/{tid}/artifacts/{manifest[1]['sha256']}") == (
                200, 'beta data!')
            bounded = task_grant(receiver, a, worker, 64)

            # Manifest validation and idempotency on the wire.
            raw = {'task_id': task_id(), 'grant_id': bounded['id'], 'target_agent_id': worker['id'],
                   'deadline': timestamp(900), 'input': 'raw', 'artifacts': [entry]}
            status, first = wire(receiver, as_sender, 'POST', '/peer/v1/tasks', raw)
            assert status == 200 and set(first) == STATUS_KEYS, first
            assert wire(receiver, as_sender, 'POST', '/peer/v1/tasks', raw) == (200, first)
            assert wire(receiver, as_sender, 'POST', '/peer/v1/tasks', {**raw, 'artifacts': [{**entry, 'name': 'x'}]})[0] == 409
            assert wire(receiver, as_sender, 'POST', '/peer/v1/tasks', {k: v for k, v in raw.items() if k != 'artifacts'})[0] == 409
            other = {'name': 'other', 'size': 1, 'sha256': sha(b'o'), 'media_type': 'x'}
            for bad in ([], None, [{**entry, 'extra': 1}], [{k: v for k, v in entry.items() if k != 'media_type'}],
                        [{**entry, 'media_type': None}], [{**entry, 'name': 'a/b'}], [{**entry, 'name': '.'}],
                        [{**entry, 'sha256': entry['sha256'].upper()}], [{**entry, 'size': MAX_SIZE + 1}],
                        [{**entry, 'size': -1}], [{**entry, 'media_type': ''}], [entry, {**other, 'name': entry['name']}],
                        [entry, {**other, 'sha256': entry['sha256']}],
                        [{**other, 'name': f'n{i}', 'sha256': sha(bytes([i]))} for i in range(65)]):
                assert wire(receiver, as_sender, 'POST', '/peer/v1/tasks', {**raw, 'task_id': task_id(), 'artifacts': bad})[0] == 400, bad
            over = {**other, 'size': 65}
            assert wire(receiver, as_sender, 'POST', '/peer/v1/tasks', {**raw, 'task_id': task_id(), 'artifacts': [over]})[0] == 403
            # Content the receiver already stores needs no fetch: the raw task is ready at once.
            ready = claim(receiver, token)
            assert ready['task']['task_id'] == raw['task_id'] and ready['task']['artifacts'] == [entry], ready
            act(receiver, token, raw['task_id'], 'reject', {'reason': 'raw'})
            # Locally, every entry must be a stored upload of that size and digest.
            local = {'peer_host_id': b['id'], 'grant_id': bounded['id'], 'target_agent_id': worker['id'], 'input': 'x'}
            for bad in ([other], [{**entry, 'size': 12}]):
                assert sender.call('POST', '/v1/tasks', {**local, 'artifacts': bad})[0] == 400, bad

            # A corrupted served input is rejected by digest: the task stays queued.
            fragile = upload(sender, 'fragile.txt', b'delta fragile')
            restore = corrupt(sender, fragile['sha256'])
            status, queued = sender.call('POST', '/v1/tasks', {**local, 'input': 'fragile', 'artifacts': [fragile]})
            assert status == 200 and queued['submit_state'] == 'accepted', queued
            fragile_id = queued['request']['task_id']
            time.sleep(3)
            assert claim(receiver, token) is None
            assert wire(receiver, as_sender, 'GET', f'/peer/v1/tasks/{fragile_id}')[1]['state'] == 'queued'
            assert not (receiver.state / 'artifacts' / fragile['sha256']).exists()
            assert adapter_call(receiver, token, 'GET', f"/adapter/v1/tasks/{fragile_id}/artifacts/{fragile['sha256']}")[0] in (403, 404)
            # A restart during the pending fetch resumes it.
            receiver.stop()
            restore()
            receiver.start()
            adapter_call(receiver, token, 'POST', '/adapter/v1/connect', {'instance_id': instance_for(receiver, token)['instance']},
                         auto_connect=False)
            handoff = wait_for(lambda: claim(receiver, token), timeout=FETCH, message='handoff after restart')
            assert handoff['task']['task_id'] == fragile_id and handoff['task']['artifacts'] == [fragile], handoff
            act(receiver, token, fragile_id, 'reject', {'reason': 'enough'})
            until_state(sender, b, fragile_id, 'rejected')

            # Quota: a receiver without room answers 507, and the submitter retries.
            tight_worker = tight.cli('agent', 'register', '--name', 'worker', '--owner', 'pat')
            tight_grant = task_grant(tight, a, tight_worker, 1000)
            filler = upload(tight, 'filler', b'f' * 30)
            assert local_raw(tight, 'POST', '/v1/artifacts?name=more', b'm' * 11)[0] == 507
            heavy = write(files, 'heavy.bin', b'h' * 20)
            waiting = submit(sender, t, tight_worker, tight_grant, [heavy])
            assert waiting['submit_state'] == 'unknown' and '507' in waiting['error'], waiting
            listed = tight.cli('artifact', 'list')
            assert listed['quota'] == 40 and listed['stored_bytes'] == 30 and listed['pending_bytes'] == 0, listed
            assert [(f['sha256'], f['size'], f['tasks']) for f in listed['files']] == [(filler['sha256'], 30, 0)], listed
            assert listed['files'][0]['upload_until'] is not None, listed
            pruned = tight.cli('artifact', 'prune')
            assert pruned == {'files_deleted': 1, 'bytes_freed': 30}, pruned
            assert tight.cli('artifact', 'list')['files'] == []
            accepted = wait_for(lambda: (r := inspect(sender, t, waiting['request']['task_id']))['submit_state'] == 'accepted' and r,
                                timeout=FETCH, message='retry after 507')
            assert accepted['attempts'] >= 2, accepted
            assert any(e['kind'] == 'artifact.pruned' and e['subject_id'] == filler['sha256']
                       for e in tight.cli('activity', '--limit', '1000'))

            # artifact prune releases every final task now; the active one keeps its files.
            before = sender.cli('artifact', 'list')
            assert before['quota'] == 10 * 2**30 and before['stored_bytes'] > 0, before
            result_pruned = sender.cli('artifact', 'prune')
            assert result_pruned['files_deleted'] >= 3, result_pruned
            assert [s for _, _, s in states(inspect(sender, b, tid))] == ['pruned'] * 3
            assert sender.cli('task', 'artifact', '--peer', b['id'], tid, report['sha256'], '--out',
                              str(root / 'gone'), success=False)
            assert wire(sender, as_receiver, 'GET', f"/peer/v1/tasks/{tid}/artifacts/{manifest[0]['sha256']}")[0] == 404
            heavy_sha = sha(b'h' * 20)
            assert [f['sha256'] for f in sender.cli('artifact', 'list')['files']] == [heavy_sha]
            assert any(e['kind'] == 'artifact.pruned' for e in sender.cli('activity', '--limit', '1000'))

            if node:
                check_mcp(sender, receiver, a, b, node, script, root, channels)
        finally:
            for channel in channels:
                channel.close()
            stop_all(hosts)
    print(f'PASS {label}: bound 0 refusals both ways, fetched and verified inputs gating handoff, results fetched '
          'by the submitter, combined bound, size limit, manifest validation, corruption rejected, non-party 404, '
          'fetch after revocation, quota 507 with retry, prune and list, restart resuming fetches'
          + (', MCP files on both sides' if node else ''), flush=True)


def check_mcp(sender, receiver, a, b, node, script, root, channels):
    """delegate_task, task_complete, and artifact_save with files through the real MCP subprocess."""
    helper = receiver.cli('agent', 'register', '--name', 'helper', '--owner', 'pat')
    delegator = sender.cli('agent', 'register', '--name', 'delegator', '--owner', 'quinn')
    grant = task_grant(receiver, a, helper, 1000)
    _, helper_secret = adapter_for(receiver, helper, 'claude-channel')
    _, delegator_secret = adapter_for(sender, delegator, 'claude-channel')
    sender.cli('adapter', 'route', 'add', '--adapter', delegator_secret['adapter']['id'], '--name', 'helper',
               '--peer', b['id'], '--agent', helper['id'], '--grant', grant['id'], '--action', 'task.submit',
               '--expires-at', timestamp(900))
    worker = Channel(node, script, receiver, helper_secret, root / 'helper-channel')
    channels.append(worker)
    origin = Channel(node, script, sender, delegator_secret, root / 'delegator-channel')
    channels.append(origin)
    workspace = root / 'mcp'
    workspace.mkdir()
    question = write(workspace, 'question.md', b'# what is in here?')
    failed, submitted = tool(origin, 'delegate_task', {'destination': 'helper', 'input': 'read the file',
                                                      'artifacts': [str(question)]})
    assert not failed and submitted['submit_state'] == 'accepted', submitted
    tid = submitted['task_id']
    assert [x['name'] for x in submitted['artifacts']] == ['question.md'], submitted
    failed, missing = tool(origin, 'delegate_task', {'destination': 'helper', 'input': 'x',
                                                    'artifacts': [str(workspace / 'absent')]})
    assert failed, missing
    task = channel_event(worker, 'task')
    assert task['meta']['task_id'] == tid, task
    entries = task['meta']['artifacts']
    assert [(x['name'], x['size'], x['sha256']) for x in entries] == [('question.md', 18, sha(b'# what is in here?'))], task
    copy = workspace / 'received.md'
    failed, saved = tool(worker, 'artifact_save', {'task_id': tid, 'sha256': entries[0]['sha256'], 'path': str(copy)})
    assert not failed and saved['size'] == 18 and copy.read_bytes() == b'# what is in here?', saved
    failed, exists = tool(worker, 'artifact_save', {'task_id': tid, 'sha256': entries[0]['sha256'], 'path': str(copy)})
    assert failed and 'exists' in json.dumps(exists), exists
    assert not tool(worker, 'task_accept', {'task_id': tid})[0]
    answer = write(workspace, 'answer.txt', b'a heading and a question')
    failed, done = tool(worker, 'task_complete', {'task_id': tid, 'status': 'succeeded', 'output': 'see the file',
                                                  'artifacts': [str(answer)]})
    assert not failed and done['state'] == 'succeeded', done
    update = channel_event(origin, 'task_update')
    while update['meta']['state'] != 'succeeded':
        assert 'artifacts' not in update['meta'], update
        update = channel_event(origin, 'task_update')
    results = update['meta']['artifacts']
    assert [(x['name'], x['sha256']) for x in results] == [('answer.txt', sha(b'a heading and a question'))], update
    target = workspace / 'answer-copy.txt'

    def save():
        failed, value = tool(origin, 'artifact_save', {'task_id': tid, 'sha256': results[0]['sha256'], 'path': str(target)})
        assert not failed or 'fetched' in json.dumps(value), value
        return not failed and value
    saved = wait_for(save, timeout=FETCH, message='MCP result save')
    assert saved['size'] == 24 and target.read_bytes() == b'a heading and a question', saved
    # Another task's digest, or another session's task, is not found.
    failed, absent = tool(origin, 'artifact_save', {'task_id': task_id(), 'sha256': results[0]['sha256'],
                                                    'path': str(workspace / 'none')})
    assert failed and not (workspace / 'none').exists(), absent


def rfc3339(moment):
    return moment.strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_time(value):
    """An RFC3339 UTC time, to the second."""
    return datetime.fromisoformat(value.rstrip('Z').partition('.')[0]).replace(tzinfo=timezone.utc)


def policy_check(coord_binary, owner_binary, sender_binary, label):
    """max_artifact_bytes in an owner policy, signed by one implementation and verified by the other."""
    from persons import Agent, ssh_key, use_agent
    from policy import PolicyHost, crafted, policy_lines
    with tempfile.TemporaryDirectory(prefix='peerspan-artifact-policy-') as temporary:
        root = Path(temporary)
        coord = Coordinator(coord_binary, root / 'coord')
        alice, bob = PolicyHost(owner_binary, root / 'alice'), PolicyHost(sender_binary, root / 'bob')
        hosts = (alice, bob)
        (root / 'keys').mkdir()
        keys = {name: ssh_key(root / 'keys', name) for name in ('pat', 'quinn')}
        agents = {}
        saved_sock = os.environ.get('SSH_AUTH_SOCK')
        try:
            for name in keys:
                (root / f'agent-{name}').mkdir()
                agents[name] = Agent(root / f'agent-{name}')
                agents[name].add(keys[name][0])
            coordinator = coord.start()
            ids = {host: host.start() for host in hosts}
            use_agent(agents['pat'])
            net = alice.cli('network', 'create', '--name', 'team', '--member', 'pat', '--coordinator', coord.address,
                            '--coordinator-key', coordinator['public_key'])['id']
            invite = alice.cli('network', 'invite', '--network', net, '--member', 'quinn', '--expires-at', timestamp())
            use_agent(agents['quinn'])
            assert bob.cli('network', 'join', '--token', invite['token'])['person']['bound']
            for host in hosts:
                host.cli('network', 'sync', net)
            reviewer = alice.cli('agent', 'register', '--name', 'reviewer', '--owner', 'pat')
            session = alice.cli('session', 'attach', '--agent', reviewer['id'], '--integration', 'test')
            token = credential(alice, session)['token']
            a = ids[alice]
            files = root / 'files'
            files.mkdir()
            small, large = write(files, 'small.txt', b'policy input'), write(files, 'large.txt', b'L' * 101)

            use_agent(agents['pat'])
            # The bound needs task.submit.
            alice.cli('access', 'allow', '--network', net, '--agent', 'reviewer', '--principal', 'network',
                      '--max-artifact-bytes', '100', success=False)
            alice.cli('access', 'allow', '--network', net, '--agent', 'reviewer', '--principal', 'network',
                      '--action', 'task.submit', '--max-artifact-bytes', str(2**30 + 1), success=False)
            # Without a bound, a task.submit rule refuses artifacts.
            v1 = alice.cli('access', 'allow', '--network', net, '--agent', 'reviewer', '--principal', 'network',
                           '--action', 'task.submit', '--allow-disconnected')
            assert 'max_artifact_bytes' not in v1['rules'][0], v1
            bob.cli('network', 'sync', net)
            refused = submit(bob, a, reviewer, files=[small])
            assert refused['submit_state'] == 'rejected' and 'HTTP 403' in refused['error'], refused
            # A bound signed by the owner and verified by the sender's host and the coordinator.
            v2 = alice.cli('access', 'allow', '--network', net, '--agent', 'reviewer', '--principal', 'network',
                           '--action', 'message.append', '--action', 'task.submit', '--max-artifact-bytes', '100',
                           '--allow-disconnected')
            assert v2['rules'][0]['max_artifact_bytes'] == 100 and v2['version'] == 2, v2
            lines = policy_lines(v2)
            # The rule's fifth line (a v2 statement, signed since database version 16, ends with the `trusted` and
            # `edits` lines).
            assert lines[lines.index('rule', 6) + 4] == '65536 true 100', lines
            bob.cli('network', 'sync', net)
            shown = bob.cli('access', 'show', '--network', net, '--person', 'pat')
            assert shown['version'] == 2 and shown['rules'] == v2['rules'], shown
            accepted = submit(bob, a, reviewer, files=[small])
            assert accepted['submit_state'] == 'accepted', accepted
            assert submit(bob, a, reviewer, files=[large])['submit_state'] == 'rejected'
            handoff = wait_for(lambda: claim(alice, token), timeout=FETCH, message='policy handoff')
            assert handoff['task']['artifacts'][0]['size'] == 12, handoff
            act(alice, token, handoff['task']['task_id'], 'accept')
            result = adapter_upload(alice, token, 'answer.txt', b'R' * 88)  # 12 + 88 = 100
            act(alice, token, handoff['task']['task_id'], 'complete',
                {'status': 'succeeded', 'output': 'ok', 'artifacts': [result]})

            # The default deadline is capped at a cited policy's valid_until.
            now = datetime.now(timezone.utc).replace(microsecond=0)
            # A renewal of v2 with a short window: v2 and copying `edits`, so that alice's edit stays reflected
            # (coordination contract, Concurrent edits).
            soon = crafted(v2, 3, now - timedelta(hours=23, minutes=30), now + timedelta(minutes=30), keys['pat'][0],
                           root)
            status, stored = bob.call('POST', f'/v1/networks/{net}/policy', {'policy': soon})
            assert status == 201, stored
            for host in hosts:
                host.cli('network', 'sync', net)
            capped = submit(bob, a, reviewer, files=[small])
            assert capped['submit_state'] == 'accepted' and capped['request']['policy']['version'] == 3, capped
            assert parse_time(capped['request']['deadline']) == parse_time(soon['valid_until']), capped
            # A grant's expiry is not known to the submitter: the default stays 1 hour.
            grant = alice.cli('grant', 'create', '--peer', ids[bob]['id'], '--agent', reviewer['id'], '--expires-at',
                              timestamp(7200), '--action', 'task.submit', '--allow-disconnected')
            hour = submit(bob, a, reviewer, grant, text='by grant')
            remaining = parse_time(hour['request']['deadline']) - datetime.now(timezone.utc)
            assert timedelta(minutes=58) < remaining <= timedelta(hours=1), hour
        finally:
            if saved_sock is None:
                os.environ.pop('SSH_AUTH_SOCK', None)
            else:
                os.environ['SSH_AUTH_SOCK'] = saved_sock
            stop_all(hosts)
            coord.stop()
            coord.logs.close()
            for agent in agents.values():
                agent.stop()
    print(f'PASS {label}: policy max_artifact_bytes signed and verified across implementations; rules without it '
          'refuse artifacts; the combined bound holds; the default deadline is capped at valid_until', flush=True)


def migration_check(original, replacement, label):
    with tempfile.TemporaryDirectory(prefix='peerspan-artifact-migration-') as directory:
        host = Host(original, Path(directory) / 'host')
        try:
            identity = host.start()
            agent = host.cli('agent', 'register', '--name', 'kept', '--owner', 'pat')
            host.stop()
            for table in [*DEC_TABLES, *OAUTH_TABLES, *BUILTIN_TABLES, *APPROVAL_TABLES, *LINKING_TABLES, *AGENT_CALL_TABLES, *POLICY_EDIT_TABLES, *CAPABILITY_TABLES, *POLICY_DELIVERY_TABLES, *DELEGATION_TABLES, *ARTIFACT_TABLES]:
                sql(host, 'DROP TABLE ' + table)
            sql(host, 'PRAGMA user_version = 9')
            host.binary = str(replacement)
            assert host.start()['id'] == identity['id']
            assert sql(host, 'PRAGMA user_version')[0][0] == SCHEMA_VERSION
            assert {row[0] for row in sql(host, "SELECT name FROM sqlite_master WHERE type = 'table'")} >= set(ARTIFACT_TABLES)
            assert host.cli('agent', 'inspect', agent['id']) == agent
            assert host.cli('artifact', 'list')['files'] == []
            assert (host.state / 'artifacts').is_dir() and (host.state / 'artifacts').stat().st_mode & 0o077 == 0
            host.stop()
            # A newer version is refused, without changes.
            sql(host, f'PRAGMA user_version = {SCHEMA_VERSION + 1}')
            for binary in (original, replacement):
                result = subprocess.run([str(binary), '--state', str(host.state), 'run'], capture_output=True, timeout=5)
                assert result.returncode != 0 and sql(host, 'PRAGMA user_version')[0][0] == SCHEMA_VERSION + 1
        finally:
            stop_all((host,))
    print(f'PASS {label}: v9→v{SCHEMA_VERSION} migration; version {SCHEMA_VERSION + 1} refused', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--coord', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True, help='peerspan-peer-probe test client')
    parser.add_argument('--node', type=Path, help='Node.js for the MCP channel cases; skipped without it')
    parser.add_argument('--pairing', action='append', help='sender/receiver, such as Go/Rust; default all')
    parser.add_argument('--skip-policy', action='store_true', help='skip the policy cases (they need OpenSSH)')
    args = parser.parse_args()
    set_probe(args.probe.resolve(strict=True))
    script = Path(__file__).resolve().parents[1] / 'integrations/claude-channel/channel.mjs'
    node = args.node.resolve() if args.node else None
    binaries = {'Go': args.go.resolve(), 'Rust': args.rust.resolve()}
    for first in binaries:
        for second in binaries:
            if args.pairing and f'{first}/{second}' not in args.pairing:
                continue
            migration_check(binaries[first], binaries[second], f'{first}→{second}')
            check(binaries[first], binaries[second], node, script, f'{first} submitter, {second} receiver')
            if not args.skip_policy:
                policy_check(args.coord.resolve(), binaries[second], binaries[first],
                             f'{second} owner, {first} submitter')


if __name__ == '__main__':
    main()
