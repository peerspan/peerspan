#!/usr/bin/env python3
"""Independent coordinator mailbox conformance from the linking wire contracts.

Uses real mTLS and opaque ciphertext, deterministic public clock/crash hooks and
public backup/restore commands. Never reads implementation source or private SQL
layout. All fixed resource limits run by default; --section selects diagnostics.
"""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import traceback

from launch_service import Key
from peer_messaging import available_port


BASE = '/coord/v2/link-mailboxes'
START = '2026-10-23T12:00:00Z'
KIB = 1024
MIB = KIB * KIB


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def shifted(value, seconds):
    return (datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ') + timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')


def need(condition, message, *actual):
    if not condition:
        raise AssertionError(message + (': ' + repr(actual)[:1500] if actual else ''))


def source(number):
    return f'127.{1 + number // 65536}.{number // 256 % 256}.{number % 256}'


class TLSConnection(http.client.HTTPConnection):
    def __init__(self, port, context, ip):
        super().__init__('127.0.0.1', port, timeout=30, source_address=(ip, 0))
        self.context = context

    def connect(self):
        raw = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # Same as HTTPConnection.connect.
        self.sock = self.context.wrap_socket(raw, server_hostname='localhost')


class Runtime:
    def __init__(self, binary, directory, initial=START, state=None, port=None):
        self.binary = str(Path(binary).resolve())
        self.root = directory
        self.root.mkdir(parents=True, exist_ok=True)
        self.state = state or directory / 'state'
        self.clock = directory / 'clock'
        self.barriers = directory / 'barriers'
        self.barriers.mkdir(exist_ok=True)
        self.port = port or available_port()
        self.now = initial
        self.set_time(initial)
        self.logs = (directory / 'coordinator.log').open('ab+')
        self.process = None
        self.connections = {}
        self.contexts = {}
        self.serial = 0
        self.requests = 0
        self.key = Key(directory, hashlib.sha256(str(directory).encode()).digest())
        self.other = Key(directory, hashlib.sha256((str(directory) + '/other').encode()).digest())
        self.start()

    def set_time(self, value):
        self.now = value
        temporary = self.clock.with_suffix('.tmp')
        temporary.write_text(value + '\n')
        temporary.replace(self.clock)

    def advance(self, seconds):
        self.set_time(shifted(self.now, seconds))

    def command(self, *args, binary=None, state=None):
        return subprocess.run([str(binary or self.binary), '--state', str(state or self.state), *args],
                              capture_output=True, timeout=120)

    def start(self):
        env = dict(os.environ, PEERSPAN_LINK_TEST_MODE='1', PEERSPAN_LINK_TEST_CLOCK_FILE=str(self.clock),
                   PEERSPAN_LINK_TEST_BARRIER_DIR=str(self.barriers))
        self.process = subprocess.Popen([self.binary, '--state', str(self.state), 'run', '--listen', f'127.0.0.1:{self.port}'],
                                        env=env, stdout=self.logs, stderr=self.logs)
        end = time.monotonic() + 20
        while time.monotonic() < end:
            need(self.process.poll() is None, 'coordinator remains alive at startup')
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=.1):
                    return
            except OSError:
                time.sleep(.02)
        raise AssertionError('coordinator did not listen')

    def stop(self, kill=False):
        # A crash must happen before closing its client connection can cancel work.
        if kill and self.process and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=10)
            self.process = None
        for conn in self.connections.values():
            conn.close()
        self.connections.clear()
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGKILL if kill else signal.SIGTERM)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.process = None

    def restart(self):
        self.stop()
        self.start()

    def close(self):
        self.stop()
        self.logs.close()

    def call(self, method, path, body=None, key=None, ip='127.0.0.1', headers=None, fresh=False):
        key = key or self.key
        index = (key.b64, ip)
        if key.b64 not in self.contexts:
            self.contexts[key.b64] = key.context('http/1.1')
        connection = self.connections.get(index)
        if fresh or connection is None:
            connection = TLSConnection(self.port, self.contexts[key.b64], ip)
            if not fresh:
                self.connections[index] = connection
        raw = wire(body) if isinstance(body, dict) else body
        self.requests += 1
        try:
            connection.request(method, path, raw, dict({'Content-Type': 'application/json'}, **(headers or {})))
            response = connection.getresponse()
            data = response.read()
            try:
                value = json.loads(data)
            except (ValueError, UnicodeDecodeError):
                raise AssertionError(f'HTTP {response.status} returned non-JSON: {data[:200]!r}')
            return response.status, {k.lower(): v for k, v in response.getheaders()}, value
        finally:
            if fresh:
                connection.close()

    def frame(self, role='request', writer=None, mailbox=None, ciphertext=16, size=None, **changes):
        self.serial += 1
        label = f'{self.root.name}/{self.serial}'.encode()
        obj = {'format': 1, 'request_id': 'link_' + hashlib.sha256(b'request' + label).hexdigest(),
               'locator': hashlib.sha256(b'locator' + label).hexdigest(), 'role': role,
               'writer_public_key': writer or self.key.b64, 'frame_id': hashlib.sha256(b'frame' + label).hexdigest(),
               'ciphertext': base64.b64encode(bytes([self.serial % 256]) * ciphertext).decode()}
        if mailbox:
            obj.update({name: mailbox[name] for name in ('request_id', 'locator')})
        obj.update(changes)
        raw = wire(obj)
        if size is not None:
            need(size >= len(raw), 'requested serialized frame fits', size, len(raw))
            raw = raw[:-1] + b' ' * (size - len(raw)) + b'}'
        return obj, raw

    def create(self, frame=None, raw=None, ip='127.0.0.1', key=None, created=None, expires=None, fresh=False):
        if frame is None:
            frame, raw = self.frame(writer=(key or self.key).b64)
        raw = raw or wire(frame)
        created = created or self.now
        expires = expires or shifted(created, 300)
        body = b'{"frame":' + raw + b',"created_at":' + wire(created) + b',"expires_at":' + wire(expires) + b'}'
        return frame, self.call('POST', BASE, body, key=key, ip=ip, fresh=fresh)

    def append(self, box, frame=None, raw=None, **kwargs):
        if frame is None:
            frame, raw = self.frame('owner', mailbox=box)
        return frame, self.call('POST', BASE + '/' + box['locator'] + '/frames', b'{"frame":' + (raw or wire(frame)) + b'}', **kwargs)

    def read(self, box, after=0, **kwargs):
        return self.call('GET', BASE + '/' + box['locator'] + '?after=' + str(after), **kwargs)

    def discard_connections(self):
        for connection in self.connections.values():
            connection.close()
        self.connections.clear()


def ok(reply, status):
    need(reply[0] == status, 'HTTP success status', status, reply)
    return reply[2]


def error(reply, status, code, retry=None):
    need(reply[0] == status, 'HTTP error status', status, reply)
    value = reply[2]
    need(set(value) == {'code', 'error', 'details'}, 'strict error envelope', value)
    need(value['code'] == code and isinstance(value['error'], str) and bool(value['error']), 'error code/message', code, value)
    details = value['details']
    need(set(details) == {'request_id', 'stage', 'required_ids', 'next'}, 'strict error details', details)
    need(all(isinstance(details[k], str) and bool(details[k]) for k in ('request_id', 'stage')), 'scalar error context', details)
    need(all(isinstance(details[k], list) and all(isinstance(v, str) for v in details[k]) for k in ('required_ids', 'next')), 'array error context', details)
    if status == 429:
        header = reply[1].get('retry-after', '')
        need(header.isascii() and header.isdecimal() and int(header) > 0, 'integer Retry-After', header)
        if retry is not None:
            need(int(header) == retry, 'exact fixed-window/interval retry delay', retry, header)


def view(reply, box, status=200, state='open', count=None):
    obj = ok(reply, status)
    need(set(obj) == {'request_id', 'locator', 'created_at', 'expires_at', 'next_sequence', 'state', 'frames'}, 'strict mailbox view', obj)
    need(obj['request_id'] == box['request_id'] and obj['locator'] == box['locator'] and obj['state'] == state, 'mailbox immutable metadata/state', obj)
    need(obj['expires_at'] == shifted(obj['created_at'], 300), 'fixed 300 second mailbox deadline', obj)
    need(type(obj['next_sequence']) is int and obj['next_sequence'] >= 2, 'next sequence integer', obj)
    need(isinstance(obj['frames'], list), 'frame array')
    for entry in obj['frames']:
        need(set(entry) == {'sequence', 'frame'} and type(entry['sequence']) is int and isinstance(entry['frame'], dict), 'strict sequence/frame entry', entry)
    sequence = [entry['sequence'] for entry in obj['frames']]
    need(sequence == sorted(set(sequence)), 'ascending distinct sequences', sequence)
    if count is not None:
        need(len(obj['frames']) == count, 'frame count', count, len(obj['frames']))
    return obj


class Suite:
    def __init__(self, args, root):
        self.args, self.root = args, root
        self.requests = 0
        self.sections = 0
        self.failures = 0

    def run(self, name, fn):
        if self.args.section and name not in self.args.section:
            return
        runtime = Runtime(self.args.coordinator, self.root / name)
        try:
            fn(runtime)
            self.sections += 1
            print(f'PASS {name}: {runtime.requests} authenticated requests', flush=True)
        except Exception:
            self.failures += 1
            exit_code = runtime.process.poll() if runtime.process else None
            runtime.logs.flush()
            artifact = Path('/tmp') / (self.root.name + '-' + name + '.log')
            shutil.copy2(runtime.logs.name, artifact)
            print(f'FAIL {name}: {runtime.requests} authenticated requests attempted; daemon_exit={exit_code}; log={artifact}', file=sys.stderr, flush=True)
            traceback.print_exc()
        finally:
            self.requests += runtime.requests
            runtime.close()

    def transport(self, r):
        frame, reply = r.create()
        original = view(reply, frame, 201, count=1)
        need(original['frames'] == [{'sequence': 1, 'frame': frame}] and original['next_sequence'] == 2, 'creation sequence and original opaque content')
        _, retry = r.create(frame)
        need(view(retry, frame, count=1) == original, 'identical create retry returns original view')
        # Whitespace outside the retained frame is not part of the immutable tuple.
        raw = b'{ "created_at" : ' + wire(r.now) + b', "expires_at" : ' + wire(shifted(r.now, 300)) + b', "frame" : ' + wire(frame) + b' }'
        need(view(r.call('POST', BASE, raw), frame, count=1) == original, 'outer envelope whitespace retry')
        for index, role in enumerate(('owner', 'selection', 'administrator', 'commit', 'result'), 2):
            item, result = r.append(frame, r.frame(role, writer=r.other.b64, mailbox=frame, ciphertext=65552 if role == 'result' else 16)[0], key=r.other)
            need(ok(result, 201) == {'sequence': index}, 'all six opaque roles accepted without inferred authority')
            _, result = r.append(frame, item, key=r.key)
            need(ok(result, 200) == {'sequence': index}, 'other TLS key may retransmit opaque frame')
        r.advance(2)
        current = view(r.read(frame), frame, count=6)
        need(current['next_sequence'] == 7, 'append next sequence')
        r.advance(2)
        tail = view(r.read(frame, after=3), frame, count=3)
        need([x['sequence'] for x in tail['frames']] == [4, 5, 6], 'after pagination')
        r.advance(2)
        view(r.read(frame, after=999), frame, count=0)
        _, conflict = r.append(frame, frame, raw=wire(frame)[:-1] + b' }')
        error(conflict, 409, 'operation_conflict')
        changed = dict(frame, ciphertext=base64.b64encode(b'x' * 16).decode())
        _, conflict = r.create(changed, ip=source(90))
        error(conflict, 409, 'operation_conflict')
        _, conflict = r.create(frame, created=shifted(START, -1), ip=source(91))
        error(conflict, 409, 'operation_conflict')
        altered = dict(frame, locator='f' * 64)
        _, conflict = r.create(altered, ip=source(92))
        error(conflict, 409, 'operation_conflict')
        wrong, _ = r.frame('owner', mailbox=frame, request_id='link_' + 'e' * 64)
        _, result = r.append(frame, wrong)
        error(result, 400, 'invalid')
        r.advance(2)
        need(view(r.read(frame), frame, count=6)['next_sequence'] == 7, 'failed writes do not consume sequence/capacity')

    def strict(self, r):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(['http/1.1'])
        anonymous = TLSConnection(r.port, context, '127.0.0.1')
        try:
            anonymous.request('GET', BASE + '/' + 'a' * 64)
            response = anonymous.getresponse()
            response.read()
            need(response.status in (401, 403), 'anonymous TLS cannot use mailbox routes', response.status)
        except (ssl.SSLError, ConnectionError, http.client.RemoteDisconnected):
            pass
        finally:
            anonymous.close()
        good, raw = r.frame()
        envelope = b'{"frame":' + raw + b',"created_at":' + wire(r.now) + b',"expires_at":' + wire(shifted(r.now, 300)) + b'}'
        bad = [('duplicate_outer', envelope[:-1] + b',"created_at":' + wire(r.now) + b'}'),
               ('unknown_outer', envelope[:-1] + b',"seed":"never-accepted"}'),
               ('null_outer', envelope.replace(wire(r.now), b'null', 1)), ('trailing', envelope + b'{}'),
               ('invalid_utf8', envelope[:-1] + b',"\xff":0}')]
        for label, value in bad:
            error(r.call('POST', BASE, value, ip=source(10)), 400, 'invalid')
        cases = {'unknown_field': dict(good, plaintext='not-authority'), 'null_field': dict(good, role=None),
                 'wrong_format': dict(good, format=2), 'bool_format': dict(good, format=True),
                 'fraction_format': dict(good, format=1.0), 'bad_request': dict(good, request_id='link_' + 'A' * 64),
                 'bad_locator': dict(good, locator='A' * 64), 'bad_frameid': dict(good, frame_id='0' * 63),
                 'bad_role': dict(good, role='unknown'), 'wrong_creator_role': dict(good, role='owner'),
                 'key_noncanonical': dict(good, writer_public_key=good['writer_public_key'].rstrip('=')),
                 'key_zero': dict(good, writer_public_key=base64.b64encode(bytes(32)).decode()),
                 'base64_noncanonical': dict(good, ciphertext=good['ciphertext'].rstrip('=')),
                 'ciphertext_short': dict(good, ciphertext=base64.b64encode(bytes(15)).decode()),
                 'ciphertext_long': dict(good, ciphertext=base64.b64encode(bytes(65553)).decode()),
                 'scalar_ciphertext': dict(good, ciphertext=16)}
        for index, (label, value) in enumerate(cases.items(), 11):
            _, result = r.create(value, ip=source(index))
            error(result, 400, 'invalid')
        duplicate = raw[:-1] + b',"role":"request"}'
        _, result = r.create(good, raw=duplicate, ip=source(40))
        error(result, 400, 'invalid')
        # Date parsing and the inclusive/exclusive interval are independent of JSON encoding.
        for index, (created, expires) in enumerate(((shifted(r.now, 1), shifted(r.now, 301)),
                (shifted(r.now, -300), r.now), (r.now, shifted(r.now, 299)), (r.now, shifted(r.now, 301)),
                (r.now.replace('Z', '+00:00'), shifted(r.now, 300))), 50):
            _, result = r.create(ip=source(index), created=created, expires=expires)
            error(result, 400, 'invalid')
        _, result = r.create(good, key=r.other, ip=source(60))
        error(result, 403, 'forbidden')
        _, result = r.create(good, ip=source(61))
        view(result, good, 201, count=1)
        for value in ('-1', '1.0', '1e1', 'null', 'x'):
            error(r.read(good, after=value, key=r.other, ip=source(62)), 400, 'invalid')
        error(r.call('GET', BASE + '/' + 'b' * 64), 404, 'not_found')
        r.clock.write_text('not a clock\n')
        error(r.read(good, key=r.other, ip=source(63)), 500, 'internal')
        r.set_time(START)
        r.advance(2)
        view(r.read(good), good, count=1)

    def terminal(self, r):
        box, reply = r.create()
        view(reply, box, 201)
        error(r.call('DELETE', BASE + '/' + box['locator'], key=r.other), 403, 'forbidden')
        r.advance(299)
        _, result = r.append(box)
        ok(result, 201)
        r.advance(1)
        view(r.read(box), box, state='expired', count=2)
        _, result = r.append(box)
        error(result, 410, 'expired')
        _, result = r.create(box, created=START, expires=shifted(START, 300))
        error(result, 410, 'expired')
        need(ok(r.call('DELETE', BASE + '/' + box['locator']), 200) == {'state': 'deleted'}, 'creator may delete retained expired mailbox')
        need(ok(r.call('DELETE', BASE + '/' + box['locator']), 200) == {'state': 'deleted'}, 'delete idempotence')
        r.advance(2)
        need(view(r.read(box), box, state='deleted', count=0)['next_sequence'] == 3, 'deletion preserves next unused sequence tombstone')
        _, result = r.append(box)
        error(result, 410, 'deleted')
        r.set_time(shifted(START, 300 + 86400 - 1))
        view(r.read(box, key=r.other), box, state='deleted', count=0)
        r.advance(1)
        error(r.read(box), 404, 'not_found')
        error(r.call('DELETE', BASE + '/' + box['locator']), 404, 'not_found')
        # Retention expiry releases the public locator, not any public operation/proof.
        _, result = r.create(box)
        view(result, box, 201, count=1)

    def per_ip_rates(self, r):
        boxes = []
        for _ in range(5):
            box, result = r.create()
            view(result, box, 201)
            boxes.append(box)
        error(r.create()[1], 429, 'rate_limited', 3600)
        r.restart()
        error(r.create()[1], 429, 'rate_limited', 3600)
        # Forwarded headers cannot select a different creation IP bucket.
        frame, raw = r.frame()
        body = b'{"frame":' + raw + b',"created_at":' + wire(r.now) + b',"expires_at":' + wire(shifted(r.now, 300)) + b'}'
        error(r.call('POST', BASE, body, headers={'X-Forwarded-For': '198.51.100.1', 'X-Real-IP': '198.51.100.2'}), 429, 'rate_limited', 3600)
        other, result = r.create(ip=source(1))
        view(result, other, 201)
        # Idempotent frame retries consume the write budget and persist over restart.
        item, result = r.append(boxes[0], ip=source(2))
        need(ok(result, 201) == {'sequence': 2}, 'first frame write')
        for _ in range(59):
            need(ok(r.append(boxes[0], item, ip=source(2))[1], 200) == {'sequence': 2}, 'write retry sequence')
        error(r.append(boxes[0], item, ip=source(2))[1], 429, 'rate_limited', 60)
        r.restart()
        error(r.append(boxes[0], item, ip=source(2))[1], 429, 'rate_limited', 60)
        r.advance(60)
        ok(r.append(boxes[0], item, ip=source(2))[1], 200)
        view(r.read(boxes[0], ip=source(3)), boxes[0])
        error(r.read(boxes[0], ip=source(4)), 429, 'rate_limited', 2)
        r.restart()
        error(r.read(boxes[0], ip=source(4)), 429, 'rate_limited', 2)
        r.advance(1)
        error(r.read(boxes[0], ip=source(4)), 429, 'rate_limited', 1)
        r.advance(1)
        view(r.read(boxes[0], ip=source(4)), boxes[0])
        r.set_time(shifted(START, 3600))
        box, reply = r.create()
        view(reply, box, 201)

    def open_limits(self, r):
        r.set_time('2026-10-23T12:59:59Z')
        boxes = []
        for _ in range(5):
            box, result = r.create()
            view(result, box, 201)
            boxes.append(box)
        r.advance(1)
        for _ in range(3):
            box, result = r.create()
            view(result, box, 201)
            boxes.append(box)
        error(r.create()[1], 409, 'quota_exceeded')
        need(ok(r.call('DELETE', BASE + '/' + boxes[0]['locator']), 200) == {'state': 'deleted'}, 'delete releases open count')
        box, result = r.create()
        view(result, box, 201)
        for index in range(248):
            box, result = r.create(ip=source(index + 100), fresh=True)
            view(result, box, 201)
        error(r.create(ip=source(500), fresh=True)[1], 409, 'quota_exceeded')
        r.advance(301)
        # Cleanup before this request releases all expired open slots.
        box, result = r.create(ip=source(501), fresh=True)
        view(result, box, 201)

    def frame_limits(self, r):
        box, reply = r.create()
        view(reply, box, 201)
        for index in range(63):
            _, result = r.append(box, ip=source(1 + index // 60))
            need(ok(result, 201) == {'sequence': index + 2}, 'inclusive 64 frames')
        error(r.append(box, ip=source(3))[1], 409, 'quota_exceeded')
        r.advance(2)
        need(view(r.read(box), box, count=64)['next_sequence'] == 65, 'frame limit atomicity')
        exact, raw = r.frame(size=512 * KIB)
        view(r.create(exact, raw=raw, ip=source(4))[1], exact, 201, count=1)
        error(r.append(exact, ip=source(5))[1], 409, 'quota_exceeded')
        over, raw = r.frame(size=512 * KIB + 1)
        error(r.create(over, raw=raw, ip=source(6))[1], 409, 'quota_exceeded')
        r.advance(2)
        need(view(r.read(exact), exact, count=1)['next_sequence'] == 2, 'byte overflow atomicity')
        # Exact bytes retained, rather than a canonical reserialization: this alias conflicts.
        error(r.create(exact, raw=wire(exact), ip=source(7))[1], 409, 'operation_conflict')

    def global_creation(self, r):
        boxes = []
        for index in range(5):
            box, result = r.create()
            view(result, box, 201)
            boxes.append(box)
        error(r.create()[1], 429, 'rate_limited', 3600)
        for index in range(995):
            if (index + 5) % 250 == 0:
                r.advance(300)
            box, result = r.create(ip=source(index + 100), fresh=True)
            view(result, box, 201)
        error(r.create(ip=source(1200), fresh=True)[1], 429, 'rate_limited')
        r.restart()
        error(r.create(ip=source(1201), fresh=True)[1], 429, 'rate_limited')
        r.set_time(shifted(START, 3600))
        box, result = r.create(ip=source(1201), fresh=True)
        view(result, box, 201)

    def global_writes(self, r):
        box, reply = r.create()
        view(reply, box, 201)
        item = r.frame('owner', mailbox=box)[0]
        # One per-IP rejection immediately below the global bound cannot charge global.
        for index in range(11999):
            ip = source(100 + index // 60)
            try:
                _, result = r.append(box, item, ip=ip)
            except (OSError, http.client.HTTPException) as exc:
                raise AssertionError(f'global write transport failed at request {index + 1} from {ip}') from exc
            need(ok(result, 201 if index == 0 else 200) == {'sequence': 2}, 'global write exact bound', index)
            if index % 60 == 59:
                r.discard_connections()  # Do not test an unrelated idle-connection capacity.
        error(r.append(box, item, ip=source(100), fresh=True)[1], 429, 'rate_limited')
        ok(r.append(box, item, ip=source(400))[1], 200)
        error(r.append(box, item, ip=source(401))[1], 429, 'rate_limited', 60)
        r.restart()
        error(r.append(box, item, ip=source(402))[1], 429, 'rate_limited', 60)
        r.advance(60)
        ok(r.append(box, item, ip=source(402))[1], 200)

    def global_polls(self, r):
        boxes = []
        for index in range(120):
            box, reply = r.create(ip=source(1000 + index), fresh=True)
            view(reply, box, 201)
            boxes.append(box)
        keys = [r.key] + [Key(r.root, hashlib.sha256(f'poll/{i}'.encode()).digest()) for i in range(100)]
        for index in range(11999):
            group, offset = divmod(index, 120)
            view(r.read(boxes[offset], key=keys[group], ip=source(100 + group)), boxes[offset], count=1)
            if offset == 119:
                r.discard_connections()
        # Same IP, different key/locator avoids the per-host interval, isolates IP budget.
        error(r.read(boxes[0], key=keys[-1], ip=source(100)), 429, 'rate_limited')
        view(r.read(boxes[-1], key=keys[99], ip=source(199)), boxes[-1], count=1)
        error(r.read(boxes[1], key=keys[-1], ip=source(300)), 429, 'rate_limited', 60)
        r.restart()
        error(r.read(boxes[1], key=keys[-1], ip=source(301)), 429, 'rate_limited', 60)
        r.advance(60)
        view(r.read(boxes[1], key=keys[-1], ip=source(301)), boxes[1], count=1)

    def retained_limit(self, r):
        first = None
        for index in range(4096):
            hour, within = divmod(index, 1000)
            r.set_time(shifted(START, hour * 3600 + within // 250 * 300))
            box, result = r.create(ip=source(index + 100), fresh=True)
            view(result, box, 201)
            first = first or box
        error(r.create(ip=source(5000), fresh=True)[1], 409, 'quota_exceeded')
        r.restart()
        error(r.create(ip=source(5001), fresh=True)[1], 409, 'quota_exceeded')
        r.set_time(shifted(START, 300 + 86400))
        error(r.read(first), 404, 'not_found')
        box, result = r.create(ip=source(5002), fresh=True)
        view(result, box, 201)

    def global_bytes(self, r):
        first = None
        for index in range(512):
            if index == 256:
                r.advance(300)
            box, raw = r.frame(size=512 * KIB)
            _, result = r.create(box, raw=raw, ip=source(index + 100), fresh=True)
            view(result, box, 201, count=1)
            first = first or box
        r.advance(300)  # Isolate bytes: every box is now expired, so no open-count fault.
        error(r.create(ip=source(1000), fresh=True)[1], 409, 'quota_exceeded')
        r.advance(2)
        view(r.read(first), first, state='expired', count=1)
        r.restart()
        error(r.create(ip=source(1001), fresh=True)[1], 409, 'quota_exceeded')
        need(ok(r.call('DELETE', BASE + '/' + first['locator']), 200) == {'state': 'deleted'}, 'delete discards ciphertext capacity')
        box, result = r.create(ip=source(1002), fresh=True)
        view(result, box, 201)

    def crash_and_backup(self, r):
        for name, append in (('coord.mailbox.after_commit', False), ('coord.frame.after_commit', True)):
            box, raw = r.frame()
            if append:
                view(r.create(box, raw=raw, ip=source(2))[1], box, 201)
                item, raw = r.frame('owner', mailbox=box)
                raw = raw[:-1] + b'       }'  # Preserve a noncanonical JSON byte alias.
            else:
                item = box
            arm = r.barriers / (name + '.arm')
            arm.write_text('')
            with ThreadPoolExecutor(max_workers=1) as pool:
                if append:
                    future = pool.submit(r.append, box, item, raw, ip=source(3), fresh=True)
                else:
                    future = pool.submit(r.create, box, raw, ip=source(3), fresh=True)
                entered = r.barriers / (name + '.entered')
                end = time.monotonic() + 15
                while not entered.exists() and time.monotonic() < end and not future.done():
                    time.sleep(.01)
                need(entered.exists(), 'documented post-commit barrier entered', name)
                need(entered.read_text().strip() == box['request_id'], 'barrier contains public request ID only')
                r.stop(kill=True)
                arm.unlink()
                try:
                    future.result(timeout=5)
                except (OSError, http.client.HTTPException):
                    pass
                r.start()
            if append:
                need(ok(r.append(box, item, raw)[1], 200) == {'sequence': 2}, 'lost frame response retry uses durable original sequence')
                r.advance(2)
                need(view(r.read(box), box, count=2)['next_sequence'] == 3, 'frame crash does not duplicate')
            else:
                view(r.create(box, raw=raw, created=START, expires=shifted(START, 300))[1], box, count=1)
        deleted_box, created = r.create()
        view(created, deleted_box, 201, count=1)
        need(ok(r.append(deleted_box)[1], 201) == {'sequence': 2}, 'deleted restore control has prior frame history')
        need(ok(r.call('DELETE', BASE + '/' + deleted_box['locator']), 200) == {'state': 'deleted'}, 'backup keeps erased-frame tombstone')
        backup = r.root / 'mailboxes.backup'
        result = r.command('backup', str(backup))
        need(result.returncode == 0, 'online backup succeeds', result.stderr)
        info = json.loads(result.stdout)
        need(info['user_version'] == 7 and stat.S_IMODE(backup.stat().st_mode) == 0o600, 'schema7 private backup', info)
        with sqlite3.connect('file:' + str(backup) + '?mode=ro', uri=True) as db:
            need(db.execute('PRAGMA user_version').fetchone()[0] == 7, 'coordinator schema7')
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            need({'link_mailboxes', 'link_frames', 'link_operations', 'link_objects', 'link_features'} <= tables, 'schema7 required categories', tables)
        # Fault injection observes opaque column names; no private layout is asserted.
        # Any one missing row breaks a nondeleted retained box's complete sequence.
        incomplete = r.root / 'missing-frame.backup'
        shutil.copy2(backup, incomplete)
        with sqlite3.connect(incomplete) as db:
            cursor = db.execute('SELECT * FROM link_frames LIMIT 1')
            row = cursor.fetchone()
            columns = [column[0] for column in cursor.description]
            need(row is not None, 'backup has encrypted frames before corruption')
            predicate = ' AND '.join('"' + column.replace('"', '""') + '" IS ?' for column in columns)
            deleted = db.execute('DELETE FROM link_frames WHERE ' + predicate, row).rowcount
            need(deleted == 1, 'remove exactly one opaque stored frame')
        invalid_state = r.root / 'incomplete-restore'
        rejected = r.command('restore', str(incomplete), state=invalid_state)
        need(rejected.returncode != 0 and not (invalid_state / 'coord.db').exists(),
             'partial frame history restore fails atomically', rejected.stdout, rejected.stderr)
        if self.args.baseline:
            # `info` can read the identity without opening the database; exercise run.
            r.stop()
            old = subprocess.Popen([str(Path(self.args.baseline).resolve()), '--state', str(r.state),
                                    'run', '--listen', f'127.0.0.1:{r.port}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                old.communicate(timeout=5)
                need(old.returncode != 0, 'schema6 binary refuses opening schema7')
            except subprocess.TimeoutExpired:
                old.kill()
                old.communicate(timeout=5)
                raise AssertionError('schema6 binary opened newer schema7 database')
            r.start()
        restored_state = r.root / 'restored-state'
        restored = r.command('restore', str(backup), state=restored_state)
        need(restored.returncode == 0, 'restore includes encrypted transport', restored.stderr)
        need(json.loads(restored.stdout)['user_version'] == 7, 'restored schema7')
        other = Runtime(r.binary, r.root / 'restored', initial=shifted(r.now, 2), state=restored_state)
        try:
            view(other.read(box, key=r.key), box, count=2)
            need(view(other.read(deleted_box, key=r.key), deleted_box, state='deleted', count=0)['next_sequence'] == 3,
                 'valid deleted-empty tombstone restores with original sequence counter')
            need(ok(other.append(box, item, raw, key=r.key)[1], 200) == {'sequence': 2}, 'restore retains exact frame bytes and original sequence')
            error(other.append(box, item, wire(item), key=r.key)[1], 409, 'operation_conflict')
        finally:
            self.requests += other.requests
            other.close()
        # Ciphertext/body canaries must never be written into coordinator request logs.
        r.logs.flush()
        logs = r.logs.name.read_bytes() if isinstance(r.logs.name, Path) else Path(r.logs.name).read_bytes()
        for secret in (item['ciphertext'].encode(), r.key.b64.encode(), r.other.b64.encode()):
            need(secret not in logs, 'logs do not expose ciphertext/public-key body material')

    def build(self):
        for name in ('transport', 'strict', 'terminal', 'per_ip_rates', 'open_limits', 'frame_limits',
                     'global_creation', 'global_writes', 'global_polls', 'retained_limit', 'global_bytes', 'crash_and_backup'):
            self.run(name, getattr(self, name))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--coordinator', required=True)
    parser.add_argument('--baseline', help='unmodified schema6 coordinator for newer-schema refusal')
    parser.add_argument('--section', action='append', help='diagnostic section; default runs every fixed bound')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='peerspan-link-mailboxes-') as temporary:
        suite = Suite(args, Path(temporary))
        suite.build()
        print(f'{suite.sections} mailbox sections passed; {suite.failures} failed; {suite.requests} authenticated requests.', flush=True)
        return int(bool(suite.failures))


if __name__ == '__main__':
    sys.exit(main())
