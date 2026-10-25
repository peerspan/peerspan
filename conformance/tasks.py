#!/usr/bin/env python3
"""Exercise single-hop task delegation (milestone 6 slice 2) with real hosts.

Runs every Go/Rust submitter/receiver pairing with deterministic adapter
consumers and no model calls: raw adapter API calls, and the real MCP channel
subprocess for the agent-initiated path. Covers grant and policy
authorization for task.submit, duplicate and conflicting submission, a lost
submit response recovered by automatic retry, the full lifecycle, rejection,
expiry, failure, cancellation, restarts on either side, refusal of transitions
by another session or credential, revocation before acceptance, submitter-only
status and events, delegate_task with task_update events, and v8→v11 migration.
Needs the Go coordinator and peerspan-peer-probe; policy cases need OpenSSH.
"""
import argparse
import json
from pathlib import Path
import secrets
import sqlite3
import subprocess
import tempfile
import time

from agent_adapter import Channel, adapter_call, credential, instance_for, sql
from coordination import Coordinator, wait_for
from host_service import LINKING_TABLES, AGENT_CALL_TABLES, ARTIFACT_TABLES, CAPABILITY_TABLES, DELEGATION_TABLES, Host, POLICY_DELIVERY_TABLES, POLICY_EDIT_TABLES, SCHEMA_VERSION, TASK_TABLES, stop_all
from peer_messaging import DropResponse, PeerHost, fixture_context, set_probe, timestamp, wire

STATUS_KEYS = {'task_id', 'sender_host_id', 'receiver_host_id', 'target_agent_id', 'state', 'cancel_requested',
               'created_at', 'updated_at', 'last_event'}
EVENT_KEYS = {'sequence', 'kind', 'state', 'message', 'output', 'created_at', 'artifacts'}
LOCAL_KEYS = {'peer_host_id', 'request', 'submit_state', 'status', 'events_after', 'cancel_state', 'adapter_id',
              'route_id', 'attempts', 'next_attempt_at', 'error', 'status_queries', 'artifacts', 'parent', 'delegation'}
DELIVERY_KEYS = {'id', 'sender_host_id', 'task_id', 'target_agent_id', 'session_id', 'adapter_id',
                 'cancel_claimed_at', 'created_at'}
NOTIFICATION_KEYS = {'id', 'peer_host_id', 'task_id', 'sequence', 'adapter_id', 'session_id', 'state', 'created_at',
                     'updated_at'}
HANDOFF_KEYS = {'delivery', 'task', 'status', 'sender_person_id', 'sender_person', 'originator_person_id', 'delegable', 'redelivered', 'adopted', 'progress'}
LAPSED = 'authorization lapsed before acceptance'
# Event polling backs off to a minute while nothing changes.
POLL = 75


def task_id():
    return 'task_' + secrets.token_hex(16)


class DropTaskResponse(DropResponse):
    """Drops the receiver's packets once it has committed the task."""

    def committed(self):
        connection = sqlite3.connect(self.receiver.state / 'host.db')
        try:
            return connection.execute('SELECT COUNT(*) FROM received_tasks WHERE task_id = ?',
                                      (self.rid,)).fetchone()[0] > 0
        finally:
            connection.close()


def task_grant(receiver, sender_identity, agent, size=65536):
    grant = receiver.cli('grant', 'create', '--peer', sender_identity['id'], '--agent', agent['id'], '--expires-at',
                         timestamp(7200), '--max-message-bytes', str(size), '--allow-disconnected', '--action',
                         'task.submit')
    assert grant['action'] == 'task.submit', grant
    return grant


def submit(sender, receiver_identity, agent, grant=None, text='work', deadline=None, tid=None, success=True):
    args = ['task', 'submit', '--peer', receiver_identity['id'], '--agent', agent['id'], '--input', text]
    if grant:
        args += ['--grant', grant['id']]
    if deadline:
        args += ['--deadline', deadline]
    if tid:
        args += ['--task', tid]
    out = sender.cli(*args, success=success)
    if success:
        assert set(out) == LOCAL_KEYS, out
    return out


def inspect(sender, peer, tid):
    return sender.cli('task', 'inspect', '--peer', peer['id'], tid)


def events(sender, peer, tid, after=0):
    return sender.cli('task', 'events', '--peer', peer['id'], tid, '--after', str(after))


def kinds(items):
    return ' '.join(f"{e['kind']}:{e['state']}" for e in items)


def until_state(sender, peer, tid, state, seconds=POLL):
    """Wait until the stored status is `state` and every event is stored."""
    def done():
        out = inspect(sender, peer, tid)
        status = out['status']
        return out if status and status['state'] == state and out['events_after'] == status['last_event'] else None
    return wait_for(done, timeout=seconds, message=f'{tid} {state}')


def claim(receiver, token):
    status, value = adapter_call(receiver, token, 'POST', '/adapter/v1/tasks/next', {})
    assert status == 200, value
    return value


def act(receiver, token, tid, op, body=None, expect=200):
    status, value = adapter_call(receiver, token, 'POST', f'/adapter/v1/tasks/{tid}/{op}', body or {})
    assert status == expect, (op, status, value)
    return value


def adapter_for(host, agent, integration='test'):
    session = host.cli('session', 'attach', '--agent', agent['id'], '--integration', integration)
    return session, credential(host, session)


def check(sender_binary, receiver_binary, node, script, label):
    with tempfile.TemporaryDirectory(prefix='peerspan-tasks-') as directory:
        root = Path(directory)
        sender, receiver = PeerHost(sender_binary, root / 'sender'), PeerHost(receiver_binary, root / 'receiver')
        stranger = PeerHost(sender_binary, root / 'stranger')
        hosts = (sender, receiver, stranger)
        channels = []
        try:
            a, b, c = sender.start(), receiver.start(), stranger.start()
            sender.configure(receiver, b)
            receiver.configure(sender, a)
            receiver.configure(stranger, c)
            worker = receiver.cli('agent', 'register', '--name', 'worker', '--owner', 'pat')
            spare = receiver.cli('agent', 'register', '--name', 'spare', '--owner', 'pat')
            other = receiver.cli('agent', 'register', '--name', 'other', '--owner', 'pat')
            session, secret = adapter_for(receiver, worker)
            token = secret['token']
            _, other_secret = adapter_for(receiver, other)
            grant = task_grant(receiver, a, worker)
            spare_grant = task_grant(receiver, a, spare, size=100)

            # Authorization: the grant's action decides.
            message_grant = receiver.grant(a, worker)
            assert message_grant['action'] == 'message.append', message_grant
            refused = submit(sender, b, worker, message_grant)
            assert refused['submit_state'] == 'rejected' and 'HTTP 403' in refused['error'], refused
            assert refused['next_attempt_at'] is None and refused['status'] is None, refused
            assert sender.submit(b, worker, grant)['state'] == 'rejected'
            receiver.cli('grant', 'create', '--peer', a['id'], '--agent', worker['id'], '--expires-at', timestamp(),
                         '--action', 'shell.exec', success=False)
            assert receiver.call('POST', '/v1/grants', {'requester_host_id': a['id'], 'target_agent_id': worker['id'],
                                                        'expires_at': timestamp(), 'max_message_bytes': 10,
                                                        'allow_disconnected': True, 'action': 'shell.exec'})[0] == 400
            assert submit(sender, b, spare, spare_grant, text='x' * 101)['submit_state'] == 'rejected'

            # The full lifecycle: queued, accepted, progress, succeeded.
            out = submit(sender, b, worker, grant, text='summarize the log')
            tid = out['request']['task_id']
            assert out['submit_state'] == 'accepted' and out['attempts'] == 1 and out['next_attempt_at'] is None, out
            assert out['request']['grant_id'] == grant['id'] and out['cancel_state'] is None, out
            assert set(out['status']) == STATUS_KEYS and out['status']['state'] == 'queued', out
            assert out['status']['last_event'] == 1 and out['status']['cancel_requested'] is False, out
            assert out['status']['sender_host_id'] == a['id'] and out['status']['receiver_host_id'] == b['id'], out
            deadline = out['request']['deadline']
            handoff = claim(receiver, token)
            assert set(handoff) == HANDOFF_KEYS, handoff
            assert handoff['originator_person_id'] is None and handoff['delegable'] is False, handoff
            assert set(handoff['delivery']) == DELIVERY_KEYS, handoff
            assert handoff['delivery']['task_id'] == tid and handoff['delivery']['session_id'] == session['id']
            assert handoff['delivery']['cancel_claimed_at'] is None
            assert handoff['task'] == {'task_id': tid, 'grant_id': grant['id'], 'target_agent_id': worker['id'],
                                       'deadline': deadline, 'input': 'summarize the log'}, handoff
            assert handoff['sender_person_id'] is None and handoff['sender_person'] is None
            assert claim(receiver, token) is None
            act(receiver, token, tid, 'progress', {'message': 'early'}, expect=409)
            running = act(receiver, token, tid, 'accept')
            assert set(running) == STATUS_KEYS and running['state'] == 'running' and running['last_event'] == 2
            assert act(receiver, token, tid, 'accept') == running
            act(receiver, token, tid, 'progress', {'message': 'halfway'})
            act(receiver, token, tid, 'progress', {'message': 'halfway'})
            done = act(receiver, token, tid, 'complete', {'status': 'succeeded', 'output': 'the summary'})
            assert done['state'] == 'succeeded' and done['last_event'] == 4, done
            act(receiver, token, tid, 'complete', {'status': 'succeeded', 'output': 'the summary'})
            act(receiver, token, tid, 'complete', {'status': 'failed', 'output': 'other'}, expect=409)
            act(receiver, token, tid, 'complete', {'status': 'done', 'output': 'x'}, expect=400)
            act(receiver, token, tid, 'progress', {}, expect=400)
            act(receiver, token, tid, 'accept', {'extra': 1}, expect=400)
            final = until_state(sender, b, tid, 'succeeded')
            assert final['status'] == done, final
            stored = events(sender, b, tid)
            assert kinds(stored) == 'queued:queued accepted:running progress:running succeeded:succeeded', stored
            assert all(set(e) == EVENT_KEYS for e in stored), stored
            assert [e['sequence'] for e in stored] == [1, 2, 3, 4]
            assert stored[2]['message'] == 'halfway' and stored[2]['output'] is None, stored
            assert stored[3]['output'] == 'the summary' and stored[3]['message'] is None, stored
            assert events(sender, b, tid, after=2) == stored[2:]

            # Status and events on the wire are for the submitter only.
            as_sender, as_stranger = fixture_context(sender), fixture_context(stranger)
            assert wire(receiver, as_sender, 'GET', f'/peer/v1/tasks/{tid}') == (200, done)
            assert wire(receiver, as_sender, 'GET', f'/peer/v1/tasks/{tid}/events?after=1&limit=2') == (200, stored[1:3])
            assert wire(receiver, as_sender, 'GET', f'/peer/v1/tasks/{tid}/events') == (200, stored)
            for query in ('limit=1001', 'limit=0', 'after=-1', 'after=x'):
                assert wire(receiver, as_sender, 'GET', f'/peer/v1/tasks/{tid}/events?{query}')[0] == 400, query
            for method, path, body in (('GET', f'/peer/v1/tasks/{tid}', None),
                                       ('GET', f'/peer/v1/tasks/{tid}/events', None),
                                       ('POST', f'/peer/v1/tasks/{tid}/cancel', {})):
                assert wire(receiver, as_stranger, method, path, body)[0] == 404, path
            assert wire(receiver, as_sender, 'GET', f'/peer/v1/tasks/{task_id()}')[0] == 404
            # Cancelling a final task changes nothing.
            assert wire(receiver, as_sender, 'POST', f'/peer/v1/tasks/{tid}/cancel', {}) == (200, done)
            assert sender.cli('task', 'cancel', '--peer', b['id'], tid)['cancel_state'] is None

            # Duplicate and conflicting submission, on the wire.
            raw = {'task_id': task_id(), 'grant_id': spare_grant['id'], 'target_agent_id': spare['id'],
                   'deadline': timestamp(900), 'input': 'raw'}
            status, first = wire(receiver, as_sender, 'POST', '/peer/v1/tasks', raw)
            assert status == 200 and set(first) == STATUS_KEYS and first['state'] == 'queued', first
            assert wire(receiver, as_sender, 'POST', '/peer/v1/tasks', raw) == (200, first)
            assert wire(receiver, as_sender, 'POST', '/peer/v1/tasks', {**raw, 'input': 'changed'})[0] == 409
            assert wire(receiver, as_sender, 'POST', '/peer/v1/tasks', {**raw, 'origin': {'agent_id': 'agent_' + '1' * 32}})[0] == 409
            for bad in ({**raw, 'extra': 1}, {**raw, 'origin': None}, {**raw, 'input': ''}, {**raw, 'task_id': 'task_x'},
                        {**raw, 'grant_id': None}, {k: v for k, v in raw.items() if k != 'grant_id'},
                        {**raw, 'task_id': task_id(), 'policy': {'person_id': 'person_' + '0' * 64, 'version': 1}}):
                assert wire(receiver, as_sender, 'POST', '/peer/v1/tasks', bad)[0] == 400, bad
            assert wire(receiver, as_sender, 'POST', '/peer/v1/tasks', {**raw, 'task_id': task_id(), 'deadline': timestamp(-5)})[0] == 403
            # Another sender's identical ID is a separate task.
            assert wire(receiver, as_stranger, 'POST', '/peer/v1/tasks', raw)[0] == 403
            assert sql(receiver, 'SELECT COUNT(*) FROM received_tasks WHERE task_id = ?', (raw['task_id'],))[0][0] == 1
            # Locally, a reused ID with other fields conflicts; an identical one returns the record.
            submit(sender, b, worker, grant, text='other', tid=tid, success=False)
            assert submit(sender, b, worker, grant, text='summarize the log', tid=tid, deadline=deadline)['status'] == done

            # A lost submit response is recovered by automatic retry with the same ID.
            lost_id = task_id()
            relay = DropTaskResponse(receiver, lost_id)
            sender.configure(receiver, b, relay.address)
            lost = submit(sender, b, spare, spare_grant, text='lost', tid=lost_id)
            relay.close()
            assert lost['submit_state'] == 'unknown' and lost['attempts'] == 1 and lost['next_attempt_at'], lost
            sender.configure(receiver, b)
            recovered = wait_for(lambda: (r := inspect(sender, b, lost_id))['submit_state'] == 'accepted' and r,
                                 timeout=30, message='automatic task retry')
            assert recovered['attempts'] >= 2 and recovered['next_attempt_at'] is None, recovered
            assert sql(receiver, 'SELECT COUNT(*) FROM received_tasks WHERE task_id = ?', (lost_id,))[0][0] == 1

            # Rejection, failure, and expiry.
            rejected = submit(sender, b, worker, grant, text='no')['request']['task_id']
            failed = submit(sender, b, worker, grant, text='try')['request']['task_id']
            assert claim(receiver, token)['task']['task_id'] == rejected
            assert claim(receiver, token)['task']['task_id'] == failed
            act(receiver, token, rejected, 'reject', {'reason': 'busy'})
            act(receiver, token, rejected, 'reject', {'reason': 'busy'})
            act(receiver, token, rejected, 'reject', {'reason': 'other'}, expect=409)
            act(receiver, token, rejected, 'accept', expect=409)
            act(receiver, token, failed, 'accept')
            act(receiver, token, failed, 'complete', {'status': 'failed', 'output': 'broke'})
            until_state(sender, b, rejected, 'rejected')
            assert events(sender, b, rejected)[-1]['message'] == 'busy'
            until_state(sender, b, failed, 'failed')
            assert events(sender, b, failed)[-1]['output'] == 'broke'
            claimed_late = submit(sender, b, worker, grant, text='claimed', deadline=timestamp(3))['request']['task_id']
            assert claim(receiver, token)['task']['task_id'] == claimed_late
            unclaimed = submit(sender, b, worker, grant, text='unclaimed', deadline=timestamp(3))['request']['task_id']
            time.sleep(4)
            act(receiver, token, claimed_late, 'accept', expect=409)
            assert claim(receiver, token) is None
            for expired in (claimed_late, unclaimed):
                until_state(sender, b, expired, 'expired')
                assert kinds(events(sender, b, expired)) == 'queued:queued expired:expired'
            # An empty reason is allowed.
            empty = submit(sender, b, worker, grant)['request']['task_id']
            claim(receiver, token)
            assert act(receiver, token, empty, 'reject', {'reason': ''})['state'] == 'rejected'

            # Cancellation, confirmed; and requested but completed anyway.
            confirmed = submit(sender, b, worker, grant, text='long')['request']['task_id']
            ignored = submit(sender, b, worker, grant, text='short')['request']['task_id']
            for expected in (confirmed, ignored):
                assert claim(receiver, token)['task']['task_id'] == expected
                act(receiver, token, expected, 'accept')
            act(receiver, token, confirmed, 'cancelled', expect=409)
            assert adapter_call(receiver, token, 'POST', '/adapter/v1/tasks/cancels/next', {}) == (200, None)
            local = sender.cli('task', 'cancel', '--peer', b['id'], confirmed)
            assert local['cancel_state'] == 'sent' and local['status']['cancel_requested'] is True, local
            assert local['status']['state'] == 'running' and local['status']['last_event'] == 3, local
            assert sender.cli('task', 'cancel', '--peer', b['id'], confirmed)['status']['last_event'] == 3
            assert wire(receiver, as_sender, 'POST', f'/peer/v1/tasks/{confirmed}/cancel', {})[1]['last_event'] == 3
            assert wire(receiver, as_sender, 'POST', f'/peer/v1/tasks/{confirmed}/cancel', {'x': 1})[0] == 400
            sender.cli('task', 'cancel', '--peer', b['id'], ignored)
            status, notice = adapter_call(receiver, token, 'POST', '/adapter/v1/tasks/cancels/next', {})
            assert status == 200 and set(notice) == {'delivery', 'status'} and notice['delivery']['task_id'] == confirmed
            assert notice['delivery']['cancel_claimed_at'] and notice['status']['cancel_requested'] is True, notice
            assert adapter_call(receiver, token, 'POST', '/adapter/v1/tasks/cancels/next', {})[1]['delivery']['task_id'] == ignored
            assert adapter_call(receiver, token, 'POST', '/adapter/v1/tasks/cancels/next', {}) == (200, None)
            assert act(receiver, token, confirmed, 'cancelled')['state'] == 'cancelled'
            act(receiver, token, confirmed, 'cancelled')
            act(receiver, token, ignored, 'complete', {'status': 'succeeded', 'output': 'done anyway'})
            until_state(sender, b, confirmed, 'cancelled')
            assert kinds(events(sender, b, confirmed)) == ('queued:queued accepted:running cancel_requested:running '
                                                         'cancelled:cancelled')
            finished = until_state(sender, b, ignored, 'succeeded')
            assert finished['status']['cancel_requested'] is True and finished['cancel_state'] == 'sent', finished

            # Another session or credential cannot change a claimed task.
            mine = submit(sender, b, worker, grant, text='mine')['request']['task_id']
            assert claim(receiver, token)['task']['task_id'] == mine
            act(receiver, other_secret['token'], mine, 'accept', expect=403)
            act(receiver, other_secret['token'], task_id(), 'accept', expect=404)
            assert adapter_call(receiver, 'token_' + '0' * 64, 'POST', f'/adapter/v1/tasks/{mine}/accept', {})[0] == 403
            assert claim(receiver, other_secret['token']) is None
            act(receiver, token, mine, 'accept')

            # Revocation before acceptance records rejected, at acceptance and at
            # handoff; an accepted task keeps running.
            at_accept = submit(sender, b, worker, grant, text='lapse at accept')['request']['task_id']
            at_handoff = submit(sender, b, worker, grant, text='lapse at handoff')['request']['task_id']
            assert claim(receiver, token)['task']['task_id'] == at_accept
            receiver.cli('grant', 'revoke', grant['id'])
            act(receiver, token, at_accept, 'accept', expect=403)
            assert claim(receiver, token) is None
            for lapsed in (at_accept, at_handoff):
                until_state(sender, b, lapsed, 'rejected')
                assert events(sender, b, lapsed)[-1]['message'] == LAPSED
            act(receiver, token, mine, 'progress', {'message': 'still going'})
            act(receiver, token, mine, 'complete', {'status': 'succeeded', 'output': 'finished after revocation'})
            until_state(sender, b, mine, 'succeeded')
            grant = task_grant(receiver, a, worker)

            # A submitter restart resumes from its stored cursor.
            resumed = submit(sender, b, worker, grant, text='resume')['request']['task_id']
            claim(receiver, token)
            act(receiver, token, resumed, 'accept')
            act(receiver, token, resumed, 'progress', {'message': 'one'})
            wait_for(lambda: inspect(sender, b, resumed)['events_after'] == 3, timeout=POLL, message='cursor 3')
            sender.stop()
            act(receiver, token, resumed, 'progress', {'message': 'two'})
            act(receiver, token, resumed, 'complete', {'status': 'succeeded', 'output': 'resumed'})
            sender.start()
            until_state(sender, b, resumed, 'succeeded')
            assert [e['sequence'] for e in events(sender, b, resumed)] == [1, 2, 3, 4, 5]
            assert sql(sender, 'SELECT COUNT(*) FROM outbound_task_events WHERE task_id = ?', (resumed,))[0][0] == 5

            # A receiver restart preserves the task and its claim.
            kept = submit(sender, b, worker, grant, text='keep')['request']['task_id']
            claim(receiver, token)
            act(receiver, token, kept, 'accept')
            receiver.stop()
            receiver.start()
            assert wire(receiver, as_sender, 'GET', f'/peer/v1/tasks/{kept}')[1]['state'] == 'running'
            assert adapter_call(receiver, token, 'POST', '/adapter/v1/connect',
                                {'instance_id': instance_for(receiver, token)['instance']}, auto_connect=False)[0] == 200
            act(receiver, token, kept, 'complete', {'status': 'succeeded', 'output': 'kept'})
            until_state(sender, b, kept, 'succeeded')

            # Local listing and activity.
            listed = sender.cli('task', 'list', '--limit', '1000')
            assert all(set(item) == {'sequence', 'task'} for item in listed), listed[:1]
            assert [item['sequence'] for item in listed] == sorted(item['sequence'] for item in listed)
            assert any(item['task']['request']['task_id'] == kept for item in listed)
            received_kinds = {e['kind'] for e in receiver.cli('activity', '--limit', '1000')}
            assert {'task.received', 'task.accepted', 'task.rejected', 'task.progress', 'task.completed',
                    'task.cancel_requested', 'task.cancelled', 'task.expired'} <= received_kinds, received_kinds
            sent_activity = [e for e in sender.cli('activity', '--limit', '1000') if e['kind'].startswith('task.')]
            assert {e['kind'] for e in sent_activity} == {'task.submitted', 'task.updated'}, sent_activity
            assert any(e['subject_id'] == f"{b['id']}/{kept}" for e in sent_activity), sent_activity

            # An agent-initiated task through a task.submit route, with
            # task_update events back to the originating session.
            author = sender.cli('agent', 'register', '--name', 'author', '--owner', 'quinn')
            origin_session, origin_secret = adapter_for(sender, author)
            route = sender.cli('adapter', 'route', 'add', '--adapter', origin_secret['adapter']['id'], '--name', 'review',
                               '--peer', b['id'], '--agent', worker['id'], '--grant', grant['id'], '--action',
                               'task.submit', '--expires-at', timestamp(900), '--max-messages', '3')
            assert route['action'] == 'task.submit', route
            chat = sender.cli('adapter', 'route', 'add', '--adapter', origin_secret['adapter']['id'], '--name', 'chat',
                              '--peer', b['id'], '--agent', worker['id'], '--grant', grant['id'], '--expires-at',
                              timestamp(900))
            assert chat['action'] == 'message.append', chat
            origin_token = origin_secret['token']
            status, destinations = adapter_call(sender, origin_token, 'GET', '/adapter/v1/destinations')
            assert status == 200 and [(d['name'], d['action']) for d in destinations] == [
                ('chat', 'message.append'), ('review', 'task.submit')], destinations
            assert adapter_call(sender, origin_token, 'POST', '/adapter/v1/send',
                                {'destination': 'review', 'request_id': 'request_' + secrets.token_hex(16),
                                 'content': 'x'})[0] == 403
            delegated_id = task_id()
            assert adapter_call(sender, origin_token, 'POST', '/adapter/v1/delegations',
                                {'destination': 'chat', 'task_id': delegated_id, 'input': 'x'})[0] == 403
            status, delegated = adapter_call(sender, origin_token, 'POST', '/adapter/v1/delegations',
                                             {'destination': 'review', 'task_id': delegated_id, 'input': 'please review'},
                                             timeout=12)
            assert status == 200 and delegated['submit_state'] == 'accepted', delegated
            assert delegated['adapter_id'] == origin_secret['adapter']['id'] and delegated['route_id'] == route['id']
            assert delegated['request']['origin'] == {'agent_id': author['id'], 'session_id': origin_session['id']}
            assert adapter_call(sender, origin_token, 'POST', '/adapter/v1/delegations',
                                {'destination': 'review', 'task_id': delegated_id, 'input': 'changed'})[0] == 409
            status, destinations = adapter_call(sender, origin_token, 'GET', '/adapter/v1/destinations')
            assert [d['messages_remaining'] for d in destinations] == [100, 2], destinations
            handoff = claim(receiver, token)
            assert handoff['task']['origin'] == delegated['request']['origin'], handoff
            act(receiver, token, delegated_id, 'accept')
            act(receiver, token, delegated_id, 'complete', {'status': 'succeeded', 'output': 'approved'})
            updates = []

            def next_update():
                status, value = adapter_call(sender, origin_token, 'POST', '/adapter/v1/task-updates/next', {})
                assert status == 200, value
                if value:
                    assert set(value) == {'delivery', 'event'} and set(value['delivery']) == NOTIFICATION_KEYS, value
                    assert value['delivery']['session_id'] == origin_session['id'] and value['delivery']['state'] == 'unknown'
                    updates.append(value)
                return len(updates) == 3
            wait_for(next_update, timeout=POLL, message='task updates')
            assert [u['event']['kind'] for u in updates] == ['queued', 'accepted', 'succeeded'], updates
            assert updates[-1]['event']['output'] == 'approved'
            for u in updates:
                path = f"/adapter/v1/task-updates/{u['delivery']['id']}/forwarded"
                assert adapter_call(sender, other_token(sender, author), 'POST', path, {})[0] in (403, 404)
                status, acked = adapter_call(sender, origin_token, 'POST', path, {})
                assert status == 200 and acked['state'] == 'forwarded', acked
            # Events may be stored before the status record that names them catches up.
            record = wait_for(lambda: (r := adapter_call(sender, origin_token, 'GET', f'/adapter/v1/delegations/{delegated_id}'))[0] == 200
                              and r[1]['status']['state'] == 'succeeded' and r[1], timeout=POLL, message='delegated status')
            assert set(record) == LOCAL_KEYS, record
            assert adapter_call(sender, origin_token, 'GET', f'/adapter/v1/delegations/{task_id()}')[0] == 404
            # Owner submissions are never handed to sessions.
            assert adapter_call(sender, origin_token, 'POST', '/adapter/v1/task-updates/next', {}) == (200, None)

            if node:
                check_mcp(sender, receiver, a, b, node, script, root, channels)
        finally:
            for channel in channels:
                channel.close()
            stop_all(hosts)
    print(f'PASS {label}: task.submit grants, duplicate/conflict, lost response retry, lifecycle, rejection, '
          'expiry, failure, cancellation, restarts, session isolation, revocation, submitter-only lookup, '
          'delegate routes with task updates' + (', MCP tools' if node else ''), flush=True)


def other_token(host, agent):
    """A credential for another session, used to show isolation."""
    if not hasattr(host, '_task_other'):
        stranger = host.cli('agent', 'register', '--name', 'bystander', '--owner', 'quinn')
        host._task_other = adapter_for(host, stranger)[1]['token']
    return host._task_other


def tool(channel, name, arguments):
    result = channel.call('tools/call', {'name': name, 'arguments': arguments}, seconds=15)
    text = result['content'][0]['text']
    try:
        return result.get('isError', False), json.loads(text)
    except json.JSONDecodeError:
        return result.get('isError', False), text


def channel_event(channel, kind, seconds=POLL):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            event = channel.notification()
        except AssertionError:
            continue
        if event['meta']['kind'] == kind:
            return event
    raise AssertionError(f'no {kind} event')


def check_mcp(sender, receiver, a, b, node, script, root, channels):
    """delegate_task and the task tools through the real MCP subprocess."""
    helper = receiver.cli('agent', 'register', '--name', 'helper', '--owner', 'pat')
    delegator = sender.cli('agent', 'register', '--name', 'delegator', '--owner', 'quinn')
    grant = task_grant(receiver, a, helper)
    helper_session, helper_secret = adapter_for(receiver, helper, 'claude-channel')
    delegator_session, delegator_secret = adapter_for(sender, delegator, 'claude-channel')
    sender.cli('adapter', 'route', 'add', '--adapter', delegator_secret['adapter']['id'], '--name', 'helper',
               '--peer', b['id'], '--agent', helper['id'], '--grant', grant['id'], '--action', 'task.submit',
               '--expires-at', timestamp(900))
    worker = Channel(node, script, receiver, helper_secret, root / 'helper-channel')
    channels.append(worker)
    origin = Channel(node, script, sender, delegator_secret, root / 'delegator-channel')
    channels.append(origin)
    failed, submitted = tool(origin, 'delegate_task', {'destination': 'helper', 'input': 'count the files'})
    assert not failed and submitted['submit_state'] == 'accepted' and submitted['state'] == 'queued', submitted
    tid = submitted['task_id']
    task = channel_event(worker, 'task')
    assert task['content'] == 'count the files' and task['meta']['task_id'] == tid, task
    assert task['meta']['origin_agent_id'] == delegator['id'], task
    assert task['meta']['origin_session_id'] == delegator_session['id'], task
    assert task['meta']['session_id'] == helper_session['id'], task
    assert not tool(worker, 'task_accept', {'task_id': tid})[0]
    assert not tool(worker, 'task_progress', {'task_id': tid, 'message': 'counting'})[0]
    failed, refused = tool(worker, 'task_cancelled', {'task_id': tid})
    assert failed, refused
    failed, status = tool(origin, 'task_status', {'task_id': tid})
    assert not failed and status['request']['task_id'] == tid, status
    sender.cli('task', 'cancel', '--peer', b['id'], tid)
    cancel = channel_event(worker, 'task_cancel_requested')
    assert cancel['meta']['task_id'] == tid, cancel
    assert not tool(worker, 'task_complete', {'task_id': tid, 'status': 'succeeded', 'output': '42 files'})[0]
    seen = []
    while not seen or seen[-1]['meta']['state'] != 'succeeded':
        seen.append(channel_event(origin, 'task_update'))
    assert [e['meta']['event_kind'] for e in seen] == ['queued', 'accepted', 'progress', 'cancel_requested',
                                                       'succeeded'], seen
    assert seen[-1]['content'] == '42 files' and seen[2]['content'] == 'counting', seen
    failed, absent = tool(origin, 'task_status', {'task_id': task_id()})
    assert not failed and absent['submit_state'] == 'not_recorded', absent
    assert tool(worker, 'task_accept', {'task_id': 'task_bad'})[0]


def policy_check(coord_binary, owner_binary, sender_binary, label):
    """task.submit in an owner policy authorizes tasks without a grant."""
    from persons import Agent, person_id, ssh_key, use_agent
    from policy import PolicyHost
    import os
    with tempfile.TemporaryDirectory(prefix='peerspan-task-policy-') as temporary:
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
            a = ids[alice]

            # No policy: refused locally before anything is persisted.
            assert 'policy' in submit(bob, a, reviewer, success=False)
            assert bob.cli('task', 'list') == []
            # A message-only rule refuses tasks.
            use_agent(agents['pat'])
            v1 = alice.cli('access', 'allow', '--network', net, '--agent', 'reviewer', '--principal', 'network',
                           '--max-message-bytes', '100', '--allow-disconnected')
            assert v1['rules'][0]['actions'] == ['message.append'], v1
            bob.cli('network', 'sync', net)
            refused = submit(bob, a, reviewer)
            assert refused['submit_state'] == 'rejected' and 'HTTP 403' in refused['error'], refused
            assert refused['request']['grant_id'] is None and refused['request']['policy']['version'] == 1, refused
            # task.submit in the rule allows them, bounded by max_message_bytes.
            alice.cli('access', 'allow', '--network', net, '--agent', 'reviewer', '--principal', 'network',
                      '--action', 'bogus', '--max-message-bytes', '100', success=False)
            v2 = alice.cli('access', 'allow', '--network', net, '--agent', 'reviewer', '--principal', 'person:quinn',
                           '--action', 'message.append', '--action', 'task.submit', '--max-message-bytes', '100',
                           '--allow-disconnected')
            assert v2['rules'][0]['actions'] == ['message.append', 'task.submit'], v2
            bob.cli('network', 'sync', net)
            accepted = submit(bob, a, reviewer, text='by policy')
            assert accepted['submit_state'] == 'accepted' and accepted['request']['policy'] == {
                'person_id': person_id(keys['pat'][2]), 'version': 2}, accepted
            assert submit(bob, a, reviewer, text='x' * 101)['submit_state'] == 'rejected'
            # A policy-cited task is rechecked at handoff: denial rejects it.
            pending = submit(bob, a, reviewer, text='pending')['request']['task_id']
            session = alice.cli('session', 'attach', '--agent', reviewer['id'], '--integration', 'test')
            token = credential(alice, session)['token']
            handoff = claim(alice, token)
            assert handoff['task']['task_id'] == accepted['request']['task_id'], handoff
            assert handoff['sender_person'] == 'quinn' and handoff['task']['policy']['version'] == 2, handoff
            alice.cli('access', 'deny', '--network', net, '--agent', 'reviewer', '--principal', 'person:quinn')
            assert claim(alice, token) is None
            act(alice, token, accepted['request']['task_id'], 'accept', expect=403)
            for tid in (pending, accepted['request']['task_id']):
                until_state(bob, a, tid, 'rejected')
                assert events(bob, a, tid)[-1]['message'] == LAPSED
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
    print(f'PASS {label}: policy task.submit authorizes tasks without grants; message-only rules refuse them; '
          'denial rejects queued tasks at handoff', flush=True)


def migration_check(original, replacement, label):
    with tempfile.TemporaryDirectory(prefix='peerspan-task-migration-') as directory:
        host = Host(original, Path(directory) / 'host')
        try:
            identity = host.start()
            agent = host.cli('agent', 'register', '--name', 'kept', '--owner', 'pat')
            host.stop()
            for table in [*LINKING_TABLES, *AGENT_CALL_TABLES, *POLICY_EDIT_TABLES, *CAPABILITY_TABLES, *POLICY_DELIVERY_TABLES, *DELEGATION_TABLES, *ARTIFACT_TABLES, *TASK_TABLES]:
                sql(host, 'DROP TABLE ' + table)
            sql(host, 'PRAGMA user_version = 8')
            host.binary = str(replacement)
            assert host.start()['id'] == identity['id']
            assert sql(host, 'PRAGMA user_version')[0][0] == SCHEMA_VERSION
            assert {row[0] for row in sql(host, "SELECT name FROM sqlite_master WHERE type = 'table'")} >= set(TASK_TABLES)
            assert host.cli('agent', 'inspect', agent['id']) == agent
            assert host.cli('task', 'list') == []
            host.stop()
            # A newer version is refused, without changes.
            sql(host, f'PRAGMA user_version = {SCHEMA_VERSION + 1}')
            for binary in (original, replacement):
                result = subprocess.run([str(binary), '--state', str(host.state), 'run'], capture_output=True, timeout=5)
                assert result.returncode != 0 and sql(host, 'PRAGMA user_version')[0][0] == SCHEMA_VERSION + 1
        finally:
            stop_all((host,))
    print(f'PASS {label}: v8→v{SCHEMA_VERSION} migration; version {SCHEMA_VERSION + 1} refused', flush=True)


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
    migration_check(binaries['Go'], binaries['Rust'], 'Go→Rust')
    migration_check(binaries['Rust'], binaries['Go'], 'Rust→Go')
    for first in binaries:
        for second in binaries:
            if args.pairing and f'{first}/{second}' not in args.pairing:
                continue
            check(binaries[first], binaries[second], node, script, f'{first} submitter, {second} receiver')
            if not args.skip_policy:
                policy_check(args.coord.resolve(), binaries[second], binaries[first],
                             f'{second} owner, {first} submitter')


if __name__ == '__main__':
    main()
