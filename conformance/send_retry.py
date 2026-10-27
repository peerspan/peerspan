#!/usr/bin/env python3
"""Check automatic retry of uncertain sends across real Go/Rust daemons.

No case below calls `message retry`: the sending daemon must recover each
uncertain outcome by itself, with the same request ID, and the receiver must
hold exactly one copy. Uses temporary state, Python's standard library, the
Go coordinator, and the peerspan-peer-probe test client.
"""
import argparse
import concurrent.futures
from pathlib import Path
import tempfile
import time

from agent_adapter import adapter_call, credential
from support import CoordHost, Coordinator, INTERVAL
from peer_messaging import DropResponse, PeerHost, request_id, set_probe, timestamp
from adapter_outbound import route


def stop_all(hosts):
    """Stop every host even if one fails to stop, then raise the first failure."""
    failure = None
    for host in hosts:
        try:
            host.stop()
        except Exception as error:
            failure = failure or error
        finally:
            host.logs.close()
    if failure is not None:
        raise failure


def wait_until(check, seconds, message):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        value = check()
        if value:
            return value
        time.sleep(0.2)
    raise AssertionError(f'timed out waiting for {message}')


def inspect(sender, peer, rid):
    return sender.cli('message', 'inspect', '--peer', peer['id'], rid)


def copies(receiver, rid):
    return sum(1 for m in receiver.cli('message', 'list') if m['request']['request_id'] == rid)


def accepted_automatically(sender, receiver, peer, rid, seconds):
    out = wait_until(lambda: (r := inspect(sender, peer, rid))['state'] == 'accepted' and r,
                     seconds, f'automatic acceptance of {rid}')
    assert out['next_attempt_at'] is None and out['attempts'] >= 2, out
    assert copies(receiver, rid) == 1
    return out


def direct_cases(sender_binary, receiver_binary):
    with tempfile.TemporaryDirectory(prefix='peerspan-retry-') as directory:
        root = Path(directory)
        sender, receiver = PeerHost(sender_binary, root / 'sender'), PeerHost(receiver_binary, root / 'receiver')
        try:
            a, b = sender.start(), receiver.start()
            sender.configure(receiver, b)
            receiver.configure(sender, a)
            agent = receiver.cli('agent', 'register', '--name', 'target', '--owner', 'receiver')
            grant = receiver.grant(a, agent)

            # A lost response: the receiver commits, the receipt never arrives.
            rid = request_id()
            relay = DropResponse(receiver, rid)
            sender.configure(receiver, b, relay.address)
            lost = sender.submit(b, agent, grant, rid=rid)
            relay.close()
            assert lost['state'] == 'unknown' and lost['attempts'] == 1 and lost['next_attempt_at'], lost
            sender.configure(receiver, b)
            accepted_automatically(sender, receiver, b, rid, 30)

            # A receiver that is down when the send is made, then comes back.
            receiver.stop()
            rid = request_id()
            offline = sender.submit(b, agent, grant, rid=rid)
            assert offline['state'] == 'unknown' and offline['next_attempt_at'], offline
            time.sleep(1)
            receiver.start()
            accepted_automatically(sender, receiver, b, rid, 40)

            # A rejection is final and never retried.
            small = receiver.grant(a, agent, size=4)
            rejected = sender.submit(b, agent, small, content='too long for this grant')
            assert rejected['state'] == 'rejected' and rejected['next_attempt_at'] is None, rejected
            time.sleep(3)
            again = inspect(sender, b, rejected['request']['request_id'])
            assert again['state'] == 'rejected' and again['attempts'] == rejected['attempts'], again

            # After the deadline, attempts only query the receipt: the request is
            # never resubmitted, so the receiver never stores it.
            receiver.stop()
            rid = request_id()
            late = sender.submit(b, agent, grant, rid=rid, deadline=timestamp(3))
            assert late['state'] == 'unknown', late
            time.sleep(6)
            receiver.start()
            before = inspect(sender, b, rid)['attempts']
            wait_until(lambda: inspect(sender, b, rid)['attempts'] > before, 40, 'a receipt query after the deadline')
            assert copies(receiver, rid) == 0
            assert inspect(sender, b, rid)['state'] == 'unknown'

            # Restart: overdue records resume spread over the startup window
            # instead of all at once, and every one is eventually attempted.
            receiver.stop()
            with concurrent.futures.ThreadPoolExecutor(5) as pool:
                pending = list(pool.map(lambda _: sender.submit(b, agent, grant, deadline=timestamp(900)), range(5)))
            ids = [out['request']['request_id'] for out in pending]
            sender.stop(crash=True)
            time.sleep(4)  # every record is now overdue
            before = {rid: inspect_offline(sender, b, rid) for rid in ids}
            sender.start()
            time.sleep(1)
            early = sum(1 for rid in ids if inspect(sender, b, rid)['attempts'] > before[rid])
            assert early <= 2, f'{early} of 5 overdue records attempted in the first second after restart'
            receiver.start()
            for rid in ids:
                accepted_automatically(sender, receiver, b, rid, 60)
        finally:
            stop_all((sender, receiver))


def inspect_offline(sender, peer, rid):
    """Read a record's attempts from the sender's database while it is stopped."""
    import json
    import sqlite3
    connection = sqlite3.connect(sender.state / 'host.db')
    try:
        record = connection.execute('SELECT record FROM outbound_messages WHERE peer = ? AND request_id = ?',
                                    (peer['id'], rid)).fetchone()[0]
    finally:
        connection.close()
    return json.loads(record).get('attempts', 0)


def adapter_case(sender_binary, receiver_binary):
    """An agent's uncertain send resolves through send_status, using one budget unit."""
    with tempfile.TemporaryDirectory(prefix='peerspan-retry-agent-') as directory:
        root = Path(directory)
        sender, receiver = PeerHost(sender_binary, root / 'sender'), PeerHost(receiver_binary, root / 'receiver')
        try:
            a, b = sender.start(), receiver.start()
            sender.configure(receiver, b)
            receiver.configure(sender, a)
            target = receiver.cli('agent', 'register', '--name', 'target', '--owner', 'receiver')
            grant = receiver.grant(a, target)
            mine = sender.cli('agent', 'register', '--name', 'origin', '--owner', 'sender')
            session = sender.cli('session', 'attach', '--agent', mine['id'], '--integration', 'test')
            secret = credential(sender, session)
            route(sender, secret, b, target, grant, budget=5)

            def remaining():
                status, items = adapter_call(sender, secret['token'], 'GET', '/adapter/v1/destinations')
                assert status == 200, items
                return items[0]['messages_remaining']

            receiver.stop()
            rid = request_id()
            status, out = adapter_call(sender, secret['token'], 'POST', '/adapter/v1/send',
                                       {'destination': 'remote', 'request_id': rid, 'content': 'from an agent'}, timeout=15)
            assert status == 200 and out['state'] == 'unknown', out
            assert remaining() == 4
            status, missing = adapter_call(sender, secret['token'], 'GET', '/adapter/v1/sends/' + request_id())
            assert status == 404, missing
            receiver.start()

            def resolved():
                status, value = adapter_call(sender, secret['token'], 'GET', '/adapter/v1/sends/' + rid)
                assert status == 200, value
                return value['state'] == 'accepted' and value

            done = wait_until(resolved, 40, 'send_status to report accepted')
            assert done['destination'] == 'remote' and done['attempts'] >= 2 and done['next_attempt_at'] is None, done
            assert remaining() == 4, 'automatic retries consumed budget'
            assert copies(receiver, rid) == 1
        finally:
            stop_all((sender, receiver))


def connected_case(coord_binary, sender_binary, receiver_binary):
    """A 503 from a receiver whose coordination went stale resolves automatically."""
    with tempfile.TemporaryDirectory(prefix='peerspan-retry-coord-') as directory:
        root = Path(directory)
        coord = Coordinator(coord_binary, root / 'coord')
        alice, bob = CoordHost(receiver_binary, root / 'alice'), CoordHost(sender_binary, root / 'bob')
        try:
            coordinator = coord.start()
            a, b = alice.start(), bob.start()
            network = alice.cli('network', 'create', '--name', 'team', '--member', 'alice',
                                '--coordinator', coord.address, '--coordinator-key', coordinator['public_key'])
            invite = alice.cli('network', 'invite', '--network', network['id'], '--member', 'bob', '--expires-at', timestamp(600))
            bob.cli('network', 'join', '--token', invite['token'])
            alice.cli('network', 'sync', network['id'])
            agent = alice.cli('agent', 'register', '--name', 'target', '--owner', 'alice')
            grant = alice.cli('grant', 'create', '--peer', b['id'], '--agent', agent['id'], '--expires-at', timestamp(1200))
            coord.stop()
            wait_until(lambda: alice.cli('network', 'list')[0]['last_sync_error'] is not None, 15, 'sync failure')
            time.sleep(3 * INTERVAL + 1)
            rid = request_id()
            stale = bob.cli('message', 'send', '--peer', a['id'], '--grant', grant['id'], '--agent', agent['id'],
                            '--deadline', timestamp(), '--content', 'while stale', '--request', rid)
            assert stale['state'] == 'unknown' and 'HTTP 503' in stale['error'] and stale['next_attempt_at'], stale
            coord.start()
            accepted_automatically(bob, alice, a, rid, 60)
        finally:
            stop_all((alice, bob))
            coord.stop()
            coord.logs.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--coord', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True, help='peerspan-peer-probe test client')
    args = parser.parse_args()
    set_probe(args.probe)
    binaries = {'Go': args.go.resolve(), 'Rust': args.rust.resolve()}
    for sender in binaries:
        for receiver in binaries:
            label = f'{sender}→{receiver}'
            direct_cases(binaries[sender], binaries[receiver])
            adapter_case(binaries[sender], binaries[receiver])
            connected_case(args.coord.resolve(), binaries[sender], binaries[receiver])
            print(f'PASS {label}: lost response, offline receiver, stale coordination (503), and agent sends '
                  'accepted automatically once; rejections final; refresh-only after the deadline; '
                  'no burst after restart', flush=True)


if __name__ == '__main__':
    main()
