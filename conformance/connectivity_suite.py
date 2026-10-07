#!/usr/bin/env python3
"""Run Capsule/iroh connectivity in disposable routed, NAT and relay fixtures.

Requires Linux root, iproute2, nftables, tc, conntrack and tcpdump. Uses only
self-hosted fixture infrastructure. Every failed/censored attempt is retained.
Control sockets are private Unix sockets; checked peer payloads cross the
actual production Capsule transport or pinned iroh. No echo route ships.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import signal
import socket
import statistics
import subprocess
import tempfile
import time

from connectivity_bench import ROOT, build, digest, distribution, execute
from host_service import UnixHTTPConnection, die_with_parent
from nat_lab import Lab
from peer_messaging import timestamp

PAIRS = {'go-go': ('capsule-go', 'capsule-go'), 'go-rust': ('capsule-go', 'capsule-rust'),
         'rust-go': ('capsule-rust', 'capsule-go'), 'rust-rust': ('capsule-rust', 'capsule-rust'),
         'iroh': ('iroh-rust-1.3.0', 'iroh-rust-1.3.0'),
         'iroh-bounds': ('iroh-rust-1.3.0', 'iroh-rust-1.3.0')}
SCENARIOS = ('direct-ipv4', 'direct-ipv6', 'delay-loss', 'mtu-1280', 'cone', 'random-port',
             'udp-blocked', 'asymmetric-udp', 'nested-nat', 'nat-rebinding', 'mapping-expiry', 'peer-address-change')


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def verified_exchange_seconds(exchange, bound, message):
    """A successful exchange must finish within the bound, including its last attempt."""
    started = time.monotonic()
    while True:
        result = exchange()
        elapsed = time.monotonic() - started
        check(elapsed <= bound, message)
        if result.get('succeeded') == 1:
            return elapsed
        time.sleep(0.2)


def reusable_rows(previous, current, scenarios, pairs):
    """Reuse only trials belonging to this requested matrix and evidence profile."""
    check(previous['binary_sha256'] == current['binary_sha256'], 'resume binary hashes differ; run a new complete matrix')
    check(previous['harness_sha256'] == current['harness_sha256'], 'resume harness sources differ; run a new complete matrix')
    for name in ('count', 'nat_repeats', 'no_capture'):
        check(previous['parameters'][name] == current['parameters'][name], f'resume {name} differs')
    seen = set()
    for row in previous['cases']:
        repeats = current['parameters']['nat_repeats'] if row['scenario'] in ('cone', 'random-port', 'udp-blocked') else 1
        key = (row['scenario'], row['pair'], row['repeat'])
        if (row['status'] == 'passed' and row['scenario'] in scenarios and row['pair'] in pairs
                and 1 <= row['repeat'] <= repeats and key not in seen):
            seen.add(key)
            yield row


class Fixture(Lab):
    def __init__(self, root, scenario):
        super().__init__(root, nat='symmetric' if scenario == 'random-port' else 'cone',
                         block_udp=scenario == 'udp-blocked')
        self.scenario = scenario
        if scenario == 'nested-nat':
            self.ns['innerA'] = f'cap{self.tag}innerA'

    def veth(self, left_role, left_name, right_role, right_name):
        if self.scenario == 'nested-nat' and left_role == 'natA' and right_role == 'hostA':
            super().veth('natA', left_name, 'innerA', 'wan')
            super().veth('innerA', 'lan', 'hostA', right_name)
        else:
            super().veth(left_role, left_name, right_role, right_name)

    def up(self):
        super().up()
        if self.scenario == 'nested-nat':
            self.run('hostA', 'ip', 'addr', 'flush', 'dev', 'eth0')
            self.run('hostA', 'ip', 'route', 'flush', 'dev', 'eth0')
            self.run('hostA', 'ip', 'addr', 'add', '10.11.0.2/24', 'dev', 'eth0')
            self.run('hostA', 'ip', 'route', 'add', 'default', 'via', '10.11.0.1')
            for device, address in [('wan', '10.1.0.2/24'), ('lan', '10.11.0.1/24')]:
                self.run('innerA', 'ip', 'addr', 'add', address, 'dev', device)
                self.run('innerA', 'ip', 'link', 'set', device, 'up')
            self.run('innerA', 'ip', 'route', 'add', 'default', 'via', '10.1.0.1')
            self.run('innerA', 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
            rules = ('table ip nat { chain post { type nat hook postrouting priority 100; oifname "wan" masquerade; }; }\n'
                     'table ip filter { chain input { type filter hook input priority 0; policy drop; '
                     'ct state established,related accept; iifname { "lo", "lan" } accept; }; '
                     'chain forwarding { type filter hook forward priority 0; policy drop; '
                     'ct state established,related accept; iifname "lan" oifname "wan" accept; }; }\n')
            path = self.root / 'inner.nft'
            path.write_text(rules)
            self.run('innerA', 'nft', '-f', str(path))
        if self.scenario in ('direct-ipv4', 'direct-ipv6', 'delay-loss', 'mtu-1280', 'peer-address-change'):
            # Two routed hosts; no NAT and no static port forwards.
            for role in ('natA', 'natB'):
                self.run(role, 'nft', 'flush', 'ruleset')
            self.run('pub', 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
            for side, network, public in [('A', '10.1.0.0/24', '203.0.113.10'), ('B', '10.2.0.0/24', '203.0.113.20')]:
                self.run('pub', 'ip', 'route', 'add', network, 'via', public)
                self.run('nat' + side, 'ip', 'route', 'add', 'default', 'via', '203.0.113.1')
        if self.scenario == 'direct-ipv6':
            self.run('pub', 'ip', '-6', 'addr', 'add', 'fd00:0::1/64', 'dev', 'br0')
            for side, number in [('A', 1), ('B', 2)]:
                self.run('nat' + side, 'ip', '-6', 'addr', 'add', f'fd00:0::{number + 10}/64', 'dev', 'wan')
                self.run('nat' + side, 'ip', '-6', 'addr', 'add', f'fd00:{number}::1/64', 'dev', 'lan')
                self.run('host' + side, 'ip', '-6', 'addr', 'add', f'fd00:{number}::2/64', 'dev', 'eth0')
                self.run('host' + side, 'ip', '-6', 'route', 'add', 'default', 'via', f'fd00:{number}::1')
                self.run('nat' + side, 'ip', '-6', 'route', 'add', 'default', 'via', 'fd00:0::1')
                self.run('pub', 'ip', '-6', 'route', 'add', f'fd00:{number}::/64', 'via', f'fd00:0::{number + 10}')
                self.run('nat' + side, 'sysctl', '-qw', 'net.ipv6.conf.all.forwarding=1')
            self.run('pub', 'sysctl', '-qw', 'net.ipv6.conf.all.forwarding=1')
            # Wait for declared IPv6 addresses to complete duplicate address detection.
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if all('tentative' not in self.run(role, 'ip', '-6', 'addr', 'show').stdout for role in self.ns):
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError('IPv6 address readiness timed out')
        if self.scenario == 'delay-loss':
            for role in ('natA', 'natB'):
                self.run(role, 'tc', 'qdisc', 'add', 'dev', 'wan', 'root', 'netem', 'delay', '20ms', '2ms', 'loss', '1%')
        if self.scenario == 'mtu-1280':
            for role, devices in [('hostA', ['eth0']), ('hostB', ['eth0']), ('natA', ['lan', 'wan']),
                                  ('natB', ['lan', 'wan']), ('pub', ['br0', 'toA', 'toB'])]:
                for device in devices:
                    self.run(role, 'ip', 'link', 'set', device, 'mtu', '1280')
        if self.scenario == 'asymmetric-udp':
            self.run('natA', 'nft', 'insert', 'rule', 'ip', 'filter', 'forwarding',
                     'iifname', 'lan', 'oifname', 'wan', 'ip', 'daddr', '203.0.113.20', 'meta', 'l4proto', 'udp', 'drop')

    @property
    def relayed(self):
        return self.scenario not in ('direct-ipv4', 'direct-ipv6', 'delay-loss', 'mtu-1280', 'peer-address-change')

    def address(self, side, port=7401):
        if self.relayed:
            return ''
        if self.scenario == 'direct-ipv6':
            return f'[fd00:{1 if side == "A" else 2}::2]:{port}'
        return f'10.{1 if side == "A" else 2}.0.2:{port}'

    def rebind(self):
        self.run('natA', 'ip', 'addr', 'del', '203.0.113.10/24', 'dev', 'wan')
        self.run('natA', 'ip', 'addr', 'add', '203.0.113.11/24', 'dev', 'wan')
        self.expire('natA')

    def expire(self, role):
        result = self.run(role, 'conntrack', '-D', '-p', 'udp', check=False)
        check(result.returncode in (0, 1), f'conntrack deletion failed: {result.stderr}')


class Process:
    def __init__(self, lab, role, argv, state, env, name):
        self.lab, self.role, self.argv, self.state, self.env, self.name = lab, role, argv, state, env, name
        self.process, self.generation = None, 0

    def start(self):
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.generation += 1
        log = self.lab.root / f'{self.name}-{self.generation}.log'
        with log.open('w') as stream:
            self.process = subprocess.Popen(['ip', 'netns', 'exec', self.lab.ns[self.role], *self.argv],
                                            env=self.env, stdout=stream, stderr=subprocess.STDOUT,
                                            preexec_fn=die_with_parent)
        return self

    def ready(self, relay=False):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            check(self.process.poll() is None, f'{self.name} exited; inspect process log')
            try:
                if relay:
                    if self.lab.reachable('pub', '203.0.113.1', 7400):
                        return None
                else:
                    value = self.cmd(op='info')
                    if value.get('id'):
                        return value
            except (OSError, ValueError):
                pass
            time.sleep(0.05)
        raise RuntimeError(f'{self.name} readiness timed out')

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)

    def call(self, method, path, body=None):
        connection = UnixHTTPConnection(self.state / 'admin.sock', timeout=240)
        try:
            connection.request(method, path, json.dumps(body).encode() if body is not None else None,
                               {'Content-Type': 'application/json'})
            response = connection.getresponse()
            result = json.loads(response.read())
            check(response.status in (200, 201), f'{self.name}: HTTP {response.status}: {result}')
            return result
        finally:
            connection.close()

    def cmd(self, **body):
        return self.call('POST', '/bench', body)

    def resource(self):
        if self.process is None or self.process.poll() is not None:
            return None
        pid = self.process.pid
        stat = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        status = Path(f'/proc/{pid}/status').read_text().splitlines()
        memory = {line.split(':')[0]: int(line.split()[1]) for line in status if line.startswith(('VmRSS:', 'VmHWM:'))}
        return {'cpu_seconds': (int(stat[11]) + int(stat[12])) / os.sysconf('SC_CLK_TCK'),
                'rss_kib': memory.get('VmRSS'), 'peak_rss_kib': memory.get('VmHWM'), 'pid': pid}


def counters(lab):
    output = {}
    for role, device in [('hostA', 'eth0'), ('hostB', 'eth0'), ('pub', 'br0')]:
        links = json.loads(lab.run(role, 'ip', '-s', '-j', 'link', 'show', 'dev', device).stdout)
        stats = links[0].get('stats64', links[0].get('stats', {}))
        output[role] = stats
    return output


def configure_pin(node, peer, iroh):
    if iroh:
        return node.cmd(op='pin', target=peer)
    return node.call('POST', '/v1/peers', peer)


def run_case(root, helpers, coord_binary, pair, scenario, repeat, count, capture):
    root.mkdir(mode=0o700)
    # Unix socket paths have a fixed kernel length limit. Artifact directory
    # names must not become a hidden prerequisite of an endpoint implementation.
    runtime=tempfile.TemporaryDirectory(prefix='capnet-')
    state_root=Path(runtime.name)
    lab = Fixture(root, scenario)
    a_backend, b_backend = PAIRS[pair]
    iroh = pair.startswith('iroh')
    processes, captures, events = [], [], []
    row = {'pair': pair, 'scenario': scenario, 'repeat': repeat, 'status': 'running', 'events': events,
           'artifact_directory': root.name, 'host_load_before': list(os.getloadavg())}
    checkpoint = lambda: (root / 'case.json').write_text(json.dumps(row, indent=2) + '\n')
    def event(name, **fields):
        events.append({'name': name, 'since_case_start_seconds': time.monotonic() - started, **fields})
        checkpoint()
    started = time.monotonic()
    try:
        lab.up()
        row['namespaces'] = lab.ns
        env = dict(os.environ, GOMAXPROCS='4')
        env.pop('SSH_AUTH_SOCK', None)
        relay_state = state_root / 'relay'
        relay = None
        if lab.relayed:
            if iroh:
                relay_env = dict(env, CAPSULE_NET_MODE='relay', CAPSULE_NET_STATE=str(relay_state))
                relay = Process(lab, 'pub', helpers[a_backend][:1], relay_state, relay_env, 'relay').start()
            else:
                relay = Process(lab, 'pub', [str(coord_binary), '--state', str(relay_state), 'run', '--listen', '203.0.113.1:7400'],
                                relay_state, env, 'coordinator').start()
            processes.append(relay)
            relay.ready(relay=True)
        def node(backend, side, name, port=7401):
            state = state_root / name
            node_env = dict(env, CAPSULE_NET_STATE=str(state), CAPSULE_NET_BIND=f'[::]:{port}' if scenario == 'direct-ipv6' else f'0.0.0.0:{port}')
            if backend.startswith('iroh'):
                node_env['CAPSULE_NET_MODE'] = 'node'
                if pair == 'iroh-bounds':
                    node_env['CAPSULE_IROH_MATCHED']='1'
                argv = helpers[backend][:1]
                if relay:
                    node_env.update(CAPSULE_NET_RELAY='https://203.0.113.1:7400', CAPSULE_NET_CA=str(relay_state / 'relay-cert.der'))
            elif backend == 'capsule-go':
                argv = [helpers[backend][0], '-test.run=^TestConnectivityNetworkHelper$', '-test.timeout=3600s']
            else:
                argv = [helpers[backend][0], 'quic::connectivity_network::connectivity_network_helper', '--exact', '--ignored', '--nocapture']
            process = Process(lab, 'host' + side, argv, state, node_env, name).start()
            processes.append(process)
            return process, process.ready()
        alice, a = node(a_backend, 'A', 'alice')
        bob, b = node(b_backend, 'B', 'bob')
        a = {**a, 'address': lab.address('A')}
        b = {**b, 'address': lab.address('B')}
        # Only the minimal identity fields go into pin requests.
        a = {k: a[k] for k in ('id', 'public_key', 'address')}
        b = {k: b[k] for k in ('id', 'public_key', 'address')}
        row['identities'] = {'alice': dict(a), 'bob': dict(b)}
        if iroh:
            configure_pin(alice, b, True)
            configure_pin(bob, a, True)
            if relay:
                (relay_state / 'allow.json').write_text(json.dumps([a['id'], b['id']]))
        elif relay:
            info = json.loads(lab.run('pub', str(coord_binary), '--state', str(relay_state), 'info').stdout)
            network = alice.call('POST', '/v1/networks', {'name': 'comparison', 'member': 'alice',
                                'coordinator_address': '203.0.113.1:7400', 'coordinator_public_key': info['public_key']})
            invite = alice.call('POST', f"/v1/networks/{network['id']}/invites", {'member': 'bob', 'expires_at': timestamp(1200), 'host_only': True})
            bob.call('POST', '/v1/networks/join', {'token': invite['token']})
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if len(alice.call('GET', f"/v1/networks/{network['id']}/members")) == 2:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError('membership readiness timed out')
        else:
            configure_pin(alice, b, False)
            configure_pin(bob, a, False)
        if capture:
            for role in ('hostA', 'hostB', 'pub'):
                path = root / f'{role}.pcap'
                with (root / f'{role}-capture.log').open('w') as log:
                    p = subprocess.Popen(['ip', 'netns', 'exec', lab.ns[role], 'tcpdump', '-U', '-n', '-i', 'any',
                                          '-s', '128', '-C', '2', '-W', '1', '-w', str(path), 'udp or tcp'], stdout=log, stderr=log)
                captures.append(p)
            row['capture'] = '128-byte snapshots; 2 MB ring per role; may overwrite early packets; any-interface captures may duplicate packets'
        row['network_before'] = counters(lab)
        def exchange(sender=alice, destination=b, label='exchange', n=1, concurrency=1, size=16, expected_failure=False, **extra):
            resources_before = {p.name: p.resource() for p in processes}
            attempts=[];wall=0.0;errors=[]
            # Checkpoint small bounded batches. A broken path must not erase
            # minutes of failed attempts by timing out the control HTTP call.
            batch=max(1,min(n,max(4,concurrency*2)))
            for offset in range(0,n,batch):
                part=sender.cmd(op='run',peer_id=destination['id'],count=min(batch,n-offset),concurrency=concurrency,size=size,
                                token=secrets.token_hex(8),**extra)
                for attempt in part.get('attempts',[]):
                    attempts.append(dict(attempt,index=attempt['index']+offset))
                wall+=part.get('wall_seconds',0.0)
                if part.get('error'):errors.append(part['error'])
                event(label+'-batch',result=part,offset=offset,expected_failure=expected_failure)
                if part.get('failed',0) and not expected_failure:break
            succeeded=sum(bool(v['verified']) for v in attempts)
            attempted=len(attempts)
            result={'attempts':attempts,'succeeded':succeeded,'failed':attempted-succeeded,'count':attempted,
                    'requested_count':n,'not_attempted':n-attempted,'concurrency':concurrency,'content_bytes':size,
                    'wall_seconds':wall,'adapter_errors':errors}
            event(label, result=result, expected_failure=expected_failure, resources_before=resources_before,
                  resources_after={p.name: p.resource() for p in processes})
            return result
        # Initial transport establishment is allowed to wait for relay registration.
        first_started = time.monotonic()
        row['first_verified_exchange_seconds'] = verified_exchange_seconds(
            lambda: exchange(label='initial-forward'), 30,
            'first checked exchange did not complete in 30 seconds')
        check(exchange(bob, a, 'initial-reverse')['succeeded'] == 1, 'reverse exchange failed')
        def paths():
            return {'alice': alice.cmd(op='path', peer_id=b['id']), 'bob': bob.cmd(op='path', peer_id=a['id'])}
        view = paths()
        event('initial-paths', paths=view)
        if lab.relayed:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and not all(p.get('path') == 'direct' for p in view.values()):
                exchange(label='traversal-probe')
                time.sleep(0.25)
                view = paths()
            event('settled-paths', paths=view)
            row['direct_within_observation_bound'] = all(p.get('path') == 'direct' for p in view.values())
            row['direct_path_seconds_since_first_attempt'] = time.monotonic()-first_started if row['direct_within_observation_bound'] else None
            if scenario in ('cone', 'nested-nat', 'nat-rebinding', 'mapping-expiry'):
                check(row['direct_within_observation_bound'], 'port-preserving fixture did not establish direct paths')
        # Same complete echoed payloads for all transports, with failures retained.
        for size in (16, 65536):
            n = min(count, 20) if scenario == 'delay-loss' else count
            for concurrency in (1, 8):
                result = exchange(label=f'workload-{size}-{concurrency}', n=n, concurrency=concurrency, size=size)
                row.setdefault('workloads', []).append(result)
                check(result.get('succeeded') == n, f'workload {size}/{concurrency} lost checked exchanges')
        row['before_recovery_paths'] = paths()
        if relay:
            direct = all(p.get('path') == 'direct' for p in row['before_recovery_paths'].values())
            relay.stop()
            event('relay-stopped', had_direct_path=direct)
            result = exchange(label='fresh-payload-with-relay-stopped',expected_failure=not direct)
            if direct:
                check(result.get('succeeded') == 1, 'direct path failed when relay stopped')
            else:
                check(result.get('succeeded') == 0, 'relay-only negative control unexpectedly succeeded')
            relay.start().ready(relay=True)
            row['relay_restart_recovery_seconds'] = verified_exchange_seconds(
                lambda: exchange(label='relay-recovery-attempt'), 45,
                'relay restart recovery exceeded 45 seconds')
        if scenario in ('nat-rebinding', 'mapping-expiry'):
            if scenario == 'nat-rebinding':
                lab.rebind()
                event('nat-public-ip-changed', public_ip='203.0.113.11')
            else:
                time.sleep(35)
                lab.expire('natA')
                lab.expire('natB')
                event('udp-conntrack-expired', idle_seconds=35, note='injected expiry, not a claim about every NAT timeout')
            row['mapping_recovery_seconds'] = verified_exchange_seconds(
                lambda: exchange(label='mapping-recovery-attempt'), 60,
                'NAT mapping recovery exceeded 60 seconds')
        # Same identity after an actual process restart; the cache is not manually flushed.
        bob.stop()
        event('peer-stopped')
        if scenario == 'peer-address-change':
            bob.env['CAPSULE_NET_BIND'] = '0.0.0.0:7402'
            b['address'] = lab.address('B', 7402)
            event('peer-address-changed', address=b['address'])
        bob.start()
        restarted = bob.ready()
        check(restarted['id'] == b['id'], 'peer identity changed across restart')
        if iroh or not relay:
            configure_pin(bob, a, iroh)
        if scenario == 'peer-address-change':
            configure_pin(alice, b, iroh)
        row['peer_restart_recovery_seconds'] = verified_exchange_seconds(
            lambda: exchange(label='peer-restart-recovery-attempt'), 45,
            'peer restart recovery exceeded 45 seconds')
        if scenario == 'direct-ipv4':
            # Exercise application admission on established connections, then restore.
            bob.cmd(op='forget', peer_id=a['id'])
            check(exchange(label='forgotten-peer-on-cached-connection',expected_failure=True).get('succeeded') == 0, 'forgotten peer still accepted')
            configure_pin(bob, a, iroh)
            check(exchange(label='restored-admission').get('succeeded') == 1, 'restored peer failed')
            check(exchange(label='peer-cannot-reach-admin', path='/v1/host',expected_failure=True).get('succeeded') == 0, 'administration exposed')
            malformed=exchange(label='malformed-http-header',raw_head='POST /bench/echo HTTP/1.1\r\nThis is not a header\r\n\r\n',expected_failure=True)
            check(malformed.get('succeeded')==0 and any('400' in str(v.get('error')) for v in malformed.get('attempts',[])), 'malformed HTTP did not receive a checked HTTP 400 rejection')
            charlie, identity = node(a_backend, 'A', 'unknown', port=7403)
            check(exchange(charlie, b, 'unknown-peer-flood', n=20, concurrency=4, target=b,expected_failure=True).get('succeeded') == 0, 'unknown peer accepted')
            wrong = dict(b, id=identity['id'], public_key=identity['public_key'])
            check(exchange(label='wrong-receiver-pin', target=wrong,expected_failure=True).get('succeeded') == 0, 'wrong receiver identity accepted')
            check(exchange(label='known-peer-after-rejections').get('succeeded') == 1, 'known peer failed after rejected traffic')
            check(exchange(label='stream-backpressure', n=96, concurrency=32, size=65536).get('succeeded') == 96, 'concurrency backpressure lost exchanges')
        row['final_paths'] = paths()
        row['network_after'] = counters(lab)
        row['status'] = 'passed'
    except Exception as error:
        row.update(status='failed', error=f'{type(error).__name__}: {error}',
                   failure_classification='assertion_failure' if isinstance(error,AssertionError) else 'fixture_or_harness_failure')
    finally:
        row['elapsed_seconds'] = time.monotonic() - started
        row['host_load_after'] = list(os.getloadavg())
        for p in captures:
            if p.poll() is None:
                p.send_signal(signal.SIGINT)
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
        for process in reversed(processes):
            process.stop()
        lab.down()
        runtime.cleanup()
        checkpoint()
    return row


def summarize(rows):
    output = {}
    for row in rows:
        key = f"{row['scenario']}/{row['pair']}"
        group = output.setdefault(key, {'passed': 0, 'failed': 0, 'first_verified_exchange_seconds': [], 'workloads': {}})
        group[row['status']] += 1
        if 'first_verified_exchange_seconds' in row:
            group['first_verified_exchange_seconds'].append(row['first_verified_exchange_seconds'])
        for workload in row.get('workloads', []):
            name = f"{workload['content_bytes']}B/c{workload['concurrency']}"
            stats = group['workloads'].setdefault(name, {'verified': 0, 'failed': 0, 'not_attempted':0, 'latency_seconds': [], 'verified_requests_per_second': []})
            stats['verified'] += workload['succeeded']
            stats['failed'] += workload['failed']
            stats['not_attempted']+=workload.get('not_attempted',0)
            stats['latency_seconds'].extend(v['seconds'] for v in workload['attempts'] if v['verified'])
            stats['verified_requests_per_second'].append(workload['succeeded'] / workload['wall_seconds'] if workload['wall_seconds'] else 0)
    for group in output.values():
        for workload in group['workloads'].values():
            samples = workload.pop('latency_seconds')
            workload['successful_latency'] = distribution(samples) if samples else None
            workload['median_verified_requests_per_second'] = statistics.median(workload['verified_requests_per_second'])
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--scenario', choices=SCENARIOS, action='append')
    parser.add_argument('--pair', choices=PAIRS, action='append')
    parser.add_argument('--count', type=int, default=100)
    parser.add_argument('--nat-repeats', type=int, default=3)
    parser.add_argument('--no-capture', action='store_true')
    parser.add_argument('--resume-report', type=Path, help='reuse completed passing trials with identical helper binary hashes and workload parameters')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Linux namespace fixtures require root')
    if args.count < 1 or args.nat_repeats < 1:
        parser.error('count and repeats must be positive')
    root = args.artifacts.resolve()
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    build_root = root / 'build'
    build_root.mkdir()
    print(f'Building helpers; evidence: {root}', flush=True)
    helpers = build(build_root)
    coord = build_root / 'capsule-coord'
    execute(['go', 'build', '-o', str(coord), './cmd/capsule-coord'], build_root / 'build-coord.log', cwd=ROOT / 'go')
    report = {'schema_version': 1, 'status': 'running', 'scope': 'controlled local Linux kernel fixtures; no real-world NAT success-rate claim',
              'iroh_version': '1.3.0', 'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'source_status': subprocess.check_output(['git', 'status', '--short'], cwd=ROOT, text=True).strip(),
              'parameters': vars(args) | {'artifacts': str(root),'resume_report':str(args.resume_report) if args.resume_report else None},
              'binary_sha256': {key: digest(Path(value[0])) for key, value in helpers.items()} | {'coordinator': digest(coord)},
              'limitations': ['helper CPU/RSS includes control, payload generation and test runtime',
                             'network byte counters include coordination and probes; captures may duplicate packets',
                             'iroh relay uses endpoint allowlist in test adapter, not Capsule signed membership',
                             'latency percentiles show successes; failures and deadline-censored attempts are retained separately',
                             'no external WAN/cellular/corporate network evidence; no security audit'], 'cases': []}
    report['iroh_profiles']={'iroh':'native defaults; TLS tickets and portmapper disabled',
        'iroh-bounds':'GSO disabled; 16 bidi/0 uni incoming streams; 30-second idle timeout; other iroh defaults retained'}
    source_paths=[ROOT/'conformance/connectivity_suite.py',ROOT/'conformance/nat_lab.py',
        ROOT/'go/internal/host/connectivity_network_test.go',ROOT/'rust/src/quic/connectivity_network.rs',
        ROOT/'rust/src/quic/connectivity_bench.rs',ROOT/'rust/src/quic.rs',ROOT/'conformance/connectivity/net_driver.rs',
        ROOT/'conformance/connectivity/driver.rs',ROOT/'conformance/connectivity/iroh/src/main.rs',
        ROOT/'conformance/connectivity/iroh/src/network.rs',ROOT/'conformance/connectivity/iroh/Cargo.toml',
        ROOT/'conformance/connectivity/iroh/Cargo.lock']
    report['harness_sha256']={str(p.relative_to(ROOT)):digest(p) for p in source_paths}
    for source in source_paths:
        target=root/'sources'/source.relative_to(ROOT);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(source.read_bytes())
    cases = args.scenario or SCENARIOS
    pairs = args.pair or list(PAIRS)
    completed=set()
    if args.resume_report:
        previous=json.loads(args.resume_report.read_text())
        report['resumed_from']=str(args.resume_report.resolve())
        for row in reusable_rows(previous, report, cases, pairs):
            row=dict(row,artifact_directory=str(args.resume_report.resolve().parent/row['artifact_directory']),
                     provenance_report=str(args.resume_report.resolve()))
            report['cases'].append(row)
            completed.add((row['scenario'],row['pair'],row['repeat']))
    report_path = root / 'report.json'
    def checkpoint():
        report['summary'] = summarize(report['cases'])
        report_path.write_text(json.dumps(report, indent=2) + '\n')
    checkpoint()
    for scenario in cases:
        repeats = args.nat_repeats if scenario in ('cone', 'random-port', 'udp-blocked') else 1
        for repeat in range(repeats):
            order = pairs[repeat % len(pairs):] + pairs[:repeat % len(pairs)]
            for pair in order:
                if (scenario,pair,repeat+1) in completed:
                    continue
                label = f'{scenario}-{repeat + 1:02d}-{pair}'
                print(f'RUN {label}', flush=True)
                row = run_case(root / label, helpers, coord, pair, scenario, repeat + 1, args.count, not args.no_capture)
                report['cases'].append(row)
                checkpoint()
                print(f"{row['status'].upper()} {label}: {row.get('error', 'checked exchanges and recovery assertions passed')}", flush=True)
    report['status'] = 'complete' if all(r['status'] == 'passed' for r in report['cases']) else 'complete_with_failures'
    checkpoint()
    print(f'Report: {report_path}', flush=True)
    raise SystemExit(0 if report['status'] == 'complete' else 1)


if __name__ == '__main__':
    main()
