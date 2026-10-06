#!/usr/bin/env python3
"""Run real Go/Rust hosts behind kernel NAT, using Linux network namespaces.

Requires root, iproute2, and nftables. Every namespace, interface, and process
is created for one run and removed afterwards; the host's own network is not
touched beyond creating and deleting namespaces.

Topology (one per scenario):

    hostA 10.1.0.2 -- natA 10.1.0.1 | 203.0.113.10 --+
                                                      |-- coordinator 203.0.113.1
    hostB 10.2.0.2 -- natB 10.2.0.1 | 203.0.113.20 --+   ("internet" bridge)

The private networks have no route to each other. Each NAT router masquerades
its private network behind its public address and forwards nothing inbound
that it did not see leave first. Like typical stateful home routers, it also
drops unsolicited packets addressed to itself. Without that input policy, a
peer's first hole-punching packet would create a conntrack entry on the
router, masquerade would then pick a different source port for the host's
own outbound probe, and neither side's mapping would ever match. Hosts listen
on 0.0.0.0, so they advertise no direct address: they start on the
coordinator relay, and only path discovery through both NATs can open a
direct path.

Scenarios:
- cone: masquerade that preserves source ports where possible. Path discovery
  must open a direct path within 15 s, which keeps working with the
  coordinator stopped.
- symmetric: masquerade with fully random source ports. The path stays on
  the relay.
- udp-blocked: both routers drop all forwarded UDP; the relay runs over TCP
  and the path stays on it.
Where the path stays relayed, a negative control also shows that with the
coordinator stopped a send cannot reach the other host.
"""

import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import tempfile
import time

from host_service import Host, die_with_parent
from peer_messaging import timestamp

COORD_IP, COORD_PORT = '203.0.113.1', 7400
PEER_PORT = 7401
INTERVAL = 1


def sh(*args, check=True):
    result = subprocess.run(args, capture_output=True, text=True)
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed: {result.stderr.strip()}")
    return result


class Lab:
    """Namespaces: pub (bridge + coordinator), natA, natB, hostA, hostB."""

    def __init__(self, root, nat='cone', block_udp=False):
        tag = secrets.token_hex(3)
        self.ns = {role: f'cap{tag}{role}' for role in ('pub', 'natA', 'natB', 'hostA', 'hostB')}
        self.root, self.nat, self.block_udp, self.tag = root, nat, block_udp, tag
        self.created = []

    def run(self, role, *args, check=True):
        return sh('ip', 'netns', 'exec', self.ns[role], *args, check=check)

    def veth(self, left_role, left_name, right_role, right_name):
        a, b = f'v{self.tag}{secrets.token_hex(2)}', f'v{self.tag}{secrets.token_hex(2)}'
        sh('ip', 'link', 'add', a, 'type', 'veth', 'peer', 'name', b)
        sh('ip', 'link', 'set', a, 'netns', self.ns[left_role], 'name', left_name)
        sh('ip', 'link', 'set', b, 'netns', self.ns[right_role], 'name', right_name)

    def up(self):
        for name in self.ns.values():
            sh('ip', 'netns', 'add', name)
            self.created.append(name)
            sh('ip', 'netns', 'exec', name, 'ip', 'link', 'set', 'lo', 'up')
        self.run('pub', 'ip', 'link', 'add', 'br0', 'type', 'bridge')
        self.run('pub', 'ip', 'addr', 'add', f'{COORD_IP}/24', 'dev', 'br0')
        self.run('pub', 'ip', 'link', 'set', 'br0', 'up')
        for side, public, private in (('A', '203.0.113.10', '10.1.0'), ('B', '203.0.113.20', '10.2.0')):
            nat, host = f'nat{side}', f'host{side}'
            self.veth(nat, 'wan', 'pub', f'to{side}')
            self.run('pub', 'ip', 'link', 'set', f'to{side}', 'master', 'br0')
            self.run('pub', 'ip', 'link', 'set', f'to{side}', 'up')
            self.run(nat, 'ip', 'addr', 'add', f'{public}/24', 'dev', 'wan')
            self.run(nat, 'ip', 'link', 'set', 'wan', 'up')
            self.veth(nat, 'lan', host, 'eth0')
            self.run(nat, 'ip', 'addr', 'add', f'{private}.1/24', 'dev', 'lan')
            self.run(nat, 'ip', 'link', 'set', 'lan', 'up')
            self.run(host, 'ip', 'addr', 'add', f'{private}.2/24', 'dev', 'eth0')
            self.run(host, 'ip', 'link', 'set', 'eth0', 'up')
            self.run(host, 'ip', 'route', 'add', 'default', 'via', f'{private}.1')
            self.run(nat, 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
            masquerade = 'masquerade fully-random' if self.nat == 'symmetric' else 'masquerade'
            udp = '  iifname "lan" oifname "wan" meta l4proto udp drop\n' if self.block_udp else ''
            rules = ('table ip nat {\n'
                     ' chain post {\n'
                     '  type nat hook postrouting priority 100;\n'
                     f'  oifname "wan" {masquerade}\n'
                     ' }\n'
                     '}\n'
                     'table ip filter {\n'
                     ' chain input {\n'
                     '  type filter hook input priority 0; policy drop;\n'
                     '  ct state established,related accept\n'
                     '  iifname { "lo", "lan" } accept\n'
                     ' }\n'
                     ' chain forwarding {\n'
                     '  type filter hook forward priority 0; policy drop;\n'
                     '  ct state established,related accept\n'
                     f'{udp}'
                     '  iifname "lan" oifname "wan" accept\n'
                     ' }\n'
                     '}\n')
            rule_file = self.root / f'{nat}.nft'
            rule_file.write_text(rules)
            self.run(nat, 'nft', '-f', str(rule_file))

    def down(self):
        for name in reversed(self.created):
            sh('ip', 'netns', 'del', name, check=False)

    def wrapper(self, role, binary):
        path = self.root / f'{role}-{Path(binary).name}'
        path.write_text(f'#!/bin/sh\nexec ip netns exec {self.ns[role]} {Path(binary).resolve()} "$@"\n')
        path.chmod(0o755)
        return path

    def reachable(self, role, ip, port):
        probe = ('import socket,sys\n'
                 f's=socket.create_connection(("{ip}",{port}),0.3)\n')
        return self.run(role, 'python3', '-c', probe, check=False).returncode == 0


class NatHost(Host):
    def __init__(self, wrapper, state):
        super().__init__(wrapper, state, ('--peer-listen', f'0.0.0.0:{PEER_PORT}',
                                          '--coordination-interval', str(INTERVAL)))


class NatCoordinator:
    def __init__(self, lab, binary, state):
        self.lab, self.state = lab, state
        self.binary = str(lab.wrapper('pub', binary))
        self.address = f'{COORD_IP}:{COORD_PORT}'
        self.process, self.logs = None, tempfile.TemporaryFile()

    def info(self):
        result = subprocess.run([self.binary, '--state', str(self.state), 'info'],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    def start(self):
        self.process = subprocess.Popen([self.binary, '--state', str(self.state), 'run', '--listen', self.address],
                                        stdout=self.logs, stderr=self.logs, preexec_fn=die_with_parent)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.logs.seek(0)
                raise AssertionError(f'coordinator exited: {self.logs.read().decode()}')
            if self.lab.reachable('pub', COORD_IP, COORD_PORT):
                return self.info()
            time.sleep(0.05)
        raise AssertionError('coordinator did not become ready')

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            self.process.wait(timeout=8)


def wait_for(predicate, timeout=15, message='condition'):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.2)
    raise AssertionError(f'timed out waiting for {message}')


def send(sender, receiver_id, grant, agent, content):
    return sender.cli('message', 'send', '--peer', receiver_id, '--grant', grant['id'], '--agent', agent['id'],
                      '--deadline', timestamp(), '--content', content)


def direct_expected(nat, block_udp):
    """Port-preserving NAT on both sides allows a direct path; the rest stay relayed."""
    return nat == 'cone' and not block_udp


def scenario(coord_binary, a_binary, b_binary, nat, block_udp):
    with tempfile.TemporaryDirectory(prefix='capsule-nat-') as directory:
        root = Path(directory)
        lab = Lab(root, nat=nat, block_udp=block_udp)
        coord = alice = bob = None
        try:
            lab.up()
            # The private networks cannot reach each other or the other NAT's inside.
            assert not lab.reachable('hostA', '10.2.0.2', PEER_PORT)
            coord = NatCoordinator(lab, coord_binary, root / 'coord')
            coordinator = coord.start()
            alice = NatHost(lab.wrapper('hostA', a_binary), root / 'alice')
            bob = NatHost(lab.wrapper('hostB', b_binary), root / 'bob')
            a, b = alice.start(), bob.start()

            network = alice.cli('network', 'create', '--name', 'nat', '--member', 'alice',
                                '--coordinator', coord.address, '--coordinator-key', coordinator['public_key'])
            assert network['last_sync_error'] is None, network
            net = network['id']
            invite = alice.cli('network', 'invite', '--network', net, '--member', 'bob', '--expires-at', timestamp(600))
            bob.cli('network', 'join', '--token', invite['token'])
            for host in (alice, bob):
                wait_for(lambda: len(host.cli('network', 'members', net)) == 2, message='membership sync')
            members = {m['host_id']: m for m in alice.cli('network', 'members', net)}
            # Listening on 0.0.0.0 advertises no direct address: only the relay can connect them.
            assert members[a['id']]['address'] == '' and members[b['id']]['address'] == '', members

            # Both directions, under connected-only grants, across real NAT.
            agent_b = bob.cli('agent', 'register', '--name', 'bob-agent', '--owner', 'bob')
            agent_a = alice.cli('agent', 'register', '--name', 'alice-agent', '--owner', 'alice')
            grant_b = bob.cli('grant', 'create', '--peer', a['id'], '--agent', agent_b['id'], '--expires-at', timestamp(1200))
            grant_a = alice.cli('grant', 'create', '--peer', b['id'], '--agent', agent_a['id'], '--expires-at', timestamp(1200))
            for content in ('first', 'second'):
                out = send(alice, b['id'], grant_b, agent_b, content)
                assert out['state'] == 'accepted', out
            out = send(bob, a['id'], grant_a, agent_a, 'reply direction')
            assert out['state'] == 'accepted', out
            assert [m['request']['content'] for m in bob.cli('message', 'list')] == ['first', 'second']
            assert [m['request']['content'] for m in alice.cli('message', 'list')] == ['reply direction']

            open_grant = bob.cli('grant', 'create', '--peer', a['id'], '--agent', agent_b['id'],
                                 '--expires-at', timestamp(1200), '--allow-disconnected')

            def path(host, peer):
                return host.cli('peer', 'path', peer['id'])

            if direct_expected(nat, block_udp):
                # Path discovery moves both directions onto a direct UDP path
                # through both NATs within 15 seconds of the relayed exchange.
                wait_for(lambda: path(alice, b)['path'] == 'direct', timeout=15, message='direct path from alice')
                wait_for(lambda: path(bob, a)['path'] == 'direct', timeout=15, message='direct path from bob')
                view = path(alice, b)
                assert view['endpoint'].startswith('203.0.113.20:') and view['rtt_ms'] is not None, view
                # The traffic no longer depends on the relay.
                coord.stop()
                time.sleep(1)
                out = send(alice, b['id'], open_grant, agent_b, 'direct without relay')
                assert out['state'] == 'accepted', out
                assert 'direct without relay' in [m['request']['content'] for m in bob.cli('message', 'list')]
                assert path(alice, b)['path'] == 'direct'
                coord.start()
            else:
                # A new port per destination, or no UDP at all: discovery cannot
                # open a direct path, so traffic stays on the relay.
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline:
                    assert send(alice, b['id'], grant_b, agent_b, 'relayed traffic')['state'] == 'accepted'
                    time.sleep(1)
                for host, peer in ((alice, b), (bob, a)):
                    view = path(host, peer)
                    assert view['path'] == 'relay' and view['endpoint'] is None, view

                # Negative control: with the relay gone there is no path, even
                # under a grant that allows disconnected use.
                coord.stop()
                time.sleep(1)
                out = send(alice, b['id'], open_grant, agent_b, 'no relay')
                assert out['state'] == 'unknown', out
                assert 'no relay' not in [m['request']['content'] for m in bob.cli('message', 'list')]

                # The relay coming back restores the path for the same unknown request.
                coord.start()
                retried = wait_for(lambda: (r := alice.cli('message', 'retry', '--peer', b['id'], out['request']['request_id']))
                                   ['state'] == 'accepted' and r, timeout=20, message='retry through restored relay')
                assert retried['state'] == 'accepted'
        finally:
            for process in (alice, bob):
                if process is not None:
                    process.stop()
                    process.logs.close()
            if coord is not None:
                coord.stop()
                coord.logs.close()
            lab.down()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--coord', type=Path, required=True)
    parser.add_argument('--scenario', choices=['cone', 'symmetric', 'udp-blocked'], action='append')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('nat_lab.py needs root to create network namespaces')
    binaries = {'Go': args.go, 'Rust': args.rust}
    for name in args.scenario or ['cone', 'symmetric', 'udp-blocked']:
        nat = 'symmetric' if name == 'symmetric' else 'cone'
        for a in binaries:
            for b in binaries:
                scenario(args.coord, binaries[a], binaries[b], nat, name == 'udp-blocked')
                if direct_expected(nat, name == 'udp-blocked'):
                    detail = 'relayed exchange both ways, direct path within 15 s, works with the coordinator stopped'
                else:
                    detail = 'relay-only exchange both ways, path stays relayed, no path without the relay, recovery after relay restart'
                print(f'PASS {name} NAT, {a}→{b}: {detail}', flush=True)


if __name__ == '__main__':
    main()
