#!/usr/bin/env python3
"""Installed-bundle recovery checks for docs/guided-setup-proposal.md.

An end-to-end companion to launch_acceptance.py, using fresh Linux accounts,
real systemd services, the local coordinator and the fixture Claude executable.
Exercises every CLI/daemon pairing without swapping the installed service.
No live model is called. Run as root with the launch acceptance prerequisites.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import socket
import subprocess
import tarfile
import tempfile
import termios
import time

from launch_acceptance import Harness, VERSION, first_json, leftovers, now

SECRET = re.compile(r'peerspan-(?:member-)?invite-v1\.[A-Za-z0-9_-]+|(?:token|instance)_[0-9a-f]{64}')


class Check:
    def __init__(self, harness, client):
        self.h = harness
        self.client = client
        self.commands = []

    def run(self, machine, *args, success=True):
        result = machine.run([str(self.client), *args], cwd=machine.project)
        shown = SECRET.sub('[redacted]', ' '.join(args))
        self.commands.append({'machine': machine.label, 'command': shown, 'exit': result.returncode})
        assert (result.returncode == 0) == success, (shown, SECRET.sub('[redacted]', result.stdout + result.stderr))
        if not args or args[0] != 'invite':
            assert not SECRET.search(result.stdout + result.stderr), shown
        return json.loads(result.stdout) if result.stdout.strip() else None

    def up(self, machine, *args, success=True):
        value = self.run(machine, 'up', *args, '--no-start', success=success)
        assert value and value['setup']['state'] == ('prepared' if success else 'incomplete'), value
        return value

    def identity(self, value):
        return (value['network']['id'], value['network']['person']['id'],
                value['attachment']['agent']['id'], value['attachment']['profile'])

    def key_digest(self, machine):
        return hashlib.sha256((machine.home / '.config/peerspan/person_ed25519').read_bytes()).hexdigest()

    def interactive(self, machine, token=None, cancel=False):
        """Use a real terminal; hide the invite and restore echo on cancellation."""
        master, slave = pty.openpty()
        before = termios.tcgetattr(slave)
        process = subprocess.Popen(machine.argv([str(self.client), 'up', '--no-start']),
                                   cwd=machine.project, stdin=slave, stdout=slave, stderr=slave,
                                   start_new_session=True)
        self.h.processes.append(process)
        output = b''

        def until(text):
            nonlocal output
            deadline = time.monotonic() + 45
            target = text.encode()
            while target not in output:
                assert process.poll() is None, SECRET.sub('[redacted]', output.decode(errors='replace'))
                assert time.monotonic() < deadline, SECRET.sub('[redacted]', output.decode(errors='replace'))
                if select.select([master], [], [], 0.2)[0]:
                    output += os.read(master, 65536)

        try:
            until('Agent (')
            os.write(master, b'claude\n')
            until('create/join')
            os.write(master, b'join\n')
            until('Invite (hidden)')
            if cancel:
                os.killpg(process.pid, signal.SIGINT)
            else:
                os.write(master, token.encode() + b'\n')
                until('Let this machine')
                os.write(master, b'\n')
                until('Let this agent')
                os.write(master, b'\n')
            process.wait(timeout=45)
            while select.select([master], [], [], 0.1)[0]:
                chunk = os.read(master, 65536)
                if not chunk:
                    break
                output += chunk
            text = output.decode(errors='replace')
            assert not SECRET.search(text), SECRET.sub('[redacted]', text)
            assert bool(termios.tcgetattr(slave)[3] & termios.ECHO) == bool(before[3] & termios.ECHO)
            if cancel:
                assert process.returncode != 0, text
            else:
                assert process.returncode == 0, text
                assert (first_json(text) or {})['setup']['state'] == 'prepared', text
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)
            os.close(master)
            os.close(slave)


def install(harness, label, implementation):
    machine = harness.new_machine(label, implementation)
    result = machine.run(['scripts/install-release.sh', VERSION, '--from', 'dist',
                          '--implementation', implementation])
    assert result.returncode == 0, result.stdout + result.stderr
    return machine


def pairing(h, cli, daemon, clients):
    checks = Check(h, clients[cli])
    owner = install(h, 'owner', daemon)
    checks.up(owner, 'claude', '--create', 'personal', '--option', 'executable=/missing/claude', success=False)
    assert checks.run(owner, 'network', 'list') == []
    assert checks.run(owner, 'agent', 'list') == []
    checks.up(owner, 'codex', '--create', 'personal', success=False)
    checks.up(owner, 'opencode', '--create', 'personal', success=False)
    checks.up(owner, 'claude', '--create', 'personal', '--expires-at', '2000-01-01T00:00:00Z', success=False)
    checks.run(owner, 'up', 'claude', '--create', 'personal', '--', '--mcp-config', '{}', success=False)
    saved_path = owner.env['PATH']
    try:
        empty = owner.home / 'empty-bin'
        empty.mkdir()
        owner.env['PATH'] = str(empty)
        checks.up(owner, 'claude', '--create', 'personal', success=False)
    finally:
        owner.env['PATH'] = saved_path
    assert checks.run(owner, 'network', 'list') == []
    assert checks.run(owner, 'agent', 'list') == []

    if cli == daemon:
        checks.run(owner, 'uninstall')
    first = checks.up(owner, 'claude', '--create', 'personal', '--as', 'alice',
                      '--coordinator', h.coord_address, '--coordinator-key', h.coord_key)
    key = checks.key_digest(owner)
    again = checks.up(owner)
    assert checks.identity(first) == checks.identity(again)
    assert again['attachment']['reused'] is True and again['attachment']['calls'] is False
    assert checks.key_digest(owner) == key
    trusted = checks.up(owner, '--trusted')
    host = checks.run(owner, 'info')['id']
    assert host in trusted['network']['access']['trusted_hosts']
    untrusted = checks.up(owner, '--untrusted')
    assert host not in untrusted['network']['access']['trusted_hosts']
    assert untrusted['network']['access']['rules'] == []
    checks.up(owner, '--calls', success=False)
    key_path = owner.home / '.config/peerspan/person_ed25519'
    key_backup = key_path.with_suffix('.saved')
    key_path.rename(key_backup)
    try:
        checks.up(owner, success=False)
        assert not key_path.exists(), 'retry generated a replacement identity'
    finally:
        key_backup.rename(key_path)
    checks.up(owner, '--create', 'other', success=False)
    checks.up(owner, 'claude', '--name', 'different-agent', success=False)
    assert len(checks.run(owner, 'network', 'list')) == 1
    assert len(checks.run(owner, 'agent', 'list')) == 1

    # A stopped service is restarted with its original executable and state.
    unit = owner.home / '.config/systemd/user/peerspan.service'
    unit_before = unit.read_bytes()
    assert owner.run(['systemctl', '--user', 'stop', 'peerspan.service']).returncode == 0
    restarted = checks.up(owner)
    assert checks.identity(first) == checks.identity(restarted)
    assert unit.read_bytes() == unit_before
    conflict = checks.run(owner, '--state', str(owner.home / 'unrelated-state'), 'up', 'claude', '--no-start', success=False)
    assert conflict['setup']['state'] == 'incomplete'
    assert unit.read_bytes() == unit_before

    invited = checks.run(owner, 'invite', 'bob')['token']
    peer = install(h, 'teammate', daemon)
    joined = checks.up(peer, 'claude', '--join', invited)
    replay = checks.up(peer, '--join', invited)
    assert checks.identity(joined) == checks.identity(replay)
    malformed = invited[:-1] + ('A' if invited[-1] != 'A' else 'B')
    checks.up(peer, '--join', malformed, success=False)
    assert joined['network']['id'] == first['network']['id']
    assert joined['network']['person']['id'] != first['network']['person']['id']

    # Another key cannot take the existing person's label. Preserve the joined
    # host and generated key, stop before registering an agent, and remain
    # incomplete on retry until the owner performs the stated identity repair.
    same_person_invite = checks.run(owner, 'invite', 'alice')['token']
    incomplete = install(h, 'incomplete-identity', daemon)
    failed = checks.up(incomplete, 'claude', '--join', same_person_invite, success=False)
    failed_key = checks.key_digest(incomplete)
    failed_network = checks.run(incomplete, 'network', 'list')
    assert len(failed_network) == 1 and checks.run(incomplete, 'agent', 'list') == []
    retry = checks.up(incomplete, 'claude', success=False)
    assert checks.run(incomplete, 'network', 'list')[0]['id'] == failed_network[0]['id']
    assert checks.key_digest(incomplete) == failed_key
    assert checks.run(incomplete, 'agent', 'list') == []
    assert failed['setup']['state'] == retry['setup']['state'] == 'incomplete'

    # Real-terminal cancellation and a successful hidden-invite prompt. Test
    # each CLI once; the four pairings above cover daemon parity separately.
    if cli == daemon:
        terminal = install(h, 'terminal', daemon)
        checks.interactive(terminal, cancel=True)
        assert checks.run(terminal, 'network', 'list') == []
        terminal_invite = checks.run(owner, 'invite', 'terminal-person')['token']
        checks.interactive(terminal, terminal_invite)
        assert len(checks.run(terminal, 'agent', 'list')) == 1

    if cli == daemon == 'rust':
        h.coord.terminate()
        h.coord.wait(timeout=10)
        try:
            offline = checks.up(peer, success=False)
            assert any('coordinator' in str(item).lower() for item in offline['attention'])
            assert len(checks.run(peer, 'network', 'list')) == 1
            assert len(checks.run(peer, 'agent', 'list')) == 1
        finally:
            log = open(h.work / 'coord-restart.log', 'ab')
            h.coord = subprocess.Popen([str(h.work / 'bin/peerspan-coord'), '--state', str(h.work / 'coord'),
                                        'run', '--listen', h.coord_address], stdout=log, stderr=log)
            deadline = time.monotonic() + 15
            host, port = h.coord_address.rsplit(':', 1)
            while True:
                try:
                    with socket.create_connection((host, int(port)), timeout=0.2):
                        break
                except OSError:
                    assert h.coord.poll() is None and time.monotonic() < deadline
                    time.sleep(0.1)
        assert checks.identity(checks.up(peer)) == checks.identity(joined)

    checks.run(owner, 'network', 'create', 'second-network')
    checks.up(owner, success=False)
    assert len(checks.run(owner, 'network', 'list')) == 2
    assert len(checks.run(owner, 'agent', 'list')) == 1
    return {'cli': cli, 'daemon': daemon, 'passed': True, 'commands': checks.commands}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', type=Path, default=Path('node'))
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--pairing', action='append', choices=['go/go', 'go/rust', 'rust/go', 'rust/rust'])
    args = parser.parse_args()
    args.keep = False
    args.coordinator = args.coordinator_key = None
    args.pace = 0
    work = Path(tempfile.mkdtemp(prefix='peerspan-up-acceptance-', dir='/var/tmp'))
    work.chmod(0o755)
    (work / 'bin').mkdir()
    harness = Harness(args, work)
    results = []
    error = None
    try:
        harness.check_prerequisites()
        harness.share_node()
        harness.start_coordinator()
        harness.package(['go', 'rust'])
        clients = {}
        for implementation, (archive, _, root) in harness.archives.items():
            directory = work / f'client-{implementation}'
            directory.mkdir(mode=0o755)
            with tarfile.open(archive) as bundle:
                bundle.extractall(directory, filter='data')
            clients[implementation] = directory / root / 'bin/peerspan'
        for name in args.pairing or ['go/go', 'go/rust', 'rust/go', 'rust/rust']:
            cli, daemon = name.split('/')
            print(f'Checking CLI {cli} / daemon {daemon}', flush=True)
            try:
                results.append(pairing(harness, cli, daemon, clients))
            finally:
                cleanup = harness.cleanup_users(harness.users)
                assert not cleanup, cleanup
                harness.users.clear()
    except Exception as failure:
        error = SECRET.sub('[redacted]', str(failure))
        raise
    finally:
        cleanup = harness.close()
        import shutil
        shutil.rmtree(work, ignore_errors=True)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({'checked_at': now(), 'runs': results, 'error': error,
                                          'release': harness.release, 'passed': bool(results) and error is None,
                                          'cleanup': {'errors': cleanup, 'leftovers': leftovers()}}, indent=2) + '\n')
    print(f'PASS {len(results)} CLI/daemon pairings; wrote {args.output}', flush=True)


if __name__ == '__main__':
    main()
