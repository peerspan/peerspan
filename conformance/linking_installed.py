#!/usr/bin/env python3
"""Installed Linux approved-link and up acceptance, independently authored.

Uses real release bundles, fresh Linux users, systemd user services and the
existing fixture adapter handshake. Public linking contracts define consent,
identity and recovery assertions. No Go/Rust implementation source is read.
Fixture readiness is recorded separately from live model task completion.
"""

import argparse
import base64
import copy
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback

from host_service import SCHEMA_VERSION
from launch_acceptance import Harness, Run, VERSION, leftovers, now
from linking_hosts import Ceremony, Host, checked, cli_ceremony, need, public_view
from linking_cold_invites import decode, encode
from linking_readers import b64, digest, message, unb64
from peer_messaging import available_port


class LiveClock:
    def __init__(self, address):
        self.port = int(address.rsplit(':', 1)[1])

    @property
    def now(self):
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    def advance(self, seconds):
        time.sleep(seconds)


class InstalledHost(Host):
    """Use the installed service; every CLI runs under its actual local user."""
    def __init__(self, machine, client, runtime):
        self.machine, self.cli_binary, self.runtime = machine, str(client), runtime
        self.state = machine.home / '.local/state/peerspan/host'
        self.home, self.config = machine.home, machine.home / '.config'
        self.unit = machine.home / '.config/systemd/user/peerspan.service'
        need(self.unit.exists(), 'bundle installer leaves the real service unit')
        command = next(line.split('=', 1)[1] for line in self.unit.read_text().splitlines() if line.startswith('ExecStart='))
        self.binary = shlex.split(command)[0]
        self.process = self.logs = None

    def run(self, *args, **kwargs):
        return self.machine.run([self.cli_binary, '--state', str(self.state), *args], cwd=self.machine.project)

    def cli_input(self, args, stdin=''):
        return subprocess.run(self.machine.argv([self.cli_binary, '--state', str(self.state), *args]),
                              input=stdin, text=True, capture_output=True, timeout=120, cwd=self.machine.project)

    def start(self):
        result = self.machine.run(['systemctl', '--user', 'start', 'peerspan.service'])
        need(result.returncode == 0, 'installed service starts without rewriting it', result.stderr)
        end = time.monotonic() + 15
        while time.monotonic() < end:
            try:
                return checked(self.call('GET', '/v1/host'))
            except (OSError, RuntimeError, http.client.HTTPException):
                time.sleep(.1)
        raise AssertionError('installed daemon did not answer its original local socket')

    def stop(self, crash=False):
        if crash:
            result = self.machine.run(['systemctl', '--user', 'kill', '--signal=SIGKILL', 'peerspan.service'])
        else:
            result = self.machine.run(['systemctl', '--user', 'stop', 'peerspan.service'])
        need(result.returncode == 0, 'installed service stops through the manager', result.stderr)

    def up(self, *args, success=True, no_start=True):
        result = self.cli_input(['up', *args, *(['--no-start'] if no_start else [])])
        secret = args[args.index('--join') + 1] if '--join' in args else None
        if secret:
            need(secret not in result.stdout + result.stderr, 'guided output never discloses the private feature invitation')
        value = (json.loads(result.stdout) if no_start else
                 terminal_setup_result(result.stdout) or terminal_setup_result(result.stderr))
        need(isinstance(value, dict), 'up returns its ordinary structured setup result', result.returncode, result.stderr)
        diagnostic = {key: item for key, item in value.items() if key != 'network'}
        if result.returncode != 0:
            report = self.machine.harness.work / (self.machine.user + '-up-failure-public.json')
            report.write_text(json.dumps({'arguments': [('[private invitation]' if item == secret else item) for item in args],
                                         'exit_code': result.returncode, 'result': diagnostic,
                                         'stderr': result.stderr}, indent=2) + '\n')
            report.chmod(0o600)
        need((result.returncode == 0) == success and value['setup']['state'] == ('prepared' if success else 'incomplete'),
             'up reports preparation separately from pending linking and adapter readiness', result.returncode, diagnostic, result.stderr)
        return value


class InstalledCeremony(Ceremony):
    def __init__(self, harness, clients, cli, daemon, directory):
        self.harness, self.root = harness, directory
        directory.mkdir()
        self.runtime = LiveClock(harness.coord_address)
        self.codes, self.hosts = [], []
        self.machines = []
        self.args = argparse.Namespace(go=str(clients['go']), rust=str(clients['rust']))
        for label in ('A', 'B', 'C'):
            machine = harness.new_machine(label, daemon)
            installed = machine.run(['scripts/install-release.sh', VERSION, '--from', 'dist', '--implementation', daemon])
            need(installed.returncode == 0, 'actual release bundle installs', label, installed.stdout, installed.stderr)
            machine.env['PATH'] = str(clients[cli].parent) + ':' + machine.env['PATH']
            self.machines.append(machine)
            self.hosts.append(InstalledHost(machine, clients[cli], self.runtime))
        self.a, self.b, self.c = self.hosts
        self.coordinator_key = harness.coord_key
        self.identity = {host.machine.label: host.start() for host in self.hosts}
        first = self.a.up('claude', '--create', 'approved-link-installed', '--as', 'alice',
                          '--coordinator', harness.coord_address, '--coordinator-key', harness.coord_key)
        self.owner_setup = first
        self.network = first['network']['id']
        public = self.a.key_file.with_suffix('.pub').read_text().split()[1]
        self.person = b64(base64.b64decode(public)[-32:])
        self.person_id = 'person_' + digest(unb64(self.person))
        need(first['network']['person']['id'] == self.person_id, 'installed original person derives from its actual local key')
        self.a.cli('network', 'enable-linking', '--network', self.network)
        self.until(self.feature_active, 'installed durable linking feature')

    def close(self):
        for host in self.hosts:
            host.stop()

    def no_secrets(self):
        for host in self.hosts:
            active = host.machine.run(['systemctl', '--user', 'is-active', 'peerspan.service']).returncode == 0
            public = ''
            if active:
                views = checked(host.call('GET', '/v1/link/requests'))
                need([view['request_id'] for view in views] == sorted(view['request_id'] for view in views), 'installed request collection order')
                for view in views:
                    public_view(view)
                public = json.dumps([views, checked(host.call('GET', '/v1/status')), checked(host.call('GET', '/v1/activity?after=0&limit=1000'))])
            journal_result = host.machine.run(['journalctl', '--user', '-u', 'peerspan.service', '--no-pager', '-o', 'cat'])
            need(journal_result.returncode == 0, 'installed service journal is readable', journal_result.stderr)
            journal = journal_result.stdout
            for code in self.codes:
                need(code not in public and code not in journal, 'installed status/activity/journal never disclose pairing code')


def setup_identity(value):
    attachment = value['attachment']
    return value['network']['id'], value['network']['person']['id'], attachment['agent']['id'], attachment['profile']


def active_attachment_identity(value):
    return (*setup_identity(value), value['attachment']['session_id'], value['attachment']['adapter_id'])


def reused_connection(value):
    attachment = value['attachment']
    connection = attachment['connection']
    need(connection['adapter_id'] == attachment['adapter_id'] and
         connection['session_id'] == attachment['session_id'] and
         (connection['state'] == 'ready' or
          (connection['state'] == 'offline' and connection['recoverable'] is True)) and
         attachment['adapter_ready'] is (connection['state'] == 'ready'),
         'reused attachment reports its exact connection and current adapter readiness separately from preparation')


def attachment_files(host, setup):
    path = Path(setup['attachment']['profile'])
    directory = path if path.is_dir() else path.parent
    need(directory.is_relative_to(host.home / '.config/peerspan/sessions'),
         'attachment profile belongs to the exact installed fixture user')
    return {str(file.relative_to(directory)): digest(file.read_bytes())
            for file in sorted(directory.rglob('*')) if file.is_file()}


def owned_fixture_group(host):
    process = host.machine.attach_process
    need(process is not None and process.poll() is None and
         process.args[:4] == ['runuser', '-u', host.machine.user, '--'] and
         os.getpgid(process.pid) == process.pid,
         'only the original tracked installed fixture process group may be paused')
    members = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            group = int((entry / 'stat').read_text().rsplit(')', 1)[1].split()[2])
            if group != process.pid:
                continue
            fields = (entry / 'status').read_text().splitlines()
            uids = [int(value) for value in next(line for line in fields if line.startswith('Uid:')).split()[1:]]
        except FileNotFoundError:
            continue
        need(all(uid == host.machine.uid for uid in uids) or
             (int(entry.name) == process.pid and all(uid == 0 for uid in uids)),
             'tracked fixture group contains only its exact user and original runuser leader')
        members.append(int(entry.name))
    need(process.pid in members, 'tracked installed fixture group still has its original leader')
    return process.pid


def valid_device_status(host, network):
    need(not host.key_file.exists() and 'SSH_AUTH_SOCK' not in host.machine.env,
         'installed device renewal status has neither original private key nor original SSH agent')
    def retained():
        with sqlite3.connect(host.state / 'host.db') as db:
            return [db.execute(query, (network,)).fetchall() for query in (
                'SELECT proof_id,kind,body FROM link_objects WHERE network_id=? ORDER BY proof_id',
                'SELECT kind,subject,version,record_hash FROM link_highwater WHERE network_id=? ORDER BY kind,subject',
                'SELECT person_key,device_key,certificate_id FROM link_signers WHERE network_id=?')] + [
                    db.execute('SELECT request_id,record FROM link_pending ORDER BY request_id').fetchall()]
    before = retained()
    value = checked(host.call('GET', '/v1/status'))
    relevant = [item for item in value['attention'] if item['subject'] == network]
    need(not any(item['kind'] in ('person_agent_unreachable', 'person_device_signer_unavailable') for item in relevant),
         'a valid selected policy device needs no original-agent or unavailable-device attention', relevant)
    need(all('ssh-agent' not in json.dumps(item).lower() and 'original person private key' not in json.dumps(item).lower()
             for item in relevant if item['kind'] in ('policy_expiring', 'policy_expired')) and retained() == before,
         'device policy status is read-only and never recommends obtaining the original key or SSH agent')
    return relevant


def terminal_setup_result(text):
    results = []
    for index, character in enumerate(text):
        if character != '{':
            continue
        try:
            value, _ = json.JSONDecoder().raw_decode(text[index:])
            if isinstance(value, dict) and 'setup' in value:
                results.append(value)
        except ValueError:
            pass
    return results[-1] if results else None


def service_snapshot(host):
    with sqlite3.connect(host.state / 'host.db') as db:
        need(db.execute('PRAGMA user_version').fetchone()[0] == SCHEMA_VERSION, 'installed service opens schema19')
    return host.unit.read_bytes(), str(host.state), checked(host.call('GET', '/v1/host'))


def installed_schema_refusal(host, baseline):
    """Refuse copied schema19/20 state under the actual installed user's UID."""
    directory = host.home / 'schema-refusal'
    directory.mkdir(mode=0o700)
    os.chown(directory, host.machine.uid, host.machine.gid)
    database = directory / 'host.db'
    with sqlite3.connect(host.state / 'host.db') as source, sqlite3.connect(database) as target:
        source.backup(target)
    database.chmod(0o600)
    os.chown(database, host.machine.uid, host.machine.gid)

    def refuses(binary, version):
        before = hashlib.sha256(database.read_bytes()).digest()
        process = subprocess.Popen(host.machine.argv([str(binary), '--state', str(directory), 'run']),
                                   cwd=host.machine.project, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise AssertionError('unsupported schema was opened instead of refused')
        need(process.returncode != 0 and str(version) in stdout + stderr and
             any(word in (stdout + stderr).lower() for word in ('schema', 'version')),
             'installed user receives an explicit unsupported-schema refusal', version, stdout, stderr)
        need(hashlib.sha256(database.read_bytes()).digest() == before, 'schema refusal leaves exact database bytes intact')

    refuses(baseline, SCHEMA_VERSION)
    with sqlite3.connect(database) as database_connection:
        database_connection.execute('PRAGMA user_version=20')
    refuses(host.binary, 20)


def guided_feature_invitation(c, harness, clients, cli, daemon):
    """Installed guided enrollment checks the same signed wrapper as join."""
    machine = harness.new_machine('guided-feature-invite', daemon)
    installed = machine.run(['scripts/install-release.sh', VERSION, '--from', 'dist', '--implementation', daemon])
    need(installed.returncode == 0, 'fresh guided recipient installs its actual release bundle', installed.stderr)
    machine.env['PATH'] = str(clients[cli].parent) + ':' + machine.env['PATH']
    target = InstalledHost(machine, clients[cli], c.runtime)
    c.machines.append(machine)
    c.hosts.append(target)
    target.start()
    before = service_snapshot(target)
    token = c.b.cli('network', 'invite', '--network', c.network, '--member', 'guided-new-person')['token']
    _, outer = decode(token, 'peerspan-feature-invite-v1')
    c.codes.extend((token, outer['token']))
    substituted = copy.deepcopy(outer)
    substituted['feature_binding']['feature_id'] = 'lf_' + '0' * 64
    expired = c.b.cli('network', 'invite', '--network', c.network, '--member', 'guided-expired-person',
                      '--expires-in', '1m')['token']
    _, expired_outer = decode(expired, 'peerspan-feature-invite-v1')
    c.codes.extend((expired, expired_outer['token']))
    until = datetime.fromisoformat(expired_outer['feature_binding']['expires_at'].replace('Z', '+00:00')).timestamp()
    time.sleep(max(0, until - time.time()) + .05)
    for bad in ('peerspan-feature-invite-v1.%', encode(substituted), expired):
        target.up('claude', '--join', bad, success=False)
        need(not target.key_file.exists() and checked(target.call('GET', '/v1/networks')) == [] and
             checked(target.call('GET', '/v1/agents')) == [] and service_snapshot(target) == before,
             'guided wrapper preflight refuses before any identity, network, attachment or service replacement')
    prepared = target.up('claude', '--join', token)
    need(prepared['network']['id'] == c.network and prepared['network']['person']['id'] != c.person_id and
         target.key_file.exists(), 'guided feature invitation creates only its explicitly invited new person')
    with sqlite3.connect(target.state / 'host.db') as db:
        intents = db.execute("SELECT subject,record FROM network_statements WHERE network_id=? AND kind='link_invite_redemption_intent'",
                             (c.network,)).fetchall()
    need(len(intents) == 1 and json.loads(intents[0][1])['submitted'] is True and
         json.loads(intents[0][1])['result_map_base64'] != '-', 'guided join uses one completed exact public redemption intent')
    repeated = target.up('--join', token)
    with sqlite3.connect(target.state / 'host.db') as db:
        after = db.execute("SELECT subject,record FROM network_statements WHERE network_id=? AND kind='link_invite_redemption_intent'",
                           (c.network,)).fetchall()
    need(setup_identity(prepared) == setup_identity(repeated) and intents == after and service_snapshot(target) == before,
         'guided exact invitation retry preserves immutable outcome, installed service and attachment identity')


def decline_pending_up(c, host, created, selection):
    """Blank means no at the exact reviewed requester consent prompt."""
    identity = created['request_id']
    packet_field = 'owner_packet_base64' if selection else 'administrator_packet_base64'
    # Incoming verified transport may legitimately advance before the prompt.
    # Fetch the already-published offer before taking the exact consent snapshot.
    def observed_offer():
        c.resume(host, identity)
        pending = host.pending(identity)
        need(not pending['commit_approved'], 'transport synchronization never approves requester commit')
        return pending[packet_field] != '-'
    c.until(observed_offer, 'verified installed offer before default-no snapshot')
    before = host.pending(identity)
    service = service_snapshot(host)
    networks = checked(host.call('GET', '/v1/networks'))
    agents = checked(host.call('GET', '/v1/agents'))
    request_ids = [value['request_id'] for value in checked(host.call('GET', '/v1/link/requests'))]
    question = 'Select this exact owner offer?' if selection else 'Commit this exact machine link?'
    master, slave = pty.openpty()
    process = subprocess.Popen(host.machine.argv([host.cli_binary, '--state', str(host.state),
                               'up', 'claude', '--no-start']), cwd=host.machine.project,
                               stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    c.harness.processes.append(process)
    captured = bytearray()
    def receive():
        if select.select([master], [], [], .1)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                return False
            captured.extend(chunk)
            return bool(chunk)
        return True
    try:
        deadline = time.monotonic() + 45
        prompted = False
        while time.monotonic() < deadline and process.poll() is None:
            receive()
            text = captured.decode(errors='replace')
            start = text.find(question)
            prompted = start >= 0 and any(marker in text[start:] for marker in ('[y/N]', '(y/N)'))
            if prompted:
                break
        need(prompted, 'installed PTY reaches the exact default-no requester consent prompt', question)
        os.write(master, b'\n')
        deadline = time.monotonic() + 45
        while process.poll() is None and time.monotonic() < deadline:
            receive()
        need(process.poll() is not None, 'declined guided consent exits without ordinary setup')
        while select.select([master], [], [], .05)[0] and receive():
            pass
        text = captured.decode(errors='replace')
        need(all(code not in text for code in c.codes), 'incomplete guided PTY output never discloses pairing codes')
        result = terminal_setup_result(text)
        need(process.returncode != 0 and result and result['setup']['state'] == 'incomplete' and
             'link resume ' + identity in json.dumps(result),
             'default-no up returns a final incomplete setup envelope and nonzero exit')
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=10)
        os.close(master)
        os.close(slave)
    after = host.pending(identity)
    fields = ('request_packet_base64', 'request_nonce', 'host_public_key', 'device_public_key',
              'coordinator_address', 'coordinator_public_key', 'selection_approved', 'commit_approved')
    if not selection:
        fields += ('owner_packet_base64', 'selection_packet_base64', 'administrator_packet_base64',
                   'owner_offer_id', 'selection_id', 'administrator_offer_id')
    differences = {field: {'before_sha256': digest(json.dumps(before[field], sort_keys=True).encode()),
                           'after_sha256': digest(json.dumps(after[field], sort_keys=True).encode())}
                   for field in fields if after[field] != before[field]}
    need(not differences and not after['commit_approved'],
         'declined consent preserves the exact pending identity and every already-approved stage', differences)
    need(checked(host.call('GET', '/v1/networks')) == networks and checked(host.call('GET', '/v1/agents')) == agents and
         [value['request_id'] for value in checked(host.call('GET', '/v1/link/requests'))] == request_ids and
         not host.key_file.exists() and service_snapshot(host) == service,
         'declined linking never falls into ordinary create/join or replaces the person, service or attachment')


def fresh_guided_link(c, harness, clients, cli, daemon):
    machine = harness.new_machine('fresh-guided-link', daemon)
    installed = machine.run(['scripts/install-release.sh', VERSION, '--from', 'dist', '--implementation', daemon])
    need(installed.returncode == 0, 'fresh guided-link user installs its actual release', installed.stderr)
    machine.env['PATH'] = str(clients[cli].parent) + ':' + machine.env['PATH']
    target = InstalledHost(machine, clients[cli], c.runtime)
    c.machines.append(machine)
    c.hosts.append(target)
    target.start()
    before = service_snapshot(target)
    master, slave = pty.openpty()
    process = subprocess.Popen(machine.argv([target.cli_binary, '--state', str(target.state), 'up', 'claude',
                               '--no-start', '--coordinator', harness.coord_address, '--coordinator-key', harness.coord_key]),
                               cwd=machine.project, stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    harness.processes.append(process)
    captured = bytearray()
    def receive():
        if select.select([master], [], [], .1)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                return False
            captured.extend(chunk)
            return bool(chunk)
        return True
    def until(check, reason):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline and process.poll() is None:
            receive()
            value = check(captured.decode(errors='replace'))
            if value:
                return value
        raise AssertionError(reason)
    try:
        until(lambda text: 'Create a network, link this machine, or join with an invite (create/link/join)' in text,
              'fresh installed up must offer the explicit machine-link choice')
        os.write(master, b'link\n')
        def one_request(_):
            views = checked(target.call('GET', '/v1/link/requests'))
            need(len(views) <= 1, 'fresh choice creates at most one owned request')
            return views[0] if views else None
        view = until(one_request, 'fresh link choice creates its one durable request')
        identity = view['request_id']
        created = c.resume(target, identity)
        c.codes.append(created['display_code'])
        pending = target.pending(identity)
        need(view['mode'] == 'new' and pending['expected_network_id'] == '-' and
             pending['expected_person_public_key'] == '-' and pending['coordinator_address'] == harness.coord_address and
             pending['coordinator_public_key'] == harness.coord_key,
             'fresh link preserves absent identity pins and the explicitly supplied actual coordinator')
        c.approval(c.b, created)
        def selection(text):
            start = text.find('Select this exact owner offer?')
            return start >= 0 and any(marker in text[start:] for marker in ('[y/N]', '(y/N)'))
        until(selection, 'fresh guided link waits for the separately reviewed owner-selection consent')
        os.write(master, b'\n')
        deadline = time.monotonic() + 45
        while process.poll() is None and time.monotonic() < deadline:
            receive()
        need(process.poll() is not None, 'fresh default-no guide stops before ordinary onboarding')
        while select.select([master], [], [], .05)[0] and receive():
            pass
        text = captured.decode(errors='replace')
        result = terminal_setup_result(text)
        need(process.returncode != 0 and result and result['setup']['state'] == 'incomplete' and
             'link resume ' + identity in json.dumps(result) and created['display_code'] not in json.dumps(result) and
             text.count(created['display_code']) <= 1,
             'fresh explicit link may display its code once, then returns private-code-free incomplete setup and exact resume guidance')
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=10)
        os.close(master)
        os.close(slave)
    after = target.pending(identity)
    need(all(after[field] == pending[field] for field in ('request_packet_base64', 'request_nonce', 'host_public_key',
             'device_public_key', 'expected_network_id', 'expected_person_public_key')) and
         not after['selection_approved'] and not after['commit_approved'] and
         len(checked(target.call('GET', '/v1/link/requests'))) == 1 and not target.key_file.exists() and
         checked(target.call('GET', '/v1/networks')) == [] and checked(target.call('GET', '/v1/agents')) == [] and
         service_snapshot(target) == before,
         'fresh declined machine link retains its exact request, host/device and service without creating a person or attachment')


def renew_attached_machine(c, original_setup):
    host = c.c
    before_service = service_snapshot(host)
    before_identity = checked(host.call('GET', '/v1/host'))
    before_provider = checked(host.call('GET', '/v1/networks/' + c.network + '/link-signer'))
    before_files = attachment_files(host, original_setup)
    fixture = host.machine.attach_process
    before_launches = sum(entry.get('event') == 'launched' for entry in host.machine.fixture_log())
    reuse_receipts = []
    def retain_reuse(stage, setup):
        reuse_receipts.append({'stage': stage, 'identity': active_attachment_identity(setup),
                               'connection': setup['attachment'].get('connection'),
                               'adapter_ready': setup['attachment'].get('adapter_ready'),
                               'profile_file_hashes': attachment_files(host, original_setup),
                               'network_attention': valid_device_status(host, c.network),
                               'original_fixture_pid': fixture.pid, 'original_fixture_exit': fixture.poll(),
                               'fixture_launches': sum(entry.get('event') == 'launched' for entry in host.machine.fixture_log())})
        report = host.machine.harness.work / (host.machine.user + '-active-reuse-public.json')
        report.write_text(json.dumps(reuse_receipts, indent=2) + '\n')
        report.chmod(0o600)
    retain_reuse('before-renewal', original_setup)
    retained = host.public_catalog(c.network)
    need(c.a.machine.run(['systemctl', '--user', 'is-active', 'peerspan.service']).returncode != 0,
         'original-person machine remains offline during installed attached-machine renewal')
    identity = c.complete(host, c.b, mode='renew')
    provider = checked(host.call('GET', '/v1/networks/' + c.network + '/link-signer'))
    need(provider['certificate_id'] != before_provider['certificate_id'] and
         provider['device_public_key'] == before_provider['device_public_key'] and
         provider['person_public_key'] == before_provider['person_public_key'] == c.person,
         'installed renewal advances the certificate while retaining the exact owned device and original person')
    need(checked(host.call('GET', '/v1/host')) == before_identity and
         all(entry in host.public_catalog(c.network)['objects'] for entry in retained['objects']) and
         service_snapshot(host) == before_service and not host.key_file.exists(),
         'renewal retains every exact proof, stable host, service and absent original-person key')
    repeated = host.up()
    retain_reuse('renewed-no-start', repeated)
    need(active_attachment_identity(repeated) == active_attachment_identity(original_setup) and repeated['attachment']['reused'] is True,
         'already attached machine renewal preserves the exact network/person/agent/profile')
    reused_connection(repeated)
    need(checked(host.call('GET', '/v1/adapters/' + original_setup['attachment']['adapter_id'] + '/connection'))['state'] == 'ready',
         'the original installed integration is ready before normal up reuse')
    normal = host.up(no_start=False)
    retain_reuse('ready-normal-up', normal)
    reused_connection(normal)
    need(active_attachment_identity(normal) == active_attachment_identity(original_setup) and normal['attachment']['adapter_ready'] is True and
         fixture.poll() is None and attachment_files(host, original_setup) == before_files and
         sum(entry.get('event') == 'launched' for entry in host.machine.fixture_log()) == before_launches,
         'normal up reuses the original ready integration without launching or replacing its credential/profile')
    group = owned_fixture_group(host)
    os.killpg(group, signal.SIGSTOP)
    try:
        host.stop()
        restored = host.up()
        retain_reuse('restarted-no-start', restored)
        reused_connection(restored)
        need(restored['attachment']['connection']['state'] == 'offline' and
             restored['attachment']['connection']['recoverable'] is True,
             'the held original fixture is offline and recoverable after the existing service restart')
        offline = host.up(success=False, no_start=False)
        retain_reuse('recoverable-normal-up', offline)
        reused_connection(offline)
        need(active_attachment_identity(offline) == active_attachment_identity(original_setup) and
             offline['attachment']['adapter_ready'] is False and
             any(stage['stage'] == 'launch' and stage['state'] == 'failed' for stage in offline['setup']['stages']) and
             any(word in json.dumps([offline['attention'], offline['next']]).lower()
                 for word in ('reconnect', 'session doctor')) and
             attachment_files(host, original_setup) == before_files and fixture.poll() is None and
             sum(entry.get('event') == 'launched' for entry in host.machine.fixture_log()) == before_launches,
             'normal up preserves the recoverable integration and reports incomplete launch guidance without duplicate launch')
    finally:
        os.killpg(group, signal.SIGCONT)
    view = c.resume(host, identity)
    events = checked(host.call('GET', '/v1/activity?after=0&limit=1000'))
    need(view['state'] == 'linked' and
         checked(host.call('GET', '/v1/networks/' + c.network + '/link-signer')) == provider and
         active_attachment_identity(restored) == active_attachment_identity(original_setup) and service_snapshot(host) == before_service and
         sum(event['kind'] == 'network.link_applied' and event['subject_id'] == identity for event in events) == 1,
         'installed restart and exact committed renewal recovery retain the new provider/profile and never duplicate application')


def pairing(harness, clients, cli, daemon, root):
    c = InstalledCeremony(harness, clients, cli, daemon, root)
    try:
        units = {host.machine.label: service_snapshot(host) for host in c.hosts}
        # Real user CLIs perform hidden-code approval and both explicit requester
        # consent stages. Cross-implementation CLI choice never swaps the daemon.
        cli_ceremony(c, clients[cli])
        b_setup = c.b.up('claude')
        need(b_setup['network']['person']['id'] == c.person_id and not c.b.key_file.exists(),
             'up reuses the linked device provider without generating/copying the original person key')
        need(b_setup['attachment']['calls'] is False, 'new linked attachment keeps capability calls default off')
        installed_schema_refusal(c.b, getattr(harness.args, 'baseline_' + daemon))
        c.a.stop()
        created = c.request(c.c)
        c.approval(c.b, created)
        decline_pending_up(c, c.c, created, selection=True)
        c.consent(c.c, created)
        c.same_review_administrator(c.b, created)
        decline_pending_up(c, c.c, created, selection=False)
        before = c.c.pending(created['request_id'])
        # An actual installed service interruption is recovered by up. It may
        # resume existing protocol work but cannot grant final requester consent.
        c.c.stop()
        incomplete = c.c.up('claude', success=False)
        need(checked(c.c.call('GET', '/v1/agents')) == [] and not c.c.key_file.exists(),
             'unfinished linking stops before replacement identity or agent attachment')
        after = c.c.pending(created['request_id'])
        for field in ('request_packet_base64', 'request_nonce', 'host_public_key', 'device_public_key',
                      'owner_packet_base64', 'selection_packet_base64', 'selection_approved'):
            need(after[field] == before[field], 'installed up recovery preserves exact selected request state', field)
        need(not after['commit_approved'], 'up never supplies final linking consent')
        need(all(code not in json.dumps(incomplete) for code in c.codes), 'up incomplete result contains no pairing code')
        c.consent(c.c, created, commit=True)
        c.until(lambda: (view if (view := c.resume(c.c, created['request_id']))['state'] == 'linked' else None), 'installed B-approved C application')
        activation = c.assert_provider(c.c, created['request_id'])
        need(activation['owner']['certificate_id'] != 'root', 'B approves another machine with its actual device while original machine is offline')
        c_setup = c.c.up('claude')
        need(c_setup['network']['person']['id'] == c.person_id and not c.c.key_file.exists(), 'second linked machine keeps the original stable person without its seed')
        for host, first in ((c.b, b_setup), (c.c, c_setup)):
            again = host.up()
            need(setup_identity(first) == setup_identity(again) and again['attachment']['reused'] is True,
                 'up repeat preserves exact network/person/agent/profile')
            need(service_snapshot(host) == units[host.machine.label], 'linking and up preserve actual service executable/unit/state/host identity')
            host.stop()
            restored = host.up()
            need(setup_identity(first) == setup_identity(restored) and service_snapshot(host) == units[host.machine.label],
                 'up restarts the same installed service and attachment profile without replacement identity')
        c.b.up('claude', '--create', 'different-network', success=False)
        need(len(c.b.cli('network', 'list')) == 1 and not c.b.key_file.exists(), 'conflicting up enrollment cannot replace a linked person or create another network')
        need(setup_identity(c.b.up()) == setup_identity(b_setup), 'identity conflict leaves the verified attachment profile intact')
        # Management must use B's separate device, with A's person key absent.
        c.b.cli('allow', 'network', '--agent', '*', '--network', c.network)
        c.b.cli('network', 'group', 'set', '--network', c.network, '--group', 'linked-machines', '--person', c.person_id)
        policy = checked(c.b.call('GET', '/v1/networks/' + c.network + '/policy?person=' + c.person_id))
        signed = json.loads(unb64(policy['authorization_base64']))
        signer = checked(c.b.call('GET', '/v1/networks/' + c.network + '/link-signer'))
        need(signed['certificate_id'] == signer['certificate_id'] and signed['person_public_key'] == c.person,
             'installed management preserves stable person and signs with the linked device')
        c.verify_signature(signer['device_public_key'], message('person_record', signed), signed['signature'])
        # The fixture completes the actual adapter handshake. Preparation alone
        # is not counted as a ready session or a model-completed task.
        run = Run(harness, 'solo-' + daemon)
        run.name = 'link-' + cli + '-' + daemon
        active_attachment = run.attach(c.c.machine)
        def ready():
            entries = c.c.machine.fixture_log()
            answered = any(entry.get('event') == 'response' and (entry.get('message') or {}).get('id') == 3 and
                           'error' not in entry['message'] for entry in entries)
            sessions = checked(c.c.call('GET', '/v1/status'))['agents']
            return answered and any(session.get('connection') == 'ready' for agent in sessions for session in agent['sessions'])
        c.until(ready, 'actual fixture adapter hello/readiness handshake', timeout=60)
        renew_attached_machine(c, dict(c_setup, attachment=active_attachment))
        fresh_guided_link(c, harness, clients, cli, daemon)
        guided_feature_invitation(c, harness, clients, cli, daemon)
        c.no_secrets()
        return {'cli': cli, 'daemon': daemon, 'passed': True, 'network_id': c.network,
                'coordinator_address': harness.coord_address, 'coordinator_public_key': harness.coord_key,
                'person_id': c.person_id, 'original_key_absent_B_C': True, 'service_preserved': True,
                'interrupted_selection_preserved': True, 'fixture_adapter_ready': True,
                'attached_renewal_service_profile_preserved': True,
                'schema19_old_binary_refusal': True, 'schema20_installed_binary_refusal': True,
                'guided_signed_feature_invite_preflight': True,
                'live_model_task_checked': False}
    finally:
        c.close()


def start_coordinator(harness, binary, label='coord'):
    port = available_port()
    state = harness.work / label
    state.mkdir(mode=0o700)
    harness.coord_address = f'127.0.0.1:{port}'
    logs = (harness.work / (label + '.log')).open('ab')
    env = dict(os.environ)
    for name in ('PEERSPAN_LINK_TEST_MODE', 'PEERSPAN_LINK_TEST_CLOCK_FILE', 'PEERSPAN_LINK_TEST_BARRIER_DIR'):
        env.pop(name, None)
    harness.coord = subprocess.Popen([str(binary), '--state', str(state), 'run', '--listen', harness.coord_address],
                                      env=env, stdout=logs, stderr=logs)
    end = time.monotonic() + 20
    while time.monotonic() < end:
        need(harness.coord.poll() is None, 'production-clock acceptance coordinator remains alive')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                break
        except OSError:
            time.sleep(.05)
    else:
        raise AssertionError('acceptance coordinator did not listen')
    info = subprocess.run([str(binary), '--state', str(state), 'info'], capture_output=True, text=True, check=True)
    harness.coord_key = json.loads(info.stdout)['public_key']


def stop_coordinator(harness):
    if harness.coord is not None and harness.coord.poll() is None:
        harness.coord.terminate()
        try:
            harness.coord.wait(timeout=10)
        except subprocess.TimeoutExpired:
            harness.coord.send_signal(signal.SIGQUIT)
            raise AssertionError('installed acceptance coordinator did not stop within the existing10s deadline; public stack retained')


def reuse_normal_bundles(harness, manifest_path):
    """Reuse exact normal-build archives for a fixture-only acceptance retry."""
    manifest = json.loads(manifest_path.read_text())
    need(set(manifest) == {'source_revision', 'coordinator_address', 'coordinator_public_key', 'archives', 'default_pin_checks'},
         'normal-package reuse manifest has exact public provenance fields')
    revision = subprocess.check_output(['git', '-C', str(harness.repo), 'rev-parse', 'HEAD'], text=True).strip()
    need(revision == manifest['source_revision'] and
         subprocess.check_output(['git', '-C', str(harness.repo), 'status', '--porcelain'], text=True) == '',
         'archive reuse requires the exact clean original packaging checkout')
    need(set(manifest['archives']) == {'go', 'rust'}, 'reuse retains both actual normal release implementations')
    for implementation, recorded in sorted(manifest['archives'].items()):
        need(set(recorded) == {'archive', 'checksum', 'sha256', 'release'}, 'exact archived build provenance')
        archive, checksum = Path(recorded['archive']), Path(recorded['checksum'])
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        need(actual == recorded['sha256'] and checksum.read_text().split() == [actual, archive.name],
             'reused archive retains its original exact SHA256 and checksum', implementation)
        with tarfile.open(archive) as bundle:
            roots = {name.split('/')[0] for name in bundle.getnames()}
            need(len(roots) == 1, 'normal release archive has one bundle root')
            root = roots.pop()
            release = json.load(bundle.extractfile(root + '/RELEASE.json'))
            need(release == recorded['release'] and release['source_revision'] == revision and
                 release['source_dirty'] is False and release['implementation'] == implementation and
                 release['version'] == VERSION and release['os'] == 'linux' and release['architecture'] == 'amd64',
                 'exact original RELEASE metadata matches the native clean packaging source')
            binary = bundle.extractfile(root + '/bin/peerspan').read()
            # Optimized Rust may materialize a short default address through
            # split immediate instructions rather than one literal string.
            # Record the actual archive CLI's public create-without-overrides
            # probe, bound to these exact bundled executable bytes.
            need(manifest['default_pin_checks'][implementation] == {
                        'binary_sha256': hashlib.sha256(binary).hexdigest(),
                        'coordinator_address': manifest['coordinator_address'],
                        'coordinator_public_key': manifest['coordinator_public_key'],
                        'compiled_defaults_cli_verified': True},
                 'actual bundled CLI verified the exact original compiled coordinator default pin', implementation)
        harness.archives[implementation] = (archive, checksum, root)
        harness.release[implementation] = {'archive': archive.name, 'sha256': actual, 'checksum_verified': True,
                    'release': release, 'reused_original_normal_package': True, 'embedded_original_pin_verified': True}
        print('Reusing verified original normal archive ' + archive.name + ' (sha256 ' + actual + ')', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--coordinator-binary', type=Path, required=True)
    parser.add_argument('--node', default='node')
    parser.add_argument('--baseline-go', type=Path, default=Path('/tmp/peerspan-schema18-go-host'))
    parser.add_argument('--baseline-rust', type=Path, default=Path('/tmp/peerspan-schema18-rust-host'))
    parser.add_argument('--pairing', action='append', choices=('go/go', 'go/rust', 'rust/go', 'rust/rust'))
    parser.add_argument('--keep', action='store_true')
    parser.add_argument('--keep-failed', action='store_true', help='retain only the first failed pairing user/state evidence')
    parser.add_argument('--reuse-normal-bundles', type=Path,
                        help='public manifest of exact already-built normal archives for a fixture-only retry')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.coordinator = args.coordinator_key = None
    args.guided, args.pace = True, 0
    work = Path(tempfile.mkdtemp(prefix='peerspan-installed-link-'))
    harness = Harness(args, work)
    results, failure = [], None
    try:
        harness.check_prerequisites()
        start_coordinator(harness, args.coordinator_binary.resolve())
        if args.reuse_normal_bundles:
            reuse_normal_bundles(harness, args.reuse_normal_bundles.resolve())
        else:
            harness.package(('go', 'rust'))
        harness.share_node()
        clients = {}
        for implementation, (archive, _, root) in harness.archives.items():
            directory = work / ('client-' + implementation)
            directory.mkdir(mode=0o755)
            with tarfile.open(archive) as bundle:
                bundle.extractall(directory, filter='data')
            clients[implementation] = directory / root / 'bin/peerspan'
        for index, choice in enumerate(args.pairing or ('go/go', 'go/rust', 'rust/go', 'rust/rust')):
            if index:
                # Three private mailboxes per independent pairing would exceed
                # the production5/IP/hour bucket in a shared coordinator state.
                # Use fresh real state, with all caller pins explicitly passed.
                stop_coordinator(harness)
                start_coordinator(harness, args.coordinator_binary.resolve(), 'coord-' + str(index))
            cli, daemon = choice.split('/')
            print('Checking installed ' + choice + ' CLI/daemon', flush=True)
            try:
                results.append(pairing(harness, clients, cli, daemon, work / choice.replace('/', '-')))
                print('PASS installed ' + choice, flush=True)
            except Exception:
                if args.keep_failed:
                    args.keep = True
                raise
            finally:
                if not args.keep:
                    errors = harness.cleanup_users(harness.users)
                    need(not errors, 'fresh installed users/services clean up', errors)
                    harness.users.clear()
    except Exception:
        failure = traceback.format_exc()
        raise
    finally:
        cleanup = harness.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({'checked_at': now(), 'runs': results, 'release': harness.release,
                    'error': failure, 'passed': bool(results) and failure is None,
                    'cleanup': {'errors': cleanup, 'leftovers': leftovers()}, 'work_directory': str(work)}, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
