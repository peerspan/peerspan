#!/usr/bin/env python3
"""PF-1 storage gate: genuine prior-main binary, additive upgrade and full restore.

Supply executable directories --old-bin (the actual pre-PF main) and --bin.
All fixture state comes from their public APIs/CLI. SQLite is read-only;
no version rewriting or manufactured rows. Reuses independent public backup,
observation and process fixtures from installed_upgrade.py.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone

from installed_upgrade import (Budget, Host, PROCESSES, alarm, database, databases,
                               logical, observations, private_json, require, review, tree)


def retain(before, after):
    require(set(before['schema']) <= set(after['schema']), 'upgrade changed an original schema definition')
    for table, rows in before['tables'].items():
        # The shared DEC contract allows only its ordinary guarded-clock update.
        if table != 'dec_clock':
            require(after['tables'].get(table) == rows, 'upgrade changed original product or authority rows')


def public(host, network, agent, session, conversation, pending):
    value = observations(host, network, agent, session, conversation)
    value['grants'] = host.api('GET', '/v1/grants')
    value['peers'] = host.api('GET', '/v1/peers')
    value['review'] = host.api('GET', '/v1/onboarding/project-flows/' + pending['flow_id'])
    return value


def refuse(host, budget):
    before = databases(host.state), tree(host.config)
    host.launch()
    process = host.process
    try:
        try:
            code = process.wait(timeout=budget.remaining(5))
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=1)
            require(False, 'actual prior-main binary did not refuse upgraded storage within five seconds')
        require(code != 0, 'actual prior-main binary opened the newer host database')
    finally:
        host.process = None
        PROCESSES.discard(process)
    require((databases(host.state), tree(host.config)) == before,
            'prior-main refusal changed database bytes/rows/schema or private keys/configuration')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--old-bin', type=Path, required=True)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--work', type=Path, help='new private evidence directory; default is a short private temporary path')
    args = parser.parse_args()
    os.umask(0o077)
    work = args.work.resolve() if args.work else Path(tempfile.mkdtemp(prefix='pfu-'))
    if args.work:
        work.mkdir(mode=0o700)
    budget, hosts = Budget(), []
    report = {'suite': 'peerfs_local_upgrade', 'passed': False}
    previous = signal.signal(signal.SIGALRM, alarm)
    signal.setitimer(signal.ITIMER_REAL, 120)
    began = time.monotonic()
    try:
        old, new = (p.resolve() / 'peerspan-host' for p in (args.old_bin, args.bin))
        require(all(p.is_file() and os.access(p, os.X_OK) for p in (old, new)), 'both public executable inputs are required')
        hashes = [hashlib.sha256(p.read_bytes()).hexdigest() for p in (old, new)]
        require(hashes[0] != hashes[1], 'old/new inputs are the same executable')
        report.update(old_binary_sha256=hashes[0], new_binary_sha256=hashes[1])
        host = Host(work / 'host', old, budget)
        peer = Host(work / 'peer', old, budget)
        hosts.extend((host, peer))
        host.start()
        peer.start()
        peer_identity = peer.api('GET', '/v1/host')
        peer.stop()
        identity = host.api('GET', '/v1/host')
        network = host.cli('network', 'create', 'retained PF storage history', '--as', 'owner')
        require(network['mode'] == 'decentralized', 'prior-main did not create verified DEC authority')
        agent = host.api('POST', '/v1/agents', {'name': 'retained-agent', 'owner': 'fixture'}, expected=201)
        agent = host.api('POST', '/v1/agents/' + agent['id'] + '/description',
                         {'description': 'retained prior-main30 description'})
        require(agent['description'] == 'retained prior-main30 description', 'actual prior-main lacks its accepted C7 description')
        session = host.api('POST', '/v1/sessions', {'agent_id': agent['id'], 'integration': 'metadata'}, expected=201)
        host.api('POST', '/v1/sessions/' + session['id'] + '/detach', {})
        host.cli('peer', 'add', '--id', peer_identity['id'], '--public-key', peer_identity['public_key'],
                 '--address', '127.0.0.1:9')
        expires = (datetime.now(timezone.utc) + timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M:%SZ')
        grant = host.api('POST', '/v1/grants', {'requester_host_id': peer_identity['id'], 'target_agent_id': agent['id'],
                                             'expires_at': expires, 'max_message_bytes': 321, 'allow_disconnected': True}, expected=201)
        conversation = host.api('POST', '/v1/conversations',
            {'participants': [identity['id'] + '/' + agent['name']], 'title': 'retained PF history',
             'content': 'retain the original conversation message'}, expected=201)['conversation']['conversation_id']
        pending = review(host, 'retained')
        baseline = public(host, network['id'], agent['id'], session['id'], conversation, pending)
        require(grant in baseline['grants'] and baseline['members']['members']
                and baseline['catalog']['catalog']['objects'] and baseline['messages'],
                'actual prior-main fixture lacks grants, signed authority or conversation history')
        host.stop()
        original = logical(database(host.state))
        report['old_schema'] = original['version']
        backup = work / 'backup'
        backup.mkdir(mode=0o700)
        manifests = {}
        for name in ('state', 'config'):
            source = getattr(host, name)
            manifests[name] = tree(source)
            shutil.copytree(source, backup / name, copy_function=shutil.copy2)
            require(tree(backup / name) == manifests[name], 'complete private backup changed file modes/hashes')
        private_json(backup / 'manifest.json', manifests)
        private_json(work / 'before.json', baseline)

        host.binary = new
        host.start()
        require(public(host, network['id'], agent['id'], session['id'], conversation, pending) == baseline,
                'PF upgrade changed original public identity, authority, grants, guided review or conversations')
        directory = work / 'space'
        directory.mkdir(mode=0o700)
        body = {'space_id': 'space_' + os.urandom(16).hex(), 'network_id': network['id'],
                'context_id': network['context_id'], 'directory': str(directory)}
        binding = host.api('POST', '/v1/fs/spaces', body, expected=201)
        require(binding['state'] == 'prepared' and binding['host_id'] == identity['id'],
                'upgraded host did not prepare a real binding with its retained identity')
        host.stop()
        upgraded = logical(database(host.state))
        require(upgraded['version'] == original['version'] + 1, 'PF storage did not allocate one additive version after actual prior-main')
        additions = set(upgraded['tables']) - set(original['tables'])
        require(len(additions) == 1, 'PF storage did not add exactly one durable binding collection')
        require(body['space_id'] in repr(upgraded['tables'][next(iter(additions))]), 'binding did not survive in additive storage')
        retain(original, upgraded)
        require(tree(host.config) == manifests['config'], 'PF upgrade changed private person/key configuration')
        host.binary = old
        refuse(host, budget)
        host.binary = new
        host.start()
        require(host.api('GET', '/v1/fs/spaces/' + body['space_id']) == binding, 'new-binary restart lost immutable binding history')
        host.stop()

        # Restore the entire private preupgrade state/config into a new empty home.
        restored = Host(work / 'restored', old, budget)
        hosts.append(restored)
        for name in ('state', 'config'):
            destination = getattr(restored, name)
            destination.rmdir()
            shutil.copytree(backup / name, destination, copy_function=shutil.copy2)
            require(tree(destination) == manifests[name], 'complete restore changed a private file mode/hash')
        require(logical(database(restored.state)) == original, 'restored database differs from the complete old backup')
        restored.start()
        require(public(restored, network['id'], agent['id'], session['id'], conversation, pending) == baseline,
                'actual prior-main did not reopen exact restored identity, authority, grants, guided review and conversations')
        restored.stop()
        restored_state = logical(database(restored.state))
        require(restored_state['version'] == original['version'], 'old binary changed restored original storage version')
        retain(original, restored_state)
        require(tree(restored.config) == manifests['config'], 'restore changed original private identity configuration')
        report.update(passed=True, new_schema=upgraded['version'], additive_collections=len(additions),
                      old_refused_without_mutation=True, complete_backup_restored=True,
                      original_public_history_retained=True, binding_survived_restart=True)
    except Exception as error:
        report['failure'] = str(error)
    finally:
        for host in reversed(hosts):
            try:
                host.stop()
            except Exception:
                report['passed'] = False
                report['cleanup_failed'] = True
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    report['seconds'] = round(time.monotonic() - began, 2)
    private_json(work / 'result.json', report)
    print(json.dumps(report, sort_keys=True))
    print('private evidence: ' + str(work))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
