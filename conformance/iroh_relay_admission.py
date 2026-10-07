#!/usr/bin/env python3
"""Prove relay admission separately from endpoint admission, with UDP blocked.

The receiver explicitly accepts a third endpoint. Only the relay's allowlist
excludes it. Changing that allowlist must enable a checked exchange with the
same endpoint key. This tests an owned iroh callback, not signed Capsule policy.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import tempfile
import time

from connectivity_bench import digest
from connectivity_suite import Fixture, Process, check


def run(binary, root, bounded):
    root.mkdir(mode=0o700)
    lab = Fixture(root, 'udp-blocked')
    processes = []
    report = {'profile': 'bounds' if bounded else 'native', 'events': [], 'status': 'running',
              'scope': 'local endpoint allowlist; no signed membership or cross-network equivalence claim'}
    with tempfile.TemporaryDirectory(prefix='capadmit-') as directory:
        state = Path(directory)
        try:
            lab.up()
            env = dict(os.environ, CAPSULE_NET_TRACE='iroh_relay=debug')
            relay_state = state / 'relay'
            relay = Process(lab, 'pub', [str(binary)], relay_state,
                            dict(env, CAPSULE_NET_MODE='relay', CAPSULE_NET_STATE=str(relay_state)), 'relay').start()
            processes.append(relay)
            relay.ready(relay=True)
            def node(name, side, port):
                node_state = state / name
                settings = dict(env, CAPSULE_NET_MODE='node', CAPSULE_NET_STATE=str(node_state),
                                CAPSULE_NET_BIND=f'0.0.0.0:{port}', CAPSULE_NET_RELAY='https://203.0.113.1:7400',
                                CAPSULE_NET_CA=str(relay_state / 'relay-cert.der'))
                if bounded:
                    settings['CAPSULE_IROH_MATCHED'] = '1'
                p = Process(lab, 'host' + side, [str(binary)], node_state, settings, name).start()
                processes.append(p)
                identity = p.ready()
                return p, {k: identity[k] for k in ('id', 'public_key')} | {'address': ''}
            alice, a = node('alice', 'A', 7401)
            bob, b = node('bob', 'B', 7401)
            outsider, c = node('outsider', 'A', 7403)
            alice.cmd(op='pin', target=b)
            outsider.cmd(op='pin', target=b)
            bob.cmd(op='pin', target=a)
            bob.cmd(op='pin', target=c)  # Endpoint policy allows the outsider.
            allow = relay_state / 'allow.json'
            allow.write_text(json.dumps([a['id'], b['id']]))
            def exchange(process):
                result = process.cmd(op='run', peer_id=b['id'], count=1, size=16, token=secrets.token_hex(8))
                report['events'].append({'endpoint': process.name, 'result': result})
                return result
            deadline = time.monotonic() + 45
            while exchange(alice).get('succeeded') != 1:
                check(time.monotonic() < deadline, 'admitted endpoint cannot reach receiver')
                time.sleep(0.2)
            check(exchange(outsider).get('succeeded') == 0, 'relay admitted excluded endpoint')
            report['excluded_endpoint_failed'] = True
            # Restart only the outsider to reset registration backoff; keep its
            # original key and the receiver's existing endpoint admission.
            allow.write_text(json.dumps([a['id'], b['id'], c['id']]))
            outsider.stop()
            outsider.start()
            check(outsider.ready()['id'] == c['id'], 'outsider identity changed')
            outsider.cmd(op='pin', target=b)
            deadline = time.monotonic() + 45
            while exchange(outsider).get('succeeded') != 1:
                check(time.monotonic() < deadline, 'adding relay admission did not enable connectivity')
                time.sleep(0.2)
            report.update(status='passed', admitted_same_key_succeeded=True,
                          identities={'alice': a, 'bob': b, 'outsider': c})
        except Exception as error:
            report.update(status='failed', error=f'{type(error).__name__}: {error}')
        finally:
            for process in reversed(processes):
                process.stop()
            lab.down()
    (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iroh', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    root = args.artifacts.resolve()
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    rows = [run(args.iroh.resolve(), root / name, name == 'bounds') for name in ('native', 'bounds')]
    report = {'binary_sha256': digest(args.iroh), 'cases': rows, 'status': 'passed' if all(r['status'] == 'passed' for r in rows) else 'failed'}
    (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    for row in rows:
        print(row['profile'], row['status'], row.get('error', 'relay admission isolated and verified'), flush=True)
    raise SystemExit(0 if report['status'] == 'passed' else 1)


if __name__ == '__main__':
    main()
