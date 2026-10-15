#!/usr/bin/env python3
"""Measure peer message latency and throughput between real host daemons.

Each pairing starts two hosts with temporary state, configures manual peers and
an allow-disconnected grant, and drives the sender's owner-local API. Three
workloads run for small and maximum-size (65,536-byte) messages:

- send: sequential POST /v1/outbound. This includes the sender's durable
  outbound record, the peer exchange, the receiver's durable acceptance, and
  the sender recording the receipt.
- lookup: sequential reply lookup for an accepted request nobody answered.
  The sender asks the peer, the receiver reads and returns pending, and
  neither side writes, so this is dominated by the peer transport. (Refreshing
  an accepted receipt is not used: an accepted record returns locally.)
- concurrent send: throughput with several simultaneous senders.

Results compare these implementations and transports on one machine over
loopback. They do not establish general language or protocol performance.
Use optimized builds: Go's default build and Rust's release profile.
"""

import argparse
import concurrent.futures
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import platform
import secrets
import socket
import statistics
import subprocess
import tempfile
import time

from host_service import Host

SIZES = {'small': 16, 'max': 65536}


def timestamp(seconds):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')


def free_port():
    """Reserve a port that is free for both TCP and UDP, so either transport can bind it."""
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
            tcp.bind(('127.0.0.1', 0))
            port = tcp.getsockname()[1]
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.bind(('127.0.0.1', port))
            except OSError:
                continue
            return port


class BenchHost(Host):
    def __init__(self, binary, state):
        self.port = free_port()
        self.address = f'127.0.0.1:{self.port}'
        super().__init__(binary, state, ('--peer-listen', self.address))

    def api(self, method, path, body=None):
        status, value = self.call(method, path, body)
        assert status in (200, 201), (method, path, status, value)
        return value


def percentiles(samples):
    ordered = sorted(samples)

    def at(fraction):
        return round(ordered[min(len(ordered) - 1, int(fraction * len(ordered)))] * 1000, 3)
    return {'p50_ms': at(0.50), 'p90_ms': at(0.90), 'p99_ms': at(0.99),
            'mean_ms': round(statistics.fmean(ordered) * 1000, 3), 'samples': len(ordered)}


def run_pairing(sender_binary, receiver_binary, count, concurrency, warmup):
    with tempfile.TemporaryDirectory(prefix='peerspan-bench-') as directory:
        root = Path(directory)
        sender, receiver = BenchHost(sender_binary, root / 'sender'), BenchHost(receiver_binary, root / 'receiver')
        try:
            a, b = sender.start(), receiver.start()
            sender.api('POST', '/v1/peers', {'id': b['id'], 'public_key': b['public_key'], 'address': receiver.address})
            receiver.api('POST', '/v1/peers', {'id': a['id'], 'public_key': a['public_key'], 'address': sender.address})
            agent = receiver.api('POST', '/v1/agents', {'name': 'bench', 'owner': 'bench'})
            grant = receiver.api('POST', '/v1/grants', {'requester_host_id': a['id'], 'target_agent_id': agent['id'],
                                                        'expires_at': timestamp(3600), 'max_message_bytes': 65536,
                                                        'allow_disconnected': True})

            def send(content):
                body = {'peer_host_id': b['id'], 'request_id': 'request_' + secrets.token_hex(16),
                        'grant_id': grant['id'], 'target_agent_id': agent['id'],
                        'deadline': timestamp(1800), 'content': content}
                started = time.perf_counter()
                out = sender.api('POST', '/v1/outbound', body)
                elapsed = time.perf_counter() - started
                assert out['state'] == 'accepted', out
                return elapsed, out['request']['request_id']

            results = {}
            for name, size in SIZES.items():
                content = 'x' * size
                for _ in range(warmup):
                    send(content)
                sends, accepted = [], []
                for _ in range(count):
                    elapsed, rid = send(content)
                    sends.append(elapsed)
                    accepted.append(rid)
                lookups = []
                for rid in accepted:
                    started = time.perf_counter()
                    out = sender.api('POST', f"/v1/outbound/{b['id']}/{rid}/reply")
                    lookups.append(time.perf_counter() - started)
                    assert out['state'] == 'pending', out
                started = time.perf_counter()
                with concurrent.futures.ThreadPoolExecutor(concurrency) as pool:
                    concurrent_latencies = [elapsed for elapsed, _ in pool.map(lambda _: send(content), range(count))]
                wall = time.perf_counter() - started
                results[name] = {
                    'content_bytes': size,
                    'send': percentiles(sends),
                    'lookup': percentiles(lookups),
                    'concurrent_send': {**percentiles(concurrent_latencies), 'concurrency': concurrency,
                                        'messages_per_second': round(count / wall, 1)},
                }
            return results
        finally:
            for host in (sender, receiver):
                host.stop()
                host.logs.close()


def version(binary):
    result = subprocess.run(['git', 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True,
                            cwd=Path(binary).resolve().parent)
    return result.stdout.strip() or None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--go', type=Path, required=True, help='optimized Go peerspan-host')
    parser.add_argument('--rust', type=Path, required=True, help='Rust peerspan-host built with --release')
    parser.add_argument('--label', required=True, help='what these binaries are, e.g. "TCP/TLS main@abc1234"')
    parser.add_argument('--count', type=int, default=200)
    parser.add_argument('--concurrency', type=int, default=8)
    parser.add_argument('--warmup', type=int, default=10)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    binaries = {'Go': args.go.resolve(), 'Rust': args.rust.resolve()}
    report = {
        'label': args.label,
        'platform': platform.platform(),
        'cpu_count': __import__('os').cpu_count(),
        'network': 'loopback, one machine',
        'count': args.count, 'concurrency': args.concurrency, 'warmup': args.warmup,
        'note': 'send includes durable writes on both hosts (SQLite synchronous=FULL); lookup is a read-only reply lookup',
        'pairings': {},
    }
    for sender in binaries:
        for receiver in binaries:
            label = f'{sender}→{receiver}'
            report['pairings'][label] = run_pairing(binaries[sender], binaries[receiver],
                                                    args.count, args.concurrency, args.warmup)
            small, large = report['pairings'][label]['small'], report['pairings'][label]['max']
            print(f"{label}: send p50 {small['send']['p50_ms']} / {large['send']['p50_ms']} ms, "
                  f"lookup p50 {small['lookup']['p50_ms']} / {large['lookup']['p50_ms']} ms, "
                  f"concurrent {small['concurrent_send']['messages_per_second']} / "
                  f"{large['concurrent_send']['messages_per_second']} msg/s (small / 64 KiB)", flush=True)
    text = json.dumps(report, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    else:
        print(text)


if __name__ == '__main__':
    main()
