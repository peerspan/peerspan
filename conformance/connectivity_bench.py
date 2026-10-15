#!/usr/bin/env python3
"""Compare Peerspan Go/Rust and pinned iroh with verified HTTP echoes on loopback.

Builds optimized helpers before timing, rotates execution order across repeats,
and retains raw samples and process logs. No production daemon exposes echo.
Relays, NAT traversal, grants, SQLite writes and agent delivery are not measured.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
BACKENDS = ('peerspan-go', 'peerspan-rust', 'iroh-rust-1.3.0')


def command(argv, cwd=ROOT):
    return subprocess.check_output(argv, cwd=cwd, text=True).strip()


def execute(argv, log, env=None, timeout=600, cwd=ROOT):
    with log.open('w') as output:
        result = subprocess.run(argv, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT,
                                timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f'{argv[0]} exited {result.returncode}; see {log}')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(raw, args):
    for key in ('count', 'cold', 'warmup', 'concurrency'):
        if raw[key] != getattr(args, key):
            raise ValueError(f'helper used wrong {key}')
    if raw['backend'] not in BACKENDS:
        raise ValueError('unknown backend')
    sets = [(raw['cold_first_echo_seconds'], args.cold)]
    if [w['content_bytes'] for w in raw['workloads']] != [16, 65536]:
        raise ValueError('unexpected payload sizes')
    for workload in raw['workloads']:
        sets.extend([(workload['sequential_seconds'], args.count),
                     (workload['concurrent_seconds'], args.count),
                     ([workload['concurrent_wall_seconds']], 1)])
    for samples, count in sets:
        if len(samples) != count or any(not math.isfinite(v) or v <= 0 for v in samples):
            raise ValueError('missing, non-finite or non-positive samples')


def distribution(samples):
    ordered = sorted(samples)
    # Nearest-rank percentiles. Raw seconds are kept for independent analysis.
    result = {f'p{p}_ms': round(ordered[max(0, math.ceil(len(ordered) * p / 100) - 1)] * 1000, 4)
              for p in (50, 90, 99)}
    return {**result, 'mean_ms': round(statistics.fmean(ordered) * 1000, 4), 'samples': len(ordered)}


def summarize(runs):
    output = {}
    for backend in BACKENDS:
        selected = [run for run in runs if run['backend'] == backend]
        if not selected:
            continue
        summary = {'cold_first_echo': distribution([v for r in selected for v in r['cold_first_echo_seconds']]),
                   'workloads': {}}
        for index, size in enumerate((16, 65536)):
            workloads = [r['workloads'][index] for r in selected]
            rates = [r['count'] / w['concurrent_wall_seconds'] for r, w in zip(selected, workloads)]
            summary['workloads'][str(size)] = {
                'sequential': distribution([v for w in workloads for v in w['sequential_seconds']]),
                'concurrent': distribution([v for w in workloads for v in w['concurrent_seconds']]),
                'requests_per_second_each_run': [round(v, 2) for v in rates],
                'median_requests_per_second': round(statistics.median(rates), 2),
                'median_payload_mib_per_second_each_direction': round(statistics.median(rates) * size / 1048576, 2),
            }
        output[backend] = summary
    return output


def build(artifacts):
    go_binary = artifacts / 'peerspan-go-bench'
    execute(['go', 'test', '-c', '-o', str(go_binary), './internal/host'], artifacts / 'build-go.log', cwd=ROOT / 'go')
    rust_log = artifacts / 'build-rust.log'
    execute(['cargo', 'test', '--release', '--locked', '--manifest-path', str(ROOT / 'rust/Cargo.toml'),
             '--lib', '--no-run', '--message-format=json'], rust_log)
    rust_binary = None
    for line in rust_log.read_text().splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get('reason') == 'compiler-artifact' and event.get('executable') and event['target']['name'] == 'peerspan_host':
            rust_binary = Path(event['executable']).resolve()
    if rust_binary is None:
        raise RuntimeError(f'no Rust test executable found; see {rust_log}')
    iroh_manifest = ROOT / 'conformance/connectivity/iroh/Cargo.toml'
    execute(['cargo', 'build', '--release', '--locked', '--manifest-path', str(iroh_manifest)], artifacts / 'build-iroh.log')
    iroh_binary = iroh_manifest.parent / 'target/release/peerspan-iroh-bench'
    return {'peerspan-go': [str(go_binary), '-test.run=^TestConnectivityBenchmark$', '-test.timeout=240s'],
            'peerspan-rust': [str(rust_binary), 'quic::connectivity_bench::connectivity_benchmark', '--exact', '--ignored', '--nocapture'],
            'iroh-rust-1.3.0': [str(iroh_binary)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--artifacts', type=Path, required=True, help='new directory for binaries, logs, raw samples and report')
    parser.add_argument('--count', type=int, default=200)
    parser.add_argument('--cold', type=int, default=20)
    parser.add_argument('--warmup', type=int, default=20)
    parser.add_argument('--concurrency', type=int, default=8)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--iroh-disable-gso', action='store_true', help='diagnostic control: disable iroh segmentation offload only')
    args = parser.parse_args()
    if args.count < 1 or args.cold < 1 or args.warmup < 0 or args.repeats < 1 or not 1 <= args.concurrency <= 16:
        parser.error('count/cold/repeats must be positive, warmup nonnegative, concurrency 1..16')
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=False)
    print(f'Building optimized helpers; logs: {artifacts}', flush=True)
    helpers = build(artifacts)
    env = os.environ.copy()
    env['GOMAXPROCS'] = '4'
    env.pop('PEERSPAN_IROH_GSO_OFF', None)
    if args.iroh_disable_gso:
        env['PEERSPAN_IROH_GSO_OFF'] = '1'
    for key in ('count', 'cold', 'warmup', 'concurrency'):
        env['PEERSPAN_BENCH_' + key.upper()] = str(getattr(args, key))
    report = {
        'schema_version': 1, 'status': 'running', 'started_at_utc': datetime.now(timezone.utc).isoformat(),
        'scope': 'IPv4 loopback; both endpoints in one process; authenticated QUIC; one HTTP/1.1 verified echo per bidi stream',
        'excluded': ['relays', 'NAT traversal', 'production request authorization', 'durable SQLite writes', 'agent delivery'],
        'platform': platform.platform(), 'cpu_count': os.cpu_count(),
        'cpu_affinity': sorted(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else None,
        'host_isolation': 'not enforced; inspect per-run host load; results are preliminary on a shared host',
        'cpu_model': next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                           if line.startswith('model name')), None) if Path('/proc/cpuinfo').exists() else None,
        'toolchains': {'go': command(['go', 'version']), 'rust': command(['rustc', '--version'])},
        'source_commit': command(['git', 'rev-parse', 'HEAD']),
        'source_status': command(['git', 'status', '--short']),
        'parameters': {key: getattr(args, key) for key in ('count', 'cold', 'warmup', 'concurrency', 'repeats')},
        'workers': 4, 'resumption': 'disabled', 'iroh_version': '1.3.0',
        'iroh_gso_disabled': args.iroh_disable_gso,
        'iroh_configuration': 'default crate features; Minimal preset; only IPv4 loopback socket; explicit peer address; portmapper disabled; max_tls_tickets=0',
        'peerspan_configuration': 'production socket, TLS pins, dial and HTTP stream client; benchmark-only echo server',
        'binary_sha256': {name: digest(Path(argv[0])) for name, argv in helpers.items()},
        'lock_sha256': {name: digest(ROOT / path) for name, path in {
            'go': 'go/go.sum', 'peerspan-rust': 'rust/Cargo.lock', 'iroh': 'conformance/connectivity/iroh/Cargo.lock'}.items()},
        'runs': [],
    }
    report_path = artifacts / 'report.json'
    # Preserve the measured source delta independently of the current checkout.
    (artifacts / 'source.diff').write_text(command(['git', 'diff', 'HEAD']))
    # New benchmark files are untracked during initial development; hash them too.
    sources = [ROOT / 'go/internal/host/connectivity_bench_test.go', ROOT / 'rust/src/quic.rs',
               ROOT / 'rust/src/quic/connectivity_bench.rs', ROOT / 'conformance/connectivity_bench.py',
               ROOT / 'conformance/connectivity/driver.rs', ROOT / 'conformance/connectivity/iroh/src/main.rs',
               ROOT / 'conformance/connectivity/iroh/Cargo.toml']
    report['harness_sha256'] = {str(path.relative_to(ROOT)): digest(path) for path in sources}
    for source in sources:
        snapshot = artifacts / 'sources' / source.relative_to(ROOT)
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(source.read_bytes())
    def checkpoint():
        report['summary'] = summarize(report['runs'])
        report_path.write_text(json.dumps(report, indent=2) + '\n')
    checkpoint()
    try:
        for repeat in range(args.repeats):
            order = BACKENDS[repeat % 3:] + BACKENDS[:repeat % 3]
            for backend in order:
                label = f'{repeat + 1:02d}-{backend}'
                raw_path = artifacts / f'{label}.json'
                env['PEERSPAN_BENCH_OUTPUT'] = str(raw_path)
                print(f'Measuring {label}', flush=True)
                started = time.perf_counter()
                load_before = list(os.getloadavg()) if hasattr(os, 'getloadavg') else None
                execute(helpers[backend], artifacts / f'{label}.log', env=env, timeout=250)
                raw = json.loads(raw_path.read_text())
                validate(raw, args)
                if raw['backend'] != backend:
                    raise ValueError('wrong backend result')
                raw.update(repeat=repeat + 1, process_wall_seconds=time.perf_counter() - started,
                           host_load_before=load_before,
                           host_load_after=list(os.getloadavg()) if hasattr(os, 'getloadavg') else None)
                report['runs'].append(raw)
                checkpoint()
        report['status'] = 'complete'
    except BaseException as error:
        report.update(status='failed', error=f'{type(error).__name__}: {error}')
        raise
    finally:
        checkpoint()
    for backend, summary in report['summary'].items():
        small, large = summary['workloads']['16'], summary['workloads']['65536']
        print(f"{backend}: cold p50 {summary['cold_first_echo']['p50_ms']} ms; "
              f"warm p50 {small['sequential']['p50_ms']} / {large['sequential']['p50_ms']} ms; "
              f"concurrent {small['median_requests_per_second']} / {large['median_requests_per_second']} req/s (16 B / 64 KiB)")
    print(f'Report: {report_path}')


if __name__ == '__main__':
    main()
