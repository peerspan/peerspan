#!/usr/bin/env python3
"""Export a compact comparison and an evidence bundle without fixture keys/binaries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tarfile


def resources(case):
    output = {}
    for event in case['events']:
        if 'resources_before' not in event:
            continue
        for name, before in event['resources_before'].items():
            after = event['resources_after'].get(name)
            if before is None or after is None:
                continue
            record = output.setdefault(name, {'measured_cpu_seconds': 0, 'max_sampled_rss_kib': 0, 'max_peak_rss_kib': 0})
            if before['pid'] == after['pid']:
                record['measured_cpu_seconds'] += max(0, after['cpu_seconds'] - before['cpu_seconds'])
            for sample in (before, after):
                record['max_sampled_rss_kib'] = max(record['max_sampled_rss_kib'], sample['rss_kib'] or 0)
                record['max_peak_rss_kib'] = max(record['max_peak_rss_kib'], sample['peak_rss_kib'] or 0)
    for record in output.values():
        record['measured_cpu_seconds'] = round(record['measured_cpu_seconds'], 3)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    if report['status'] not in ('complete', 'complete_with_failures'):
        parser.error('matrix is not finished')
    cases = report['cases']
    keys = [(c['scenario'], c['pair'], c['repeat']) for c in cases]
    if len(keys) != len(set(keys)):
        parser.error('duplicate fixture trials')
    audit = []
    for c in cases:
        for field, bound in [('first_verified_exchange_seconds', 30), ('relay_restart_recovery_seconds', 45),
                             ('peer_restart_recovery_seconds', 45), ('mapping_recovery_seconds', 60)]:
            if c.get(field, 0) > bound:
                audit.append({'scenario': c['scenario'], 'pair': c['pair'], 'repeat': c['repeat'], 'field': field,
                              'observed_seconds': c[field], 'claimed_bound_seconds': bound})
    compact = {k: v for k, v in report.items() if k != 'cases'}
    compact['completion_audit'] = {'trials': len(cases), 'passed': sum(c['status'] == 'passed' for c in cases),
                                 'failed': sum(c['status'] == 'failed' for c in cases), 'bounds_exceeded': audit}
    compact['cases'] = [{k: v for k, v in c.items() if k not in ('events', 'workloads', 'network_before', 'network_after')}
                        | {'helper_resources': resources(c), 'network_before': c.get('network_before'), 'network_after': c.get('network_after')}
                        for c in cases]
    # Include raw observations, sources, logs and captures from reused trials.
    # Exclude private runtime state and executable files from the export.
    with tarfile.open(args.bundle, 'w:gz') as archive:
        archive.add(args.report, arcname='report.json')
        sources = args.report.parent / 'sources'
        if sources.exists():
            archive.add(sources, arcname='sources')
        for c in cases:
            directory = Path(c['artifact_directory'])
            if not directory.is_absolute():
                directory = args.report.parent / directory
            name = f"{c['scenario']}-{c['repeat']:02d}-{c['pair']}"
            for path in sorted(directory.iterdir()):
                if path.is_file() and (path.suffix in ('.json', '.log', '.nft') or '.pcap' in path.name):
                    archive.add(path, arcname=f'{name}/{path.name}')
        # Original reports keep reused-trial provenance and interrupted runs.
        for path in {Path(c['provenance_report']) for c in cases if c.get('provenance_report')}:
            archive.add(path, arcname=f'provenance/{path.parent.name}-report.json')
            original_sources = path.parent / 'sources'
            if original_sources.exists():
                archive.add(original_sources, arcname=f'provenance/{path.parent.name}-sources')
    compact['evidence_bundle'] = {'path': os.path.relpath(args.bundle.resolve(), args.output.resolve().parent),
                                'sha256': hashlib.sha256(args.bundle.read_bytes()).hexdigest(),
                                'contains': 'raw attempts, source snapshots, logs, bounded pcap snapshots; excludes runtime keys and executables'}
    args.output.write_text(json.dumps(compact, indent=2) + '\n')
    print(f"Trials: {len(cases)}; passed: {compact['completion_audit']['passed']}; failed: {compact['completion_audit']['failed']}; bound audit: {len(audit)}")
    print(f'Compact report: {args.output}')
    print(f'Evidence bundle: {args.bundle}')


if __name__ == '__main__':
    main()
