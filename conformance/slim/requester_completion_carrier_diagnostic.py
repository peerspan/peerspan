#!/usr/bin/env python3
"""Run unchanged requester_completion with bounded receive-only failure metadata.

GU.impl48/7615bbe: no additional host/API/database/network/subprocess work.
Only existing CountedUDP recvfrom results are observed; original forwarding,
case registration, comparisons, timeouts, argv and verdict remain authoritative.
Addresses stay private and are used only for equality against held peer ports.
"""
from collections import deque
from functools import wraps
import json
from pathlib import Path
import runpy
import socket
import threading

import counted_peer
import harness


def header_class(data):
    if type(data) is not bytes or not data:
        return 'unknown'
    first = data[0]
    if first & 0x80:
        if len(data) < 5:
            return 'unknown'
        if data[1:5] != b'\x00\x00\x00\x01':
            return 'long_other_version'
        if not first & 0x40:
            return 'unknown'
        return 'long_v1_initial' if first & 0x30 == 0 else 'long_v1_other'
    return 'short' if first & 0x40 else 'unknown'


def peer_match(source, host):
    port = getattr(host, 'peer_port', None)
    if type(port) is not int or not 0 < port < 65536:
        return 'unknown'
    return source == ('127.0.0.1', port)


def process_running(host):
    if host is None or not hasattr(host, 'process'):
        return 'unknown'
    return host.process is not None and host.process.poll() is None


class Observer:
    def __init__(self):
        self.lock = threading.Lock()
        self.endpoints = {}
        self.fixture = None

    def register(self, endpoint):
        with self.lock:
            if endpoint.socket not in self.endpoints and len(self.endpoints) < 256:
                self.endpoints[endpoint.socket] = (endpoint, deque(maxlen=32))

    def receive(self, listener, result):
        # Called after the original recvfrom and before the unchanged forwarder
        # increments its receive counter. Registration may miss startup events.
        with self.lock:
            entry = self.endpoints.get(listener)
            if entry is None:
                return
            endpoint, events = entry
            data, client = result
            ordinal = endpoint.received_datagrams + 1
            if type(ordinal) is not int or ordinal < 1 or type(data) is not bytes:
                return
            events.append((ordinal, len(data), client, client in endpoint.routes, header_class(data)))

    def report(self, actual, expected, phase, mode):
        if actual == expected:
            return
        try:
            f = self.fixture
            if type(f) is not dict:
                raise ValueError
            hosts = [('issuer', f.get('a')), ('requester', f.get('h'))]
            offset = sum(bool(getattr(host, 'relay', None)) for _, host in hosts)
            endpoints = [(role, getattr(host, 'counted_peer', None)) for role, host in hosts
                         if getattr(host, 'counted_peer', None) is not None]
            if len(actual) != offset + len(endpoints) or len(expected) != len(actual):
                raise ValueError
            crossed = []
            for index, (role, endpoint) in enumerate(endpoints, offset):
                before, after = expected[index], actual[index]
                if before == after:
                    continue
                if len(before) != 4 or len(after) != 4 or any(
                        type(a) is not int or type(b) is not int or a < 0 or b < a
                        for a, b in zip(before, after)):
                    raise ValueError
                with self.lock:
                    registered = self.endpoints.get(endpoint.socket)
                    if registered is None or registered[0] is not endpoint:
                        raise ValueError
                    window = [event for event in registered[1] if before[0] < event[0] <= after[0]]
                events = [{'length': length, 'header_class': kind,
                           'source_matches_requester_peer': peer_match(source, f.get('h')),
                           'source_matches_issuer_peer': peer_match(source, f.get('a')),
                           'route_previously_present': had_route}
                          for _, length, source, had_route, kind in window[-8:]]
                thread = getattr(endpoint, 'thread', None)
                crossed.append({'participant': role, 'events': events,
                    'observer_buffer_truncated': len(window) > 8 or len(window) != after[0] - before[0],
                    'forwarder_thread_alive': thread.is_alive() if thread is not None else 'unknown',
                    'issuer_process_running': process_running(f.get('a')),
                    'requester_process_running': process_running(f.get('h'))})
            if crossed:
                summary = {'phase': phase if phase in ('expired', 'detached', 'restarted') else 'unknown',
                           'mode': mode if mode in ('API', 'CLI') else 'unknown', 'carriers': crossed}
                print('requester_completion_receive_failure_public=' + json.dumps(summary, sort_keys=True), flush=True)
        except BaseException:
            try:
                print('requester_completion_receive_diagnostic_unavailable', flush=True)
            except BaseException:
                pass  # Observer failure never changes the original verdict.


def observed_socket(base, observer):
    class ReceiveObservedSocket(base):
        def recvfrom(self, *args, **kwargs):
            result = super().recvfrom(*args, **kwargs)
            try:
                observer.receive(self, result)
            except BaseException:
                pass
            return result
    return ReceiveObservedSocket


def observed_udp_init(original, observer):
    @wraps(original)
    def initialize(endpoint, *args, **kwargs):
        result = original(endpoint, *args, **kwargs)
        try:
            observer.register(endpoint)
        except BaseException:
            pass
        return result
    return initialize


def observed_case(original, observer):
    @wraps(original)
    def case(suite, *args, **kwargs):
        decorator = original(suite, *args, **kwargs)

        def register(function):
            namespace = function.__globals__
            saved = {key: namespace[key] for key in ('traffic', 'terminal_carrier_diagnostic') if key in namespace}
            observer.fixture = None
            try:
                if 'traffic' in saved:
                    @wraps(saved['traffic'])
                    def traffic(*args, **kwargs):
                        result = saved['traffic'](*args, **kwargs)
                        try:
                            observer.fixture = args[0] if args else kwargs.get('f')
                        except BaseException:
                            pass
                        return result
                    namespace['traffic'] = traffic
                if 'terminal_carrier_diagnostic' in saved:
                    @wraps(saved['terminal_carrier_diagnostic'])
                    def terminal(*args, **kwargs):
                        result = saved['terminal_carrier_diagnostic'](*args, **kwargs)
                        try:
                            values = dict(zip(('actual', 'expected', 'phase', 'mode'), args))
                            values.update(kwargs)
                            observer.report(values['actual'], values['expected'], values['phase'], values['mode'])
                        except BaseException:
                            pass
                        return result
                    namespace['terminal_carrier_diagnostic'] = terminal
                return decorator(function)
            finally:
                namespace.update(saved)
                observer.fixture = None
        return register
    return case


def main():
    original_socket = socket.socket
    original_init = counted_peer.CountedUDP.__init__
    original_case = harness.Suite.case
    observer = Observer()
    try:
        socket.socket = observed_socket(original_socket, observer)
        counted_peer.CountedUDP.__init__ = observed_udp_init(original_init, observer)
        harness.Suite.case = observed_case(original_case, observer)
        return runpy.run_path(str(Path(__file__).with_name('requester_completion.py')), run_name='__main__')
    finally:
        socket.socket = original_socket
        counted_peer.CountedUDP.__init__ = original_init
        harness.Suite.case = original_case


if __name__ == '__main__':
    main()
