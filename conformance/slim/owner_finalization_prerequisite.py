#!/usr/bin/env python3
"""GU.impl48: establish a genuine current own hint before expired-history reads.

Contract68ee627 and GU.impl33e/g; independent public test prerequisites only.
The unchanged final case keeps its exact expiry advance, spare create/cancel,
all subject calls, snapshots, counters and timeouts. No inspection warmup.
"""
import base64
from contextlib import closing
from datetime import timedelta
from functools import wraps
import hashlib
import json
from pathlib import Path
import runpy
import sqlite3

import harness


CASE = 'same_request_explicit_original_F_and_requester_commit_then_pure_refusal_and_owner_history'
CONTACT = set('format context_id host_public_key sequence issued_at expires_at payload_base64 signature'.split())


def verify_contact(namespace, f, retained, *, cleanup=False):
    h = f['h']; expected = retained['contact']; check = namespace['check']; parse = namespace['parse_time']
    with closing(sqlite3.connect(f'file:{namespace["db_path"](h)}?mode=ro', uri=True, timeout=2)) as db:
        db.execute('BEGIN')
        row = db.execute('SELECT sequence,record FROM dec_contacts WHERE network_id=? AND context_id=? AND host_key=?',
                         (f['network']['id'], retained['context'], h.public_key)).fetchone()
        if cleanup:
            pending = db.execute('SELECT secret,terminal_read_cap FROM dec_pending WHERE request_id=?', (retained['invitation'],)).fetchone()
            frames = db.execute('SELECT count(*) FROM dec_frames WHERE request_id=?', (retained['invitation'],)).fetchone()[0]
            check((pending is None or pending == (None, None)) and frames == 0,
                  'original spare maintenance did not retire actual temporary contact references')
    check(row is not None, 'current own contact prerequisite lacks retained contact')
    stored_sequence = row[0]
    check(type(stored_sequence) is int or type(stored_sequence) is bytes and len(stored_sequence) == 8 and stored_sequence[0] & 0x80,
          'current own contact sequence does not use the documented U64 codec')
    sequence = int.from_bytes(stored_sequence, 'big') if type(stored_sequence) is bytes else stored_sequence
    record = json.loads(row[1])
    check(type(sequence) is int and 0 <= sequence <= 2**64 - 1
          and type(record) is dict and set(record) == {'format', 'message_hashes', 'conflicted', 'contacts_base64'}
          and type(record['format']) is int and record['format'] == 1 and record['conflicted'] is False
          and type(record['contacts_base64']) is list and len(record['contacts_base64']) == 1
          and type(record['message_hashes']) is list,
          'current own contact prerequisite has malformed retained guard')
    contact_bytes = base64.b64decode(record['contacts_base64'][0], validate=True)
    check(len(contact_bytes) <= 8192, 'current own contact exceeds public bound')
    contact = json.loads(contact_bytes)
    check(type(contact) is dict and set(contact) == CONTACT and contact == expected,
          'retained own contact differs from actual signed handoff')
    payload = base64.b64decode(contact['payload_base64'], validate=True)
    check(type(contact['format']) is int and contact['format'] == 1 and contact['host_public_key'] == h.public_key
          and contact['context_id'] == retained['context'] and type(contact['sequence']) is int and contact['sequence'] == sequence
          and json.loads(payload) == {'quic_addresses': [h.peer_address], 'bootstrap_addresses': [h.relay.address], 'relays': []}
          and parse(contact['issued_at']) > parse(f['view']['expires_at']) and parse(contact['issued_at']) <= h.now()
          and max(h.now(), retained['cleanup']) + timedelta(seconds=60) <= parse(contact['expires_at'])
          and parse(contact['expires_at']) - parse(contact['issued_at']) <= timedelta(seconds=300),
          'current signed own contact does not cover known transport and cleanup bounds')
    message = '\n'.join(('peerspan-decentralized-contact-v1', contact['context_id'], h.public_key,
        str(contact['sequence']), contact['issued_at'], contact['expires_at'], hashlib.sha256(payload).hexdigest())).encode()
    check(record['message_hashes'] == [hashlib.sha256(message).hexdigest()], 'current own contact message guard differs')
    namespace['ed25519'](h.public_key, contact['signature'], message, 'history-current-own-contact')


def prepare_contact(namespace, f, original_advance):
    h = f['h']; check = namespace['check']; parse = namespace['parse_time']
    view = namespace['get'](h, '/v2/networks/' + f['network']['id'])
    key = namespace['ssh_key'](namespace['suite'].work, 'history-current-own-contact-recipient')
    status, issued = h.api('POST', '/v2/networks/' + f['network']['id'] + '/invitations', {
        'member': 'Unused current-contact prerequisite', 'expected_person_public_key': namespace['ssh_public_base64'](key),
        'expires_at': namespace['rfc3339'](h.now() + timedelta(seconds=65))})
    check(status == 201 and type(issued) is dict and issued.get('invitation', '').startswith('psi2-'),
          'genuine unused current-contact invitation prerequisite failed')
    encoded = issued['invitation'][5:]
    envelope = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
    invitation = json.loads(base64.b64decode(envelope['payload_base64'], validate=True))
    contacts = [contact for contact in invitation['contacts'] if contact['host_public_key'] == h.public_key
                and contact['context_id'] == view['context_id']]
    check(contacts and all(type(contact['sequence']) is int and 0 <= contact['sequence'] <= 2**64 - 1 for contact in contacts),
          'genuine short invitation lacks actual bound own contact')
    contact = max(contacts, key=lambda value: value['sequence']); cleanup = parse(issued['expires_at']) + timedelta(seconds=1)
    check(view['authority']['state'] == 'usable' and cleanup < parse(view['authority']['not_after'])
          and parse(contact['expires_at']) >= cleanup + timedelta(seconds=60),
          'current authority or own contact does not cover actual short-ref cleanup')
    retained = {'contact': contact, 'invitation': issued['invitation_id'], 'context': view['context_id'], 'cleanup': cleanup}
    verify_contact(namespace, f, retained)
    original_advance(h, cleanup)
    return retained


def wrap_case(original):
    @wraps(original)
    def case(suite, *args, **kwargs):
        decorator = original(suite, *args, **kwargs)
        name = args[0] if args else kwargs.get('name')

        def register(function):
            if name != CASE:
                return decorator(function)
            namespace = function.__globals__; advance = namespace['advance_to']; quiet = namespace['quiet']
            state = {}

            @wraps(advance)
            def after_expiry(h, moment):
                result = advance(h, moment)
                f = namespace['shared']
                expected = namespace['parse_time'](f['view']['expires_at']) + timedelta(seconds=1)
                namespace['check'](not state and h is f['h'] and moment == expected,
                                   'current-contact prerequisite expected one exact original expiry advance')
                state['f'] = f; state['retained'] = prepare_contact(namespace, f, advance)
                return result

            @wraps(quiet)
            def before_snapshot(f, *args, **kwargs):
                if state:
                    namespace['check'](f is state['f'], 'current-contact prerequisite changed fixture')
                    verify_contact(namespace, f, state['retained'], cleanup=True)
                return quiet(f, *args, **kwargs)

            namespace['advance_to'], namespace['quiet'] = after_expiry, before_snapshot
            try:
                return decorator(function)
            finally:
                namespace['advance_to'], namespace['quiet'] = advance, quiet
        return register
    return case


def main():
    original = harness.Suite.case
    try:
        harness.Suite.case = wrap_case(original)
        return runpy.run_path(str(Path(__file__).with_name('owner_finalization.py')), run_name='__main__')
    finally:
        harness.Suite.case = original


if __name__ == '__main__':
    main()
