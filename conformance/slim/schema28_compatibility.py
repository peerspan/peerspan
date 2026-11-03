"""Public conversation tables missing from synthetic pre-conversation fixtures.

Final acceptance section1 permits these offline fixtures to remove both newer
histories. Real old-binary acceptance lives separately in installed_upgrade.py.
"""

CONVERSATION_TABLES = ('conversation_notifications', 'conversation_targets',
                       'conversation_invites', 'conversation_roster_outbound',
                       'conversation_reads', 'conversation_events',
                       'conversation_messages', 'conversations')


# Schema 30 (conversations C7) adds this table; a synthetic older state
# drops it too, so the migration creates it from a real older state.
NEWER_TABLES = ('agent_descriptions',)


def drop_conversations(db):
    for table in CONVERSATION_TABLES + NEWER_TABLES:
        db.execute('DROP TABLE ' + table)
