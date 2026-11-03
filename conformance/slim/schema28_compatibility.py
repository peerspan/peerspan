"""Public conversation tables missing from synthetic pre-conversation fixtures.

Final acceptance section1 permits these offline fixtures to remove both newer
histories. Real old-binary acceptance lives separately in installed_upgrade.py.
"""

CONVERSATION_TABLES = ('conversation_notifications', 'conversation_targets',
                       'conversation_invites', 'conversation_roster_outbound',
                       'conversation_reads', 'conversation_events',
                       'conversation_messages', 'conversations')


# Schemas30 (conversations C7) and31 (PF-1(a)) add these tables; a synthetic
# older state drops them too, so migration sees only the intended old history.
NEWER_TABLES = ('agent_descriptions', 'peerfs_bindings')


def drop_conversations(db):
    for table in CONVERSATION_TABLES + NEWER_TABLES:
        db.execute('DROP TABLE ' + table)
