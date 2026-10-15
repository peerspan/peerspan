use peerspan_host::{
    model::{AttachSession, RegisterAgent},
    store::Store,
};
use std::os::unix::fs::{PermissionsExt, symlink};

#[test]
fn restart_preserves_identity_and_agents_but_disconnects_sessions() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("host");
    let store = Store::open(&path).unwrap();
    let identity = store.identity();
    let agent = store
        .register_agent(RegisterAgent {
            name: "bob".into(),
            owner: "bob".into(),
            capabilities: vec![],
        })
        .unwrap();
    let session = store
        .attach_session(AttachSession {
            agent_id: agent.id.clone(),
            integration: "test".into(),
        })
        .unwrap();
    assert!(Store::open(&path).is_err());
    drop(store);
    let restarted = Store::open(&path).unwrap();
    assert_eq!(restarted.identity(), identity);
    assert_eq!(restarted.agent(&agent.id).unwrap(), agent);
    assert_eq!(restarted.session(&session.id).unwrap().state, "detached");
    let events = restarted.events(0, 100).unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[2].kind, "session.disconnected");
}

#[test]
fn mutation_and_activity_commit_together() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("host");
    let store = Store::open(&path).unwrap();
    let connection = rusqlite::Connection::open(path.join("host.db")).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'injected event failure'); END").unwrap();
    let request = || RegisterAgent {
        name: "bob".into(),
        owner: "bob".into(),
        capabilities: vec![],
    };
    assert!(store.register_agent(request()).is_err());
    assert!(store.agents().unwrap().is_empty());
    connection.execute_batch("DROP TRIGGER fail_event").unwrap();
    assert!(store.register_agent(request()).is_ok());
}

#[test]
fn private_state_files_are_required() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Store::open(directory.path()).is_err());
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(outside.path(), "keep").unwrap();
    symlink(outside.path(), directory.path().join("host.db")).unwrap();
    assert!(Store::open(directory.path()).is_err());
    assert_eq!(std::fs::read(outside.path()).unwrap(), b"keep");
}
