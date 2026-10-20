use super::*;
use crate::{
    adapter_connection::AdapterAuth,
    adapter_outbound::tests::connected_adapter,
    peer_store::{CreateGrant, Origin, key_id},
    policy::{DELEGATE_ACTION, TASK_ACTION},
    store::rfc3339,
    task::{Change, LAPSED, TaskRequest},
    task_outbound::{SubmitTask, TaskParent},
};
use chrono::TimeDelta;

const NET: &str = "net_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PERSON: &str = "person_72456720412037a6b339f884ce6d91bb4cc163a7dc3e4c58c658e6c2097b92a2";

fn seeded(start: u8) -> SigningKey {
    let seed: [u8; 32] = std::array::from_fn(|i| start + i as u8);
    SigningKey::from_bytes(&seed)
}
fn id_of(key: &SigningKey) -> String {
    key_id(key.verifying_key().as_bytes())
}
fn agent(n: char) -> String {
    format!("agent_{}", n.to_string().repeat(32))
}
fn task_id(n: char) -> String {
    format!("task_{}", n.to_string().repeat(32))
}
fn network() -> Vec<String> {
    vec![NETWORK.into()]
}

#[test]
fn links_reproduce_the_shared_vector() {
    let (k0, k1) = (seeded(0x00), seeded(0x20));
    assert_eq!(
        id_of(&k0),
        "host_56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c"
    );
    assert_eq!(
        id_of(&k1),
        "host_24f6ed6acbfe1009c030d7ca567c33ca4830911498236b5561a6c82abec5de28"
    );
    let originator = "agent_0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f";
    let link0 = Link::sign(
        &k0,
        Unsigned {
            network_id: NET,
            previous: None,
            audience_host_id: &id_of(&k1),
            task_id: "task_00112233445566778899aabbccddeeff",
            originator_agent_id: originator,
            principals: &network(),
            deadline: "2026-10-10T00:00:00Z",
            depth: 2,
        },
    );
    assert_eq!(
        link0.statement(),
        format!(
            "peerspan-delegation-v1\n{NET}\n0\nnone\n{}\n{}\ntask_00112233445566778899aabbccddeeff\n{originator}\nnetwork\n2026-10-10T00:00:00Z\n2",
            id_of(&k0),
            id_of(&k1)
        )
    );
    assert_eq!(
        link0.signature,
        "S2sFkjmIIkmXC6D4qNIerxRpeYZ0GNL22iWGjG2TPLCX1PnV+x0sGr7rG8BfOHS4hzyQRiSh//2Rh8ZwhhliCQ=="
    );
    assert_eq!(
        link0.digest(),
        "bc5f57c2363071701a685c896296288dbb90d293604e20ee6ca38153bbc474a3"
    );
    let link1 = Link::sign(
        &k1,
        Unsigned {
            network_id: NET,
            previous: Some(&link0),
            audience_host_id: "host_fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            task_id: "task_ffeeddccbbaa99887766554433221100",
            originator_agent_id: originator,
            principals: &network(),
            deadline: "2026-10-09T12:00:00Z",
            depth: 1,
        },
    );
    assert_eq!(link1.index, 1);
    assert_eq!(link1.previous, link0.digest());
    assert_eq!(
        link1.signature,
        "p084GJDwcslS5CxDwZqspuxecXittC3XEV2UyGHMSX26xoCN49NAOFeWdfzKpRNfYoSBYaEe5nO4AGAXqyzuDA=="
    );
    assert_eq!(
        link1.digest(),
        "3b01028b7cb9b4d5ed6f23ba49e92966030711983a17792a11edd23834926d1c"
    );
    let key = |k: &SigningKey| STANDARD.encode(k.verifying_key().as_bytes());
    assert!(link0.verify(&key(&k0)) && link1.verify(&key(&k1)));
    assert!(!link0.verify(&key(&k1)));
    let mut tampered = link0.clone();
    tampered.depth = 1;
    assert!(!tampered.verify(&key(&k0)));
    // The JSON shape: exactly the 11 fields, in the shared order.
    let encoded = serde_json::to_value(&link0).unwrap();
    let keys: Vec<&str> = encoded
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let mut sorted = [
        "network_id",
        "index",
        "previous",
        "issuer_host_id",
        "audience_host_id",
        "task_id",
        "originator_agent_id",
        "principals",
        "deadline",
        "depth",
        "signature",
    ];
    sorted.sort();
    assert_eq!(keys, sorted);
    validate(&[link0, link1]).unwrap();
}

#[test]
fn malformed_chains_are_invalid() {
    let k = seeded(0);
    let link = Link::sign(
        &k,
        Unsigned {
            network_id: NET,
            previous: None,
            audience_host_id: &id_of(&seeded(0x20)),
            task_id: &task_id('1'),
            originator_agent_id: &agent('1'),
            principals: &network(),
            deadline: "2026-10-10T00:00:00Z",
            depth: 1,
        },
    );
    let base = serde_json::to_value(&link).unwrap();
    for (field, value) in [
        ("extra", serde_json::json!(1)),
        ("index", serde_json::json!(-1)),
        ("depth", serde_json::json!("1")),
        ("principals", serde_json::Value::Null),
    ] {
        let mut v = base.clone();
        v[field] = value;
        assert!(serde_json::from_value::<Link>(v).is_err(), "{field}");
    }
    let mut missing = base.clone();
    missing.as_object_mut().unwrap().remove("previous");
    assert!(serde_json::from_value::<Link>(missing).is_err());
    let invalid = |change: &dyn Fn(&mut Link)| {
        let mut l = link.clone();
        change(&mut l);
        matches!(validate(&[l]), Err(Error::Invalid(_)))
    };
    assert!(invalid(&|l| l.principals = vec!["person:x".into()]));
    assert!(invalid(&|l| l.principals = vec![]));
    assert!(invalid(
        &|l| l.principals = vec!["network".into(), "network".into()]
    ));
    assert!(invalid(
        &|l| l.principals = vec![format!("person:{PERSON}"), "host:x".into()]
    ));
    assert!(invalid(
        &|l| l.principals = vec!["network".into(), format!("host:{}", id_of(&k))]
    ));
    assert!(invalid(
        &|l| l.principals = (0..17).map(|i| format!("host:host_{:064x}", i)).collect()
    ));
    assert!(invalid(&|l| l.deadline = "2026-10-10T02:00:00+02:00".into()));
    assert!(invalid(&|l| l.previous = "abc".into()));
    assert!(invalid(&|l| l.network_id = "net_x".into()));
    assert!(invalid(&|l| l.signature = "AAAA".into()));
    assert!(invalid(&|l| l.task_id = "task_1".into()));
    // Sorted principals of every shape are well formed; depth and index
    // values are checks, not shapes.
    let mut sorted = vec![
        format!("host:{}", id_of(&k)),
        "network".into(),
        format!("person:{PERSON}"),
    ];
    sorted.sort();
    assert!(!invalid(&|l| l.principals = sorted.clone()));
    assert!(!invalid(&|l| l.depth = 7));
    assert!(matches!(validate(&[]), Err(Error::Invalid(_))));
    assert!(matches!(
        validate(&[link.clone(), link.clone(), link.clone(), link.clone()]),
        Err(Error::Invalid(_))
    ));
    // On the wire an empty or null chain is malformed.
    let request = serde_json::json!({
        "task_id": task_id('1'),
        "grant_id": format!("grant_{}", "0".repeat(32)),
        "target_agent_id": agent('2'),
        "deadline": "2026-10-10T00:00:00Z",
        "input": "hi",
    });
    let mut null = request.clone();
    null["delegation"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<TaskRequest>(null).is_err());
    let mut empty = request;
    empty["delegation"] = serde_json::json!([]);
    let empty: TaskRequest = serde_json::from_value(empty).unwrap();
    assert!(matches!(
        crate::task::validate_task(&empty),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn principals_cover_by_current_bindings() {
    let h = format!("host_{}", "a".repeat(64));
    let other = format!("host_{}", "b".repeat(64));
    let bound = |host: &str| (host == h).then(|| PERSON.to_owned());
    let person = format!("person:{PERSON}");
    let host = format!("host:{h}");
    assert!(covers(NETWORK, &person, &bound));
    assert!(covers(NETWORK, NETWORK, &bound));
    assert!(covers(&person, &person, &bound));
    assert!(covers(&person, &host, &bound));
    assert!(!covers(&person, &format!("host:{other}"), &bound));
    assert!(!covers(&person, NETWORK, &bound));
    assert!(covers(&host, &host, &bound));
    assert!(!covers(&host, &person, &bound));
    assert!(!covers(&host, NETWORK, &bound));
    assert_eq!(
        normalized_principals(None).unwrap(),
        vec![NETWORK.to_owned()]
    );
    assert_eq!(
        normalized_principals(Some(vec![host.clone(), person.clone(), host.clone()])).unwrap(),
        vec![host, person]
    );
}

/// A receiving host R in a network with originator A, middle hosts B and C,
/// and a further host D. A is bound to a person.
struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    me: String,
    a: SigningKey,
    b: SigningKey,
    c: SigningKey,
    d: SigningKey,
    target: String,
    auth: AdapterAuth,
}
fn add_member(store: &Store, host: &str, key: &str, person: Option<&str>) {
    let m = Member {
        host_id: host.into(),
        public_key: key.into(),
        member: "m".into(),
        address: String::new(),
        candidates: vec![],
        updated_at: crate::store::now(),
        membership: None,
        admission: None,
        person_id: person.map(Into::into),
        person_member: None,
    };
    store
        .connection()
        .unwrap()
        .execute(
            "INSERT OR REPLACE INTO network_members VALUES (?1, ?2, ?3)",
            params![NET, host, serde_json::to_string(&m).unwrap()],
        )
        .unwrap();
}
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("host")).unwrap();
    let me = store.identity();
    add_member(&store, &me.id, &me.public_key, None);
    let (a, b, c, d) = (seeded(0x00), seeded(0x20), seeded(0x40), seeded(0x60));
    for (k, person) in [(&a, Some(PERSON)), (&b, None), (&c, None), (&d, None)] {
        add_member(
            &store,
            &id_of(k),
            &STANDARD.encode(k.verifying_key().as_bytes()),
            person,
        );
    }
    let auth = connected_adapter(&store, "worker");
    let target = store.adapter_session(&auth).unwrap().agent_id;
    Fixture {
        _dir: dir,
        store,
        me: me.id,
        a,
        b,
        c,
        d,
        target,
        auth,
    }
}
impl Fixture {
    fn grant(&self, requester: &str, action: &str) -> String {
        self.store
            .create_grant(CreateGrant {
                requester_host_id: requester.into(),
                target_agent_id: self.target.clone(),
                expires_at: rfc3339(Utc::now() + TimeDelta::hours(2)),
                max_message_bytes: 1000,
                max_artifact_bytes: 0,
                allow_disconnected: true,
                requester_agent_id: None,
                action: Some(action.into()),
            })
            .unwrap()
            .id
    }
    fn deadline(minutes: i64) -> String {
        rfc3339(Utc::now() + TimeDelta::minutes(minutes))
    }
    /// Link 0 from A to `audience`, then one link per further key; the last
    /// link names R and `task`.
    fn chain(&self, hops: &[&SigningKey], depth: u64, task: &str, deadline: &str) -> Vec<Link> {
        let mut issuers: Vec<&SigningKey> = vec![&self.a];
        issuers.extend_from_slice(hops);
        let mut chain: Vec<Link> = Vec::new();
        for (k, issuer) in issuers.iter().enumerate() {
            let last = k == issuers.len() - 1;
            let audience = if last {
                self.me.clone()
            } else {
                id_of(issuers[k + 1])
            };
            let link = Link::sign(
                issuer,
                Unsigned {
                    network_id: NET,
                    previous: chain.last(),
                    audience_host_id: &audience,
                    task_id: &if last { task.to_owned() } else { task_id('0') },
                    originator_agent_id: &agent('a'),
                    principals: &network(),
                    deadline,
                    depth: depth - k as u64,
                },
            );
            chain.push(link);
        }
        chain
    }
    fn request(&self, grant: &str, task: &str, deadline: &str, chain: Vec<Link>) -> TaskRequest {
        TaskRequest {
            task_id: task.into(),
            grant_id: Some(grant.into()),
            policy: None,
            self_access: None,
            target_agent_id: self.target.clone(),
            deadline: deadline.into(),
            input: "part of the work".into(),
            origin: Some(Origin {
                agent_id: if chain.len() == 1 {
                    chain[0].originator_agent_id.clone()
                } else {
                    agent('b')
                },
                session_id: None,
            }),
            artifacts: None,
            delegation: Some(chain),
        }
    }
    /// Re-signs link `k` after `change`, and re-links those after it.
    fn resign(&self, chain: &mut [Link], k: usize, change: impl Fn(&mut Link)) {
        let keys = [&self.a, &self.b, &self.c, &self.d];
        change(&mut chain[k]);
        for i in k..chain.len() {
            if i > k {
                chain[i].previous = chain[i - 1].digest();
            }
            let signer = keys
                .iter()
                .find(|key| id_of(key) == chain[i].issuer_host_id)
                .unwrap();
            chain[i].signature =
                STANDARD.encode(signer.sign(chain[i].statement().as_bytes()).to_bytes());
        }
    }
}

#[test]
fn the_final_receiver_authorizes_the_originator() {
    let f = fixture();
    let (a, b) = (id_of(&f.a), id_of(&f.b));
    let deadline = Fixture::deadline(30);
    let chain = f.chain(&[&f.b], 2, &task_id('1'), &deadline);
    // Only the sender is allowed: refused.
    let sender_only = f.grant(&b, TASK_ACTION);
    assert!(matches!(
        f.store.accept_task(
            &b,
            f.request(&sender_only, &task_id('1'), &deadline, chain.clone())
        ),
        Err(Error::Forbidden)
    ));
    // The originator's grant authorizes it; the sender needs none.
    let originator = f.grant(&a, TASK_ACTION);
    let r = f.request(&originator, &task_id('1'), &deadline, chain.clone());
    let status = f.store.accept_task(&b, r.clone()).unwrap();
    assert_eq!(status.sender_host_id, b);
    assert_eq!(f.store.accept_task(&b, r.clone()).unwrap(), status);
    // A different chain under the same task ID conflicts.
    let mut other = r.clone();
    other.delegation = Some(f.chain(&[&f.b], 1, &task_id('1'), &deadline));
    assert!(matches!(
        f.store.accept_task(&b, other),
        Err(Error::Conflict(_))
    ));
    // The handoff carries the chain and the originator's person.
    let handoff = f.store.next_task(&f.auth).unwrap().unwrap();
    let shown = serde_json::to_value(&handoff).unwrap();
    assert_eq!(
        shown["task"]["delegation"],
        serde_json::to_value(&chain).unwrap()
    );
    assert_eq!(shown["originator_person_id"], PERSON);
    assert_eq!(shown["delegable"], false);
    // A grant to the originator's other agent does not apply.
    let pinned = f
        .store
        .create_grant(CreateGrant {
            requester_host_id: a.clone(),
            target_agent_id: f.target.clone(),
            expires_at: rfc3339(Utc::now() + TimeDelta::hours(2)),
            max_message_bytes: 1000,
            max_artifact_bytes: 0,
            allow_disconnected: true,
            requester_agent_id: Some(agent('c')),
            action: Some(TASK_ACTION.into()),
        })
        .unwrap();
    let chain2 = f.chain(&[&f.b], 2, &task_id('2'), &deadline);
    assert!(matches!(
        f.store
            .accept_task(&b, f.request(&pinned.id, &task_id('2'), &deadline, chain2)),
        Err(Error::Forbidden)
    ));
}

#[test]
fn a_single_link_names_the_sender_and_its_origin() {
    let f = fixture();
    let a = id_of(&f.a);
    let grant = f.grant(&a, TASK_ACTION);
    let deadline = Fixture::deadline(30);
    let chain = f.chain(&[], 1, &task_id('1'), &deadline);
    let r = f.request(&grant, &task_id('1'), &deadline, chain.clone());
    let mut no_origin = r.clone();
    no_origin.origin = None;
    assert!(matches!(
        f.store.accept_task(&a, no_origin),
        Err(Error::Forbidden)
    ));
    let mut other_agent = r.clone();
    other_agent.origin = Some(Origin {
        agent_id: agent('c'),
        session_id: None,
    });
    assert!(matches!(
        f.store.accept_task(&a, other_agent),
        Err(Error::Forbidden)
    ));
    // Link 0 must allow 1 or 2 hops.
    let mut zero = r.clone();
    f.resign(zero.delegation.as_mut().unwrap(), 0, |l| l.depth = 0);
    assert!(matches!(
        f.store.accept_task(&a, zero),
        Err(Error::Forbidden)
    ));
    let mut three = r.clone();
    f.resign(three.delegation.as_mut().unwrap(), 0, |l| l.depth = 3);
    assert!(matches!(
        f.store.accept_task(&a, three),
        Err(Error::Forbidden)
    ));
    // Sent by anyone but its issuer, it fails.
    let b = id_of(&f.b);
    f.grant(&b, TASK_ACTION);
    assert!(matches!(
        f.store.accept_task(&b, r.clone()),
        Err(Error::Forbidden)
    ));
    f.store.accept_task(&a, r).unwrap();
}

#[test]
fn adversarial_chains_are_refused() {
    let f = fixture();
    let (a, b) = (id_of(&f.a), id_of(&f.b));
    let grant = f.grant(&a, TASK_ACTION);
    let deadline = Fixture::deadline(30);
    let good = f.chain(&[&f.b], 2, &task_id('1'), &deadline);
    let r = f.request(&grant, &task_id('1'), &deadline, good.clone());
    let refused = |chain: Vec<Link>| {
        let mut request = r.clone();
        request.delegation = Some(chain);
        matches!(f.store.accept_task(&b, request), Err(Error::Forbidden))
    };
    let modified = |k: usize, change: &dyn Fn(&mut Link)| {
        let mut chain = good.clone();
        f.resign(&mut chain, k, change);
        chain
    };
    // Narrowed principals are accepted; widened ones are not.
    let me = format!("host:{}", f.me);
    let mut narrow = good.clone();
    f.resign(&mut narrow, 0, |l| l.principals = vec![me.clone()]);
    f.resign(&mut narrow, 1, |l| l.principals = vec![me.clone()]);
    assert!(!refused(narrow.clone()));
    let mut widened = narrow.clone();
    f.resign(&mut widened, 1, |l| l.principals = network());
    assert!(refused(widened));
    // The audience must be covered too.
    let mut uncovered = narrow;
    f.resign(&mut uncovered, 0, |l| {
        l.principals = vec![format!("host:{b}")]
    });
    f.resign(&mut uncovered, 1, |l| {
        l.principals = vec![format!("host:{b}")]
    });
    assert!(refused(uncovered));
    assert!(refused(modified(1, &|l| l.depth = 2)));
    let later = Fixture::deadline(40);
    let mut late = good.clone();
    f.resign(&mut late, 0, |l| l.deadline = deadline.clone());
    f.resign(&mut late, 1, |l| l.deadline = later.clone());
    let mut late_request = r.clone();
    late_request.deadline = later.clone();
    late_request.delegation = Some(late);
    assert!(matches!(
        f.store.accept_task(&b, late_request),
        Err(Error::Forbidden)
    ));
    // A spliced, reordered, or mislinked chain, or a bad signature.
    let mut reordered = good.clone();
    reordered.swap(0, 1);
    assert!(refused(reordered));
    let other = f.chain(&[&f.b], 2, &task_id('1'), &Fixture::deadline(20));
    assert!(refused(vec![other[0].clone(), good[1].clone()]));
    let mut previous = good.clone();
    previous[1].previous = "0".repeat(64);
    assert!(refused(previous));
    let mut signature = good.clone();
    signature[1].signature = good[0].signature.clone();
    assert!(refused(signature));
    let mut unsigned = good.clone();
    unsigned[0].originator_agent_id = agent('c');
    assert!(refused(unsigned));
    // Mismatched task ID, audience, index, network, or originator agent.
    assert!(refused(modified(1, &|l| l.task_id = task_id('9'))));
    assert!(refused(modified(1, &|l| l.audience_host_id = id_of(&f.d))));
    assert!(refused(modified(0, &|l| l.audience_host_id = id_of(&f.c))));
    assert!(refused(modified(1, &|l| l.index = 2)));
    assert!(refused(modified(1, &|l| l.originator_agent_id = agent('c'))));
    assert!(refused(modified(0, &|l| {
        l.network_id = format!("net_{}", "f".repeat(64))
    })));
    // Replayed under another task, or to another host.
    let mut replay = r.clone();
    replay.task_id = task_id('2');
    assert!(matches!(
        f.store.accept_task(&b, replay),
        Err(Error::Forbidden)
    ));
    let c = id_of(&f.c);
    f.grant(&c, TASK_ACTION);
    assert!(matches!(
        f.store.accept_task(&c, r.clone()),
        Err(Error::Forbidden)
    ));
    // An expired link.
    let past = rfc3339(Utc::now() - TimeDelta::seconds(1));
    let expired = f.chain(&[&f.b], 2, &task_id('1'), &past);
    let mut expired_request = r.clone();
    expired_request.deadline = past;
    expired_request.delegation = Some(expired);
    assert!(matches!(
        f.store.accept_task(&b, expired_request),
        Err(Error::Forbidden)
    ));
    // The narrowed chain was accepted, so another chain under its task ID
    // conflicts.
    assert!(matches!(
        f.store.accept_task(&b, r),
        Err(Error::Conflict(_))
    ));
}

#[test]
fn blocked_and_revoked_participants_refuse_at_submission_and_handoff() {
    let f = fixture();
    let (a, b) = (id_of(&f.a), id_of(&f.b));
    let grant = f.grant(&a, TASK_ACTION);
    let deadline = Fixture::deadline(30);
    let request = |n: char| {
        let chain = f.chain(&[&f.b], 2, &task_id(n), &deadline);
        f.request(&grant, &task_id(n), &deadline, chain)
    };
    let block = |person: Option<&str>, host: Option<&str>| crate::policy::BlockRequest {
        person: person.map(Into::into),
        host: host.map(Into::into),
    };
    // A blocked middle hop.
    f.store.block(block(None, Some(&b))).unwrap();
    assert!(matches!(
        f.store.accept_task(&b, request('1')),
        Err(Error::Forbidden)
    ));
    f.store.unblock(block(None, Some(&b))).unwrap();
    // The originator's person.
    f.store.block(block(Some(PERSON), None)).unwrap();
    assert!(matches!(
        f.store.accept_task(&b, request('1')),
        Err(Error::Forbidden)
    ));
    f.store.unblock(block(Some(PERSON), None)).unwrap();
    // Queued, then a participant is blocked: rejected at handoff.
    f.store.accept_task(&b, request('1')).unwrap();
    f.store.block(block(Some(PERSON), None)).unwrap();
    assert!(f.store.next_task(&f.auth).unwrap().is_none());
    let events = f.store.task_events(&b, &task_id('1'), 1, 10).unwrap();
    assert_eq!(events[0].kind, "rejected");
    assert_eq!(events[0].message.as_deref(), Some(LAPSED));
    f.store.unblock(block(Some(PERSON), None)).unwrap();
    // Claimed, then the originator is revoked: rejected at acceptance.
    f.store.accept_task(&b, request('2')).unwrap();
    f.store.next_task(&f.auth).unwrap().unwrap();
    let revoke = |host: &str| {
        f.store
            .connection()
            .unwrap()
            .execute(
                "DELETE FROM network_members WHERE network_id = ?1 AND host_id = ?2",
                params![NET, host],
            )
            .unwrap();
    };
    revoke(&a);
    assert!(matches!(
        f.store.change_task(&f.auth, &task_id('2'), Change::Accept),
        Err(Error::Forbidden)
    ));
    assert_eq!(
        f.store.task_status(&b, &task_id('2')).unwrap().state,
        "rejected"
    );
    // A revoked member refuses at submission too.
    assert!(matches!(
        f.store.accept_task(&b, request('3')),
        Err(Error::Forbidden)
    ));
}

/// Accepts a two-hop task from B under `action`, claims, and starts it.
fn running(f: &Fixture, action: &str, depth: u64, n: char) -> TaskRequest {
    let (a, b) = (id_of(&f.a), id_of(&f.b));
    let grant = f.grant(&a, action);
    let deadline = Fixture::deadline(30);
    let chain = f.chain(&[&f.b], depth, &task_id(n), &deadline);
    let r = f.request(&grant, &task_id(n), &deadline, chain);
    f.store.accept_task(&b, r.clone()).unwrap();
    let handoff = f.store.next_task(&f.auth).unwrap().unwrap();
    assert_eq!(handoff.delegable, action == DELEGATE_ACTION && depth >= 2);
    f.store
        .change_task(&f.auth, &r.task_id, Change::Accept)
        .unwrap();
    r
}
fn forward(
    f: &Fixture,
    parent: &TaskRequest,
    peer: &str,
    child: char,
) -> Result<crate::task_outbound::OutboundTask, Error> {
    f.store.prepare_task(SubmitTask {
        peer_host_id: peer.into(),
        task_id: task_id(child),
        grant_id: Some(format!("grant_{}", "1".repeat(32))),
        target_agent_id: agent('d'),
        deadline: None,
        input: "a smaller part".into(),
        origin: None,
        artifacts: None,
        delegation_depth: 0,
        delegation_principals: None,
        parent: Some(TaskParent {
            sender_host_id: id_of(&f.b),
            task_id: parent.task_id.clone(),
        }),
    })
}

#[test]
fn a_delegable_running_task_is_forwarded_with_a_narrowed_link() {
    let f = fixture();
    let parent = running(&f, DELEGATE_ACTION, 2, '1');
    let d = id_of(&f.d);
    let out = forward(&f, &parent, &d, '5').unwrap();
    let chain = out.request.delegation.clone().unwrap();
    assert_eq!(out.delegation.as_ref(), Some(&chain));
    assert_eq!(chain.len(), 3);
    assert_eq!(&chain[..2], &parent.delegation.clone().unwrap()[..]);
    let link = &chain[2];
    assert_eq!(
        (
            link.index,
            link.issuer_host_id.as_str(),
            link.audience_host_id.as_str(),
            link.task_id.as_str(),
            link.depth,
            link.previous.clone()
        ),
        (
            2,
            f.me.as_str(),
            d.as_str(),
            task_id('5').as_str(),
            0,
            chain[1].digest()
        )
    );
    assert_eq!(link.principals, chain[1].principals);
    assert_eq!(link.originator_agent_id, agent('a'));
    assert_eq!(link.deadline, out.request.deadline);
    assert!(time(&link.deadline) <= time(&parent.deadline));
    assert!(link.verify(&f.store.identity().public_key));
    // The forwarding agent is the origin.
    assert_eq!(out.request.origin.as_ref().unwrap().agent_id, f.target);
    let shown = serde_json::to_value(&out).unwrap();
    assert_eq!(shown["parent"]["sender_host_id"], id_of(&f.b));
    assert_eq!(shown["parent"]["task_id"], parent.task_id);
    let kinds: Vec<String> = f
        .store
        .events(0, 1000)
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "task.delegated")
        .map(|e| e.subject_id)
        .collect();
    assert_eq!(kinds, [format!("{d}/{}", task_id('5'))]);
    // A repeat returns the record; a changed one conflicts.
    assert_eq!(forward(&f, &parent, &d, '5').unwrap().request, out.request);
    // Cancelling the parent marks the child for cancellation.
    let (status, children) = f
        .store
        .cancel_received(&id_of(&f.b), &parent.task_id)
        .unwrap();
    assert!(status.cancel_requested);
    assert_eq!(children, [(d.clone(), task_id('5'))]);
    assert_eq!(
        f.store
            .outbound_task(&d, &task_id('5'))
            .unwrap()
            .cancel_state
            .as_deref(),
        Some("unknown")
    );
    // Further forwards are refused once cancellation was requested.
    assert!(matches!(
        forward(&f, &parent, &d, '6'),
        Err(Error::Conflict(_))
    ));
}

#[test]
fn forwarding_is_refused_unless_every_rule_holds() {
    let f = fixture();
    let d = id_of(&f.d);
    // Without task.delegate.
    let plain = running(&f, TASK_ACTION, 2, '1');
    assert!(matches!(
        forward(&f, &plain, &d, '5'),
        Err(Error::Forbidden)
    ));
    // At depth 0 after this hop.
    let shallow = running(&f, DELEGATE_ACTION, 1, '2');
    assert!(matches!(
        forward(&f, &shallow, &d, '5'),
        Err(Error::Forbidden)
    ));
    // To a host outside the principals, or outside the network.
    let parent = running(&f, DELEGATE_ACTION, 2, '3');
    let mut narrowed = parent.clone();
    narrowed.task_id = task_id('4');
    let deadline = narrowed.deadline.clone();
    let mut chain = f.chain(&[&f.b], 2, &task_id('4'), &deadline);
    let mut principals = vec![format!("host:{}", f.me), format!("person:{PERSON}")];
    principals.sort();
    f.resign(&mut chain, 0, |l| l.principals = principals.clone());
    f.resign(&mut chain, 1, |l| {
        l.principals = vec![format!("person:{PERSON}")]
    });
    narrowed.delegation = Some(chain);
    f.store.accept_task(&id_of(&f.b), narrowed.clone()).unwrap();
    f.store.next_task(&f.auth).unwrap().unwrap();
    f.store
        .change_task(&f.auth, &narrowed.task_id, Change::Accept)
        .unwrap();
    assert!(matches!(
        forward(&f, &narrowed, &d, '5'),
        Err(Error::Forbidden)
    ));
    // The originator's own host is bound to that person.
    forward(&f, &narrowed, &id_of(&f.a), '6').unwrap();
    let outsider = format!("host_{}", "e".repeat(64));
    add_member(&f.store, &outsider, &STANDARD.encode([9u8; 32]), None);
    f.store
        .connection()
        .unwrap()
        .execute(
            "UPDATE network_members SET network_id = 'net_other' WHERE host_id = ?1",
            [&outsider],
        )
        .unwrap();
    assert!(matches!(
        forward(&f, &parent, &outsider, '7'),
        Err(Error::Forbidden)
    ));
    // With a later deadline than the parent's.
    let mut late = SubmitTask {
        peer_host_id: d.clone(),
        task_id: task_id('8'),
        grant_id: Some(format!("grant_{}", "1".repeat(32))),
        target_agent_id: agent('d'),
        deadline: Some(rfc3339(time(&parent.deadline) + TimeDelta::seconds(1))),
        input: "x".into(),
        origin: None,
        artifacts: None,
        delegation_depth: 0,
        delegation_principals: None,
        parent: Some(TaskParent {
            sender_host_id: id_of(&f.b),
            task_id: parent.task_id.clone(),
        }),
    };
    assert!(matches!(
        f.store.prepare_task(SubmitTask {
            parent: late.parent.clone(),
            deadline: late.deadline.clone(),
            ..forward_body(&late)
        }),
        Err(Error::Forbidden)
    ));
    // Not with a depth of its own, and not for an unknown parent.
    late.deadline = None;
    late.delegation_depth = 1;
    assert!(matches!(
        f.store.prepare_task(forward_body(&late)),
        Err(Error::Invalid(_))
    ));
    late.delegation_depth = 0;
    late.parent.as_mut().unwrap().task_id = task_id('9');
    assert!(matches!(
        f.store.prepare_task(forward_body(&late)),
        Err(Error::NotFound)
    ));
    // Past 3 links.
    let full = {
        let deadline = Fixture::deadline(30);
        let chain = f.chain(&[&f.b, &f.c], 2, &task_id('a'), &deadline);
        let grant = f.grant(&id_of(&f.a), DELEGATE_ACTION);
        let r = f.request(&grant, &task_id('a'), &deadline, chain);
        f.store.accept_task(&id_of(&f.c), r.clone()).unwrap();
        f.store.next_task(&f.auth).unwrap().unwrap();
        f.store
            .change_task(&f.auth, &r.task_id, Change::Accept)
            .unwrap();
        r
    };
    let mut past = forward_body(&late);
    past.parent = Some(TaskParent {
        sender_host_id: id_of(&f.c),
        task_id: full.task_id.clone(),
    });
    assert!(matches!(f.store.prepare_task(past), Err(Error::Forbidden)));
    // Not before it runs.
    let deadline = Fixture::deadline(30);
    let chain = f.chain(&[&f.b], 2, &task_id('b'), &deadline);
    let grant = f.grant(&id_of(&f.a), DELEGATE_ACTION);
    let queued = f.request(&grant, &task_id('b'), &deadline, chain);
    f.store.accept_task(&id_of(&f.b), queued.clone()).unwrap();
    assert!(matches!(
        forward(&f, &queued, &d, 'c'),
        Err(Error::Forbidden)
    ));
}
fn forward_body(s: &SubmitTask) -> SubmitTask {
    SubmitTask {
        peer_host_id: s.peer_host_id.clone(),
        task_id: s.task_id.clone(),
        grant_id: s.grant_id.clone(),
        target_agent_id: s.target_agent_id.clone(),
        deadline: s.deadline.clone(),
        input: s.input.clone(),
        origin: s.origin.clone(),
        artifacts: None,
        delegation_depth: s.delegation_depth,
        delegation_principals: s.delegation_principals.clone(),
        parent: s.parent.clone(),
    }
}

#[test]
fn submitters_create_link_zero() {
    let f = fixture();
    let d = id_of(&f.d);
    let submit = |depth: u64, principals: Option<Vec<String>>, origin: bool| SubmitTask {
        peer_host_id: d.clone(),
        task_id: String::new(),
        grant_id: Some(format!("grant_{}", "1".repeat(32))),
        target_agent_id: agent('d'),
        deadline: None,
        input: "work".into(),
        origin: origin.then(|| Origin {
            agent_id: f.target.clone(),
            session_id: None,
        }),
        artifacts: None,
        delegation_depth: depth,
        delegation_principals: principals,
        parent: None,
    };
    let none = f.store.prepare_task(submit(0, None, true)).unwrap();
    assert!(none.request.delegation.is_none() && none.delegation.is_none());
    assert!(matches!(
        f.store.prepare_task(submit(1, None, false)),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        f.store.prepare_task(submit(3, None, true)),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        f.store
            .prepare_task(submit(0, Some(vec![NETWORK.into()]), true)),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        f.store
            .prepare_task(submit(1, Some(vec!["person:x".into()]), true)),
        Err(Error::Invalid(_))
    ));
    let person = format!("person:{PERSON}");
    let host = format!("host:{d}");
    let out = f
        .store
        .prepare_task(submit(
            2,
            Some(vec![person.clone(), host.clone(), person.clone()]),
            true,
        ))
        .unwrap();
    let chain = out.request.delegation.clone().unwrap();
    assert_eq!(chain.len(), 1);
    let link = &chain[0];
    assert_eq!(
        (
            link.network_id.as_str(),
            link.index,
            link.previous.as_str(),
            link.issuer_host_id.as_str(),
            link.audience_host_id.as_str(),
            link.depth
        ),
        (NET, 0, NONE, f.me.as_str(), d.as_str(), 2)
    );
    assert_eq!(link.principals, [host, person]);
    assert_eq!(link.task_id, out.request.task_id);
    assert_eq!(link.originator_agent_id, f.target);
    assert_eq!(link.deadline, out.request.deadline);
    assert!(out.parent.is_none());
    // Without a shared network there is no chain.
    let stranger = crate::peer_store::tests::add_test_peer(&f.store).id;
    let mut lonely = submit(1, None, true);
    lonely.peer_host_id = stranger;
    assert!(matches!(
        f.store.prepare_task(lonely),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn delegate_actions_imply_task_submit_only() {
    use crate::policy::{ACTION, allows, task_actions};
    assert!(allows(DELEGATE_ACTION, TASK_ACTION));
    assert!(allows(TASK_ACTION, TASK_ACTION));
    assert!(!allows(TASK_ACTION, DELEGATE_ACTION));
    assert!(!allows(DELEGATE_ACTION, ACTION));
    assert!(task_actions([DELEGATE_ACTION].into_iter()));
    assert!(!task_actions([ACTION].into_iter()));
    let f = fixture();
    let a = id_of(&f.a);
    // A delegate grant authorizes tasks, with artifacts, but not messages.
    let grant = f
        .store
        .create_grant(CreateGrant {
            requester_host_id: a.clone(),
            target_agent_id: f.target.clone(),
            expires_at: rfc3339(Utc::now() + TimeDelta::hours(2)),
            max_message_bytes: 1000,
            max_artifact_bytes: 100,
            allow_disconnected: true,
            requester_agent_id: None,
            action: Some(DELEGATE_ACTION.into()),
        })
        .unwrap();
    assert_eq!(grant.action, DELEGATE_ACTION);
    let deadline = Fixture::deadline(30);
    let mut single = f.request(&grant.id, &task_id('1'), &deadline, vec![]);
    single.delegation = None;
    f.store.accept_task(&a, single).unwrap();
    let message = crate::peer_store::tests::request(&grant.id, &f.target, None);
    assert!(matches!(
        f.store.accept_message(&a, message),
        Err(Error::Forbidden)
    ));
    // A plain task without a chain is never delegable.
    let handoff = f.store.next_task(&f.auth).unwrap().unwrap();
    assert!(!handoff.delegable && handoff.originator_person_id.is_none());
    // Routes cannot name task.delegate.
    assert!(!crate::policy::ROUTE_ACTIONS.contains(&DELEGATE_ACTION));
}

#[test]
fn rules_with_task_delegate_sign_as_another_action() {
    use crate::policy::{Rule, TASK_ACTION};
    let rule = Rule {
        agent: "worker".into(),
        principals: vec![NETWORK.into()],
        actions: vec![DELEGATE_ACTION.into()],
        max_message_bytes: 10,
        max_artifact_bytes: 100,
        allow_disconnected: false,
    };
    let signer = crate::persons::PersonSigner::File(seeded(5));
    let policy = crate::policy::Policy::sign(
        &signer,
        NET,
        1,
        "2026-10-10T00:00:00Z",
        "2026-10-17T00:00:00Z",
        vec![rule.clone()],
    )
    .unwrap();
    policy.verify(NET).unwrap();
    let mut bad = rule;
    bad.actions = vec!["task.forward".into()];
    assert!(
        crate::policy::Policy::sign(
            &signer,
            NET,
            1,
            "2026-10-10T00:00:00Z",
            "2026-10-17T00:00:00Z",
            vec![bad],
        )
        .is_err()
    );
    let _ = TASK_ACTION;
}

#[test]
fn version_ten_migrates_to_latest_and_nineteen_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host");
    drop(Store::open(&path).unwrap());
    Connection::open(path.join("host.db"))
        .unwrap()
        .execute_batch(
            "DROP TABLE call_update_notifications; DROP TABLE adapter_calls; DROP TABLE policy_edits; DROP TABLE outbound_calls; DROP TABLE received_calls; DROP TABLE source_access; DROP TABLE capabilities; DROP TABLE tool_values; DROP TABLE tool_servers; DROP TABLE directory_sends; DROP TABLE policy_deliveries; DROP TABLE task_children; PRAGMA user_version = 10;",
        )
        .unwrap();
    let store = Store::open(&path).unwrap();
    let conn = store.connection().unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 18);
    let sql: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name = 'task_children'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        sql,
        "CREATE TABLE task_children (sender TEXT NOT NULL, task_id TEXT NOT NULL, peer TEXT NOT NULL, child_task_id TEXT NOT NULL, PRIMARY KEY(sender, task_id, peer, child_task_id))"
    );
    drop(conn);
    drop(store);
    Connection::open(path.join("host.db"))
        .unwrap()
        .execute_batch("PRAGMA user_version = 19;")
        .unwrap();
    assert!(Store::open(&path).is_err());
}

fn time(text: &str) -> chrono::DateTime<Utc> {
    crate::task::time(text).unwrap()
}
