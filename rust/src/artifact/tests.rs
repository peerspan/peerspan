use super::*;
use crate::{
    adapter_outbound::tests::connected_adapter,
    peer_store::{CreateGrant, tests::add_test_peer},
    task::{Change, TaskEvent, TaskRequest, TaskStatus},
    task_outbound::SubmitTask,
};

fn digest(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
fn entry(name: &str, data: &[u8]) -> ArtifactEntry {
    ArtifactEntry {
        name: name.into(),
        size: data.len() as i64,
        sha256: digest(data),
        media_type: DEFAULT_MEDIA_TYPE.into(),
    }
}
/// Stores content as an upload would.
fn upload(store: &Store, name: &str, data: &[u8]) -> Result<ArtifactEntry, Error> {
    let temp = store.temporary_path().unwrap();
    fs::write(&temp, data).unwrap();
    store.finish_upload(
        temp,
        data.len() as i64,
        digest(data),
        name.into(),
        DEFAULT_MEDIA_TYPE.into(),
    )
}
/// Completes a fetch with verified content.
fn deliver(store: &Store, k: &RowKey, data: &[u8]) {
    let temp = store.temporary_path().unwrap();
    fs::write(&temp, data).unwrap();
    store.fetched(k, Some(temp)).unwrap();
}
fn activity(store: &Store, kind: &str) -> Vec<String> {
    store
        .events(0, 1000)
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == kind)
        .map(|e| e.subject_id)
        .collect()
}
fn read_all((mut file, len): (File, u64)) -> Vec<u8> {
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    assert_eq!(data.len() as u64, len);
    data
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    peer: String,
    agent: String,
    auth: AdapterAuth,
}
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("host")).unwrap();
    let peer = add_test_peer(&store).id;
    let auth = connected_adapter(&store, "a");
    let agent = store.adapter_session(&auth).unwrap().agent_id;
    Fixture {
        _dir: dir,
        store,
        peer,
        agent,
        auth,
    }
}
impl Fixture {
    fn grant(&self, bound: i64) -> String {
        self.store
            .create_grant(CreateGrant {
                requester_host_id: self.peer.clone(),
                target_agent_id: self.agent.clone(),
                expires_at: rfc3339(crate::clock::now() + TimeDelta::hours(2)),
                max_message_bytes: 1000,
                max_artifact_bytes: bound,
                allow_disconnected: true,
                requester_agent_id: None,
                action: Some(crate::policy::TASK_ACTION.into()),
            })
            .unwrap()
            .id
    }
    fn request(&self, n: char, grant: &str, inputs: Option<Vec<ArtifactEntry>>) -> TaskRequest {
        TaskRequest {
            task_id: format!("task_{}", n.to_string().repeat(32)),
            grant_id: Some(grant.into()),
            policy: None,
            self_access: None,
            target_agent_id: self.agent.clone(),
            deadline: rfc3339(crate::clock::now() + TimeDelta::minutes(30)),
            input: "summarize the attached report".into(),
            origin: None,
            artifacts: inputs,
            delegation: None,
        }
    }
    fn input_key(&self, r: &TaskRequest, e: &ArtifactEntry) -> RowKey {
        RowKey {
            side: RECEIVED.into(),
            peer: self.peer.clone(),
            task_id: r.task_id.clone(),
            direction: INPUT.into(),
            sha256: e.sha256.clone(),
        }
    }
    fn complete(
        &self,
        r: &TaskRequest,
        results: Option<Vec<ArtifactEntry>>,
    ) -> Result<TaskStatus, Error> {
        self.store.change_task(
            &self.auth,
            &r.task_id,
            Change::Complete {
                status: "succeeded".into(),
                output: "done".into(),
                artifacts: results,
            },
        )
    }
}

#[test]
fn manifests_are_strict() {
    let good = entry("report.pdf", b"x");
    validate_manifest(std::slice::from_ref(&good)).unwrap();
    assert!(validate_manifest(&[]).is_err());
    let too_many: Vec<ArtifactEntry> = (0..65)
        .map(|i| entry(&format!("f{i}"), format!("{i}").as_bytes()))
        .collect();
    assert!(validate_manifest(&too_many).is_err());
    validate_manifest(&too_many[..64]).unwrap();
    for bad in [
        ArtifactEntry {
            name: "a/b".into(),
            ..good.clone()
        },
        ArtifactEntry {
            name: "a\\b".into(),
            ..good.clone()
        },
        ArtifactEntry {
            name: "a\u{0}b".into(),
            ..good.clone()
        },
        ArtifactEntry {
            name: "a\u{85}b".into(),
            ..good.clone()
        },
        ArtifactEntry {
            name: "..".into(),
            ..good.clone()
        },
        ArtifactEntry {
            name: String::new(),
            ..good.clone()
        },
        ArtifactEntry {
            name: "x".repeat(256),
            ..good.clone()
        },
        ArtifactEntry {
            size: MAX_SIZE + 1,
            ..good.clone()
        },
        ArtifactEntry {
            size: -1,
            ..good.clone()
        },
        ArtifactEntry {
            sha256: good.sha256.to_uppercase(),
            ..good.clone()
        },
        ArtifactEntry {
            media_type: String::new(),
            ..good.clone()
        },
        ArtifactEntry {
            media_type: "text/plain\u{7f}".into(),
            ..good.clone()
        },
    ] {
        assert!(
            validate_manifest(std::slice::from_ref(&bad)).is_err(),
            "{bad:?}"
        );
    }
    validate_manifest(&[ArtifactEntry {
        name: "résumé v2.txt".into(),
        size: MAX_SIZE,
        media_type: "text/plain; charset=utf-8".into(),
        ..good.clone()
    }])
    .unwrap();
    let same_name = ArtifactEntry {
        sha256: digest(b"other"),
        ..good.clone()
    };
    assert!(validate_manifest(&[good.clone(), same_name]).is_err());
    let same_digest = ArtifactEntry {
        name: "copy".into(),
        ..good.clone()
    };
    assert!(validate_manifest(&[good.clone(), same_digest]).is_err());
    // All four fields, never null, nothing else.
    let wire = serde_json::to_value(&good).unwrap();
    assert_eq!(
        wire.as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        ["media_type", "name", "sha256", "size"]
    );
    for field in ["name", "size", "sha256", "media_type"] {
        let mut missing = wire.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<ArtifactEntry>(missing).is_err());
        let mut null = wire.clone();
        null[field] = serde_json::Value::Null;
        assert!(serde_json::from_value::<ArtifactEntry>(null).is_err());
    }
    let mut extra = wire.clone();
    extra["extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<ArtifactEntry>(extra).is_err());
}

#[test]
fn grant_bounds_are_validated_and_need_task_submit() {
    let f = fixture();
    let create = |action: &str, bound: i64| {
        f.store.create_grant(CreateGrant {
            requester_host_id: f.peer.clone(),
            target_agent_id: f.agent.clone(),
            expires_at: rfc3339(crate::clock::now() + TimeDelta::hours(2)),
            max_message_bytes: 1000,
            max_artifact_bytes: bound,
            allow_disconnected: true,
            requester_agent_id: None,
            action: Some(action.into()),
        })
    };
    assert!(matches!(
        create(crate::policy::ACTION, 1),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        create(crate::policy::TASK_ACTION, MAX_BOUND + 1),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        create(crate::policy::TASK_ACTION, -1),
        Err(Error::Invalid(_))
    ));
    let g = create(crate::policy::TASK_ACTION, MAX_BOUND).unwrap();
    assert_eq!(g.max_artifact_bytes, MAX_BOUND);
    let shown = serde_json::to_value(create(crate::policy::ACTION, 0).unwrap()).unwrap();
    assert_eq!(shown["max_artifact_bytes"], 0);
    // Older grant records read as 0.
    let mut old = shown.clone();
    old.as_object_mut().unwrap().remove("max_artifact_bytes");
    let old: crate::peer_store::Grant = serde_json::from_value(old).unwrap();
    assert_eq!(old.max_artifact_bytes, 0);
}

#[test]
fn inputs_are_bounded_fetched_and_gate_the_handoff() {
    let f = fixture();
    let data = b"quarterly numbers".to_vec();
    let input = entry("report.txt", &data);
    // A bound of 0 refuses any artifacts; a smaller bound refuses the total.
    let none = f.grant(0);
    assert!(matches!(
        f.store
            .accept_task(&f.peer, f.request('1', &none, Some(vec![input.clone()]))),
        Err(Error::Forbidden)
    ));
    let small = f.grant(data.len() as i64 - 1);
    assert!(matches!(
        f.store
            .accept_task(&f.peer, f.request('1', &small, Some(vec![input.clone()]))),
        Err(Error::Forbidden)
    ));
    // On the wire an empty manifest is invalid.
    assert!(matches!(
        f.store
            .accept_task(&f.peer, f.request('1', &none, Some(vec![]))),
        Err(Error::Invalid(_))
    ));
    // A task without artifacts needs no bound.
    f.store
        .accept_task(&f.peer, f.request('0', &none, None))
        .unwrap();
    let plain = f.store.next_task(&f.auth).unwrap().unwrap();
    assert!(
        serde_json::to_value(&plain.task)
            .unwrap()
            .get("artifacts")
            .is_none()
    );

    let grant = f.grant(1000);
    let r = f.request('1', &grant, Some(vec![input.clone()]));
    let status = f.store.accept_task(&f.peer, r.clone()).unwrap();
    assert_eq!(status.state, "queued");
    // Identical repeats return the record; a changed manifest conflicts.
    assert_eq!(f.store.accept_task(&f.peer, r.clone()).unwrap(), status);
    let changed = TaskRequest {
        artifacts: Some(vec![ArtifactEntry {
            media_type: "text/plain".into(),
            ..input.clone()
        }]),
        ..r.clone()
    };
    assert!(matches!(
        f.store.accept_task(&f.peer, changed),
        Err(Error::Conflict(_))
    ));
    let k = f.input_key(&r, &input);
    assert_eq!(f.store.pending_fetches().unwrap(), std::slice::from_ref(&k));
    assert_eq!(
        f.store.artifact_list().unwrap().pending_bytes,
        data.len() as i64
    );
    // Not handed off while an input is pending.
    assert!(f.store.next_task(&f.auth).unwrap().is_none());
    // A fetch that fails verification leaves nothing behind.
    deliver(&f.store, &k, &data);
    assert!(f.store.pending_fetches().unwrap().is_empty());
    assert_eq!(
        activity(&f.store, "task.artifact_fetched"),
        [format!("{}/{}/{}", f.peer, r.task_id, input.sha256)]
    );
    let list = f.store.artifact_list().unwrap();
    assert_eq!(
        (list.stored_bytes, list.pending_bytes, list.files.len()),
        (data.len() as i64, 0, 1)
    );
    assert_eq!(list.files[0].tasks, 1);
    assert!(list.files[0].upload_until.is_none());
    let handoff = f.store.next_task(&f.auth).unwrap().unwrap();
    assert_eq!(handoff.task.artifacts, Some(vec![input.clone()]));
    // The claiming session reads the input; another session cannot.
    assert_eq!(
        read_all(
            f.store
                .claimed_artifact(&f.auth, &r.task_id, &input.sha256)
                .unwrap()
        ),
        data
    );
    let other = connected_adapter(&f.store, "b");
    assert!(matches!(
        f.store.claimed_artifact(&other, &r.task_id, &input.sha256),
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        f.store
            .claimed_artifact(&f.auth, &format!("task_{}", "9".repeat(32)), &input.sha256),
        Err(Error::NotFound)
    ));
    // Inputs of a task this host received are never served back.
    assert!(matches!(
        f.store.peer_artifact(&f.peer, &r.task_id, &input.sha256),
        Err(Error::NotFound)
    ));
    // Content already stored needs no fetch.
    let again = f.request('2', &grant, Some(vec![input.clone()]));
    f.store.accept_task(&f.peer, again.clone()).unwrap();
    assert!(f.store.pending_fetches().unwrap().is_empty());
    assert_eq!(activity(&f.store, "task.artifact_fetched").len(), 1);
    assert!(f.store.next_task(&f.auth).unwrap().is_some());
}

#[test]
fn quota_refuses_manifests_and_uploads() {
    let f = fixture();
    f.store.set_artifact_quota(10);
    let grant = f.grant(1000);
    let big = entry("big", &[7u8; 11]);
    assert!(matches!(
        f.store
            .accept_task(&f.peer, f.request('1', &grant, Some(vec![big.clone()]))),
        Err(Error::InsufficientStorage(_))
    ));
    let six = entry("six", &[1u8; 6]);
    f.store
        .accept_task(&f.peer, f.request('2', &grant, Some(vec![six.clone()])))
        .unwrap();
    // Pending fetches count toward the quota.
    assert!(matches!(
        upload(&f.store, "five", &[2u8; 5]),
        Err(Error::InsufficientStorage(_))
    ));
    upload(&f.store, "four", &[3u8; 4]).unwrap();
    // Content already stored is never refused, and re-uploading extends its hold.
    upload(&f.store, "again", &[3u8; 4]).unwrap();
    assert_eq!(f.store.artifact_list().unwrap().files.len(), 1);
    // No partial files remain.
    let names: Vec<String> = fs::read_dir(f.store.artifact_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, [digest(&[3u8; 4])]);
}

#[test]
fn results_are_bounded_by_the_bound_stored_at_acceptance() {
    let f = fixture();
    let input_data = vec![1u8; 300];
    let input = entry("in.bin", &input_data);
    let grant = f.grant(1000);
    let r = f.request('1', &grant, Some(vec![input.clone()]));
    f.store.accept_task(&f.peer, r.clone()).unwrap();
    deliver(&f.store, &f.input_key(&r, &input), &input_data);
    f.store.next_task(&f.auth).unwrap().unwrap();
    f.store
        .change_task(&f.auth, &r.task_id, Change::Accept)
        .unwrap();
    // Later revocation does not change the accepted task's bound.
    f.store.revoke_grant(&grant).unwrap();
    let result_data = vec![2u8; 700];
    let unstored = entry("out.bin", &result_data);
    assert!(matches!(
        f.complete(&r, Some(vec![unstored.clone()])),
        Err(Error::Invalid(_))
    ));
    let too_big = upload(&f.store, "out.bin", &[3u8; 701]).unwrap();
    assert!(matches!(
        f.complete(&r, Some(vec![too_big])),
        Err(Error::Forbidden)
    ));
    assert_eq!(
        f.store.task_status(&f.peer, &r.task_id).unwrap().state,
        "running"
    );
    let result = upload(&f.store, "out.bin", &result_data).unwrap();
    let done = f.complete(&r, Some(vec![result.clone()])).unwrap();
    assert_eq!(done.state, "succeeded");
    // The status record never shows the stored bound.
    let shown = serde_json::to_value(f.store.task_status(&f.peer, &r.task_id).unwrap()).unwrap();
    assert_eq!(shown.as_object().unwrap().len(), 9);
    assert_eq!(f.complete(&r, Some(vec![result.clone()])).unwrap(), done);
    assert!(matches!(f.complete(&r, None), Err(Error::Conflict(_))));
    let events = f.store.task_events(&f.peer, &r.task_id, 0, 10).unwrap();
    assert!(
        events[..events.len() - 1]
            .iter()
            .all(|e| e.artifacts.is_none())
    );
    assert_eq!(events.last().unwrap().artifacts, Some(vec![result.clone()]));
    assert!(
        serde_json::to_value(&events[0])
            .unwrap()
            .get("artifacts")
            .unwrap()
            .is_null()
    );
    // The submitter fetches the result; nobody else can.
    assert_eq!(
        read_all(
            f.store
                .peer_artifact(&f.peer, &r.task_id, &result.sha256)
                .unwrap()
        ),
        result_data
    );
    let stranger = add_test_peer(&f.store).id;
    assert!(matches!(
        f.store.peer_artifact(&stranger, &r.task_id, &result.sha256),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        f.store
            .peer_artifact(&f.peer, &r.task_id, &digest(b"unlisted")),
        Err(Error::NotFound)
    ));
}

#[test]
fn a_zero_bound_refuses_results_and_completion_without_results_proceeds() {
    let f = fixture();
    let grant = f.grant(0);
    let r = f.request('1', &grant, None);
    f.store.accept_task(&f.peer, r.clone()).unwrap();
    f.store.next_task(&f.auth).unwrap().unwrap();
    f.store
        .change_task(&f.auth, &r.task_id, Change::Accept)
        .unwrap();
    let result = upload(&f.store, "out", b"x").unwrap();
    assert!(matches!(
        f.complete(&r, Some(vec![result])),
        Err(Error::Forbidden)
    ));
    // An empty manifest is no manifest.
    let done = f.complete(&r, Some(vec![])).unwrap();
    assert_eq!(done.state, "succeeded");
    let last = f.store.task_events(&f.peer, &r.task_id, 0, 10).unwrap();
    assert!(last.last().unwrap().artifacts.is_none());
}

#[test]
fn submitters_attach_uploads_and_fetch_results() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("host")).unwrap();
    let peer = add_test_peer(&store).id;
    let data = b"design doc".to_vec();
    let submit = |artifacts: Option<Vec<ArtifactEntry>>| SubmitTask {
        peer_host_id: peer.clone(),
        task_id: format!("task_{}", "a".repeat(32)),
        grant_id: Some(format!("grant_{}", "1".repeat(32))),
        target_agent_id: format!("agent_{}", "2".repeat(32)),
        deadline: None,
        input: "review".into(),
        origin: None,
        artifacts,
        delegation_depth: 0,
        delegation_principals: None,
        parent: None,
    };
    // Every entry must be a stored upload of that size.
    assert!(matches!(
        store.prepare_task(submit(Some(vec![entry("doc", &data)]))),
        Err(Error::Invalid(_))
    ));
    let uploaded = upload(&store, "doc", &data).unwrap();
    let wrong_size = ArtifactEntry {
        size: 3,
        ..uploaded.clone()
    };
    assert!(matches!(
        store.prepare_task(submit(Some(vec![wrong_size]))),
        Err(Error::Invalid(_))
    ));
    let out = store
        .prepare_task(submit(Some(vec![uploaded.clone()])))
        .unwrap();
    assert_eq!(out.request.artifacts, Some(vec![uploaded.clone()]));
    assert_eq!(
        out.artifacts,
        [LocalArtifact {
            direction: INPUT.into(),
            name: "doc".into(),
            size: data.len() as i64,
            sha256: uploaded.sha256.clone(),
            media_type: DEFAULT_MEDIA_TYPE.into(),
            state: STORED.into(),
        }]
    );
    // A repeat returns the record with its artifacts.
    assert_eq!(
        store
            .prepare_task(submit(Some(vec![uploaded.clone()])))
            .unwrap()
            .artifacts,
        out.artifacts
    );
    // The stored record never holds the derived list.
    let raw: String = store
        .connection()
        .unwrap()
        .query_row("SELECT record FROM outbound_tasks", [], |r| r.get(0))
        .unwrap();
    let raw: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(raw.get("artifacts").is_none());
    // The receiver may fetch the input; nobody else.
    let id = out.request.task_id.clone();
    assert_eq!(
        read_all(store.peer_artifact(&peer, &id, &uploaded.sha256).unwrap()),
        data
    );
    let stranger = add_test_peer(&store).id;
    assert!(matches!(
        store.peer_artifact(&stranger, &id, &uploaded.sha256),
        Err(Error::NotFound)
    ));
    assert_eq!(
        read_all(
            store
                .outbound_artifact(&peer, &id, &uploaded.sha256)
                .unwrap()
        ),
        data
    );
    // A final event's results are fetched after it is stored.
    let mut accepted = out.clone();
    accepted.submit_state = "accepted".into();
    store.finish_task_submit(accepted).unwrap();
    let result_data = b"review notes".to_vec();
    let result = entry("notes.md", &result_data);
    let event = |sequence: i64, kind: &str, artifacts: Option<Vec<ArtifactEntry>>| TaskEvent {
        sequence,
        kind: kind.into(),
        state: if kind == "queued" { "queued" } else { kind }.into(),
        message: None,
        output: (kind == "succeeded").then(|| "ok".into()),
        created_at: now(),
        artifacts,
    };
    assert!(!event(1, "queued", Some(vec![result.clone()])).well_formed());
    assert!(event(2, "succeeded", Some(vec![result.clone()])).well_formed());
    let (stored, _) = store
        .store_task_events(
            &peer,
            &id,
            None,
            vec![
                event(1, "queued", None),
                event(2, "succeeded", Some(vec![result.clone()])),
            ],
        )
        .unwrap();
    assert_eq!(
        stored
            .artifacts
            .iter()
            .map(|a| (a.direction.as_str(), a.state.as_str()))
            .collect::<Vec<_>>(),
        [(INPUT, STORED), (RESULT, PENDING)]
    );
    assert!(matches!(
        store.outbound_artifact(&peer, &id, &result.sha256),
        Err(Error::Conflict(_))
    ));
    let k = RowKey {
        side: SENT.into(),
        peer: peer.clone(),
        task_id: id.clone(),
        direction: RESULT.into(),
        sha256: result.sha256.clone(),
    };
    assert_eq!(store.pending_fetches().unwrap(), std::slice::from_ref(&k));
    deliver(&store, &k, &result_data);
    assert_eq!(
        read_all(store.outbound_artifact(&peer, &id, &result.sha256).unwrap()),
        result_data
    );
    // Results the submitter fetched are not served back to the receiver.
    assert!(matches!(
        store.peer_artifact(&peer, &id, &result.sha256),
        Err(Error::NotFound)
    ));
    assert_eq!(
        store.outbound_task(&peer, &id).unwrap().artifacts[1].state,
        STORED
    );
}

#[test]
fn retention_keeps_uploads_and_tasks_until_released() {
    let f = fixture();
    let grant = f.grant(1000);
    let upload_only = upload(&f.store, "draft", b"draft").unwrap();
    let data = b"input".to_vec();
    let input = entry("in", &data);
    let r = f.request('1', &grant, Some(vec![input.clone()]));
    f.store.accept_task(&f.peer, r.clone()).unwrap();
    deliver(&f.store, &f.input_key(&r, &input), &data);
    // The sweep keeps an upload for 24 hours and a live task's artifacts.
    assert_eq!(f.store.prune_artifacts(false).unwrap().files_deleted, 0);
    assert_eq!(f.store.artifact_list().unwrap().files.len(), 2);
    // A task final for less than 7 days keeps them, until pruned.
    f.store.next_task(&f.auth).unwrap().unwrap();
    f.store
        .change_task(&f.auth, &r.task_id, Change::Reject("no".into()))
        .unwrap();
    assert_eq!(f.store.prune_artifacts(false).unwrap().files_deleted, 0);
    let pruned = f.store.prune_artifacts(true).unwrap();
    assert_eq!(
        (pruned.files_deleted, pruned.bytes_freed),
        (2, (data.len() + 5) as i64)
    );
    assert!(f.store.artifact_list().unwrap().files.is_empty());
    assert!(!f.store.artifact_path(&upload_only.sha256).exists());
    assert!(!f.store.artifact_path(&input.sha256).exists());
    assert_eq!(activity(&f.store, "artifact.pruned").len(), 2);
    assert!(matches!(
        f.store.claimed_artifact(&f.auth, &r.task_id, &input.sha256),
        Err(Error::NotFound)
    ));
    let state: String = f
        .store
        .connection()
        .unwrap()
        .query_row(
            "SELECT json_extract(record, '$.state') FROM task_artifacts",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, PRUNED);
    // An expired upload hold or a week-old final task releases by itself.
    let held = upload(&f.store, "held", b"held").unwrap();
    let past = rfc3339(crate::clock::now() - TimeDelta::seconds(1));
    f.store
        .connection()
        .unwrap()
        .execute(
            "UPDATE artifact_files SET record = json_set(record, '$.upload_until', ?1)",
            [&past],
        )
        .unwrap();
    assert_eq!(f.store.prune_artifacts(false).unwrap().files_deleted, 1);
    assert!(!f.store.artifact_path(&held.sha256).exists());
    let r2 = f.request('2', &grant, Some(vec![input.clone()]));
    f.store.accept_task(&f.peer, r2.clone()).unwrap();
    deliver(&f.store, &f.input_key(&r2, &input), &data);
    f.store.next_task(&f.auth).unwrap().unwrap();
    f.store
        .change_task(&f.auth, &r2.task_id, Change::Reject("no".into()))
        .unwrap();
    let week_ago = rfc3339(crate::clock::now() - TASK_HOLD - TimeDelta::seconds(1));
    f.store
        .connection()
        .unwrap()
        .execute(
            "UPDATE received_tasks SET record = json_set(record, '$.updated_at', ?1)",
            [&week_ago],
        )
        .unwrap();
    assert_eq!(f.store.prune_artifacts(false).unwrap().files_deleted, 1);
}

#[test]
fn restart_discards_partial_files_and_resumes_fetches() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host");
    let (peer, key) = {
        let f_store = Store::open(&path).unwrap();
        let peer = add_test_peer(&f_store).id;
        let auth = connected_adapter(&f_store, "a");
        let agent = f_store.adapter_session(&auth).unwrap().agent_id;
        let grant = f_store
            .create_grant(CreateGrant {
                requester_host_id: peer.clone(),
                target_agent_id: agent.clone(),
                expires_at: rfc3339(crate::clock::now() + TimeDelta::hours(2)),
                max_message_bytes: 1000,
                max_artifact_bytes: 1000,
                allow_disconnected: true,
                requester_agent_id: None,
                action: Some(crate::policy::TASK_ACTION.into()),
            })
            .unwrap();
        let input = entry("in", b"payload");
        let r = TaskRequest {
            task_id: format!("task_{}", "1".repeat(32)),
            grant_id: Some(grant.id),
            policy: None,
            self_access: None,
            target_agent_id: agent,
            deadline: rfc3339(crate::clock::now() + TimeDelta::minutes(30)),
            input: "x".into(),
            origin: None,
            artifacts: Some(vec![input.clone()]),
            delegation: None,
        };
        f_store.accept_task(&peer, r.clone()).unwrap();
        // A crash mid-download leaves a partial file and an unrecorded one.
        fs::write(f_store.temporary_path().unwrap(), b"pay").unwrap();
        fs::write(f_store.artifact_path(&input.sha256), b"payload").unwrap();
        (
            peer.clone(),
            RowKey {
                side: RECEIVED.into(),
                peer,
                task_id: r.task_id,
                direction: INPUT.into(),
                sha256: input.sha256,
            },
        )
    };
    let store = Store::open(&path).unwrap();
    assert_eq!(fs::read_dir(store.artifact_dir()).unwrap().count(), 0);
    assert_eq!(store.pending_fetches().unwrap(), std::slice::from_ref(&key));
    deliver(&store, &key, b"payload");
    assert!(store.pending_fetches().unwrap().is_empty());
    let _ = peer;
}

#[test]
fn migration_from_version_nine_adds_the_artifact_tables() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host");
    drop(Store::open(&path).unwrap());
    rusqlite::Connection::open(path.join("host.db"))
        .unwrap()
        .execute_batch(
            "DROP TABLE onboarding_project_flows; DROP TABLE oauth_credentials; DROP TABLE oauth_clients; DROP TABLE dec_contexts; DROP TABLE dec_objects; DROP TABLE dec_admissions; DROP TABLE dec_restrictions; DROP TABLE dec_activations; DROP TABLE dec_heads; DROP TABLE dec_highwater; DROP TABLE dec_signers; DROP TABLE dec_clock; DROP TABLE dec_intents; DROP TABLE dec_pending; DROP TABLE dec_frames; DROP TABLE dec_operations; DROP TABLE dec_outbox; DROP TABLE dec_migrations; DROP TABLE dec_contacts; DROP TABLE dec_helpers; DROP TABLE builtin_sources; DROP TABLE approval_notices; DROP TABLE call_approvals; DROP TABLE link_signers; DROP TABLE link_highwater; DROP TABLE link_features; DROP TABLE link_objects; DROP TABLE link_operations; DROP TABLE link_frames; DROP TABLE link_pending; DROP TABLE link_device_keys; DROP TABLE call_update_notifications; DROP TABLE adapter_calls; DROP TABLE policy_edits; DROP TABLE outbound_calls; DROP TABLE received_calls; DROP TABLE source_access; DROP TABLE capabilities; DROP TABLE tool_values; DROP TABLE tool_servers; DROP TABLE directory_sends; DROP TABLE policy_deliveries; DROP TABLE task_children; DROP TABLE task_artifacts; DROP TABLE artifact_files; PRAGMA user_version = 9;",
        )
        .unwrap();
    let store = Store::open(&path).unwrap();
    let conn = store.connection().unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 24);
    let tables: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('artifact_files', 'task_artifacts')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(tables, 2);
}

#[tokio::test]
async fn sinks_hash_bound_and_discard() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(&dir.path().join("host")).unwrap());
    let mut sink = Sink::create(&store, 8).await.unwrap();
    sink.push(b"abcd").await.unwrap();
    sink.push(b"efgh").await.unwrap();
    assert!(matches!(sink.push(b"i").await, Err(Error::TooLarge(_))));
    sink.discard().await;
    let mut sink = Sink::create(&store, 1 << 22).await.unwrap();
    let data = vec![9u8; (1 << 21) + 3];
    sink.push(&data).await.unwrap();
    let (temp, size, sha) = sink.finish().await.unwrap();
    assert_eq!((size, sha), (data.len() as u64, digest(&data)));
    assert_eq!(fs::read(&temp).unwrap(), data);
    // A file body streams the same bytes back.
    let file = File::open(&temp).unwrap();
    let collected = Body::new(FileBody::new(file, data.len() as u64))
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(collected.as_ref(), data.as_slice());
    fs::remove_file(temp).unwrap();
    // Abandoned sinks remove their files too.
    drop(Sink::create(&store, 1).await.unwrap());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(fs::read_dir(store.artifact_dir()).unwrap().count(), 0);
}

#[tokio::test]
async fn receivers_fetch_inputs_over_quic_and_reject_corruption() {
    let open = || {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&dir.path().join("host")).unwrap());
        (dir, store)
    };
    let (_submitter_dir, submitter) = open();
    let (_receiver_dir, receiver) = open();
    let bound = crate::quic::listen(&submitter, "127.0.0.1:0".parse().unwrap()).unwrap();
    let (shutdown, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(crate::quic::serve(submitter.clone(), rx));
    let as_peer = |store: &Store, address: String| crate::peer_store::Peer {
        id: store.identity().id,
        public_key: store.identity().public_key,
        address,
    };
    submitter
        .add_peer(as_peer(&receiver, "127.0.0.1:9".into()))
        .unwrap();
    receiver
        .add_peer(as_peer(&submitter, bound.to_string()))
        .unwrap();
    let auth = connected_adapter(&receiver, "worker");
    let agent = receiver.adapter_session(&auth).unwrap().agent_id;
    let grant = receiver
        .create_grant(CreateGrant {
            requester_host_id: submitter.identity().id,
            target_agent_id: agent.clone(),
            expires_at: rfc3339(crate::clock::now() + TimeDelta::hours(2)),
            max_message_bytes: 1000,
            max_artifact_bytes: MAX_BOUND,
            allow_disconnected: true,
            requester_agent_id: None,
            action: Some(crate::policy::TASK_ACTION.into()),
        })
        .unwrap();
    // Larger than any other peer response.
    let data: Vec<u8> = (0..(3 << 20) + 17).map(|i| (i % 251) as u8).collect();
    let large = upload(&submitter, "large.bin", &data).unwrap();
    let small = upload(&submitter, "small.txt", b"corrupt me").unwrap();
    let out = submitter
        .prepare_task(SubmitTask {
            peer_host_id: receiver.identity().id,
            task_id: String::new(),
            grant_id: Some(grant.id.clone()),
            target_agent_id: agent,
            deadline: None,
            input: "process these".into(),
            origin: None,
            artifacts: Some(vec![large.clone(), small.clone()]),
            delegation_depth: 0,
            delegation_principals: None,
            parent: None,
        })
        .unwrap();
    receiver
        .accept_task(&submitter.identity().id, out.request.clone())
        .unwrap();
    let keys = receiver.pending_fetches().unwrap();
    assert_eq!(keys.len(), 2);
    assert!(fetch(receiver.clone(), keys[0].clone()).await);
    assert_eq!(
        fs::read(receiver.artifact_path(&large.sha256)).unwrap(),
        data
    );
    // A served file that no longer matches its digest is discarded and the
    // task stays queued.
    fs::write(submitter.artifact_path(&small.sha256), b"corrupt us").unwrap();
    assert!(!fetch(receiver.clone(), keys[1].clone()).await);
    assert!(!receiver.artifact_path(&small.sha256).exists());
    assert_eq!(receiver.pending_fetches().unwrap(), [keys[1].clone()]);
    assert!(receiver.next_task(&auth).unwrap().is_none());
    fs::write(submitter.artifact_path(&small.sha256), b"corrupt me").unwrap();
    assert!(fetch(receiver.clone(), keys[1].clone()).await);
    let handoff = receiver.next_task(&auth).unwrap().unwrap();
    assert_eq!(handoff.task.artifacts.unwrap().len(), 2);
    // Fetching authorizes nothing new: it works after revocation.
    receiver.revoke_grant(&grant.id).unwrap();
    let peer = receiver.dial_target(&submitter.identity().id).unwrap();
    let path = format!(
        "/peer/v1/tasks/{}/artifacts/{}",
        out.request.task_id, large.sha256
    );
    let mut response = crate::quic::download(receiver.clone(), &peer, &path)
        .await
        .unwrap();
    assert_eq!(
        (response.status, response.length),
        (200, Some(data.len() as u64))
    );
    let mut total = 0;
    while let Some(chunk) = response.chunk().await.unwrap() {
        total += chunk.len();
    }
    assert_eq!(total, data.len());
    let unlisted = format!(
        "/peer/v1/tasks/{}/artifacts/{}",
        out.request.task_id,
        digest(b"unlisted")
    );
    let response = crate::quic::download(receiver.clone(), &peer, &unlisted)
        .await
        .unwrap();
    assert_eq!(response.status, 404);
    drop(shutdown);
}

#[test]
fn routers_accept_the_artifact_routes() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(&dir.path().join("host")).unwrap());
    let _ = crate::api::router(store.clone());
    let _ = crate::adapter::router(store.clone());
    let _ = crate::peer::peer_router(store, "host_x".into());
}
