//! Atomic local cutover of the exact all-host transition preapproved by ACK.
//! Late finite authority stays expired; history never creates a new outcome.
use super::{
    actions,
    codec::*,
    controls, creation,
    intents::Intent,
    migration, migration_ack, migration_evidence,
    migration_local::{self, Source},
    migration_prefix::Prefix,
    migration_prepare, requests, runtime,
    storage::{OwnIdentity, Snapshot},
};
use crate::store::Store;
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};
fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn checked(
    store: &Store,
    c: &Connection,
    network: &str,
    proposal: &str,
    commit: &str,
) -> Result<(
    super::storage::MigrationRecord,
    super::statement::Descriptor,
    Prefix,
    OwnIdentity,
)> {
    let (id, r) = migration_prepare::load(c, network)?.ok_or_else(|| Error::new("not_found"))?;
    require(id == proposal, "operation_conflict")?;
    require(
        r.approved && r.fenced && r.local_acknowledgment_base64 != "-",
        "review_required",
    )?;
    let d = migration_evidence::descriptor(&r)?;
    let p = Prefix::read(&d, &r)?;
    require(
        p.commit.as_ref().is_some_and(|s| s.id == commit) && r.migration_base64 != "-",
        "operation_conflict",
    )?;
    let host = store.identity().public_key;
    let row = object(
        array(&p.proposal.payload, "roster")?
            .iter()
            .find(|r| r.get("host_public_key").and_then(Value::as_str) == Some(&host))
            .ok_or_else(|| Error::new("forbidden"))?,
    )?;
    let identity = OwnIdentity {
        member: text(row, "member")?.into(),
        person_public_key: text(row, "person_public_key")?.into(),
        host_public_key: host.clone(),
    };
    let ack =
        super::statement::Statement::read(&d, &b64(&r.local_acknowledgment_base64, MAX_OBJECT)?)?;
    require(
        p.acknowledgments
            .get(&host)
            .is_some_and(|a| a.body == ack.body),
        "state_conflict",
    )?;
    let i = Intent::load(c, &r.local_ack_intent_id)?;
    require(
        i.record.approved
            && i.record.completed
            && i.record.host_public_key == host
            && i.record.operation_id == proposal
            && i.record.templates.len() == 1
            && i.record.templates[0].object_type == "migration_ack"
            && i.assembled(&d)?[0].bytes() == ack.body,
        "state_conflict",
    )?;
    if r.state == "adopted" {
        let s = Snapshot::load(c, network, &host)?;
        require(
            s.context.origin == "migration"
                && s.context.migration_proposal_id == proposal
                && s.context.origin_proof_id
                    == super::statement::proof_id(
                        "migration",
                        &b64(&r.migration_base64, MAX_OBJECT)?,
                    ),
            "state_conflict",
        )?;
    } else {
        let source = Source::load(store, c, network)?;
        p.known(&source, &r)?;
        migration_prepare::own_roster(c, &source, &host, array(&p.proposal.payload, "roster")?)?;
        require(
            source.facts.root_public_key == text(&p.proposal.payload, "legacy_root_public_key")?
                && source.facts.epoch == num(&p.proposal.payload, "legacy_epoch")?,
            "state_conflict",
        )?;
        if identity.person_public_key != "-" {
            migration_ack::device_seed(c, network, &host, row)?;
        }
    }
    Ok((r, d, p, identity))
}
fn finish_pending(
    c: &Connection,
    proposal: &str,
    d: &super::statement::Descriptor,
    m: &migration::Migration,
) -> Result<()> {
    let mut activations = std::collections::BTreeMap::new();
    for proof in m
        .prepared
        .proofs
        .values()
        .filter(|p| p.kind == "activation")
    {
        let a = super::transcript::Activation::read(d, &proof.body)?;
        if let Some(old) = activations.insert(a.request_id.clone(), a.clone()) {
            require(old.id == a.id, "state_conflict")?;
        }
    }
    let mut q = c.prepare("SELECT request_id FROM dec_pending WHERE json_extract(record,'$.migration_proposal_id')=?1 ORDER BY request_id").map_err(db)?;
    let ids = q
        .query_map([proposal], |r| r.get::<_, String>(0))
        .map_err(db)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db)?;
    drop(q);
    for id in ids {
        let mut pending = requests::load(c, &id)?;
        if matches!(pending.record.terminal.as_str(), "cancelled" | "expired") {
            // These resolved precommit attempts supply no signed activation.
            // Keep their history without requiring them in the cutover body.
            require(pending.record.commit_packet_base64 == "-", "state_conflict")?;
            continue;
        }
        require(
            matches!(
                pending.record.terminal.as_str(),
                "migration_prepared" | "migration_adopted"
            ),
            "recovery_required",
        )?;
        let a = activations.get(&id).ok_or_else(|| Error::missing(&id))?;
        require(
            a.id == pending.record.activation_id && a.manifest_id == pending.record.manifest_id,
            "operation_conflict",
        )?;
        pending.record.terminal = "migration_adopted".into();
        pending.record.outbound_frames.clear();
        pending.secret = None;
        pending.terminal_read_cap = None;
        c.execute("DELETE FROM dec_frames WHERE request_id=?1", [&id])
            .map_err(db)?;
        requests::save(c, &pending)?;
    }
    Ok(())
}
pub(crate) fn adopt(store: &Store, network: &str, input: &Obj) -> Result<Vec<u8>> {
    fields(input, "proposal_id commit_id approve")?;
    let proposal = text(input, "proposal_id")?;
    let commit = text(input, "commit_id")?;
    check(ident(proposal, "ds_") && ident(commit, "ds_"))?;
    let approve = input
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("invalid"))?;
    if approve {
        let already_adopted = {
            let c = store.connection().map_err(|_| Error::new("internal"))?;
            checked(store, &c, network, proposal, commit)?.0.state == "adopted"
        };
        if already_adopted {
            return result(store, network);
        }
        controls::barrier(store, "dec.apply.before_transaction", proposal)?;
    }
    let changed = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let mut tx = c.transaction().map_err(db)?;
        let (mut r, d, p, identity) = checked(store, &tx, network, proposal, commit)?;
        if r.state == "adopted" {
            false
        } else {
            let whole = b64(&r.migration_base64, MAX_OBJECT)?;
            let m = migration::Migration::read(&d, &whole)?;
            let now = creation::decision(&tx, network, &controls::local_decision_time()?)?;
            // Read-only previews verify the same complete origin and current
            // source. Expired finite D does not invalidate historical cutover.
            if !approve {
                return actions::bytes(&json!({"migration":p.view(&d,&r)?,"network":Value::Null}));
            }
            let host = &identity.host_public_key;
            let mut identity_intent = migration_local::approved_identity(&tx, network, host)?
                .ok_or_else(|| Error::new("review_required"))?;
            if identity.person_public_key != "-" {
                let row = object(
                    array(&p.proposal.payload, "roster")?
                        .iter()
                        .find(|r| r.get("host_public_key").and_then(Value::as_str) == Some(host))
                        .ok_or_else(|| Error::new("forbidden"))?,
                )?;
                let key = migration_ack::device_seed(&tx, network, host, row)?;
                let public = encode(key.verifying_key().as_bytes());
                let existing: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT seed FROM link_device_keys WHERE public_key=?1",
                        [&public],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(db)?;
                if let Some(old) = existing {
                    require(old == key.to_bytes(), "state_conflict")?;
                } else {
                    tx.execute(
                        "INSERT INTO link_device_keys(public_key,seed,created_at) VALUES(?1,?2,?3)",
                        rusqlite::params![
                            public,
                            key.to_bytes().as_slice(),
                            identity_intent.record.created_at
                        ],
                    )
                    .map_err(db)?;
                }
            }
            // Move a generated pending identity's one seed home in this TX.
            identity_intent.secret = None;
            identity_intent.record.terminal = "applied".into();
            identity_intent.save(&tx)?;
            r.state = "adopted".into();
            migration_prepare::save(&tx, network, proposal, &r)?;
            let descriptor =
                actions::bytes(&serde_json::to_value(&d).map_err(|_| Error::new("internal"))?)?;
            Snapshot::install_migration(&mut tx, &descriptor, &whole, &now, &identity)?;
            finish_pending(&tx, proposal, &d, &m)?;
            tx.execute(
                "INSERT INTO events(kind,subject_id,created_at) VALUES('network.migrated',?1,?2)",
                rusqlite::params![network, now],
            )
            .map_err(db)?;
            tx.commit().map_err(db)?;
            true
        }
    };
    if changed {
        controls::barrier(store, "dec.apply.after_commit", proposal)?;
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        store
            .refresh_member_pins(&c)
            .map_err(|_| Error::new("internal"))?;
    }
    result(store, network)
}
fn result(store: &Store, network: &str) -> Result<Vec<u8>> {
    let migration = {
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        let (_, r) =
            migration_prepare::load(&c, network)?.ok_or_else(|| Error::new("not_found"))?;
        let d = migration_evidence::descriptor(&r)?;
        let p = Prefix::read(&d, &r)?;
        p.view(&d, &r)?
    };
    let network = parse(&runtime::read_network(store, network, "", "-")?, 32 << 20)?;
    actions::bytes(&json!({"migration":migration,"network":network}))
}
pub(super) fn resume(store: &Store, network: &str) -> Result<Option<Vec<u8>>> {
    let target = {
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        let Some((proposal, r)) = migration_prepare::load(&c, network)? else {
            return Ok(None);
        };
        if !r.fenced || r.commit_base64 == "-" || r.state == "adopted" {
            return Ok(None);
        }
        let d = migration_evidence::descriptor(&r)?;
        let p = Prefix::read(&d, &r)?;
        (
            proposal,
            p.commit.ok_or_else(|| Error::new("state_conflict"))?.id,
        )
    };
    adopt(
        store,
        network,
        object(&json!({"proposal_id":target.0,"commit_id":target.1,"approve":true}))?,
    )
    .map(Some)
}
