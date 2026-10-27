//! Exact public migration evidence and local participation review. Importing
//! bytes is preparation only; neither this carrier nor its roster is a prior.
use super::{
    actions,
    catalog::Catalog,
    codec::*,
    controls, creation,
    migration_local::{self, Source},
    migration_prefix::Prefix,
    migration_prepare,
    statement::{Descriptor, Statement},
    storage::{MigrationRecord, Snapshot},
};
use crate::store::Store;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn bytes(v: &Value) -> Result<Vec<u8>> {
    actions::bytes(v)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Carrier {
    proposal_base64: String,
    source_catalog_base64: String,
    source_state_base64: String,
    prepared_catalog_base64: String,
    acknowledgments_base64: Vec<String>,
    commit_base64: String,
}
impl Carrier {
    fn read(input: &Obj) -> Result<Self> {
        fields(
            input,
            "proposal_base64 source_catalog_base64 source_state_base64 prepared_catalog_base64 acknowledgments_base64 commit_base64",
        )?;
        let c: Self = serde_json::from_value(Value::Object(input.clone()))
            .map_err(|_| Error::new("invalid"))?;
        // First import always supplies the original signed proposal and both
        // frozen source components. Unknowns are confined to later evidence.
        b64(&c.proposal_base64, MAX_OBJECT)?;
        b64(&c.source_catalog_base64, 512 << 10)?;
        b64(&c.source_state_base64, MAX_PAYLOAD)?;
        if c.prepared_catalog_base64 != "-" {
            b64(&c.prepared_catalog_base64, MAX_OBJECT)?;
        }
        if c.commit_base64 != "-" {
            b64(&c.commit_base64, MAX_OBJECT)?;
        }
        require(c.acknowledgments_base64.len() <= 4096, "quota_exceeded")?;
        for a in &c.acknowledgments_base64 {
            b64(a, MAX_OBJECT)?;
        }
        Ok(c)
    }
    fn of(r: &MigrationRecord) -> Self {
        Self {
            proposal_base64: r.proposal_base64.clone(),
            source_catalog_base64: r.source_catalog_base64.clone(),
            source_state_base64: r.source_state_base64.clone(),
            prepared_catalog_base64: r.prepared_catalog_base64.clone(),
            acknowledgments_base64: r.acknowledgments_base64.clone(),
            commit_base64: r.commit_base64.clone(),
        }
    }
    fn record(&self, d: &Descriptor) -> MigrationRecord {
        MigrationRecord {
            format: 1,
            context_id: d.context_id(),
            state: "needs_approvals".into(),
            proposal_base64: self.proposal_base64.clone(),
            source_catalog_base64: self.source_catalog_base64.clone(),
            source_state_base64: self.source_state_base64.clone(),
            prepared_catalog_base64: self.prepared_catalog_base64.clone(),
            initial_root_state_base64: "-".into(),
            acknowledgments_base64: self.acknowledgments_base64.clone(),
            commit_base64: self.commit_base64.clone(),
            migration_base64: "-".into(),
            local_acknowledgment_base64: "-".into(),
            root_intent_ids: vec![],
            local_ack_intent_id: "-".into(),
            approved: false,
            fenced: false,
            publication_started: false,
        }
    }
}

pub(super) fn descriptor(r: &MigrationRecord) -> Result<Descriptor> {
    let outer = parse(&b64(&r.proposal_base64, MAX_OBJECT)?, MAX_OBJECT)?;
    let p = parse(
        &b64(text(object(&outer)?, "payload_base64")?, MAX_PAYLOAD)?,
        MAX_PAYLOAD,
    )?;
    Descriptor::from_value(
        p.get("new_descriptor")
            .ok_or_else(|| Error::new("invalid"))?,
    )
}
pub(super) fn review(
    d: &Descriptor,
    p: &Prefix,
    r: &MigrationRecord,
    stage: &str,
) -> Result<Value> {
    let o = &p.proposal.payload;
    Ok(
        json!({"stage":stage,"network_id":d.network_id,"proposal_id":p.proposal.id,"legacy_root_public_key":text(o,"legacy_root_public_key")?,"legacy_epoch":num(o,"legacy_epoch")?,"new_context_id":d.context_id(),"roster":array(o,"roster")?,"source_catalog_sha256":text(o,"source_catalog_sha256")?,"source_state_sha256":text(o,"source_state_sha256")?,"prepared_catalog_sha256":p.catalog.as_ref().map_or("-".to_owned(),|c|hash(&c.bytes)),"authority_warning":if r.state=="adopted" {"The original whole-network transition is retained as immutable history. Its finite grants must independently remain current; this read creates no renewed authority."} else {"Review the exact source, roster and finite authority. Every original person and known host separately consents. Participation neither acknowledges nor adopts; a later acknowledgment creates a durable fence with no timeout abort."}}),
    )
}
pub(super) fn wrapper(
    d: &Descriptor,
    p: &Prefix,
    r: &MigrationRecord,
    stage: &str,
) -> Result<Vec<u8>> {
    bytes(&json!({"migration":p.view(d,r)?,"review":review(d,p,r,stage)?,"signing_requests":[]}))
}
fn check_adopted(
    store: &Store,
    c: &Connection,
    network: &str,
    p: &Prefix,
    r: &MigrationRecord,
) -> Result<()> {
    if r.state == "adopted" {
        let s = Snapshot::load(c, network, &store.identity().public_key)?;
        require(
            s.context.origin == "migration"
                && s.context.migration_proposal_id == p.proposal.id
                && s.network.context_id == r.context_id
                && r.migration_base64 != "-",
            "state_conflict",
        )?;
        let origin = s.prior.catalog.proof(&s.context.origin_proof_id)?;
        require(
            origin.kind == "migration" && origin.body == b64(&r.migration_base64, MAX_OBJECT)?,
            "state_conflict",
        )?;
    }
    Ok(())
}
pub(crate) fn status(store: &Store, network: &str) -> Result<Vec<u8>> {
    check(ident(network, "net_"))?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let Some((id, r)) = migration_prepare::load(&tx, network)? else {
        Source::load(store, &tx, network)?;
        return bytes(&migration_local::empty_view(network));
    };
    if r.proposal_base64 == "-" {
        let s = Source::load(store, &tx, network)?;
        return migration_prepare::status(&tx, &s);
    }
    let d = descriptor(&r)?;
    require(d.network_id == network, "state_conflict")?;
    let p = Prefix::read(&d, &r)?;
    require(p.proposal.id == id, "state_conflict")?;
    check_adopted(store, &tx, network, &p, &r)?;
    bytes(&p.view(&d, &r)?)
}
pub(crate) fn export(store: &Store, network: &str) -> Result<Vec<u8>> {
    check(ident(network, "net_"))?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let (id, r) = migration_prepare::load(&tx, network)?.ok_or_else(|| Error::new("not_found"))?;
    require(r.proposal_base64 != "-", "not_found")?;
    let d = descriptor(&r)?;
    require(d.network_id == network, "state_conflict")?;
    let p = Prefix::read(&d, &r)?;
    require(p.proposal.id == id, "state_conflict")?;
    check_adopted(store, &tx, network, &p, &r)?;
    let raw = serde_json::to_vec(&Carrier::of(&r)).map_err(|_| Error::new("internal"))?;
    require(raw.len() <= 32 << 20, "quota_exceeded")?;
    Ok(raw)
}
fn merge(
    d: &Descriptor,
    r: &mut MigrationRecord,
    input: &Carrier,
    incoming: &Prefix,
) -> Result<()> {
    require(
        r.context_id == d.context_id()
            && r.source_catalog_base64 == input.source_catalog_base64
            && r.source_state_base64 == input.source_state_base64,
        "state_conflict",
    )?;
    if r.proposal_base64 == "-" {
        r.proposal_base64 = input.proposal_base64.clone();
    } else {
        let old = Statement::read(d, &b64(&r.proposal_base64, MAX_OBJECT)?)?;
        require(
            old.id == incoming.proposal.id && old.payload_bytes == incoming.proposal.payload_bytes,
            "state_conflict",
        )?;
    }
    if let Some(next) = &incoming.catalog {
        if r.prepared_catalog_base64 == "-" {
            r.prepared_catalog_base64 = input.prepared_catalog_base64.clone();
        } else {
            let old = Catalog::read_prepared(d, &b64(&r.prepared_catalog_base64, MAX_OBJECT)?)?;
            if old.bytes != next.bytes {
                require(
                    !r.fenced
                        && r.acknowledgments_base64.is_empty()
                        && r.local_acknowledgment_base64 == "-"
                        && r.commit_base64 == "-"
                        && r.migration_base64 == "-",
                    "operation_conflict",
                )?;
                let contains = old.proofs.iter().all(|(id, p)| {
                    next.proofs
                        .get(id)
                        .is_some_and(|n| n.kind == p.kind && n.body == p.body)
                });
                r.prepared_catalog_base64 = if contains {
                    input.prepared_catalog_base64.clone()
                } else {
                    require(
                        input.acknowledgments_base64.is_empty() && input.commit_base64 == "-",
                        "operation_conflict",
                    )?;
                    encode(&Catalog::union(d, &old, next)?.bytes)
                };
            }
        }
    }
    if let Some(next) = &incoming.root {
        if r.initial_root_state_base64 == "-" {
            r.initial_root_state_base64 = encode(&next.body);
        } else {
            require(
                Statement::read(d, &b64(&r.initial_root_state_base64, MAX_OBJECT)?)?.id == next.id,
                "state_conflict",
            )?;
        }
    }
    let mut acks = BTreeMap::<String, (String, String)>::new();
    for encoded in r
        .acknowledgments_base64
        .iter()
        .chain(input.acknowledgments_base64.iter())
    {
        let ack = Statement::read(d, &b64(encoded, MAX_OBJECT)?)?;
        let host = text(&ack.payload, "host_public_key")?.to_owned();
        if let Some((id, _)) = acks.get(&host) {
            require(*id == ack.id, "state_conflict")?;
        } else {
            acks.insert(host, (ack.id, encoded.clone()));
        }
    }
    r.acknowledgments_base64 = acks.into_values().map(|(_, raw)| raw).collect();
    if input.commit_base64 != "-" {
        require(
            r.commit_base64 == "-" || r.commit_base64 == input.commit_base64,
            "state_conflict",
        )?;
        r.commit_base64 = input.commit_base64.clone();
    }
    Prefix::complete_body(r)?;
    let combined = Prefix::read(d, r)?;
    require(
        combined.proposal.id == incoming.proposal.id,
        "state_conflict",
    )?;
    if r.commit_base64 != "-" && r.migration_base64 == "-" {
        r.migration_base64 = encode(&Prefix::complete_body(r)?);
        if r.state == "needs_approvals" {
            r.state = "prepared".into();
        }
    }
    Ok(())
}
// The authenticated sender is a transport host ID, never a key supplied by the
// candidate carrier. Qualify it using only independently retained source facts.
fn peer_carrier(store: &Store, c: &Connection, network: &str, sender: &str) -> Result<Vec<u8>> {
    check(ident(network, "net_") && ident(sender, "host_"))?;
    let raw: Option<String> = c
        .query_row("SELECT record FROM networks WHERE id=?1", [network], |r| {
            r.get(0)
        })
        .optional()
        .map_err(db)?;
    let raw = raw.ok_or_else(|| Error::new("not_found"))?;
    require(raw.len() <= 32 << 20, "quota_exceeded")?;
    let tag: Value = serde_json::from_str(&raw).map_err(|_| Error::new("state_conflict"))?;
    let retained = migration_prepare::load(c, network)?;
    if tag.get("mode").and_then(Value::as_str) == Some("decentralized") {
        let (id, r) = retained.ok_or_else(|| Error::new("forbidden"))?;
        require(
            r.state == "adopted"
                && r.fenced
                && r.approved
                && r.local_acknowledgment_base64 != "-"
                && r.migration_base64 != "-",
            "forbidden",
        )?;
        let d = descriptor(&r)?;
        require(d.network_id == network, "state_conflict")?;
        let p = Prefix::read(&d, &r)?;
        require(p.proposal.id == id, "state_conflict")?;
        // Archival delivery depends only on the original complete transition
        // and its private origin pin. Later policy/H proof loss cannot supply
        // or revoke this narrow, non-actionable historical read identity.
        let n: super::storage::NetworkRecord =
            serde_json::from_value(parse(raw.as_bytes(), 32 << 20)?)
                .map_err(|_| Error::new("state_conflict"))?;
        let actual = Descriptor::read(&b64(&n.descriptor_base64, MAX_OBJECT)?)?;
        let context_raw: String = c
            .query_row(
                "SELECT record FROM dec_contexts WHERE network_id=?1 AND context_id=?2",
                rusqlite::params![network, n.context_id],
                |r| r.get(0),
            )
            .map_err(db)?;
        let context: super::storage::ContextRecord =
            serde_json::from_value(parse(context_raw.as_bytes(), 32 << 20)?)
                .map_err(|_| Error::new("state_conflict"))?;
        let migration = b64(&r.migration_base64, MAX_OBJECT)?;
        require(
            n.format == 2
                && n.mode == "decentralized"
                && actual.network_id == network
                && actual.context_id() == d.context_id()
                && n.context_id == d.context_id()
                && n.own_identity.host_public_key == store.identity().public_key
                && context.format == 1
                && context.descriptor_base64 == n.descriptor_base64
                && context.origin == "migration"
                && context.migration_proposal_id == p.proposal.id
                && context.initial_root_state_id
                    == p.root
                        .as_ref()
                        .ok_or_else(|| Error::new("state_conflict"))?
                        .id
                && context.origin_proof_id == super::statement::proof_id("migration", &migration),
            "state_conflict",
        )?;
        stamp(&context.adopted_at)?;
        let origin: Option<(String, Vec<u8>)> = c.query_row(
            "SELECT kind,body FROM dec_objects WHERE network_id=?1 AND context_id=?2 AND proof_id=?3",
            rusqlite::params![network,n.context_id,context.origin_proof_id], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(db)?;
        let (kind, body) = origin.ok_or_else(|| Error::missing(&context.origin_proof_id))?;
        require(kind == "migration" && body == migration, "state_conflict")?;
        super::migration::verify(
            &d,
            &Value::from("-"),
            &Value::from("-"),
            &b64(&r.migration_base64, MAX_OBJECT)?,
            &controls::local_decision_time()?,
            "evidence",
            "-",
        )?;
        let own = store.identity().public_key;
        let ack = p
            .acknowledgments
            .get(&own)
            .ok_or_else(|| Error::new("forbidden"))?;
        require(
            ack.body == b64(&r.local_acknowledgment_base64, MAX_OBJECT)?,
            "state_conflict",
        )?;
        require(
            p.acknowledgments.keys().any(|key| {
                b64(key, 32).is_ok_and(|bytes| crate::peer_store::key_id(&bytes) == sender)
            }),
            "forbidden",
        )?;
        return serde_json::to_vec(&Carrier::of(&r)).map_err(|_| Error::new("internal"));
    }
    let source = Source::load(store, c, network)?;
    let known = super::migration::SourceState::read(network, &source.state_bytes)?;
    require(
        known.hosts.contains(&store.identity().public_key)
            && known.hosts.iter().any(|key| {
                b64(key, 32).is_ok_and(|bytes| crate::peer_store::key_id(&bytes) == sender)
            }),
        "forbidden",
    )?;
    let Some((id, r)) = retained.filter(|(_, r)| r.proposal_base64 != "-") else {
        return bytes(
            &json!({"proposal_base64":"-","source_catalog_base64":"-","source_state_base64":"-","prepared_catalog_base64":"-","acknowledgments_base64":[],"commit_base64":"-"}),
        );
    };
    let d = descriptor(&r)?;
    require(d.network_id == network, "state_conflict")?;
    let p = Prefix::read(&d, &r)?;
    require(p.proposal.id == id, "state_conflict")?;
    p.known(&source, &r)?;
    serde_json::to_vec(&Carrier::of(&r)).map_err(|_| Error::new("internal"))
}

pub(crate) fn peer_export(store: &Store, network: &str, sender: &str) -> Result<Vec<u8>> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    peer_carrier(store, &tx, network, sender)
}
pub(crate) fn peer_receive(
    store: &Store,
    network: &str,
    sender: &str,
    input: &Obj,
) -> Result<Vec<u8>> {
    receive_inner(store, network, input, Some(sender))
}
pub(crate) fn receive(store: &Store, network: &str, input: &Obj) -> Result<Vec<u8>> {
    receive_inner(store, network, input, None)
}
fn receive_inner(
    store: &Store,
    network: &str,
    input: &Obj,
    sender: Option<&str>,
) -> Result<Vec<u8>> {
    check(ident(network, "net_"))?;
    let (output, id, fresh) = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        if let Some(sender) = sender {
            peer_carrier(store, &tx, network, sender)?;
        }
        let incoming = Carrier::read(input)?;
        if let Some((id, retained)) = migration_prepare::load(&tx, network)?
            && retained.state == "adopted"
        {
            // A completed transition is immutable history. Validate every
            // received component before recognizing that same signed intent;
            // never reopen the legacy parser or replace the stored origin.
            let d = descriptor(&retained)?;
            let old = Prefix::read(&d, &retained)?;
            check_adopted(store, &tx, network, &old, &retained)?;
            let candidate = incoming.record(&d);
            Prefix::complete_body(&candidate)?;
            let next = Prefix::read(&d, &candidate)?;
            require(
                next.proposal.id == id
                    && next.proposal.payload_bytes == old.proposal.payload_bytes
                    && incoming.source_catalog_base64 == retained.source_catalog_base64
                    && incoming.source_state_base64 == retained.source_state_base64
                    && next.catalog.as_ref().map(|c| &c.bytes)
                        == old.catalog.as_ref().map(|c| &c.bytes)
                    && next.commit.as_ref().map(|s| &s.payload_bytes)
                        == old.commit.as_ref().map(|s| &s.payload_bytes)
                    && next.commit.is_some()
                    && next
                        .acknowledgments
                        .iter()
                        .map(|(host, ack)| (host, &ack.id))
                        .collect::<Vec<_>>()
                        == old
                            .acknowledgments
                            .iter()
                            .map(|(host, ack)| (host, &ack.id))
                            .collect::<Vec<_>>(),
                "operation_conflict",
            )?;
            return wrapper(&d, &old, &retained, "adoption");
        }
        let local = Source::load(store, &tx, network)?;
        let candidate = incoming.record(&local.descriptor);
        Prefix::complete_body(&candidate)?;
        let p = Prefix::read(&local.descriptor, &candidate)?;
        p.known(&local, &candidate)?;
        let old = migration_prepare::load(&tx, network)?;
        let fresh = old.is_none();
        let id = p.proposal.id.clone();
        let mut r = if let Some((old_id, r)) = old {
            require(old_id == id, "state_conflict")?;
            r
        } else {
            let count: i64 = tx
                .query_row("SELECT COUNT(*) FROM dec_migrations", [], |r| r.get(0))
                .map_err(db)?;
            require(count < 4096, "quota_exceeded")?;
            // This is public evidence only; it does not infer this machine's
            // identity approval from another participant's signed roster.
            let mut r = candidate.clone();
            r.prepared_catalog_base64 = "-".into();
            r.acknowledgments_base64.clear();
            r.commit_base64 = "-".into();
            r
        };
        merge(&local.descriptor, &mut r, &incoming, &p)?;
        let p = Prefix::read(&local.descriptor, &r)?;
        let latest = creation::decision(&tx, network, &controls::local_decision_time()?)?;
        decision_clock(&latest, &local.time)?;
        migration_prepare::save(&tx, network, &id, &r)?;
        creation::remember_clock(&tx, network, &latest)?;
        let output = wrapper(&local.descriptor, &p, &r, "participation")?;
        tx.commit().map_err(db)?;
        (output, id, fresh)
    };
    if fresh {
        controls::barrier(store, "dec.migration_proposal.after_commit", &id)?;
    }
    Ok(output)
}
pub(crate) fn participate(store: &Store, network: &str, input: &Obj) -> Result<Vec<u8>> {
    fields(input, "proposal_id approve")?;
    let id = text(input, "proposal_id")?;
    check(ident(network, "net_") && ident(id, "ds_"))?;
    let approve = input
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("invalid"))?;
    let (output, changed) = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let local = Source::load(store, &tx, network)?;
        let (actual, mut r) =
            migration_prepare::load(&tx, network)?.ok_or_else(|| Error::new("not_found"))?;
        require(actual == id, "operation_conflict")?;
        require(r.proposal_base64 != "-", "proof_required").map_err(|_| Error::missing(id))?;
        let p = Prefix::read(&local.descriptor, &r)?;
        p.known(&local, &r)?;
        require(
            local.time.as_str() >= text(&p.proposal.payload, "issued_at")?,
            "not_yet_valid",
        )?;
        require(
            local.time.as_str() < text(&p.proposal.payload, "expires_at")?,
            "expired",
        )?;
        migration_prepare::own_roster(
            &tx,
            &local,
            &store.identity().public_key,
            array(&p.proposal.payload, "roster")?,
        )?;
        Prefix::complete_body(&r)?;
        let changed = approve && !r.approved;
        if changed {
            let latest = creation::decision(&tx, network, &controls::local_decision_time()?)?;
            decision_clock(&latest, &local.time)?;
            require(
                latest.as_str() < text(&p.proposal.payload, "expires_at")?,
                "expired",
            )?;
            r.approved = true;
            migration_prepare::save(&tx, network, id, &r)?;
            creation::remember_clock(&tx, network, &latest)?;
        }
        let output = wrapper(&local.descriptor, &p, &r, "participation")?;
        if changed {
            tx.commit().map_err(db)?;
        }
        (output, changed)
    };
    if changed {
        controls::barrier(store, "dec.approval.after_commit", id)?;
    }
    Ok(output)
}
pub(crate) fn resume(store: &Store, network: &str, input: &Obj) -> Result<Vec<u8>> {
    fields(input, "")?;
    if super::migration_adopt::resume(store, network)?.is_some() {
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        let (_, r) =
            migration_prepare::load(&c, network)?.ok_or_else(|| Error::new("not_found"))?;
        let d = descriptor(&r)?;
        let p = Prefix::read(&d, &r)?;
        return wrapper(&d, &p, &r, "adoption");
    }
    if let Some(ready) = super::migration_device_bans::resume(store, network)? {
        return Ok(ready);
    }
    super::migration_host::resume(store, network)?;
    super::migration_ack::advance(store, network)?;
    if super::migration_commit::advance(store, network, None)? {
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        let (_, r) =
            migration_prepare::load(&c, network)?.ok_or_else(|| Error::new("not_found"))?;
        let d = descriptor(&r)?;
        let p = Prefix::read(&d, &r)?;
        return wrapper(&d, &p, &r, "root_commit");
    }
    let root = {
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        let (_, r) =
            migration_prepare::load(&c, network)?.ok_or_else(|| Error::new("not_found"))?;
        !r.root_intent_ids.is_empty() && !r.fenced
    };
    if root {
        return migration_prepare::resume(store, network, input);
    }
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let (_, r) = migration_prepare::load(&tx, network)?.ok_or_else(|| Error::new("not_found"))?;
    let d = descriptor(&r)?;
    require(d.network_id == network, "state_conflict")?;
    let p = Prefix::read(&d, &r)?;
    if r.state != "adopted" {
        p.known(&Source::load(store, &tx, network)?, &r)?;
    }
    check_adopted(store, &tx, network, &p, &r)?;
    wrapper(&d, &p, &r, "participation")
}
