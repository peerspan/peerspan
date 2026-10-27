//! Own unbound host consent for one fixed migration H. The host key signs only
//! this reviewed typed template; it is never a reusable network provider.
use super::{
    actions,
    catalog::Catalog,
    codec::*,
    controls, creation,
    intents::{Filled, Intent, Provider, Record, Template},
    migration_local::Source,
    migration_prefix::Prefix,
    migration_prepare,
    statement::{Descriptor, Statement, proof_id},
    storage::MigrationRecord,
    template::FixedStatement,
};
use crate::store::Store;
use ed25519_dalek::Signer;
use rusqlite::Connection;
use serde_json::{Value, json};

fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
pub(super) struct Context {
    pub source: Source,
    pub record: MigrationRecord,
    pub prefix: Prefix,
    pub own: Obj,
}
impl Context {
    pub(super) fn load(
        store: &Store,
        c: &Connection,
        network: &str,
        proposal: &str,
    ) -> Result<Self> {
        Self::load_mode(store, c, network, proposal, false)
    }
    pub(super) fn load_fenced(
        store: &Store,
        c: &Connection,
        network: &str,
        proposal: &str,
    ) -> Result<Self> {
        Self::load_mode(store, c, network, proposal, true)
    }
    fn load_mode(
        store: &Store,
        c: &Connection,
        network: &str,
        proposal: &str,
        allow_fenced: bool,
    ) -> Result<Self> {
        check(ident(network, "net_") && ident(proposal, "ds_"))?;
        let source = Source::load(store, c, network)?;
        let (id, record) =
            migration_prepare::load(c, network)?.ok_or_else(|| Error::new("not_found"))?;
        require(id == proposal, "operation_conflict")?;
        require(
            record.approved && record.proposal_base64 != "-",
            "review_required",
        )?;
        require(allow_fenced || !record.fenced, "migration_pending")?;
        require(
            !matches!(record.state.as_str(), "adopted" | "conflict"),
            "state_conflict",
        )?;
        let prefix = Prefix::read(&source.descriptor, &record)?;
        prefix.known(&source, &record)?;
        let p = &prefix.proposal.payload;
        require(
            source.time.as_str() >= text(p, "issued_at")?,
            "not_yet_valid",
        )?;
        require(source.time.as_str() < text(p, "expires_at")?, "expired")?;
        let host = store.identity().public_key;
        let roster = array(p, "roster")?;
        migration_prepare::own_roster(c, &source, &host, roster)?;
        let own = object(
            roster
                .iter()
                .find(|r| r.get("host_public_key").and_then(Value::as_str) == Some(&host))
                .ok_or_else(|| Error::new("forbidden"))?,
        )?
        .clone();
        Ok(Self {
            source,
            record,
            prefix,
            own,
        })
    }
}
fn host_review(network: &str, proposal: &str, s: &Statement) -> Result<Value> {
    Ok(
        json!({"stage":"host_membership","network_id":network,"proposal_id":proposal,"host_public_key":text(s.subject()?,"host_public_key")?,"member":text(s.subject()?,"member")?,"root_state_id":text(&s.payload,"root_state_id")?,"host_lease_id":s.id,"issued_at":s.issued_at()?,"not_before":text(&s.payload,"not_before")?,"not_after":text(&s.payload,"not_after")?,"authority_warning":"Approve only this exact finite host membership for the reviewed whole-network migration. This signs no person/device authority, acknowledgment, fence, active context or adoption."}),
    )
}
fn check_template(
    d: &Descriptor,
    p: &Prefix,
    own: &Obj,
    host: &str,
    raw: &[u8],
    partial: bool,
    now: Option<&str>,
) -> Result<FixedStatement> {
    let t = FixedStatement::read(d, raw)?;
    let s = t.typed();
    let root = p
        .root
        .as_ref()
        .ok_or_else(|| Error::missing(&p.proposal.id))?;
    require(
        text(own, "host_public_key")? == host
            && text(own, "person_public_key")? == "-"
            && text(own, "device_public_key")? == "-"
            && num(own, "scopes")? == 0,
        "forbidden",
    )?;
    check(
        s.kind == "host_lease"
            && s.signatures.len() == 2
            && text(&s.payload, "operation_id")? == p.proposal.id
            && text(&s.payload, "root_state_id")? == root.id
            && s.sequence()? == 1
            && ids(&s.payload, "predecessors", "ds_")?.is_empty()
            && ids(&s.payload, "resolves", "ds_")?.is_empty()
            && ids(&s.payload, "retained_statement_ids", "ds_")?.is_empty()
            && s.parents()?.is_empty()
            && text(s.issuer()?, "kind")? == "root"
            && text(s.issuer()?, "person_public_key")? == "-"
            && text(s.subject()?, "host_public_key")? == host
            && text(s.subject()?, "person_public_key")? == "-"
            && text(s.subject()?, "device_public_key")? == "-"
            && num(s.subject()?, "scopes")? == 0
            && text(s.subject()?, "member")? == text(own, "member")?
            && s.signer("host")?.public_key == host
            && s.signer("host")?.format == "ed25519"
            && s.signer("issuer")?.public_key
                == text(&p.proposal.payload, "legacy_root_public_key")?
            && s.signer("issuer")?.signature != "-",
    )?;
    check(!partial || s.signer("host")?.signature == "-")?;
    let proposal = &p.proposal.payload;
    check(
        s.issued_at()? >= text(proposal, "issued_at")?
            && s.issued_at()? <= text(proposal, "expires_at")?,
    )?;
    if let Some(now) = now {
        require(
            now >= s.issued_at()? && now >= text(&s.payload, "not_before")?,
            "not_yet_valid",
        )?;
        require(now < text(&s.payload, "not_after")?, "authority_expired")?;
        require(now < text(proposal, "expires_at")?, "expired")?;
    }
    Ok(t)
}
fn find(c: &Connection, network: &str, proposal: &str, host: &str) -> Result<Option<Intent>> {
    let mut q=c.prepare("SELECT intent_id FROM dec_intents WHERE network_id=?1 AND kind='migration' ORDER BY intent_id").map_err(db)?;
    let rows = q
        .query_map([network], |r| r.get::<_, String>(0))
        .map_err(db)?;
    let mut found = None;
    for row in rows {
        let i = Intent::load(c, &row.map_err(db)?)?;
        if i.record.operation_id != proposal
            || i.record.provider.kind != "host"
            || i.record.host_public_key != host
            || i.record
                .templates
                .first()
                .is_none_or(|t| t.object_type != "host_lease")
        {
            continue;
        }
        require(found.is_none(), "state_conflict")?;
        found = Some(i);
    }
    Ok(found)
}
fn validated(
    d: &Descriptor,
    p: &Prefix,
    own: &Obj,
    host: &str,
    i: &Intent,
) -> Result<FixedStatement> {
    i.shape()?;
    let r = &i.record;
    check(
        i.kind == "migration"
            && i.network_id == d.network_id
            && i.context_id == d.context_id()
            && r.operation_id == p.proposal.id
            && r.provider.kind == "host"
            && r.host_public_key == host
            && r.provider.signer_public_key == host
            && r.provider.signature_format == "ed25519"
            && r.provider.lease_id == "-"
            && r.person_public_key == "-"
            && r.device_public_key == "-"
            && r.scopes == 0
            && r.templates.len() == 1
            && r.templates[0].object_type == "host_lease"
            && r.terminal == "-"
            && r.result_base64 == "-"
            && i.secret.is_none()
            && r.approved,
    )?;
    let original = b64(&r.templates[0].template_base64, MAX_OBJECT)?;
    let original = check_template(d, p, own, host, &original, true, None)?;
    let assembled = i.assembled(d)?;
    let t = assembled
        .into_iter()
        .next()
        .ok_or_else(|| Error::new("state_conflict"))?;
    check_template(d, p, own, host, t.bytes(), false, None)?;
    let mut saved = object(&parse(&b64(&r.review_base64, MAX_OBJECT)?, MAX_OBJECT)?)?.clone();
    let mut expected = object(&host_review(
        &d.network_id,
        &p.proposal.id,
        original.typed(),
    )?)?
    .clone();
    fields(
        &saved,
        "stage network_id proposal_id host_public_key member root_state_id host_lease_id issued_at not_before not_after authority_warning",
    )?;
    let warning = text(&saved, "authority_warning")?;
    check(!warning.is_empty() && warning.len() <= 1024)?;
    saved.remove("authority_warning");
    expected.remove("authority_warning");
    check(
        r.completed == t.pending().is_empty()
            && r.root_state_id == text(&t.typed().payload, "root_state_id")?
            && r.not_after == text(&t.typed().payload, "not_after")?
            && r.expires_at == text(&p.proposal.payload, "expires_at")?
            && saved == expected,
    )?;
    Ok(t)
}
fn catalog_with(d: &Descriptor, p: &Prefix, t: &FixedStatement, budget: bool) -> Result<Vec<u8>> {
    let mut proofs = p
        .catalog
        .as_ref()
        .ok_or_else(|| Error::missing(&p.proposal.id))?
        .proofs
        .clone();
    let body = if budget {
        t.budget_bytes()?
    } else {
        t.bytes().to_vec()
    };
    let id = proof_id("host_lease", &body);
    proofs.insert(
        id.clone(),
        super::catalog::Proof {
            id,
            kind: "host_lease".into(),
            body,
        },
    );
    let raw = actions::bytes(
        &json!({"format":1,"context_id":d.context_id(),"objects":proofs.values().map(|p|json!({"id":p.id,"kind":p.kind,"body_base64":encode(&p.body)})).collect::<Vec<_>>()}),
    )?;
    require(raw.len() <= MAX_OBJECT, "quota_exceeded")?;
    if !budget {
        Catalog::read_prepared(d, &raw)?;
    }
    Ok(raw)
}
fn wrapper(
    d: &Descriptor,
    p: &Prefix,
    r: &MigrationRecord,
    t: &FixedStatement,
    review: Option<Value>,
) -> Result<Vec<u8>> {
    actions::bytes(
        &json!({"migration":p.view(d,r)?,"host_lease_base64":encode(t.bytes()),"review":review.unwrap_or(host_review(&d.network_id,&p.proposal.id,t.typed())?),"signing_requests":[]}),
    )
}
pub(crate) fn prepare(store: &Store, network: &str, input: &Obj) -> Result<Vec<u8>> {
    fields(input, "proposal_id host_lease_base64 approve")?;
    let proposal = text(input, "proposal_id")?;
    let raw = b64(text(input, "host_lease_base64")?, MAX_OBJECT)?;
    let approve = input
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("invalid"))?;
    let host = store.identity().public_key;
    let approved = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        if let Some(i) = find(&tx, network, proposal, &host)? {
            require(
                b64(&i.record.templates[0].template_base64, MAX_OBJECT)? == raw,
                "operation_conflict",
            )?;
            let (_, r) = migration_prepare::load(&tx, network)?
                .ok_or_else(|| Error::new("state_conflict"))?;
            let d = super::migration_evidence::descriptor(&r)?;
            let p = Prefix::read(&d, &r)?;
            let own = object(
                array(&p.proposal.payload, "roster")?
                    .iter()
                    .find(|r| r.get("host_public_key").and_then(Value::as_str) == Some(&host))
                    .ok_or_else(|| Error::new("forbidden"))?,
            )?;
            let t = validated(&d, &p, own, &host, &i)?;
            if t.pending().is_empty() || !approve {
                return wrapper(
                    &d,
                    &p,
                    &r,
                    &t,
                    Some(parse(
                        &b64(&i.record.review_base64, MAX_OBJECT)?,
                        MAX_OBJECT,
                    )?),
                );
            }
            false
        } else {
            let context = Context::load(store, &tx, network, proposal)?;
            let d = &context.source.descriptor;
            let t = check_template(
                d,
                &context.prefix,
                &context.own,
                &host,
                &raw,
                true,
                Some(&context.source.time),
            )?;
            let mut candidate = context.record.clone();
            candidate.prepared_catalog_base64 =
                encode(&catalog_with(d, &context.prefix, &t, true)?);
            Prefix::complete_body(&candidate)?;
            if !approve {
                return wrapper(d, &context.prefix, &context.record, &t, None);
            }
            let total: i64 = tx
                .query_row("SELECT COUNT(*) FROM dec_intents", [], |r| r.get(0))
                .map_err(db)?;
            let open:i64=tx.query_row("SELECT COUNT(*) FROM dec_intents WHERE json_extract(record,'$.terminal')='-' AND json_extract(record,'$.completed')=0",[],|r|r.get(0)).map_err(db)?;
            require(total < 4096 && open < 64, "quota_exceeded")?;
            let now = creation::decision(&tx, network, &controls::local_decision_time()?)?;
            decision_clock(&now, &context.source.time)?;
            check_template(
                d,
                &context.prefix,
                &context.own,
                &host,
                &raw,
                true,
                Some(&now),
            )?;
            let review = host_review(network, proposal, t.typed())?;
            let i = Intent {
                id: crate::store::new_id("dint").map_err(|_| Error::new("internal"))?,
                network_id: network.into(),
                context_id: d.context_id(),
                kind: "migration".into(),
                secret: None,
                record: Record {
                    format: 1,
                    operation_id: proposal.into(),
                    approved: true,
                    approved_at: now.clone(),
                    review_base64: encode(&actions::bytes(&review)?),
                    provider: Provider {
                        kind: "host".into(),
                        signer_public_key: host.clone(),
                        signature_format: "ed25519".into(),
                        lease_id: "-".into(),
                    },
                    root_state_id: text(&t.typed().payload, "root_state_id")?.into(),
                    person_public_key: "-".into(),
                    host_public_key: host.clone(),
                    device_public_key: "-".into(),
                    scopes: 0,
                    not_after: text(&t.typed().payload, "not_after")?.into(),
                    created_at: now.clone(),
                    expires_at: text(&context.prefix.proposal.payload, "expires_at")?.into(),
                    templates: vec![Template {
                        slot_id: 1,
                        object_type: "host_lease".into(),
                        template_base64: encode(&raw),
                    }],
                    signatures: vec![],
                    completed: false,
                    terminal: "-".into(),
                    result_base64: "-".into(),
                },
            };
            validated(d, &context.prefix, &context.own, &host, &i)?;
            i.save(&tx)?;
            creation::remember_clock(&tx, network, &now)?;
            tx.commit().map_err(db)?;
            true
        }
    };
    if approved {
        controls::barrier(store, "dec.intent.after_commit", proposal)?;
        controls::barrier(store, "dec.approval.after_commit", proposal)?;
    }
    sign(store, network, proposal)?;
    result(store, network, proposal)
}
fn sign(store: &Store, network: &str, proposal: &str) -> Result<()> {
    let host = store.identity().public_key;
    let changed = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let mut i = find(&tx, network, proposal, &host)?.ok_or_else(|| Error::new("not_found"))?;
        if i.record.completed {
            return Ok(());
        }
        let mut context = Context::load(store, &tx, network, proposal)?;
        require(
            context.record.acknowledgments_base64.is_empty()
                && context.record.commit_base64 == "-"
                && context.record.migration_base64 == "-",
            "operation_conflict",
        )?;
        let d = &context.source.descriptor;
        let t = validated(d, &context.prefix, &context.own, &host, &i)?;
        let now = creation::decision(&tx, network, &controls::local_decision_time()?)?;
        decision_clock(&now, &context.source.time)?;
        require(now >= i.record.created_at, "clock_rollback")?;
        check_template(
            d,
            &context.prefix,
            &context.own,
            &host,
            t.bytes(),
            true,
            Some(&now),
        )?;
        let slots = t.pending();
        check(
            slots.len() == 1
                && slots[0].role == "host"
                && slots[0].public_key == host
                && slots[0].signature_format == "ed25519",
        )?;
        let signature = encode(
            &store
                .signing_key
                .sign(&b64(&slots[0].message_base64, 4096)?)
                .to_bytes(),
        );
        let filled = t.fill(d, "host", &signature)?;
        Statement::read(d, filled.bytes())?;
        context.record.prepared_catalog_base64 =
            encode(&catalog_with(d, &context.prefix, &filled, false)?);
        Prefix::complete_body(&context.record)?;
        Prefix::read(d, &context.record)?;
        i.record.signatures.push(Filled {
            slot_id: 1,
            role: "host".into(),
            signature,
        });
        i.record.completed = true;
        validated(d, &context.prefix, &context.own, &host, &i)?;
        i.save(&tx)?;
        migration_prepare::save(&tx, network, proposal, &context.record)?;
        creation::remember_clock(&tx, network, &now)?;
        tx.commit().map_err(db)?;
        true
    };
    if changed {
        controls::barrier(store, "dec.signature.after_commit", proposal)?;
    }
    Ok(())
}
fn result(store: &Store, network: &str, proposal: &str) -> Result<Vec<u8>> {
    let c = store.connection().map_err(|_| Error::new("internal"))?;
    let host = store.identity().public_key;
    let i = find(&c, network, proposal, &host)?.ok_or_else(|| Error::new("not_found"))?;
    let (_, r) =
        migration_prepare::load(&c, network)?.ok_or_else(|| Error::new("state_conflict"))?;
    let d = super::migration_evidence::descriptor(&r)?;
    let p = Prefix::read(&d, &r)?;
    let own = object(
        array(&p.proposal.payload, "roster")?
            .iter()
            .find(|r| r.get("host_public_key").and_then(Value::as_str) == Some(&host))
            .ok_or_else(|| Error::new("forbidden"))?,
    )?;
    let t = validated(&d, &p, own, &host, &i)?;
    wrapper(
        &d,
        &p,
        &r,
        &t,
        Some(parse(
            &b64(&i.record.review_base64, MAX_OBJECT)?,
            MAX_OBJECT,
        )?),
    )
}
pub(super) fn resume(store: &Store, network: &str) -> Result<()> {
    let proposal = {
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        let Some((p, _)) = migration_prepare::load(&c, network)? else {
            return Ok(());
        };
        let Some(i) = find(&c, network, &p, &store.identity().public_key)? else {
            return Ok(());
        };
        if i.record.completed {
            return Ok(());
        }
        p
    };
    sign(store, network, &proposal)
}
