//! A home host signing its owner's next policy version with a peerbox rule
//! change by itself, through the owner's selected provider, as automatic
//! renewal signs (peerbox contract, Invitations for new participants 4).
//! A provider that needs the owner's interaction leaves the change to
//! `peerbox share --pending`.
use super::{actions, codec::*, controls, edits, provider::Resolved, renewal, storage::Snapshot};
use crate::{policy::PeerboxRule, store::Store};
use serde_json::{Value, json};

/// What signing a peerbox rule change came to.
pub(crate) enum Signed {
    /// A new policy version holds the change.
    Signed,
    /// The current policy already holds it: nothing was signed.
    Unchanged,
    /// The provider needs the owner's interaction (an SSH person key, for
    /// example): nothing was signed.
    NeedsOwner,
}

fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}

/// Signs the next policy version of this host's owner in `network` with
/// `change` applied to the peerbox rules, as a new local edit. `change`
/// gets this host's ID.
pub(crate) fn sign_peerbox_rules(
    store: &Store,
    network: &str,
    change: impl FnOnce(&str, &mut Vec<PeerboxRule>),
) -> Result<Signed> {
    let host = store.identity().id;
    let (request, provider) = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
        let p = s.project(&controls::local_decision_time()?)?;
        let provider = match Resolved::resolve(&tx, &s, &p, "auto", "auto", "policy") {
            Ok(provider) => provider,
            Err(e) if e.code == "signer_unavailable" => return Ok(Signed::NeedsOwner),
            Err(e) => return Err(e),
        };
        require(provider.provider.kind != "root", "forbidden")?;
        let public = provider.public(&p, &store.identity().public_key, false)?;
        require(num(object(&public)?, "scopes")? & 1 == 1, "forbidden")?;
        let person = text(&provider.actor, "person_public_key")?.to_owned();
        require(
            person == s.network.own_identity.person_public_key,
            "forbidden",
        )?;
        // No edit of this host may be unsettled (spec 12.1).
        let rows = edits::read(&tx, &p, &person)?;
        require(
            !rows.iter().any(|e| e.state == "unsettled"),
            "state_conflict",
        )?;
        let current = renewal::head(&p, &person)?.map(edits::policy).transpose()?;
        let mut body = current.unwrap_or_else(|| crate::policy::PolicyBody {
            format: Some(2),
            network_id: network.into(),
            person_public_key: person.clone(),
            version: 0,
            issued_at: p.decision_time.clone(),
            valid_until: p.decision_time.clone(),
            rules: Vec::new(),
            capability_rules: Some(Vec::new()),
            runtime_rules: None,
            peerbox_rules: None,
            trusted_hosts: Some(Vec::new()),
            edits: Some(Vec::new()),
        });
        let mut content = body.content();
        let before = content.peerbox_rules.clone();
        change(&host, &mut content.peerbox_rules);
        if content.peerbox_rules == before {
            return Ok(Signed::Unchanged);
        }
        // This host's next local edit number (DEC-S16).
        let largest: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(seq),0) FROM policy_edits WHERE network_id=?1 AND person_id=?2",
                rusqlite::params![network, crate::persons::person_id(&b64(&person, 32)?)],
                |r| r.get(0),
            )
            .map_err(db)?;
        let seq = u64::try_from(largest)
            .map_err(|_| Error::new("state_conflict"))?
            .checked_add(1)
            .ok_or_else(|| Error::new("version_exhausted"))?;
        body.set_content(content);
        body.edits = Some(body.edits_with(&host, seq));
        let payload = renewal::payload(&p, &provider, body)?;
        let raw = serde_json::to_vec(&payload).map_err(|_| Error::new("internal"))?;
        (
            json!({"kind":"policy","provider_id":"auto","signature_format":"auto","payload_base64":encode(&raw),"approve":true}),
            provider,
        )
    };
    // The signer may be an agent or a file: never consulted inside a
    // transaction.
    if provider.available(store).is_err() {
        return Ok(Signed::NeedsOwner);
    }
    let outcome = match actions::prepare(store, network, object(&request)?, false) {
        Ok(outcome) => outcome,
        Err(e) if e.code == "signer_unavailable" => return Ok(Signed::NeedsOwner),
        Err(e) => return Err(e),
    };
    let value: Value = parse(&outcome, 32 << 20)?;
    require(
        value.get("committed").and_then(Value::as_bool) == Some(true),
        "signer_unavailable",
    )?;
    Ok(Signed::Signed)
}
