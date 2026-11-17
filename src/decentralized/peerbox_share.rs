//! A home host signing its owner's next policy version with a peerbox rule
//! change by itself, through the owner's selected provider, as automatic
//! renewal signs (peerbox contract, Invitations for new participants 4).
//! A provider that needs the owner's interaction leaves the change to
//! `peerbox share --pending`.
//!
//! An approved agent proposal to share a peerbox (peerbox contract, Agent
//! proposals, Execution) signs the same way, or with the OpenSSH person key
//! the person named at `approve`, which is read for that signing only.
use super::{actions, codec::*, controls, edits, provider::Resolved, renewal, storage::Snapshot};
use crate::{persons::PersonSigner, policy::PeerboxRule, store::Store};
use serde_json::{Value, json};

/// An adjustment of the next policy body's raw JSON, given the stored
/// body's raw JSON (none for a first policy).
pub(crate) type Adjust<'a> = &'a dyn Fn(&mut Value, Option<&Value>);

/// What signing a peerbox rule change came to.
pub(crate) enum Signing {
    /// A new policy version holds the change.
    Done,
    /// The current policy already holds it: nothing was signed.
    Unchanged,
    /// The provider needs the owner's interaction (an SSH person key, for
    /// example): nothing was signed.
    NeedsOwner,
}

/// Who signs a proposal's share: the network's provider for the owner,
/// or the person key the person gave.
pub(crate) enum ProposalSigner {
    Provider,
    Key(Box<PersonSigner>),
}
/// What signing an approved share proposal came to.
pub(crate) enum ProposalSigning {
    /// The policy version signed.
    Signed(u64),
    /// Nothing changed: the current version.
    Unchanged(u64),
    /// Signing needs the person's interaction.
    NeedsOwner,
    /// The rules the signature builds on differ from the reviewed ones.
    Changed,
}

fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}

/// How the core signs: automatically for a pending share, with the
/// provider for a proposal (an SSH provider when the daemon holds its
/// key), or with a key file.
enum How<'a> {
    Automatic,
    Provider,
    Key(&'a PersonSigner),
}

enum Core {
    Done(u64),
    Unchanged(u64),
    NeedsOwner,
    Changed,
}

/// Signs the next policy version of this host's owner in `network` with
/// `change` applied to the peerbox rules, as a new local edit. `change`
/// gets this host's ID.
pub(crate) fn sign_peerbox_rules(
    store: &Store,
    network: &str,
    change: impl FnOnce(&str, &mut Vec<PeerboxRule>),
) -> Result<Signing> {
    Ok(
        match core(
            store,
            network,
            How::Automatic,
            &|_| true,
            None,
            None,
            |host, content| change(host, &mut content.peerbox_rules),
        )? {
            Core::Done(_) => Signing::Done,
            Core::Unchanged(_) | Core::Changed => Signing::Unchanged,
            Core::NeedsOwner => Signing::NeedsOwner,
        },
    )
}

/// What signing an agent-access change of an invitation grant came to
/// (guided session contract section55).
pub(crate) enum ContentSigning {
    /// The policy version signed.
    Signed(u64),
    /// The current version already holds it.
    Unchanged(u64),
    /// The provider needs the owner's interaction.
    NeedsOwner,
}

/// Signs the next policy version of this host's owner in `network` with
/// `change` applied to its content: automatically (a provider this host
/// holds the seed of) or, when `explicit`, also through the daemon's
/// ssh-agent or owner key file, as an owner's explicit press may.
pub(crate) fn sign_content(
    store: &Store,
    network: &str,
    explicit: bool,
    adjust: Option<Adjust<'_>>,
    participant: Option<&str>,
    change: impl FnOnce(&str, &mut crate::policy::Content),
) -> Result<ContentSigning> {
    let how = if explicit {
        How::Provider
    } else {
        How::Automatic
    };
    Ok(
        match core(store, network, how, &|_| true, adjust, participant, change)? {
            Core::Done(v) => ContentSigning::Signed(v),
            Core::Unchanged(v) => ContentSigning::Unchanged(v),
            Core::Changed => ContentSigning::Unchanged(0),
            Core::NeedsOwner => ContentSigning::NeedsOwner,
        },
    )
}

/// Whether the network's provider for the owner signs a policy version on
/// this host without the person's interaction (`approve` without
/// `--person-key`).
pub(crate) fn provider_signs(store: &Store, network: &str) -> Result<bool> {
    let resolved = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
        let p = s.project(&controls::local_decision_time()?)?;
        provider(store, &tx, &s, &p, &How::Provider)?
    };
    let Some(provider) = resolved else {
        return Ok(false);
    };
    Ok(usable(store, &provider, &How::Provider))
}

/// Signs an approved share proposal: `reviewed` gets the peerbox rules the
/// signature builds on and says whether they are still the reviewed ones;
/// then `change` is applied as for [`sign_peerbox_rules`].
pub(crate) fn sign_proposal_share(
    store: &Store,
    network: &str,
    signer: &ProposalSigner,
    reviewed: &dyn Fn(&[PeerboxRule]) -> bool,
    change: impl FnOnce(&str, &mut Vec<PeerboxRule>),
) -> Result<ProposalSigning> {
    let how = match signer {
        ProposalSigner::Provider => How::Provider,
        ProposalSigner::Key(key) => How::Key(key),
    };
    Ok(
        match core(
            store,
            network,
            how,
            reviewed,
            None,
            None,
            |host, content| change(host, &mut content.peerbox_rules),
        )? {
            Core::Done(v) => ProposalSigning::Signed(v),
            Core::Unchanged(v) => ProposalSigning::Unchanged(v),
            Core::NeedsOwner => ProposalSigning::NeedsOwner,
            Core::Changed => ProposalSigning::Changed,
        },
    )
}

/// The provider `how` signs with, or None when it needs the owner.
fn provider(
    store: &Store,
    tx: &rusqlite::Transaction<'_>,
    s: &Snapshot,
    p: &super::state::Projection,
    how: &How<'_>,
) -> Result<Option<Resolved>> {
    let (requested, format) = match how {
        How::Key(key) => (key.public_key_b64(), "sshsig"),
        _ => ("auto".to_owned(), "auto"),
    };
    // No usable selected provider is the owner's to repair: no
    // selection, one without policy scope, or no signer here.
    let provider = match Resolved::resolve(tx, s, p, &requested, format, "policy") {
        Ok(provider) => provider,
        Err(e)
            if matches!(how, How::Automatic | How::Provider)
                && matches!(e.code, "signer_unavailable" | "not_found" | "forbidden") =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    if provider.provider.kind == "root" {
        return Ok(None);
    }
    // Only a key this host holds signs without the owner: an SSH person
    // key (`sshsig`, no seed here) needs the owner's interaction
    // (Invitations for new participants 4). For a proposal, an SSH key the
    // daemon reaches (its ssh-agent or owner key file) signs as well.
    if matches!(how, How::Automatic)
        && (provider.provider.signature_format != "ed25519" || provider.seed.is_none())
    {
        return Ok(None);
    }
    let public = provider.public(p, &store.identity().public_key, false)?;
    if num(object(&public)?, "scopes")? & 1 != 1 {
        return Ok(None);
    }
    Ok(Some(provider))
}

/// Whether the resolved provider can sign now without the person. Never
/// called inside a transaction: it may consult an agent or a file.
fn usable(store: &Store, provider: &Resolved, how: &How<'_>) -> bool {
    match how {
        How::Key(_) => true,
        _ if provider.provider.signature_format == "ed25519" => provider.seed.is_some(),
        How::Automatic => false,
        How::Provider => {
            let Ok(key) = b64(&provider.provider.signer_public_key, 32) else {
                return false;
            };
            let Ok(key): std::result::Result<[u8; 32], _> = key.try_into() else {
                return false;
            };
            store.renewal_signer(key).is_ok()
        }
    }
}

fn core(
    store: &Store,
    network: &str,
    how: How<'_>,
    reviewed: &dyn Fn(&[PeerboxRule]) -> bool,
    adjust: Option<Adjust<'_>>,
    participant: Option<&str>,
    change: impl FnOnce(&str, &mut crate::policy::Content),
) -> Result<Core> {
    let host = store.identity().id;
    let (request, provider, version) = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
        let p = s.project(&controls::local_decision_time()?)?;
        let Some(provider) = provider(store, &tx, &s, &p, &how)? else {
            return Ok(Core::NeedsOwner);
        };
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
        let head = renewal::head(&p, &person)?;
        // The stored body's raw JSON, for an adjustment that keeps explicit
        // optional fields the typed body drops.
        let baseline = head
            .map(|s| super::statement::access_body(&s.payload).map(Value::Object))
            .transpose()?;
        let current = head.map(edits::policy).transpose()?;
        let current_version = current.as_ref().map_or(0, |b| b.version);
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
            fs_rules: None,
            trusted_hosts: Some(Vec::new()),
            edits: Some(Vec::new()),
        });
        let mut content = body.content();
        if !reviewed(&content.peerbox_rules) {
            return Ok(Core::Changed);
        }
        let before = content.clone();
        change(&host, &mut content);
        if content == before {
            return Ok(Core::Unchanged(current_version));
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
        let adjust = adjust.map(|f| move |raw: &mut Value| f(raw, baseline.as_ref()));
        let payload = renewal::payload_adjusted(
            &p,
            &provider,
            body,
            adjust.as_ref().map(|f| f as &dyn Fn(&mut Value)),
            participant,
        )?;
        let version = payload
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::new("internal"))?;
        let raw = serde_json::to_vec(&payload).map_err(|_| Error::new("internal"))?;
        let (id, format) = match &how {
            How::Key(_) => (person.clone(), "sshsig"),
            _ => ("auto".to_owned(), "auto"),
        };
        (
            json!({"kind":"policy","provider_id":id,"signature_format":format,"payload_base64":encode(&raw),"approve":true}),
            provider,
            version,
        )
    };
    // The signer may be an agent or a file: never consulted inside a
    // transaction.
    if !usable(store, &provider, &how) {
        return Ok(Core::NeedsOwner);
    }
    let outcome = match actions::prepare(store, network, object(&request)?, false) {
        Ok(outcome) => outcome,
        Err(e) if e.code == "signer_unavailable" && !matches!(how, How::Key(_)) => {
            return Ok(Core::NeedsOwner);
        }
        Err(e) => return Err(e),
    };
    let mut value: Value = parse(&outcome, 32 << 20)?;
    if let (How::Key(key), false) = (
        &how,
        value.get("committed").and_then(Value::as_bool) == Some(true),
    ) {
        // The issuer slot of the person key: signed here with the key the
        // person gave, then stored as the CLI's signatures are.
        let id = text(object(&value)?, "action_id")?.to_owned();
        let slots = array(object(&value)?, "signing_requests")?.to_vec();
        require(!slots.is_empty(), "signer_unavailable")?;
        let mut signatures = Vec::new();
        let mut intent = None;
        for slot in slots.iter() {
            let slot = object(slot)?;
            require(
                text(slot, "role")? == "issuer"
                    && text(slot, "format")? == "sshsig"
                    && text(slot, "public_key")? == key.public_key_b64(),
                "signer_unavailable",
            )?;
            let message = b64(text(slot, "message_base64")?, 4096)?;
            let message = std::str::from_utf8(&message).map_err(|_| Error::new("invalid"))?;
            let signature = key
                .sign(&message.split('\n').collect::<Vec<_>>())
                .map_err(|_| Error::new("signer_unavailable"))?;
            intent = Some(text(slot, "intent_id")?.to_owned());
            signatures.push(json!({"slot_id":1,"role":"issuer","signature":signature}));
        }
        let signed = json!({"intent_id": intent, "signatures": signatures});
        let outcome = actions::signed(store, network, &id, object(&signed)?, false)?;
        value = parse(&outcome, 32 << 20)?;
    }
    require(
        value.get("committed").and_then(Value::as_bool) == Some(true),
        "signer_unavailable",
    )?;
    Ok(Core::Done(version))
}
