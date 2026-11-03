//! Typed local signer resolution. Public authority and private availability are
//! separate; an explicit choice never changes the persisted owner selection.
use super::{codec::*, intents::Provider, state::Projection, storage::Snapshot};
use crate::store::Store;
use ed25519_dalek::SigningKey;
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};

pub(crate) struct Resolved {
    pub provider: Provider,
    pub concrete_id: String,
    pub actor: Obj,
    pub automatic: bool,
    pub seed: Option<[u8; 32]>,
}
fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn seed(connection: &Connection, query: &str, id: &str, public: &str) -> Result<Option<[u8; 32]>> {
    let value: Option<Vec<u8>> = connection
        .query_row(query, [id], |r| r.get(0))
        .optional()
        .map_err(db)?
        .flatten();
    let Some(raw) = value else { return Ok(None) };
    let seed: [u8; 32] = raw.try_into().map_err(|_| Error::new("state_conflict"))?;
    require(
        encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes()) == public,
        "state_conflict",
    )?;
    Ok(Some(seed))
}
impl Resolved {
    pub fn resolve(
        connection: &Connection,
        snapshot: &Snapshot,
        p: &Projection,
        requested: &str,
        format: &str,
        kind: &str,
    ) -> Result<Self> {
        check(matches!(format, "auto" | "ed25519" | "sshsig"))?;
        let automatic = requested == "auto";
        let selected = if automatic {
            Some(
                snapshot
                    .selection
                    .as_ref()
                    .ok_or_else(|| Error::new("not_found"))?,
            )
        } else {
            None
        };
        let id = selected
            .map(|s| {
                if s.kind == "device" {
                    s.lease_id.as_str()
                } else {
                    s.person_key.as_str()
                }
            })
            .unwrap_or(requested);
        let root = p.catalog.get(p.root_state_id()?)?;
        let host = &snapshot.network.own_identity.host_public_key;
        if id == "network_root" {
            check(!automatic)?;
            let key = text(&root.payload, "root_public_key")?.to_owned();
            let seed = seed(
                connection,
                "SELECT root_seed FROM networks WHERE id=?1",
                &snapshot.descriptor.network_id,
                &key,
            )?;
            let actual = if format == "auto" {
                if seed.is_some() { "ed25519" } else { "sshsig" }
            } else {
                format
            };
            if actual == "ed25519" {
                require(seed.is_some(), "signer_unavailable")?;
            }
            return Ok(Self {provider:Provider{kind:"root".into(),signer_public_key:key,signature_format:actual.into(),lease_id:"-".into()},concrete_id:id.into(),actor:object(&json!({"person_public_key":"-","host_public_key":"-","device_public_key":"-","issuer_id":root.id}))?.clone(),automatic:format=="auto",seed});
        }
        let device = ident(id, "ds_");
        check(device || key(id))?;
        let person = if device {
            text(p.catalog.get(id)?.subject()?, "person_public_key")?
        } else {
            id
        };
        let remembered = &snapshot.network.own_identity.person_public_key;
        require(remembered == "-" || remembered == person, "forbidden")?;
        if let Some(selected) = selected {
            require(selected.person_key == person, "state_conflict")?;
        }
        // An explicit original-person binding may initialize or renew its own
        // binding from the current P/H path. Its exact subject/parents and target host are checked by
        // the ordinary action verifier; it cannot mint a different identity.
        let original_binding = kind == "binding_lease" && !device && !automatic;
        if original_binding {
            p.binding_provider(person, host)?;
        } else {
            p.provider_potential(person, host, device.then_some(id))?;
        }
        if device {
            check(format != "sshsig")?;
            let statement = p.catalog.get(id)?;
            require(
                statement.kind == "device_lease"
                    && text(statement.subject()?, "host_public_key")? == host,
                "forbidden",
            )?;
            let public = text(statement.subject()?, "device_public_key")?.to_owned();
            if let Some(selected) = selected {
                require(selected.device_key == public, "state_conflict")?;
            }
            let seed = seed(
                connection,
                "SELECT seed FROM link_device_keys WHERE public_key=?1",
                &public,
                &public,
            )?;
            require(seed.is_some(), "signer_unavailable")?;
            Ok(Self {provider:Provider{kind:"device".into(),signer_public_key:public.clone(),signature_format:"ed25519".into(),lease_id:id.into()},concrete_id:id.into(),actor:object(&json!({"person_public_key":person,"host_public_key":host,"device_public_key":public,"issuer_id":id}))?.clone(),automatic,seed})
        } else {
            check(format != "ed25519")?;
            Ok(Self {provider:Provider{kind:"original".into(),signer_public_key:person.into(),signature_format:"sshsig".into(),lease_id:"-".into()},concrete_id:person.into(),actor:object(&json!({"person_public_key":person,"host_public_key":"-","device_public_key":"-","issuer_id":"-"}))?.clone(),automatic,seed:None})
        }
    }
    /// May consult a local SSH agent/file. Never call while holding Store's
    /// connection or a transaction. Explicit external SSH slots need no key.
    pub fn available(&self, store: &Store) -> Result<()> {
        if self.provider.signature_format == "ed25519" {
            return require(self.seed.is_some(), "signer_unavailable");
        }
        if self.automatic {
            let key: [u8; 32] = b64(&self.provider.signer_public_key, 32)?
                .try_into()
                .map_err(|_| Error::new("invalid"))?;
            store
                .renewal_signer(key)
                .map_err(|_| Error::new("signer_unavailable"))?;
        }
        Ok(())
    }
    pub fn public(&self, p: &Projection, host: &str, original_binding: bool) -> Result<Value> {
        if self.provider.kind == "root" {
            return Ok(
                json!({"kind":"network_root","person_public_key":"-","host_public_key":"-","device_public_key":"-","lease_id":"-","root_state_id":p.root_state_id()?,"scopes":8,"not_after":"-"}),
            );
        }
        let person = text(&self.actor, "person_public_key")?;
        if original_binding {
            p.binding_provider(person, host)
        } else {
            p.provider_potential(
                person,
                host,
                (self.provider.kind == "device").then_some(self.provider.lease_id.as_str()),
            )
        }
    }
}
