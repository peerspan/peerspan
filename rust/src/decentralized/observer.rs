//! Received evidence is private preparation state until exact final consent is
//! complete. A carrier frame or owner selection never adopts network authority.
use super::{
    bootstrap::Invitation,
    catalog::Catalog,
    codec::*,
    controls,
    requests::{self, Pending},
    state::{self, CeremonyPrefix, Projection},
    statement::Descriptor,
    storage::Snapshot,
    transcript::Packet,
};
use crate::store::Store;
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn bytes(value: &impl serde::Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error::new("internal"))
}
pub(crate) struct ObservedPacket {
    pub packet: Packet,
    pub bytes: Vec<u8>,
}
pub(crate) struct Evidence {
    pub packets: BTreeMap<String, ObservedPacket>,
    pub catalogs: BTreeMap<String, Catalog>,
}
pub(crate) struct Offer {
    pub descriptor: Descriptor,
    pub owner: Packet,
    pub owner_bytes: Vec<u8>,
    pub catalog: Option<Catalog>,
    pub provider: Value,
    pub decision_time: String,
    pub staging: Option<Projection>,
}
impl Evidence {
    fn matching(
        &self,
        role: &str,
        pinned: &str,
        fields: &[(&str, &str)],
    ) -> Result<Option<&ObservedPacket>> {
        if pinned != "-" {
            let packet = self
                .packets
                .get(pinned)
                .ok_or_else(|| Error::missing(pinned))?;
            check(
                text(&packet.packet.object, "role")? == role
                    && fields.iter().all(|(field, want)| {
                        packet.packet.payload.get(*field).and_then(Value::as_str) == Some(*want)
                    }),
            )?;
            return Ok(Some(packet));
        }
        let candidates: Vec<_> = self
            .packets
            .values()
            .filter(|p| {
                p.packet.object.get("role").and_then(Value::as_str) == Some(role)
                    && fields.iter().all(|(field, want)| {
                        p.packet.payload.get(*field).and_then(Value::as_str) == Some(*want)
                    })
            })
            .collect();
        require(candidates.len() <= 1, "operation_conflict")?;
        Ok(candidates.first().copied())
    }
    pub fn read(c: &Connection, pending: &Pending, now: &str) -> Result<Self> {
        let mut result = Self {
            packets: BTreeMap::new(),
            catalogs: BTreeMap::new(),
        };
        // A completed packet is durable before its later ciphertext commit.
        // Resume must verify that exact packet without asking the carrier to
        // supply evidence which has deliberately not been published yet.
        for raw in [
            &pending.record.request_packet_base64,
            &pending.record.owner_packet_base64,
            &pending.record.selection_packet_base64,
            &pending.record.administrator_packet_base64,
            &pending.record.owner_finalization_packet_base64,
            &pending.record.commit_packet_base64,
            &pending.record.outcome_packet_base64,
        ] {
            if raw != "-" {
                let bytes = b64(raw, MAX_OBJECT)?;
                let packet = Packet::read(&bytes)?;
                result
                    .packets
                    .insert(packet.id.clone(), ObservedPacket { packet, bytes });
            }
        }
        let Some(secret) = pending.secret else {
            return Ok(result);
        };
        let mut components = Vec::new();
        let mut descriptors = BTreeMap::new();
        if pending.record.descriptor_base64 != "-" {
            let descriptor =
                Descriptor::read(&b64(&pending.record.descriptor_base64, MAX_OBJECT)?)?;
            if pending.record.catalog_base64 != "-" {
                result.catalogs.insert(
                    descriptor.context_id(),
                    Catalog::read(
                        &descriptor,
                        &b64(&pending.record.catalog_base64, MAX_CATALOG)?,
                    )?,
                );
            }
            descriptors.insert(descriptor.context_id(), descriptor);
        }
        for frame in requests::frames(c, pending)? {
            let plain = frame.open(&secret, now)?;
            let plain = object(&plain)?;
            if text(plain, "catalog_base64")? != "-" {
                components.push(b64(text(plain, "catalog_base64")?, 2 << 20)?);
            }
            if text(plain, "packet_base64")? == "-" {
                continue;
            }
            let raw = b64(text(plain, "packet_base64")?, MAX_OBJECT)?;
            let packet = Packet::read(&raw)?;
            if text(&packet.object, "role")? == "request" {
                check(raw == b64(&pending.record.request_packet_base64, 8 << 10)?)?;
            }
            if text(&packet.object, "role")? == "owner" {
                let descriptor = Descriptor::read(&bytes(
                    packet
                        .payload
                        .get("descriptor")
                        .ok_or_else(|| Error::new("invalid"))?,
                )?)?;
                check(descriptor.context_id() == text(&packet.object, "context_id")?)?;
                descriptors.insert(descriptor.context_id(), descriptor);
            }
            if let Some(old) = result.packets.get(&packet.id) {
                require(old.bytes == raw, "operation_conflict")?;
            } else {
                result
                    .packets
                    .insert(packet.id.clone(), ObservedPacket { packet, bytes: raw });
            }
        }
        // A proof component belongs to its own descriptor context. Never use
        // the first offer's context as an implicit choice for another offer.
        for raw in components {
            let value = parse(&raw, 2 << 20)?;
            let context = text(object(&value)?, "context_id")?;
            let Some(descriptor) = descriptors.get(context) else {
                continue;
            };
            let candidate = Catalog::read(descriptor, &raw)?;
            let candidate = if let Some(old) = result.catalogs.get(context) {
                Catalog::union(descriptor, old, &candidate)?
            } else {
                candidate
            };
            result.catalogs.insert(context.into(), candidate);
        }
        Ok(result)
    }
    pub fn offer(
        &self,
        c: &Connection,
        store: &Store,
        p: &Pending,
        id: &str,
        now: &str,
    ) -> Result<Offer> {
        let observed = self.packets.get(id).ok_or_else(|| Error::missing(id))?;
        let owner = &observed.packet;
        check(text(&owner.object, "role")? == "owner")?;
        let request = p.packet()?;
        let o = &owner.payload;
        let descriptor = Descriptor::read(&bytes(
            o.get("descriptor").ok_or_else(|| Error::new("invalid"))?,
        )?)?;
        let context = descriptor.context_id();
        let person = text(&owner.object, "person_public_key")?;
        check(
            text(o, "request_packet_id")? == request.id
                && text(&owner.object, "request_id")? == p.id
                && text(&owner.object, "context_id")? == context
                && text(o, "mode")? == p.record.mode
                && text(o, "host_public_key")? == p.record.host_public_key
                && text(o, "device_public_key")? == p.record.device_public_key
                && text(o, "renewed_device_lease_id")?
                    == text(&request.payload, "renewed_device_lease_id")?
                && (p.record.expected_network_id == "-"
                    || p.record.expected_network_id == descriptor.network_id)
                && (p.record.expected_context_id == "-" || p.record.expected_context_id == context)
                && (p.record.expected_person_public_key == "-"
                    || p.record.expected_person_public_key == person),
        )?;
        if p.record.selection_approved {
            check(p.record.owner_offer_id == id)?
        }
        if p.record.contact_invitation_base64 != "-" {
            let invite = Invitation::read(
                &b64(&p.record.contact_invitation_base64, 32 << 10)?,
                text(&request.payload, "created_at")?,
            )?;
            check(
                invite.descriptor.context_id() == context
                    && invite.member == text(o, "member")?
                    && (invite.expected_person_public_key == "-"
                        || invite.expected_person_public_key == person),
            )?;
        }
        if p.record.migration_proposal_id != "-" {
            let catalog = self
                .catalogs
                .get(&context)
                .ok_or_else(|| Error::missing(&p.record.migration_proposal_id))?;
            let staged = super::migration_link::observed_owner(store, c, p, owner, catalog)?;
            check(staged.descriptor.context_id() == context)?;
            require(
                text(o, "not_after")? > staged.time.as_str(),
                "authority_expired",
            )?;
            return Ok(Offer {
                descriptor,
                owner: owner.clone(),
                owner_bytes: observed.bytes.clone(),
                catalog: Some(staged.catalog),
                provider: staged.provider,
                decision_time: staged.time,
                staging: Some(staged.staging),
            });
        }
        let present: bool = c
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
                [&descriptor.network_id],
                |r| r.get(0),
            )
            .map_err(db)?;
        let snapshot = if present {
            Some(Snapshot::load(
                c,
                &descriptor.network_id,
                &store.identity().public_key,
            )?)
        } else {
            None
        };
        if let Some(snapshot) = &snapshot {
            check(snapshot.descriptor.context_id() == context)?
        }
        let catalog = self.catalogs.get(&context);
        let (provider, catalog, decision_time) = if text(o, "root_state_id")? == "-" {
            // This exception proves possession only, under the exact reviewed
            // invitation. It has no current membership/root/provider power.
            check(
                p.record.mode == "new"
                    && p.record.expected_person_public_key == person
                    && text(o, "person_lease_id")? == "-"
                    && text(&owner.object, "issuer_id")? == "-"
                    && text(&owner.object, "signer_public_key")? == person
                    && ids(o, "issuer_lease_ids", "ds_")?.is_empty(),
            )?;
            if p.record.roles.iter().any(|role| role == "requester") {
                check(p.record.contact_invitation_base64 != "-")?;
            } else {
                check(
                    snapshot.is_some()
                        && p.record.expected_context_id == context
                        && p.record.expected_network_id == descriptor.network_id,
                )?;
            }
            if let Some(snapshot) = &snapshot {
                require(
                    !snapshot
                        .prior
                        .maxima
                        .contains_key(&vec!["person".to_owned(), person.to_owned()]),
                    "forbidden",
                )?;
            }
            let guard = snapshot
                .as_ref()
                .map(|s| s.prior.clock_guard.as_str())
                .unwrap_or("-");
            (
                json!({"kind":"original_person","person_public_key":person,"host_public_key":text(&owner.object,"writer_host_public_key")?,"device_public_key":"-","lease_id":"-","root_state_id":"-","scopes":0,"not_after":"-"}),
                catalog.cloned(),
                decision_clock(now, guard)?,
            )
        } else {
            let catalog =
                catalog.ok_or_else(|| Error::missing(text(o, "root_state_id").unwrap_or("-")))?;
            let prior = snapshot
                .as_ref()
                .map(|s| s.prior.value.clone())
                .unwrap_or(Value::from("-"));
            let path =
                Projection::prepare_owner_offer(&descriptor, &prior, &catalog.bytes, owner, now)?;
            (path.provider, Some(path.catalog), path.decision_time)
        };
        require(
            stamp(text(o, "not_after")?)? > stamp(&decision_time)?,
            "authority_expired",
        )?;
        Ok(Offer {
            descriptor,
            owner: owner.clone(),
            owner_bytes: observed.bytes.clone(),
            catalog,
            provider,
            decision_time,
            staging: None,
        })
    }
}
impl Offer {
    pub fn review(&self, p: &Pending, stage: &str) -> Result<Value> {
        let person = text(&self.owner.object, "person_public_key")?;
        let person_id = crate::persons::person_id_of(person).map_err(|_| Error::new("invalid"))?;
        Ok(
            json!({"stage":stage,"network_id":self.descriptor.network_id,"context_id":self.descriptor.context_id(),"person_id":person_id,"person_public_key":person,"host_public_key":p.record.host_public_key,"device_public_key":p.record.device_public_key,"root_state_id":text(&self.owner.payload,"root_state_id")?,"provider":self.provider,"owner_offer_id":self.owner.id,"selection_id":p.record.selection_id,"administrator_offer_id":p.record.administrator_offer_id,"person_lease_id":text(&self.owner.payload,"person_lease_id")?,"host_lease_id":"-","binding_lease_id":"-","device_lease_id":"-","scopes":num(&self.owner.payload,"scopes")?,"not_after":text(&self.owner.payload,"not_after")?,"authority_warning":"Finite authority may remain usable during an unseen revocation until its signed deadline; administrator scope is conditional on the current role."}),
        )
    }
    pub fn remember(&self, p: &mut Pending) -> Result<()> {
        if p.record.selection_approved {
            check(p.record.owner_offer_id == self.owner.id)?
        }
        p.record.descriptor_base64 = encode(&bytes(&self.descriptor)?);
        p.record.owner_packet_base64 = encode(&self.owner_bytes);
        p.record.owner_offer_id = self.owner.id.clone();
        p.record.catalog_base64 = self
            .catalog
            .as_ref()
            .map(|c| encode(&c.bytes))
            .unwrap_or_else(|| "-".into());
        Ok(())
    }
}
pub(crate) fn observe(store: &Store, id: &str) -> Result<()> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let mut p = requests::load(&tx, id)?;
    if p.record.terminal != "-" {
        return Ok(());
    }
    let now = controls::local_decision_time()?;
    if stamp(&now)? >= stamp(&p.deadline)? {
        return Ok(());
    }
    let evidence = Evidence::read(&tx, &p, &now)?;
    let previous_owner = p.record.owner_offer_id.clone();
    let chosen = if p.record.owner_offer_id != "-" {
        Some(evidence.offer(&tx, store, &p, &p.record.owner_offer_id, &now)?)
    } else {
        let mut offers = Vec::new();
        for observed in evidence
            .packets
            .values()
            .filter(|o| o.packet.object.get("role").and_then(Value::as_str) == Some("owner"))
        {
            if let Ok(offer) = evidence.offer(&tx, store, &p, &observed.packet.id, &now) {
                offers.push(offer)
            }
        }
        // Ambiguous offers are retained independently. Their IDs can be
        // selected explicitly; no hash or arrival-order winner grants consent.
        if offers.len() == 1 {
            Some(offers.remove(0))
        } else {
            None
        }
    };
    let mut barriers = Vec::new();
    if let Some(offer) = chosen {
        offer.remember(&mut p)?;
        if previous_owner == "-" {
            barriers.push("dec.owner.after_commit")
        }
        advance_prefix(&tx, store, &mut p, &evidence, &offer, &now, &mut barriers)?;
    }
    requests::save(&tx, &p)?;
    tx.commit().map_err(db)?;
    drop(c);
    for barrier in barriers {
        controls::barrier(store, barrier, id)?
    }
    Ok(())
}

fn advance_prefix(
    c: &Connection,
    store: &Store,
    p: &mut Pending,
    evidence: &Evidence,
    offer: &Offer,
    now: &str,
    barriers: &mut Vec<&'static str>,
) -> Result<()> {
    let Some(selection) = evidence.matching(
        "selection",
        &p.record.selection_id,
        &[("owner_offer_id", offer.owner.id.as_str())],
    )?
    else {
        return Ok(());
    };
    state::check_requester_selection(
        &p.packet()?,
        &offer.owner,
        &selection.packet,
        &offer.descriptor,
    )?;
    // A received valid signature is not an owner-local consent event. Only
    // other participants may cache the requester's already-signed selection.
    if p.record.roles.iter().any(|r| r == "requester") {
        if !p.record.selection_approved || p.record.selection_packet_base64 == "-" {
            return Ok(());
        }
        check(b64(&p.record.selection_packet_base64, MAX_OBJECT)? == selection.bytes)?;
    }
    p.record.selection_packet_base64 = encode(&selection.bytes);
    p.record.selection_id = selection.packet.id.clone();
    let administrator = evidence.matching(
        "administrator",
        &p.record.administrator_offer_id,
        &[
            ("owner_offer_id", offer.owner.id.as_str()),
            ("selection_id", selection.packet.id.as_str()),
        ],
    )?;
    // A folded admin stage (spec 8.2, DEC-S7, DEC-Q4): the owner's
    // finalization names no administrator packet.
    let folded_finalization = if administrator.is_none() && p.record.mode != "renew" {
        let folded = evidence.matching(
            "owner_finalization",
            &p.record.owner_finalization_id,
            &[
                ("selection_id", selection.packet.id.as_str()),
                ("administrator_offer_id", "-"),
            ],
        )?;
        if folded.is_none() {
            return Ok(());
        }
        folded
    } else {
        None
    };
    let Some(catalog) = &offer.catalog else {
        return Err(Error::missing(text(
            &administrator
                .ok_or_else(|| Error::new("proof_required"))?
                .packet
                .payload,
            "root_state_id",
        )?));
    };
    let present: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
            [&offer.descriptor.network_id],
            |r| r.get(0),
        )
        .map_err(db)?;
    let prior = if present && offer.staging.is_none() {
        Snapshot::load(
            c,
            &offer.descriptor.network_id,
            &store.identity().public_key,
        )?
        .prior
        .value
    } else {
        Value::from("-")
    };
    let request = p.packet()?;
    let folded = match folded_finalization {
        Some(f) => state::folded_host(catalog, &request, None, &f.packet)?,
        None => None,
    };
    let prefix = CeremonyPrefix {
        descriptor: &offer.descriptor,
        prior: &prior,
        catalog,
        request: &request,
        owner: &offer.owner,
        selection: &selection.packet,
        administrator: administrator.map(|a| &a.packet),
        now,
        staging: offer.staging.as_ref(),
        folded_host: folded.as_ref(),
    };
    let admissions = Projection::prepare_administrator(prefix)?;
    if let Some(administrator) = administrator {
        if p.record.administrator_offer_id == "-" {
            barriers.push("dec.administrator.after_commit")
        }
        p.record.administrator_packet_base64 = encode(&administrator.bytes);
        p.record.administrator_offer_id = administrator.packet.id.clone();
    }
    p.record.catalog_base64 = encode(&admissions.catalog.bytes);
    let Some(finalization) = evidence.matching(
        "owner_finalization",
        &p.record.owner_finalization_id,
        &[
            ("selection_id", selection.packet.id.as_str()),
            (
                "administrator_offer_id",
                p.record.administrator_offer_id.as_str(),
            ),
        ],
    )?
    else {
        return Ok(());
    };
    let prepared = Projection::prepare_finalization(prefix, &finalization.packet)?;
    if p.record.owner_finalization_id == "-" {
        barriers.push("dec.owner_finalization.after_commit")
    }
    p.record.owner_finalization_packet_base64 = encode(&finalization.bytes);
    p.record.owner_finalization_id = finalization.packet.id.clone();
    p.record.catalog_base64 = encode(&prepared.admissions.catalog.bytes);
    // These are exact pending components, not a cached usable provider. Their
    // concrete root and guarded time are checked again at final requester work.
    check(
        prepared.admissions.root == text(&finalization.packet.payload, "root_state_id")?
            && stamp(&prepared.admissions.decision_time)? < stamp(&p.deadline)?,
    )?;
    if p.record.migration_proposal_id != "-"
        && let Some(commit) = evidence.matching("commit", "-", &[])?
    {
        if p.record.roles.iter().any(|r| r == "requester") {
            require(
                p.record.commit_approved && p.record.commit_packet_base64 != "-",
                "review_required",
            )?;
            check(b64(&p.record.commit_packet_base64, MAX_OBJECT)? == commit.bytes)?;
        }
        let raw = super::requester::activation_bytes(p, &commit.bytes)?;
        let activation = super::transcript::Activation::read(&offer.descriptor, &raw)?;
        let proof = super::statement::proof_id("activation", &raw);
        let addition = Catalog::read(
            &offer.descriptor,
            &bytes(
                &json!({"format":1,"context_id":offer.descriptor.context_id(),"objects":[{"id":proof,"kind":"activation","body_base64":encode(&raw)}]}),
            )?,
        )?;
        let full = Catalog::union(&offer.descriptor, catalog, &addition)?;
        let checked = offer
            .staging
            .as_ref()
            .ok_or_else(|| Error::new("forbidden"))?
            .migration_owner_prefix(&full.bytes, &offer.owner, now)?;
        checked.activation_response(&p.id, &Value::from("-"))?;
        p.record.commit_packet_base64 = encode(&commit.bytes);
        p.record.activation_id = activation.id;
        p.record.manifest_id = activation.manifest_id;
        p.record.catalog_base64 = encode(&full.bytes);
        super::migration_link::retain_prepared(store, c, p)?;
    }
    Ok(())
}

pub(crate) fn owned_device(
    store: &Store,
    c: &Connection,
    p: &Pending,
) -> Result<ed25519_dalek::SigningKey> {
    if p.record.migration_proposal_id != "-" {
        let staged = super::migration_link::Owned::load(
            store,
            c,
            &p.record.expected_network_id,
            &p.record.migration_proposal_id,
        )?;
        staged.matches(p)?;
        return Ok(staged.device);
    }
    let seed: Option<Vec<u8>> = c
        .query_row(
            "SELECT seed FROM link_device_keys WHERE public_key=?1",
            [&p.record.device_public_key],
            |r| r.get(0),
        )
        .optional()
        .map_err(db)?;
    let seed: [u8; 32] = seed
        .ok_or_else(|| Error::new("signer_unavailable"))?
        .try_into()
        .map_err(|_| Error::new("signer_unavailable"))?;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    require(
        encode(key.verifying_key().as_bytes()) == p.record.device_public_key,
        "signer_unavailable",
    )?;
    Ok(key)
}
