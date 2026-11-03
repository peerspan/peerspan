//! Current partial ceremony validation before requester consent and finalization.
use super::*;

#[derive(Clone)]
pub struct OwnerOfferEvidence {
    pub request_id: String,
    pub request_packet_id: String,
    pub owner_offer_id: String,
    pub network_id: String,
    pub feature_id: String,
    pub person_public_key: String,
    pub host_public_key: String,
    pub device_public_key: String,
    pub certificate_id: String,
    pub issuer_certificate_id: String,
    pub signer_public_key: String,
    pub mode: String,
    pub not_after: String,
    pub scopes: u64,
    pub certificate: Vec<u8>,
    pub binding_draft: Vec<u8>,
    pub binding_authorization_message: Vec<u8>,
    pub membership_proof_id: String,
    pub binding_proof_id: String,
}
pub struct SelectionEvidence {
    pub owner: OwnerOfferEvidence,
    pub selection_id: String,
}
pub struct AdministratorOfferEvidence {
    pub selection: SelectionEvidence,
    pub administrator_offer_id: String,
    pub admission_record_id: String,
    pub administrator_signer_public_key: String,
    pub admission_record: Vec<u8>,
}

fn fresh<'a>(
    ctx: &ActivationContext<'a>,
    catalog: &[u8],
    objects: &[&[u8]],
) -> Result<Verifier<'a>> {
    check(
        ctx.network.len() + objects.iter().map(|b| b.len()).sum::<usize>() <= MAX_ACTIVATION
            && catalog.len() <= MAX_STORED_CATALOG
            && ctx.verification == "first"
            && key(ctx.caller_host_public_key)
            && (ctx.expected_person_public_key == "-" || key(ctx.expected_person_public_key)),
        "invalid",
    )?;
    check(ctx.known_feature_id != "-", "upgrade_required")?;
    let mut v = Verifier::new(ctx.network, ctx.epoch, ctx.known_feature_id, ctx.now)?;
    v.stored_snapshot = true;
    v.catalog(catalog)?;
    let owner = obj(objects.get(1).ok_or_else(|| problem("invalid"))?)?;
    let (offer_raw, _) = p_obj(&owner)?;
    v.index("certificate", &raw_field(&offer_raw, "certificate")?)?;
    v.bootstrap(true)?;
    v.revocations()?;
    Ok(v)
}

fn normalized<T>(r: Result<T>) -> Result<T> {
    r.map_err(|e| {
        if e.downcast_ref::<PathError>().is_some() {
            e
        } else {
            problem("invalid")
        }
    })
}

impl Verifier<'_> {
    fn binding_draft(
        &self,
        raw: &[u8],
        id: &str,
        person: &str,
        cert: &str,
        signer: &str,
        host: &str,
    ) -> Result<Vec<u8>> {
        let o = obj(raw)?;
        fields(
            &o,
            "format kind network_id epoch operation_id person_public_key certificate_id payload_base64 signature host_signature",
            &[],
        )?;
        version(&o, 1)?;
        check(
            s(&o, "kind") == "peerspan-host-bind-v1"
                && s(&o, "network_id") == self.net
                && s(&o, "operation_id") == id
                && s(&o, "person_public_key") == person
                && s(&o, "certificate_id") == cert
                && s(&o, "host_signature") == "-"
                && num(&o, "epoch")? == self.epoch,
            "invalid",
        )?;
        let (b, p) = p_obj(&o)?;
        record_payload("peerspan-host-bind-v1", &p)?;
        check(
            s(&p, "network_id") == self.net
                && s(&p, "person_public_key") == person
                && s(&p, "host_public_key") == host,
            "invalid",
        )?;
        let message = lines(&[
            "peerspan-person-authorization-v1",
            "peerspan-host-bind-v1",
            &self.net,
            &self.epoch.to_string(),
            id,
            person,
            cert,
            &hash(&b),
        ]);
        ssh(signer, &message, text(&o, "signature")?)?;
        Ok(message)
    }

    fn pending_owner(
        &mut self,
        ctx: &ActivationContext<'_>,
        request: &[u8],
        owner: &[u8],
    ) -> Result<OwnerOfferEvidence> {
        let request_object = obj(request)?;
        let id = text(&request_object, "request_id")?.to_owned();
        let (_, request_payload) = p_obj(&request_object)?;
        let (_, req, rid, _) = self.packet(
            request,
            "request",
            &id,
            ctx.caller_host_public_key,
            text(&request_payload, "device_public_key")?,
        )?;
        let host = text(&req, "host_public_key")?.to_owned();
        let device = text(&req, "device_public_key")?.to_owned();
        check(
            host == ctx.caller_host_public_key
                && host != device
                && s(&req, "coordinator_address") == s(&self.network, "coordinator_address")
                && s(&req, "coordinator_public_key") == s(&self.network, "coordinator_public_key"),
            "invalid",
        )?;
        check(
            id == format!(
                "link_{}",
                hash(&lines(&[
                    "peerspan-link-request-id-v1",
                    text(&req, "coordinator_public_key")?,
                    &host,
                    &device,
                    text(&req, "request_nonce")?
                ]))
            ),
            "invalid",
        )?;
        let created = stamp(text(&req, "created_at")?)?;
        let expires = stamp(text(&req, "expires_at")?)?;
        check(
            expires - created == chrono::Duration::seconds(300),
            "invalid",
        )?;
        check(self.ctx.now >= created && self.ctx.now < expires, "expired")?;
        let oo = obj(owner)?;
        let (_, offer) = p_obj(&oo)?;
        let person = text(&offer, "person_public_key")?.to_owned();
        let issuer = text(&oo, "certificate_id")?.to_owned();
        check(
            s(&oo, "person_public_key") == person
                && (ctx.expected_person_public_key == "-"
                    || ctx.expected_person_public_key == person)
                && (s(&req, "expected_network_id") == "-"
                    || s(&req, "expected_network_id") == self.net)
                && (s(&req, "expected_person_public_key") == "-"
                    || s(&req, "expected_person_public_key") == person),
            "invalid",
        )?;
        check(
            object(offer.get("network").ok_or_else(|| problem("invalid"))?)? == &self.network
                && num(&offer, "epoch")? == self.epoch
                && s(&offer, "feature_id") == self.feature
                && s(&offer, "request_packet_id") == rid,
            "invalid",
        )?;
        check(
            !self.history.hosts.contains(&host)
                && !self.history.persons.contains(&person)
                && !self
                    .history
                    .unbound
                    .contains(&(person.clone(), host.clone())),
            "forbidden",
        )?;
        let mode = text(&req, "mode")?.to_owned();
        let required = if mode == "renew" { 4 } else { 6 };
        let path = self.authority(&person, &issuer, required, 0)?;
        let (_, offer, oid, offer_raw) =
            self.packet(owner, "owner", &id, &path.signer_public_key, "-")?;
        let cert_raw = raw_field(&offer_raw, "certificate")?;
        let cid = certificate_id(&obj(&cert_raw)?)?;
        let c = Cert::candidate(&cid, &cert_raw)?;
        if issuer != "root" {
            let parent = self.structural(&issuer, &person)?;
            check(
                c.scopes & parent.scopes == c.scopes
                    && c.issued >= parent.issued
                    && c.until <= parent.until,
                "forbidden",
            )?;
        }
        self.structural(&cid, &person)?;
        check(
            c.person == person
                && c.host == host
                && c.device == device
                && c.parent == issuer
                && c.request == id
                && c.net == self.net,
            "invalid",
        )?;
        let device_key = DeviceKey {
            person_public_key: person.clone(),
            device_public_key: device.clone(),
        };
        check(
            !self.state.revoked_devices.contains(&device_key),
            "device_revoked",
        )?;
        check(
            self.ctx.now >= c.issued && self.ctx.now < c.until,
            "authority_expired",
        )?;
        let mut evidence = OwnerOfferEvidence {
            request_id: id.clone(),
            request_packet_id: rid,
            owner_offer_id: oid,
            network_id: self.net.clone(),
            feature_id: self.feature.clone(),
            person_public_key: person.clone(),
            host_public_key: host.clone(),
            device_public_key: device,
            certificate_id: cid,
            issuer_certificate_id: issuer.clone(),
            signer_public_key: path.signer_public_key.clone(),
            mode: mode.clone(),
            not_after: c.until.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            scopes: c.scopes,
            certificate: cert_raw,
            binding_draft: Vec::new(),
            binding_authorization_message: Vec::new(),
            membership_proof_id: text(&offer, "membership_proof_id")?.into(),
            binding_proof_id: text(&offer, "binding_proof_id")?.into(),
        };
        if mode == "new" {
            check(
                s(&req, "renewed_certificate_id") == "-"
                    && evidence.membership_proof_id == "-"
                    && evidence.binding_proof_id == "-"
                    && !absent_value(offer.get("binding_record")),
                "invalid",
            )?;
            evidence.binding_draft = raw_field(&offer_raw, "binding_record")?;
            evidence.binding_authorization_message = self.binding_draft(
                &evidence.binding_draft,
                &id,
                &person,
                &issuer,
                &path.signer_public_key,
                &host,
            )?;
            self.host_activations(&host, 0)?;
            check(
                self.state.hosts.get(&host) != Some(&true)
                    && self.state.bindings.get(&host).is_none_or(|p| p == "-"),
                "state_conflict",
            )?;
        } else if mode == "renew" {
            check(
                absent_value(offer.get("binding_record"))
                    && ident(&evidence.membership_proof_id, "pf_")
                    && ident(&evidence.binding_proof_id, "pf_")
                    && s(&req, "expected_network_id") == self.net
                    && s(&req, "expected_person_public_key") == person,
                "invalid",
            )?;
            let old = self.structural(text(&req, "renewed_certificate_id")?, &person)?;
            check(
                old.host == host && old.device == evidence.device_public_key,
                "invalid",
            )?;
            if !self.state.activated_certificates.contains(&old.id) {
                self.activate(&old.request, true, 0)?;
            }
            self.renewal_proof(
                &evidence.membership_proof_id,
                "peerspan-host-admit-v1",
                &person,
                &host,
                0,
                false,
            )?;
            self.renewal_proof(
                &evidence.binding_proof_id,
                "peerspan-host-bind-v1",
                &person,
                &host,
                0,
                false,
            )?;
            check(
                self.state.hosts.get(&host) == Some(&true)
                    && self.state.bindings.get(&host) == Some(&person),
                "forbidden",
            )?;
        } else {
            return Err(problem("invalid"));
        }
        self.revocations()?;
        self.authority(&person, &issuer, required, 0)?;
        check(
            !self.state.revoked_devices.contains(&device_key),
            "device_revoked",
        )?;
        Ok(evidence)
    }

    fn pending_selection(
        &self,
        owner: OwnerOfferEvidence,
        raw: &[u8],
    ) -> Result<SelectionEvidence> {
        let (o, p, sid, _) = self.packet(
            raw,
            "selection",
            &owner.request_id,
            &owner.host_public_key,
            &owner.device_public_key,
        )?;
        check(
            num(&p, "epoch")? == self.epoch
                && s(&o, "person_public_key") == owner.person_public_key
                && s(&p, "owner_offer_id") == owner.owner_offer_id
                && s(&p, "network_id") == self.net
                && s(&p, "feature_id") == self.feature
                && s(&p, "person_public_key") == owner.person_public_key,
            "invalid",
        )?;
        Ok(SelectionEvidence {
            owner,
            selection_id: sid,
        })
    }
}

pub fn verify_stored_owner_offer(
    ctx: ActivationContext<'_>,
    catalog: &[u8],
    request: &[u8],
    owner: &[u8],
) -> Result<OwnerOfferEvidence> {
    normalized((|| {
        let mut v = fresh(&ctx, catalog, &[request, owner])?;
        v.pending_owner(&ctx, request, owner)
    })())
}
pub fn verify_stored_selection(
    ctx: ActivationContext<'_>,
    catalog: &[u8],
    request: &[u8],
    owner: &[u8],
    selection: &[u8],
) -> Result<SelectionEvidence> {
    normalized((|| {
        let mut v = fresh(&ctx, catalog, &[request, owner, selection])?;
        let owner = v.pending_owner(&ctx, request, owner)?;
        v.pending_selection(owner, selection)
    })())
}
pub fn verify_stored_administrator_offer(
    ctx: ActivationContext<'_>,
    catalog: &[u8],
    request: &[u8],
    owner: &[u8],
    selection: &[u8],
    administrator: &[u8],
) -> Result<AdministratorOfferEvidence> {
    normalized((|| {
        let mut v = fresh(&ctx, catalog, &[request, owner, selection, administrator])?;
        let owner = v.pending_owner(&ctx, request, owner)?;
        let selection = v.pending_selection(owner, selection)?;
        let owner = &selection.owner;
        check(owner.mode == "new", "invalid")?;
        let a = obj(administrator)?;
        let person = text(&a, "person_public_key")?;
        let cert = text(&a, "certificate_id")?;
        let signer = if cert == "network_root" {
            check(person == "-", "invalid")?;
            v.root.clone()
        } else {
            v.authority(person, cert, 8, 0)?.signer_public_key
        };
        let (_, p, aid, admin_raw) = v.packet(
            administrator,
            "administrator",
            &owner.request_id,
            &signer,
            "-",
        )?;
        check(
            s(&p, "owner_offer_id") == owner.owner_offer_id
                && s(&p, "selection_id") == selection.selection_id,
            "invalid",
        )?;
        let raw = raw_field(&admin_raw, "admission_record")?;
        let admission = obj(&raw)?;
        let (person, cert) = if cert == "network_root" {
            ("-", "-")
        } else {
            check(admission.contains_key("person_public_key"), "invalid")?;
            (person, cert)
        };
        let (r, p) = v.record(
            &raw,
            "peerspan-host-admit-v1",
            &owner.request_id,
            person,
            cert,
            &signer,
        )?;
        check(
            num(&p, "epoch")? == v.epoch
                && s(&p, "host_public_key") == owner.host_public_key
                && v.persons
                    .get(&owner.person_public_key)
                    .is_some_and(|l| l == s(&p, "member")),
            "invalid",
        )?;
        Ok(AdministratorOfferEvidence {
            selection,
            administrator_offer_id: aid,
            admission_record_id: r.id,
            administrator_signer_public_key: signer,
            admission_record: raw,
        })
    })())
}
