//! Materialize supported ordinary grants without exposing partially checked state.
use super::*;

pub(super) fn ordinary_scope(kind: &str) -> u64 {
    match kind {
        "peerspan-host-bind-v1" | "peerspan-host-unbind-v1" => 2,
        "peerspan-host-admit-v1"
        | "peerspan-person-admit-v1"
        | "peerspan-person-remove-v1"
        | "peerspan-revoke-host-v1"
        | "peerspan-revoke-invite-v1" => 8,
        _ => 0,
    }
}

pub(super) fn ordinary_restriction(kind: &str) -> bool {
    matches!(
        kind,
        "peerspan-host-unbind-v1"
            | "peerspan-person-remove-v1"
            | "peerspan-revoke-host-v1"
            | "peerspan-revoke-invite-v1"
    )
}

pub(super) struct Grant {
    pub(super) record: SignedObject,
    pub(super) payload: Obj,
    pub(super) person: String,
    pub(super) cert: String,
    pub(super) scope: u64,
}

impl Verifier<'_> {
    pub(super) fn read_ordinary(&self, p: &Proof) -> Result<Grant> {
        let o = &p.object;
        let person = text(o, "person_public_key")?;
        let cert = text(o, "certificate_id")?;
        let scope = ordinary_scope(s(o, "kind"));
        check(
            p.kind == "person_record"
                && scope != 0
                && key(person)
                && (cert == "root" || ident(cert, "dc_")),
            "invalid",
        )?;
        let signer = if cert == "root" {
            person.to_owned()
        } else {
            let c = self.structural(cert, person)?;
            check(c.scopes & scope == scope, "forbidden")?;
            c.device
        };
        let (record, payload) =
            self.record(&p.body, text(o, "kind")?, "-", person, cert, &signer)?;
        Ok(Grant {
            record,
            payload,
            person: person.into(),
            cert: cert.into(),
            scope,
        })
    }

    // Try independent admissions before declaring a dependency incomplete. A
    // record's own signature never supplies its person's missing authority.
    pub(super) fn ensure_person(&mut self, person: &str) -> Result<()> {
        let known = self.state.persons.contains_key(person);
        if self.state.persons.get(person).is_some_and(|p| p.admitted)
            || self.history.persons.contains(person)
        {
            return Ok(());
        }
        let candidates: Vec<_> = self
            .proofs
            .iter()
            .filter(|(id, p)| {
                (p.kind == "person_record"
                    && s(&p.object, "operation_id") == "-"
                    && s(&p.object, "kind") == "peerspan-person-admit-v1"
                    && !self.active_records.contains(*id)
                    && !self.inert_records.contains(*id))
                    || (p.kind == "invite_redemption"
                        && s(&p.object, "person_action") == "admit"
                        && s(&p.object, "person_public_key") == person)
            })
            .map(|(id, p)| (id.clone(), p.clone()))
            .collect();
        let mut failure = None;
        for (id, p) in candidates {
            let result = if p.kind == "invite_redemption" {
                self.redemption_record(&id)
            } else {
                let (_, target) = p_obj(&p.object)?;
                if s(&target, "person_public_key") != person {
                    continue;
                }
                self.ordinary_record(&id)
            };
            if let Err(e) = result
                && failure.is_none()
            {
                failure = Some(e);
            }
            if self.state.persons.get(person).is_some_and(|p| p.admitted) {
                return Ok(());
            }
        }
        if known || self.state.persons.contains_key(person) {
            Ok(())
        } else {
            Err(failure.unwrap_or_else(|| problem("proof_required")))
        }
    }

    pub(super) fn ordinary_record(&mut self, id: &str) -> Result<()> {
        if self.active_records.contains(id) || self.inert_records.contains(id) {
            return Ok(());
        }
        let busy = format!("ordinary:{id}");
        check(
            !self.busy.contains(&busy) && self.busy.len() < 24,
            "invalid",
        )?;
        self.busy.insert(busy.clone());
        let result = self.ordinary_inner(id);
        self.busy.remove(&busy);
        result
    }

    fn ordinary_inner(&mut self, id: &str) -> Result<()> {
        let p = self.proofs.get(id).ok_or_else(|| missing(id))?.clone();
        let g = self.read_ordinary(&p)?;
        if g.scope == 8 && !self.ordinary_admin_kept(&g.person, &g.record.id)? {
            match s(&p.object, "kind") {
                "peerspan-person-admit-v1" => {
                    let person = text(&g.payload, "person_public_key")?.to_owned();
                    let administrator = self.admins.contains(&person);
                    self.state.persons.entry(person).or_insert(PersonState {
                        admitted: false,
                        administrator,
                    });
                }
                "peerspan-host-admit-v1" => {
                    self.state
                        .hosts
                        .entry(text(&g.payload, "host_public_key")?.into())
                        .or_insert(false);
                }
                _ => {}
            }
            self.inert_records.insert(id.into());
            return Ok(());
        }
        self.actor(&g.person, &g.cert, g.scope, true, 0)?;
        self.historical_record(&g.record, &p.object, g.scope, 0)?;
        match s(&p.object, "kind") {
            "peerspan-host-bind-v1" => {
                self.add_binding(text(&g.payload, "host_public_key")?, &g.person)?
            }
            "peerspan-host-admit-v1" => {
                let host = text(&g.payload, "host_public_key")?;
                let label = text(&g.payload, "member")?;
                check(
                    self.hosts.get(host).is_none_or(|old| old == label),
                    "state_conflict",
                )?;
                self.hosts.insert(host.into(), label.into());
                self.state.hosts.insert(host.into(), true);
            }
            "peerspan-person-admit-v1" => {
                let person = text(&g.payload, "person_public_key")?;
                let label = text(&g.payload, "member")?;
                check(
                    self.persons.get(person).is_none_or(|old| old == label),
                    "state_conflict",
                )?;
                self.persons.insert(person.into(), label.into());
                self.state.persons.insert(
                    person.into(),
                    PersonState {
                        admitted: true,
                        administrator: self.admins.contains(person),
                    },
                );
            }
            kind => self.apply_ordinary_restriction(&g, kind),
        }
        self.restrict_state();
        self.active_records.insert(id.into());
        Ok(())
    }

    pub(super) fn ordinary_records(&mut self) -> Result<()> {
        let ids: Vec<_> = self
            .proofs
            .iter()
            .filter(|(_, p)| p.kind == "person_record" && s(&p.object, "operation_id") == "-")
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.ordinary_record(&id)?;
        }
        Ok(())
    }
}

/// Verified caller pins. Unknown historical feature is not writer readiness.
pub struct CatalogFactContext<'a> {
    pub network: &'a [u8],
    pub epoch: u64,
    pub known_feature_id: &'a str,
    pub now: chrono::DateTime<chrono::Utc>,
}

pub struct CatalogFacts {
    pub network_id: String,
    pub feature_id: String,
    pub state: PathState,
    pub person_labels: BTreeMap<String, String>,
    pub host_labels: BTreeMap<String, String>,
}

pub fn verify_catalog_facts(ctx: CatalogFactContext<'_>, catalog: &[u8]) -> Result<CatalogFacts> {
    let run = || -> Result<CatalogFacts> {
        check(
            ctx.network.len() + catalog.len() <= MAX_ACTIVATION,
            "invalid",
        )?;
        let mut v = Verifier::new(ctx.network, ctx.epoch, ctx.known_feature_id, ctx.now)?;
        v.catalog(catalog)?;
        v.bootstrap(true)?;
        v.revocations()?;
        Ok(CatalogFacts {
            network_id: v.net,
            feature_id: v.feature,
            state: v.state,
            person_labels: v.persons,
            host_labels: v.hosts,
        })
    };
    run().map_err(|e| {
        if e.downcast_ref::<PathError>().is_some() {
            e
        } else {
            problem("invalid")
        }
    })
}

pub(super) fn probe_catalog_facts(o: &Obj) -> Value {
    let run = || -> Result<Value> {
        fields(
            o,
            "kind network_base64 catalog_base64 epoch known_feature_id now",
            &[],
        )?;
        let network = decode(text(o, "network_base64")?, MAX_ACTIVATION)?;
        let catalog = decode(text(o, "catalog_base64")?, MAX_ACTIVATION)?;
        let r = verify_catalog_facts(
            CatalogFactContext {
                network: &network,
                epoch: num(o, "epoch")?,
                known_feature_id: text(o, "known_feature_id")?,
                now: stamp(text(o, "now")?)?,
            },
            &catalog,
        )?;
        let persons: Vec<_> = r
            .state
            .persons
            .iter()
            .map(|(key, p)| {
                json!({
            "person_public_key":key,"member":r.person_labels.get(key).map_or("-", String::as_str),
            "admitted":p.admitted,"administrator":p.administrator})
            })
            .collect();
        let hosts: Vec<_> = r.state.hosts.iter().map(|(key, admitted)| json!({
            "host_public_key":key,"member":r.host_labels.get(key).map_or("-", String::as_str),"admitted":admitted})).collect();
        let bindings: Vec<_> = r
            .state
            .bindings
            .iter()
            .map(|(host, person)| json!({"host_public_key":host,"person_public_key":person}))
            .collect();
        let revoked: Vec<_> = r.state.revoked_devices.iter().map(|d| json!({"person_public_key":d.person_public_key,"device_public_key":d.device_public_key})).collect();
        Ok(
            json!({"ok":true,"network_id":r.network_id,"feature_id":r.feature_id,
            "persons":persons,"hosts":hosts,"bindings":bindings,
            "activated_certificate_ids":r.state.activated_certificates,"revoked_devices":revoked}),
        )
    };
    run().unwrap_or_else(|e| {
        if let Some(e) = e.downcast_ref::<PathError>() {
            if e.code == "proof_required" {
                json!({"ok":false,"code":e.code,"required_ids":e.required_ids})
            } else {
                json!({"ok":false,"code":e.code})
            }
        } else {
            json!({"ok":false,"code":"invalid"})
        }
    })
}
