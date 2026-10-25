//! Completed public invitation proofs, with no first-redemption writer.
use super::*;

pub(super) struct InviteHalf {
    pub(super) host: bool,
    legacy: bool,
    kept: bool,
    pub(super) person: String,
    pub(super) cert: String,
    key: String,
    pub(super) label: String,
    expires: String,
    record: String,
    epoch: u64,
}

pub(super) struct Redemption {
    object: Obj,
    pub(super) halves: Vec<InviteHalf>,
}

pub(super) fn invite_kind(kind: &str) -> bool {
    matches!(kind, "peerspan-invite-v1" | "peerspan-person-invite-v1")
}

fn redemption_parts(o: &Obj) -> Result<Vec<&'static str>> {
    fields(
        o,
        "format mode person_action host_public_key person_public_key joined_at host_invite person_invite host_member_signature person_member_signature",
        &[],
    )?;
    version(o, 1)?;
    let mode = text(o, "mode")?;
    let action = text(o, "person_action")?;
    let host = text(o, "host_public_key")?;
    let person = text(o, "person_public_key")?;
    stamp(text(o, "joined_at")?)?;
    check(
        matches!(
            (mode, action),
            ("host", "none") | ("person", "admit") | ("member", "admit" | "skip")
        ),
        "invalid",
    )?;
    let mut parts = Vec::new();
    for (part, subject, sig, needed) in [
        (
            "host_invite",
            host,
            text(o, "host_member_signature")?,
            mode != "person",
        ),
        (
            "person_invite",
            person,
            text(o, "person_member_signature")?,
            action == "admit",
        ),
    ] {
        if needed {
            check(key(subject) && sig != "-", "invalid")?;
            object(o.get(part).ok_or_else(|| problem("invalid"))?)?;
            parts.push(part);
        } else {
            check(s(o, part) == "-" && sig == "-", "invalid")?;
        }
    }
    check(
        (mode != "host" || person == "-")
            && (mode != "person" || host == "-")
            && (action != "skip" || key(person)),
        "invalid",
    )?;
    Ok(parts)
}

impl Verifier<'_> {
    // Register signed AR identities without activating a certificate or invite.
    pub(super) fn index_redemption(&mut self, o: &Obj) -> Result<()> {
        for part in redemption_parts(o)? {
            let value = o.get(part).ok_or_else(|| problem("invalid"))?;
            let p = object(value)?;
            if !p.contains_key("format") {
                continue;
            }
            nested_record(value)?;
            let kind = if part == "host_invite" {
                "peerspan-invite-v1"
            } else {
                "peerspan-person-invite-v1"
            };
            check(
                s(p, "kind") == kind
                    && key(s(p, "person_public_key"))
                    && s(p, "operation_id") == "-",
                "invalid",
            )?;
            let (payload, _) = p_obj(p)?;
            let epoch = num(p, "epoch")?.to_string();
            let m = lines(&[
                "peerspan-person-authorization-v1",
                kind,
                text(p, "network_id")?,
                &epoch,
                "-",
                text(p, "person_public_key")?,
                text(p, "certificate_id")?,
                &hash(&payload),
            ]);
            let id = format!(
                "ar_{}",
                hash(&lines(&[
                    "peerspan-authorized-record-v1",
                    &hash(&m),
                    text(p, "signature")?,
                    text(p, "host_signature")?
                ]))
            );
            self.semantic(&id, p)?;
            self.evidence.insert(
                id.clone(),
                Proof {
                    kind: "person_record".into(),
                    body: serde_json::to_vec(value)?,
                    object: p.clone(),
                },
            );
            self.inline_invites.insert(id);
        }
        Ok(())
    }

    fn read_invite(&self, value: &Value, host: bool) -> Result<InviteHalf> {
        let mut o = object(value)?.clone();
        let mut h = InviteHalf {
            host,
            legacy: false,
            kept: false,
            person: String::new(),
            cert: "root".into(),
            key: String::new(),
            label: String::new(),
            expires: String::new(),
            record: String::new(),
            epoch: 0,
        };
        let kind = if host {
            "peerspan-invite-v1"
        } else {
            "peerspan-person-invite-v1"
        };
        if o.contains_key("format") {
            h.epoch = num(&o, "epoch")?;
            h.person = text(&o, "person_public_key")?.into();
            h.cert = text(&o, "certificate_id")?.into();
            check(
                key(&h.person) && (h.cert == "root" || ident(&h.cert, "dc_")),
                "invalid",
            )?;
            let (signer, limit) = if h.cert == "root" {
                (h.person.clone(), None)
            } else {
                let c = self.structural(&h.cert, &h.person)?;
                check(c.scopes & 8 != 0, "forbidden")?;
                (c.device, Some(c.until))
            };
            let (r, payload) = self.record(
                &serde_json::to_vec(value)?,
                kind,
                "-",
                &h.person,
                &h.cert,
                &signer,
            )?;
            h.record = r.id;
            o = payload;
            if let Some(until) = limit {
                check(stamp(text(&o, "invite_expires_at")?)? <= until, "forbidden")?;
            }
        } else {
            fields(
                &o,
                if host {
                    "network_id invite_public_key member invite_expires_at signature"
                } else {
                    "network_id invite_epoch invite_public_key member invite_expires_at signature"
                },
                &[],
            )?;
            check(s(&o, "network_id") == self.net, "invalid")?;
            let mut parts = vec![kind, self.net.as_str()];
            let invite_epoch = if !host {
                h.epoch = self.epoch_root(&o, "invite_epoch")?.1;
                h.epoch.to_string()
            } else {
                String::new()
            };
            if !host {
                parts.push(&invite_epoch);
            }
            parts.extend([
                text(&o, "invite_public_key")?,
                text(&o, "member")?,
                text(&o, "invite_expires_at")?,
            ]);
            let m = lines(&parts);
            let sig = text(&o, "signature")?;
            h.kept = if host {
                self.legacy_authority(&m, sig)?
            } else {
                self.legacy_grant(&o, "invite_epoch", &m, sig)?
            };
            h.legacy = true;
            h.person = if self.any_root_signature(&m, sig) {
                "-".into()
            } else {
                crate::persons::sshsig_signer(sig).ok_or_else(|| problem("invalid"))?
            };
        }
        h.key = text(&o, "invite_public_key")?.into();
        h.label = text(&o, "member")?.into();
        h.expires = text(&o, "invite_expires_at")?.into();
        check(
            key(&h.key) && crate::membership::label(&h.label).is_ok(),
            "invalid",
        )?;
        if h.legacy {
            legacy_stamp(&h.expires)?;
        } else {
            stamp(&h.expires)?;
        }
        Ok(h)
    }

    pub(super) fn read_redemption(&self, p: &Proof) -> Result<Redemption> {
        let mut r = Redemption {
            object: p.object.clone(),
            halves: Vec::new(),
        };
        let joined = stamp(text(&p.object, "joined_at")?)?;
        for part in redemption_parts(&p.object)? {
            let host = part == "host_invite";
            let h =
                self.read_invite(p.object.get(part).ok_or_else(|| problem("invalid"))?, host)?;
            check(joined <= legacy_stamp(&h.expires)?, "invalid")?;
            let (field, sig, domain) = if host {
                (
                    "host_public_key",
                    "host_member_signature",
                    "peerspan-member-v1",
                )
            } else {
                (
                    "person_public_key",
                    "person_member_signature",
                    "peerspan-person-member-v1",
                )
            };
            raw(
                &h.key,
                &lines(&[
                    domain,
                    &self.net,
                    &h.key,
                    text(&p.object, field)?,
                    text(&p.object, "joined_at")?,
                ]),
                text(&p.object, sig)?,
            )?;
            if let Some(old) = r.halves.first() {
                check(
                    old.key == h.key
                        && old.label == h.label
                        && old.expires == h.expires
                        && old.person == h.person
                        && old.cert == h.cert,
                    "invalid",
                )?;
            }
            r.halves.push(h);
        }
        Ok(r)
    }

    pub(super) fn redemption_half(&mut self, id: &str, h: &InviteHalf) -> Result<bool> {
        if h.legacy {
            let attested = h.host
                && h.person == "-"
                && self.proofs.get(id).is_some_and(|p| {
                    self.attested
                        .get(s(&p.object, "host_public_key"))
                        .is_some_and(|label| label == &h.label)
                });
            return Ok((h.kept || attested) && !self.invite_revoked(&h.key));
        }
        let (kept, withdrawn) = self.redemption_admin_kept(&h.person, &h.record, id)?;
        if !kept {
            return Ok(false);
        }
        if !withdrawn {
            self.ensure_person(&h.person)?;
            check(
                self.state
                    .persons
                    .get(&h.person)
                    .is_some_and(|p| p.admitted),
                "forbidden",
            )?;
        }
        self.actor(&h.person, &h.cert, 8, true, 0)?;
        if self.ctx.now >= legacy_stamp(&h.expires)? || !self.record_path_live(&h.person, &h.cert) {
            self.retained_redemption(id, h)?;
        }
        Ok(!self.invite_revoked(&h.key))
    }

    fn retained_redemption(&mut self, id: &str, h: &InviteHalf) -> Result<()> {
        let busy = format!("retain:{id}:{}", h.record);
        check(
            !self.busy.contains(&busy) && self.busy.len() < 24,
            "invalid",
        )?;
        self.busy.insert(busy.clone());
        let result = self.redemption_checkpoint(id, h);
        self.busy.remove(&busy);
        result
    }

    fn redemption_checkpoint(&mut self, id: &str, h: &InviteHalf) -> Result<()> {
        let candidates: Vec<_> = self
            .proofs
            .values()
            .filter(|p| {
                p.kind == "checkpoint"
                    && s(&p.object, "network_id") == self.net
                    && s(&p.object, "person_public_key") == h.person
                    && string_list(&p.object, "records")
                        .is_ok_and(|ids| ids.contains(&id) && ids.contains(&h.record.as_str()))
            })
            .cloned()
            .collect();
        let mut failure = None;
        for root_only in [true, false] {
            for p in &candidates {
                if (s(&p.object, "issuer_certificate_id") == "root") != root_only {
                    continue;
                }
                match self.checkpoint(p, id, &h.person, 0) {
                    Ok(()) => return Ok(()),
                    Err(e) if failure.is_none() => failure = Some(e),
                    Err(_) => {}
                }
            }
        }
        Err(failure.unwrap_or_else(|| missing(id)))
    }

    pub(super) fn redemption_record(&mut self, id: &str) -> Result<()> {
        if self.redemptions.contains(id) {
            return Ok(());
        }
        let busy = format!("redemption:{id}");
        check(
            !self.busy.contains(&busy) && self.busy.len() < 24,
            "invalid",
        )?;
        self.busy.insert(busy.clone());
        let result = self.redemption_inner(id);
        self.busy.remove(&busy);
        result
    }

    fn redemption_inner(&mut self, id: &str) -> Result<()> {
        let p = self.proofs.get(id).ok_or_else(|| missing(id))?.clone();
        let r = self.read_redemption(&p)?;
        if s(&r.object, "person_action") == "skip" {
            let person = text(&r.object, "person_public_key")?;
            self.ensure_person(person)?;
            check(
                self.state.persons.get(person).is_some_and(|p| p.admitted),
                "forbidden",
            )?;
            check(
                self.persons.get(person) == Some(&r.halves[0].label),
                "invalid",
            )?;
        }
        let mut usable = Vec::new();
        for h in &r.halves {
            usable.push(self.redemption_half(id, h)?);
            let field = if h.host {
                "host_public_key"
            } else {
                "person_public_key"
            };
            let subject = text(&r.object, field)?;
            let half = format!("{field}:{}", h.key);
            check(
                self.invite_uses.get(&half).is_none_or(|old| old == subject),
                "state_conflict",
            )?;
            self.invite_uses.insert(half, subject.into());
        }
        for (h, valid) in r.halves.iter().zip(usable) {
            if h.host {
                let host = text(&r.object, "host_public_key")?;
                if valid {
                    check(
                        self.hosts.get(host).is_none_or(|old| old == &h.label),
                        "state_conflict",
                    )?;
                    self.hosts.insert(host.into(), h.label.clone());
                    self.state.hosts.insert(host.into(), true);
                } else {
                    self.state.hosts.entry(host.into()).or_insert(false);
                }
            } else {
                let person = text(&r.object, "person_public_key")?;
                // Cache the signed invitation epoch, not the selected root tip.
                // Historical root labels confer no current admission.
                if valid || h.legacy && h.person == "-" && !self.invite_revoked(&h.key) {
                    self.historical_persons
                        .insert((person.into(), h.epoch, h.label.clone()));
                }
                let administrator = self.admins.contains(person);
                if valid {
                    check(
                        self.persons.get(person).is_none_or(|old| old == &h.label),
                        "state_conflict",
                    )?;
                    self.persons.insert(person.into(), h.label.clone());
                    self.state.persons.insert(
                        person.into(),
                        PersonState {
                            admitted: true,
                            administrator,
                        },
                    );
                } else {
                    self.state
                        .persons
                        .entry(person.into())
                        .or_insert(PersonState {
                            admitted: false,
                            administrator,
                        });
                }
            }
        }
        self.restrict_state();
        self.redemptions.insert(id.into());
        Ok(())
    }

    pub(super) fn redemption_records(&mut self) -> Result<()> {
        let ids: Vec<_> = self
            .proofs
            .iter()
            .filter(|(_, p)| p.kind == "invite_redemption")
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.redemption_record(&id)?;
        }
        Ok(())
    }
}
