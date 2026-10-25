//! Fresh legacy writer authority remains narrower than historical recognition.
use super::*;
pub(super) fn mutation(kind: &str) -> bool {
    matches!(
        kind,
        "admin_delegation"
            | "admin_removal"
            | "person_admission"
            | "person_membership"
            | "host_membership"
            | "host_admission"
            | "host_binding"
            | "host_unbinding"
            | "host_leave"
            | "host_revocation"
            | "invite_revocation"
            | "person_removal"
            | "policy"
            | "group"
            | "coordinator_move"
    )
}
impl Verifier<'_> {
    pub(super) fn fresh_legacy(&mut self, p: &Proof) -> Result<()> {
        let o = &p.object;
        let mut root_only = false;
        let mut sig = s(o, "signature");
        let n = self.epoch.to_string();
        let parts: Vec<String> = match p.kind.as_str() {
            "admin_delegation" => {
                check(num(o, "epoch")? == self.epoch, "forbidden")?;
                root_only = true;
                vec![
                    "peerspan-admin-delegate-v1".into(),
                    self.net.clone(),
                    n,
                    text(o, "person_public_key")?.into(),
                    text(o, "delegated_at")?.into(),
                ]
            }
            "admin_removal" => {
                root_only = true;
                if o.contains_key("format") {
                    return read("admin_removal_v2", &p.body, &self.root, "-")
                        .map(|_| ())
                        .map_err(|_| problem("forbidden"));
                }
                let revoke = o
                    .get("revoke_admitted")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| problem("invalid"))?;
                let mut parts = vec![
                    "peerspan-admin-remove-v1".into(),
                    self.net.clone(),
                    text(o, "person_public_key")?.into(),
                    revoke.to_string(),
                    text(o, "removed_at")?.into(),
                ];
                parts.extend(string_list(o, "kept")?.into_iter().map(str::to_owned));
                parts
            }
            "person_admission" | "host_admission" => {
                check(num(o, "epoch")? == self.epoch, "forbidden")?;
                let (domain, subject) = if p.kind == "person_admission" {
                    ("peerspan-person-admit-v1", "person_public_key")
                } else {
                    ("peerspan-host-admit-v1", "host_public_key")
                };
                vec![
                    domain.into(),
                    self.net.clone(),
                    n,
                    text(o, subject)?.into(),
                    text(o, "member")?.into(),
                    text(o, "admitted_at")?.into(),
                ]
            }
            "host_membership" | "person_membership" => {
                let mut parts = if p.kind == "person_membership" {
                    check(num(o, "invite_epoch")? == self.epoch, "forbidden")?;
                    vec!["peerspan-person-invite-v1".into(), self.net.clone(), n]
                } else {
                    vec!["peerspan-invite-v1".into(), self.net.clone()]
                };
                parts.extend([
                    text(o, "invite_public_key")?.into(),
                    text(o, "member")?.into(),
                    text(o, "invite_expires_at")?.into(),
                ]);
                check(
                    self.ctx.now < legacy_stamp(text(o, "invite_expires_at")?)?,
                    "expired",
                )?;
                check(
                    legacy_stamp(text(o, "joined_at")?)? <= self.ctx.now,
                    "invalid",
                )?;
                sig = text(o, "invite_signature")?;
                parts
            }
            "host_binding" | "host_unbinding" => {
                let person = text(o, "person_public_key")?;
                let host = text(o, "host_public_key")?;
                self.authority(person, "root", 2, 0)?;
                check(self.state.hosts.get(host) == Some(&true), "forbidden")?;
                if p.kind == "host_unbinding" {
                    check(
                        self.state.bindings.get(host).is_some_and(|p| p == person),
                        "state_conflict",
                    )?;
                }
                return Ok(());
            }
            "host_leave" => {
                return check(
                    self.state.hosts.get(text(o, "host_public_key")?) == Some(&true),
                    "forbidden",
                );
            }
            "host_revocation" | "invite_revocation" | "person_removal" => {
                let (domain, subject, at) = match p.kind.as_str() {
                    "host_revocation" => {
                        ("peerspan-revoke-host-v1", "host_public_key", "revoked_at")
                    }
                    "invite_revocation" => (
                        "peerspan-revoke-invite-v1",
                        "invite_public_key",
                        "revoked_at",
                    ),
                    _ => (
                        "peerspan-person-remove-v1",
                        "person_public_key",
                        "removed_at",
                    ),
                };
                vec![
                    domain.into(),
                    self.net.clone(),
                    text(o, subject)?.into(),
                    text(o, at)?.into(),
                ]
            }
            "coordinator_move" => {
                root_only = s(o, "signer") == "root";
                if !root_only {
                    check(
                        crate::persons::sshsig_signer(sig).as_deref() == Some(text(o, "signer")?),
                        "invalid",
                    )?;
                }
                vec![
                    "peerspan-coordinator-move-v1".into(),
                    self.net.clone(),
                    num(o, "sequence")?.to_string(),
                    text(o, "address")?.into(),
                    text(o, "public_key")?.into(),
                    text(o, "moved_at")?.into(),
                ]
            }
            _ => return Ok(()),
        };
        let refs: Vec<_> = parts.iter().map(String::as_str).collect();
        let message = lines(&refs);
        if root(&self.root, &message, sig).is_ok() {
            return Ok(());
        }
        check(!root_only, "forbidden")?;
        let person = crate::persons::sshsig_signer(sig).ok_or_else(|| problem("forbidden"))?;
        check(
            self.state
                .persons
                .get(&person)
                .is_some_and(|p| p.admitted && p.administrator)
                && !self.access_admin_withdrawn(&person),
            "forbidden",
        )?;
        ssh(&person, &message, sig).map_err(|_| problem("invalid"))
    }
}
