//! Historical transport signatures, never current pin-selection authority.
use super::*;

impl Verifier<'_> {
    pub(super) fn coordinator_evidence(&self) -> Result<()> {
        let mut seen = BTreeMap::<String, Obj>::new();
        for p in self.proofs.values().filter(|p| {
            matches!(
                p.kind.as_str(),
                "coordinator_move" | "coordinator_successor"
            )
        }) {
            let o = &p.object;
            let sequence = num(o, "sequence")?;
            check(
                sequence > 0 && sequence <= i64::MAX as u64 && key(s(o, "public_key")),
                "invalid",
            )?;
            check(coordinator_address::valid(text(o, "address")?), "invalid")?;
            let sequence = sequence.to_string();
            let identity = if p.kind == "coordinator_move" {
                fields(
                    o,
                    "network_id sequence address public_key moved_at signer signature",
                    &[],
                )?;
                check(s(o, "network_id") == self.net, "invalid")?;
                stamp(text(o, "moved_at")?)?;
                let message = lines(&[
                    "peerspan-coordinator-move-v1",
                    &self.net,
                    &sequence,
                    text(o, "address")?,
                    text(o, "public_key")?,
                    text(o, "moved_at")?,
                ]);
                let signer = text(o, "signer")?;
                if signer == "root" {
                    check(
                        self.any_root_signature(&message, text(o, "signature")?),
                        "invalid",
                    )?;
                } else {
                    check(key(signer), "invalid")?;
                    check(self.access_admin_known(signer), "forbidden")?;
                    ssh(signer, &message, text(o, "signature")?)?;
                }
                format!("move:{}:{sequence}", self.net)
            } else {
                fields(
                    o,
                    "sequence previous_public_key address public_key signed_at signature",
                    &[],
                )?;
                check(key(s(o, "previous_public_key")), "invalid")?;
                stamp(text(o, "signed_at")?)?;
                let message = lines(&[
                    "peerspan-coordinator-successor-v1",
                    &sequence,
                    text(o, "previous_public_key")?,
                    text(o, "address")?,
                    text(o, "public_key")?,
                    text(o, "signed_at")?,
                ]);
                raw(
                    text(o, "previous_public_key")?,
                    &message,
                    text(o, "signature")?,
                )?;
                format!("successor:{}:{sequence}", text(o, "previous_public_key")?)
            };
            check(
                seen.get(&identity).is_none_or(|old| old == o),
                "state_conflict",
            )?;
            seen.insert(identity, o.clone());
        }
        Ok(())
    }
}
