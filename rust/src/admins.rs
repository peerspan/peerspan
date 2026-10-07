//! Delegated administrators and administrator-defined groups. The root
//! delegates administrators; administrators admit, revoke, and define groups
//! with `SSHSIG` signatures. Every host decides which signers it accepts from
//! the statements it has verified itself.
use crate::{
    membership::{KeySigner, check_network, invalid, public_key, time, verify_lines},
    model::Error,
    persons::{person_id_of, sshsig_signer},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The root's delegation of administrator rights to a person key at an epoch.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdminDelegation {
    pub network_id: String,
    pub epoch: u64,
    pub person_public_key: String,
    pub delegated_at: String,
    pub signature: String,
}
impl AdminDelegation {
    fn lines<'a>(&'a self, epoch: &'a str) -> [&'a str; 5] {
        [
            "capsule-admin-delegate-v1",
            &self.network_id,
            epoch,
            &self.person_public_key,
            &self.delegated_at,
        ]
    }
    pub fn sign(
        root: &KeySigner,
        network: &str,
        epoch: u64,
        person: &str,
        at: &str,
    ) -> Result<Self, Error> {
        let mut s = Self {
            network_id: network.into(),
            epoch,
            person_public_key: person.into(),
            delegated_at: at.into(),
            signature: String::new(),
        };
        let epoch_text = epoch.to_string();
        s.signature = root.sign(&s.lines(&epoch_text))?;
        Ok(s)
    }
    /// Valid only at the current epoch under the current root.
    pub fn verify(&self, network: &str, epoch: u64, root: &str) -> Result<(), Error> {
        check_network(&self.network_id, network)?;
        if self.epoch != epoch {
            return Err(invalid("delegation is for another epoch"));
        }
        public_key(&self.person_public_key)?;
        time(&self.delegated_at)?;
        let epoch_text = epoch.to_string();
        verify_lines(root, &self.lines(&epoch_text), &self.signature)
    }
}

/// The root's sticky removal of an administrator. With `revoke_admitted`,
/// every statement that administrator signed becomes invalid.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdminRemoval {
    pub network_id: String,
    pub person_public_key: String,
    pub revoke_admitted: bool,
    pub removed_at: String,
    /// Without `revoke_admitted`, the digests of the statements that stay
    /// valid, ascending; empty with `revoke_admitted`.
    pub kept: Vec<String>,
    pub signature: String,
}
impl AdminRemoval {
    fn lines(&self) -> Vec<&str> {
        let mut lines = vec![
            "capsule-admin-remove-v1",
            &self.network_id,
            &self.person_public_key,
            if self.revoke_admitted {
                "true"
            } else {
                "false"
            },
            &self.removed_at,
        ];
        lines.extend(self.kept.iter().map(String::as_str));
        lines
    }
    /// `kept` is sorted and deduplicated here; it must be empty with
    /// `revoke_admitted`.
    pub fn sign(
        root: &KeySigner,
        network: &str,
        person: &str,
        revoke_admitted: bool,
        kept: &[String],
        at: &str,
    ) -> Result<Self, Error> {
        let mut kept = kept.to_vec();
        kept.sort();
        kept.dedup();
        let mut s = Self {
            network_id: network.into(),
            person_public_key: person.into(),
            revoke_admitted,
            removed_at: at.into(),
            kept,
            signature: String::new(),
        };
        s.check_kept()?;
        s.signature = root.sign(&s.lines())?;
        Ok(s)
    }
    fn check_kept(&self) -> Result<(), Error> {
        let digest = |d: &String| {
            d.len() == 64
                && d.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if (self.revoke_admitted && !self.kept.is_empty())
            || !self.kept.iter().all(digest)
            || self.kept.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(invalid(
                "kept must be distinct ascending digests, and empty with revoke_admitted",
            ));
        }
        Ok(())
    }
    /// Valid when signed by any root of the chain.
    pub fn verify(&self, network: &str, roots: &[String]) -> Result<(), Error> {
        check_network(&self.network_id, network)?;
        public_key(&self.person_public_key)?;
        time(&self.removed_at)?;
        self.check_kept()?;
        roots
            .iter()
            .find_map(|root| verify_lines(root, &self.lines(), &self.signature).ok())
            .ok_or_else(|| invalid("administrator removal not signed by a network root"))
    }
}

/// One version of a group: a set of person IDs, signed by the root or an
/// administrator. The highest valid version per name applies; a version with
/// no members deletes the group.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub network_id: String,
    pub name: String,
    pub version: u64,
    pub defined_at: String,
    pub members: Vec<String>,
    pub signature: String,
}
/// Group names: 1–64 bytes of `a-z`, `0-9`, `.`, `_`, `-`, starting with a
/// letter or digit.
pub fn group_name(name: &str) -> Result<(), Error> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if ok {
        Ok(())
    } else {
        Err(invalid(
            "group names are 1-64 of a-z, 0-9, '.', '_', '-', starting with a letter or digit",
        ))
    }
}
fn person_id_shape(id: &str) -> bool {
    id.strip_prefix("person_").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
impl Group {
    fn lines(&self) -> Vec<String> {
        let mut lines = vec![
            "capsule-group-v1".to_owned(),
            self.network_id.clone(),
            self.name.clone(),
            self.version.to_string(),
            self.defined_at.clone(),
        ];
        lines.extend(self.members.iter().cloned());
        lines
    }
    /// Members are sorted and deduplicated here, as the statement requires.
    pub fn sign(
        signer: &KeySigner,
        network: &str,
        name: &str,
        version: u64,
        members: &[String],
        at: &str,
    ) -> Result<Self, Error> {
        let mut members = members.to_vec();
        members.sort();
        members.dedup();
        let mut g = Self {
            network_id: network.into(),
            name: name.into(),
            version,
            defined_at: at.into(),
            members,
            signature: String::new(),
        };
        g.check_shape()?;
        let lines = g.lines();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        g.signature = signer.sign(&refs)?;
        Ok(g)
    }
    fn check_shape(&self) -> Result<(), Error> {
        group_name(&self.name)?;
        if self.version < 1 {
            return Err(invalid("group versions start at 1"));
        }
        time(&self.defined_at)?;
        if !self.members.iter().all(|m| person_id_shape(m))
            || self.members.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(invalid(
                "group members must be distinct person IDs in ascending order",
            ));
        }
        Ok(())
    }
    pub fn digest(&self) -> String {
        let lines = self.lines();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        crate::membership::statement_digest(&refs)
    }
    pub fn verify_signed_by(&self, network: &str, key: &str) -> Result<(), Error> {
        check_network(&self.network_id, network)?;
        self.check_shape()?;
        let lines = self.lines();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        verify_lines(key, &refs, &self.signature)
    }
    /// The signing key: the `SSHSIG` signer, or None for a raw root signature.
    pub fn signer(&self) -> Option<String> {
        sshsig_signer(&self.signature)
    }
}

/// Which signers this host accepts for administrator-capable statements.
#[derive(Clone, Debug, Default)]
pub(crate) struct Authority {
    /// The root chain, genesis first; the last entry is the current root.
    pub roots: Vec<String>,
    /// Keys whose administrator signatures count: every key with a verified
    /// delegation, except those removed with `revoke_admitted`.
    pub signers: BTreeSet<String>,
    /// Current administrators: delegated at the current epoch, not removed,
    /// and valid, unremoved persons. Only they may sign new statements.
    pub admins: BTreeSet<String>,
    /// Removed with `revoke_admitted`: every statement they signed is invalid.
    pub cascaded: BTreeSet<String>,
    /// Removed without `revoke_admitted`: only the statements whose digests
    /// the removal lists stay valid.
    pub kept: BTreeMap<String, BTreeSet<String>>,
}
impl Authority {
    /// The signers a host accepts, from verified delegations and removals.
    pub fn new(
        roots: Vec<String>,
        delegations: &[AdminDelegation],
        removals: &[AdminRemoval],
    ) -> Self {
        let mut authority = Self {
            roots,
            ..Self::default()
        };
        for r in removals {
            if r.revoke_admitted {
                authority.cascaded.insert(r.person_public_key.clone());
            } else {
                // One removal per key; kept lists are never merged.
                authority.kept.insert(
                    r.person_public_key.clone(),
                    r.kept.iter().cloned().collect(),
                );
            }
        }
        authority.signers = delegations
            .iter()
            .map(|d| d.person_public_key.clone())
            .filter(|k| !authority.cascaded.contains(k))
            .collect();
        authority
    }
    pub fn current(&self) -> &str {
        self.roots.last().map(String::as_str).unwrap_or_default()
    }
    /// The administrator whose `SSHSIG` this is, if this host accepts that
    /// administrator as the signer of the statement with `digest`. Raw
    /// signatures and roots return None.
    pub fn admin_signer(&self, signature: &str, digest: &str) -> Option<String> {
        let key = sshsig_signer(signature)?;
        let kept = self.kept.get(&key).is_none_or(|kept| kept.contains(digest));
        (!self.roots.contains(&key) && self.signers.contains(&key) && kept).then_some(key)
    }
    /// True when `signature` was made by an administrator removed with
    /// `revoke_admitted`, so its statement no longer counts.
    pub fn is_cascaded(&self, signature: &str) -> bool {
        sshsig_signer(signature).is_some_and(|k| self.cascaded.contains(&k))
    }
    /// Root keys (any of the chain) plus the acceptable administrator signer,
    /// for statements valid under any root.
    pub fn any_root_or_admin(&self, signature: &str, digest: &str) -> Vec<String> {
        let mut keys = self.roots.clone();
        keys.extend(self.admin_signer(signature, digest));
        keys
    }
    /// The current root plus the acceptable administrator signer.
    pub fn current_or_admin(&self, signature: &str, digest: &str) -> Vec<String> {
        let mut keys = vec![self.current().to_owned()];
        keys.extend(self.admin_signer(signature, digest));
        keys
    }
}

/// Keeps, per person key, the latest delegation valid under the root of its
/// epoch.
pub(crate) fn latest_delegations(
    network: &str,
    roots: &[String],
    offered: impl IntoIterator<Item = AdminDelegation>,
) -> Vec<AdminDelegation> {
    let mut out: std::collections::BTreeMap<String, AdminDelegation> = Default::default();
    for d in offered {
        let Some(root) = roots.get(d.epoch as usize) else {
            continue;
        };
        if d.verify(network, d.epoch, root).is_err() {
            continue;
        }
        if out
            .get(&d.person_public_key)
            .is_none_or(|previous| d.epoch > previous.epoch)
        {
            out.insert(d.person_public_key.clone(), d);
        }
    }
    out.into_values().collect()
}

/// A group as `network groups` shows it.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct GroupView {
    pub name: String,
    pub version: u64,
    pub members: Vec<String>,
    /// The signing key (standard Base64): the root or an administrator.
    pub signer: String,
}
impl GroupView {
    pub fn of(group: &Group, root_signer: &str) -> Self {
        Self {
            name: group.name.clone(),
            version: group.version,
            members: group.members.clone(),
            signer: group.signer().unwrap_or_else(|| root_signer.to_owned()),
        }
    }
}

/// Resolves a person given as an ID, a public key, or a label to one person,
/// failing on an unknown or ambiguous label.
pub(crate) fn resolve_person<'a>(
    persons: &'a [crate::network::PersonEntry],
    given: &str,
) -> Result<&'a crate::network::PersonEntry, Error> {
    if let Some(p) = persons
        .iter()
        .find(|p| p.person_id == given || p.person_public_key == given)
    {
        return Ok(p);
    }
    if let Ok(key) = crate::persons::normalize_person_key(given)
        && let Some(p) = persons.iter().find(|p| p.person_public_key == key)
    {
        return Ok(p);
    }
    let matches: Vec<_> = persons
        .iter()
        .filter(|p| crate::network::labels_conflict(&p.member, given))
        .collect();
    match matches.as_slice() {
        [one] => Ok(one),
        [] => Err(Error::NotFound),
        many => Err(Error::Invalid(format!(
            "label {given:?} is ambiguous: {}",
            many.iter()
                .map(|p| format!("{} ({})", p.member, p.person_id))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}
/// The person ID of a person public key, for events.
pub(crate) fn person_of(key: &str) -> String {
    person_id_of(key).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        membership::{self, Attestation, HostRevocation, InviteToken, Rotation},
        persons::{HostAdmission, PersonAdmission, PersonSigner},
    };
    use base64::{Engine, engine::general_purpose::STANDARD};

    const ROOT_SEED: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const ROOT: &str = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";
    const NETWORK: &str = "net_34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e";
    const HOST: &str = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=";
    const PERSON_SEED: &str = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=";
    const PERSON: &str = "bnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/E=";
    const PERSON_ID: &str =
        "person_7599776c3085e3f9da0d13071eb0b4ab50fd2bf64c06dd92c2365af3a328eca3";
    const SECOND_SEED: &str = "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY=";
    const SECOND: &str = "iodf/x6zhFFXes1a/uQFRWVo3XyJ4JCGOgVXvHr0nxc=";
    const SECOND_ID: &str =
        "person_72456720412037a6b339f884ce6d91bb4cc163a7dc3e4c58c658e6c2097b92a2";
    const AT: &str = "2026-10-09T00:00:00Z";
    const DELEGATE_SIG: &str =
        "lmKnLMD6XXbYk4pExnNpxbFHR9bZccZWHmlTq7Yssam9dkzfeE7n/2rKom9raC5FmPM7HY7P/TLzx1Vn43zlAg==";
    const REMOVE_SIG: &str =
        "R1qwK9h6ZU+QyzpsXKf5fZWFzqDo0CoTYyi3S/KReuGQn6Dbr0KRGaMDwsciCb6ANbAF5Ye2Vs6V/qBnWwoABA==";
    const HOST_ADMIT_SIG: &str = "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAARY2Fwc3VsZS1wZXJzb24tdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABAGcn2mQsdrkxxBpUyZFanSkCt4bNXYd5C9IjqaLeEs9HxQBscBZYl7WlhEUHuoffN6pW+hZDICMZH5jTfbs4mAg==";
    const GROUP_SIG: &str = "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAARY2Fwc3VsZS1wZXJzb24tdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABAVIvTT/9fTeKaYW0R9edFKS2bknw2Pu/MYty3zhnrayKHhm+lT0xtwfNsdawnv4hFr7UW5PDYaHTIflrZ/f9MAA==";

    fn root() -> ed25519_dalek::SigningKey {
        membership::seed(ROOT_SEED).unwrap()
    }
    fn person() -> PersonSigner {
        PersonSigner::File(membership::seed(PERSON_SEED).unwrap())
    }
    fn second() -> PersonSigner {
        PersonSigner::File(membership::seed(SECOND_SEED).unwrap())
    }

    #[test]
    fn statements_reproduce_the_vectors() {
        let root = root();
        let raw = KeySigner::Raw(&root);
        let d = AdminDelegation::sign(&raw, NETWORK, 0, PERSON, AT).unwrap();
        assert_eq!(d.signature, DELEGATE_SIG);
        d.verify(NETWORK, 0, ROOT).unwrap();
        assert!(d.verify(NETWORK, 1, ROOT).is_err(), "bound to its epoch");
        let r = AdminRemoval::sign(&raw, NETWORK, PERSON, true, &[], AT).unwrap();
        assert_eq!(r.signature, REMOVE_SIG);
        r.verify(NETWORK, &[ROOT.to_owned()]).unwrap();
        let mut flipped = r.clone();
        flipped.revoke_admitted = false;
        assert!(flipped.verify(NETWORK, &[ROOT.to_owned()]).is_err());

        let admin = person();
        let ssh = KeySigner::Ssh(&admin);
        let host = HostAdmission::sign_with(&ssh, NETWORK, 0, HOST, "carol", AT).unwrap();
        assert_eq!(host.signature, HOST_ADMIT_SIG);
        host.verify_signed_by(NETWORK, PERSON).unwrap();
        assert!(
            host.verify(NETWORK, 0, ROOT).is_err(),
            "an administrator signature is not a root signature"
        );
        assert_eq!(sshsig_signer(&host.signature).as_deref(), Some(PERSON));

        assert_eq!(second().public_key_b64(), SECOND);
        assert_eq!(person_id_of(SECOND).unwrap(), SECOND_ID);
        // Members are sorted by the signer.
        let members = vec![PERSON_ID.to_owned(), SECOND_ID.to_owned()];
        let g = Group::sign(&ssh, NETWORK, "backend", 1, &members, AT).unwrap();
        assert_eq!(g.members, vec![SECOND_ID.to_owned(), PERSON_ID.to_owned()]);
        assert_eq!(g.signature, GROUP_SIG);
        g.verify_signed_by(NETWORK, PERSON).unwrap();
        assert!(g.verify_signed_by(NETWORK, ROOT).is_err());
        assert_eq!(g.signer().as_deref(), Some(PERSON));
        let json = serde_json::to_value(&g).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "network_id": NETWORK, "name": "backend", "version": 1,
                "defined_at": AT, "members": [SECOND_ID, PERSON_ID], "signature": GROUP_SIG,
            })
        );
    }

    #[test]
    fn root_statements_verify_in_raw_or_sshsig_form() {
        // An SSH root signs every root statement with SSHSIG; verifiers accept
        // both forms.
        let ssh_root = person();
        let ssh = KeySigner::Ssh(&ssh_root);
        let a = Attestation::sign_with(&ssh, NETWORK, 1, HOST, "carol", AT).unwrap();
        a.verify(NETWORK, 1, PERSON).unwrap();
        let p = PersonAdmission::sign_with(&ssh, NETWORK, 1, SECOND, "dana", AT).unwrap();
        p.verify(NETWORK, 1, PERSON).unwrap();
        let rev = HostRevocation::sign_with(&ssh, NETWORK, HOST, AT).unwrap();
        rev.verify(NETWORK, &[ROOT.to_owned(), PERSON.to_owned()])
            .unwrap();
        let d = AdminDelegation::sign(&ssh, NETWORK, 1, SECOND, AT).unwrap();
        d.verify(NETWORK, 1, PERSON).unwrap();
        // Rotations: raw to SSH, then SSH to SSH.
        let root = root();
        let to_ssh = Rotation::sign(&root, NETWORK, 1, PERSON, AT);
        to_ssh.verify_from(NETWORK, 1, ROOT).unwrap();
        let next = second();
        let onward = Rotation::sign_with(&ssh, NETWORK, 2, &next.public_key_b64(), AT).unwrap();
        onward.verify_from(NETWORK, 2, PERSON).unwrap();
        assert!(onward.verify_from(NETWORK, 2, ROOT).is_err());
        // An invite token signed by an administrator names that signer.
        let invite = membership::seed(SECOND_SEED).unwrap();
        let signed =
            membership::sign_invite_with(NETWORK, &ssh, &invite, "erin", "2099-01-01T00:00:00Z")
                .unwrap();
        let token = InviteToken {
            network_id: NETWORK.into(),
            network_name: "team".into(),
            root_public_key: ROOT.into(),
            coordinator_address: "127.0.0.1:1".into(),
            coordinator_public_key: ROOT.into(),
            member: signed.member,
            invite_public_key: signed.invite_public_key,
            invite_seed: STANDARD.encode(invite.to_bytes()),
            invite_expires_at: signed.invite_expires_at,
            invite_signature: signed.invite_signature,
        };
        let decoded = InviteToken::decode(&token.encode()).unwrap();
        assert_eq!(
            sshsig_signer(&decoded.invite_signature).as_deref(),
            Some(PERSON)
        );
    }

    #[test]
    fn authority_accepts_signers_until_a_cascading_removal() {
        let root = root();
        let raw = KeySigner::Raw(&root);
        let admin = person();
        let host =
            HostAdmission::sign_with(&KeySigner::Ssh(&admin), NETWORK, 0, HOST, "c", AT).unwrap();
        let roots = vec![ROOT.to_owned()];
        // The latest delegation per key that verifies under its epoch's root.
        let d0 = AdminDelegation::sign(&raw, NETWORK, 0, PERSON, AT).unwrap();
        let forged =
            AdminDelegation::sign(&KeySigner::Ssh(&admin), NETWORK, 0, SECOND, AT).unwrap();
        let later = AdminDelegation::sign(&raw, NETWORK, 1, PERSON, AT).unwrap();
        let kept = latest_delegations(NETWORK, &roots, vec![d0.clone(), forged, later]);
        assert_eq!(
            kept,
            vec![d0],
            "beyond the chain or not by the root is ignored"
        );

        let delegations = vec![AdminDelegation::sign(&raw, NETWORK, 0, PERSON, AT).unwrap()];
        let mut authority = Authority::new(roots.clone(), &delegations, &[]);
        let digest = host.digest();
        assert_eq!(
            authority.admin_signer(&host.signature, &digest).as_deref(),
            Some(PERSON)
        );
        assert_eq!(
            authority.current_or_admin(&host.signature, &digest),
            vec![ROOT, PERSON]
        );
        // A plain removal keeps exactly the listed statements.
        let other =
            HostAdmission::sign_with(&KeySigner::Ssh(&admin), NETWORK, 0, SECOND, "d", AT).unwrap();
        let kept = vec![digest.clone()];
        let plain = AdminRemoval::sign(&raw, NETWORK, PERSON, false, &kept, AT).unwrap();
        plain.verify(NETWORK, &roots).unwrap();
        let mut dropped = plain.clone();
        dropped.kept.clear();
        assert!(
            dropped.verify(NETWORK, &roots).is_err(),
            "kept lines are signed"
        );
        authority = Authority::new(roots.clone(), &delegations, std::slice::from_ref(&plain));
        assert_eq!(
            authority.admin_signer(&host.signature, &digest).as_deref(),
            Some(PERSON)
        );
        assert!(
            authority
                .admin_signer(&other.signature, &other.digest())
                .is_none(),
            "a statement not listed (say, backdated after removal) is refused"
        );
        // revoke_admitted invalidates everything they signed, and lists nothing.
        assert!(AdminRemoval::sign(&raw, NETWORK, PERSON, true, &kept, AT).is_err());
        let cascade = AdminRemoval::sign(&raw, NETWORK, PERSON, true, &[], AT).unwrap();
        authority = Authority::new(roots.clone(), &delegations, &[plain, cascade]);
        assert!(authority.admin_signer(&host.signature, &digest).is_none());
        assert!(authority.is_cascaded(&host.signature));
        // A raw root signature is never an administrator's.
        let raw_host = HostAdmission::sign(&root, NETWORK, 0, HOST, "c", AT);
        assert!(
            authority
                .admin_signer(&raw_host.signature, &raw_host.digest())
                .is_none()
        );
        assert!(!authority.is_cascaded(&raw_host.signature));
        // Digests are lowercase hex SHA-256 of the signed lines.
        assert_eq!(
            membership::statement_digest(&["a", "b"]),
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b"a\nb"))
        );
    }

    #[test]
    fn group_shapes_are_checked() {
        let admin = person();
        let ssh = KeySigner::Ssh(&admin);
        for bad in ["", "-x", "Backend", "a b", &"a".repeat(65)] {
            assert!(
                Group::sign(&ssh, NETWORK, bad, 1, &[], AT).is_err(),
                "{bad:?}"
            );
        }
        assert!(Group::sign(&ssh, NETWORK, "x", 0, &[], AT).is_err());
        assert!(Group::sign(&ssh, NETWORK, "x", 1, &["person_x".into()], AT).is_err());
        let deleted = Group::sign(&ssh, NETWORK, "a.b_c-1", 2, &[], AT).unwrap();
        deleted.verify_signed_by(NETWORK, PERSON).unwrap();
        let mut unsorted = Group::sign(
            &ssh,
            NETWORK,
            "x",
            1,
            &[PERSON_ID.to_owned(), SECOND_ID.to_owned()],
            AT,
        )
        .unwrap();
        unsorted.members.reverse();
        assert!(unsorted.verify_signed_by(NETWORK, PERSON).is_err());
    }
}
