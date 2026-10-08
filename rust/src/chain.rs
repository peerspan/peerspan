//! Multi-hop delegation chains (roadmap milestone 6, slice 4). A chain is a
//! list of host-signed links carried with a task request: link 0 is created
//! by the originator's host, and each later link by the host that forwards
//! the task, narrowing or keeping the authority it received. The final
//! receiver verifies that the whole chain only narrows, and authorizes the
//! originator.
use crate::{
    membership::canonical,
    model::Error,
    network::Member,
    peer_store::{json, valid_id},
    store::Store,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Database version 11: the tasks forwarded from each received task.
pub(crate) const SCHEMA: &str = "
CREATE TABLE task_children (sender TEXT NOT NULL, task_id TEXT NOT NULL, peer TEXT NOT NULL, child_task_id TEXT NOT NULL, PRIMARY KEY(sender, task_id, peer, child_task_id));
PRAGMA user_version = 11;
";

/// The first line of every link's signed statement.
const TAG: &str = "capsule-delegation-v1";
/// Chains have at most 3 links: 3 hops past the originator.
pub const MAX_LINKS: usize = 3;
/// A link names at most 16 principals.
pub const MAX_PRINCIPALS: usize = 16;
/// Link 0's `previous`.
pub const NONE: &str = "none";
/// The deepest delegation a submitter may allow.
pub const MAX_DEPTH: u64 = 2;
/// The principal every default chain names.
pub const NETWORK: &str = "network";

/// One link: the issuer passes the task's authority to the audience.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub network_id: String,
    pub index: u64,
    pub previous: String,
    pub issuer_host_id: String,
    pub audience_host_id: String,
    pub task_id: String,
    pub originator_agent_id: String,
    pub principals: Vec<String>,
    pub deadline: String,
    pub depth: u64,
    pub signature: String,
}

/// What a submitter or forwarder signs into a new link.
pub(crate) struct Unsigned<'a> {
    pub network_id: &'a str,
    pub previous: Option<&'a Link>,
    pub audience_host_id: &'a str,
    pub task_id: &'a str,
    pub originator_agent_id: &'a str,
    pub principals: &'a [String],
    pub deadline: &'a str,
    pub depth: u64,
}

impl Link {
    /// The signed statement's lines: every field except `signature`.
    fn lines(&self) -> Vec<String> {
        vec![
            TAG.into(),
            self.network_id.clone(),
            self.index.to_string(),
            self.previous.clone(),
            self.issuer_host_id.clone(),
            self.audience_host_id.clone(),
            self.task_id.clone(),
            self.originator_agent_id.clone(),
            self.principals.join(" "),
            self.deadline.clone(),
            self.depth.to_string(),
        ]
    }
    /// The signed statement: its lines joined by `\n`, with no trailing
    /// newline.
    pub fn statement(&self) -> String {
        self.lines().join("\n")
    }
    /// What the next link's `previous` names: the lowercase hex SHA-256 of
    /// this link's statement, `\n`, and its signature.
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(
            format!("{}\n{}", self.statement(), self.signature).as_bytes(),
        ))
    }
    /// Signs a new link as `key`'s host, after `fields.previous` if any.
    pub(crate) fn sign(key: &SigningKey, fields: Unsigned<'_>) -> Self {
        let issuer = crate::peer_store::key_id(key.verifying_key().as_bytes());
        let mut link = Self {
            network_id: fields.network_id.into(),
            index: fields.previous.map_or(0, |p| p.index + 1),
            previous: fields.previous.map_or_else(|| NONE.into(), Link::digest),
            issuer_host_id: issuer,
            audience_host_id: fields.audience_host_id.into(),
            task_id: fields.task_id.into(),
            originator_agent_id: fields.originator_agent_id.into(),
            principals: fields.principals.to_vec(),
            deadline: fields.deadline.into(),
            depth: fields.depth,
            signature: String::new(),
        };
        link.signature = STANDARD.encode(key.sign(link.statement().as_bytes()).to_bytes());
        link
    }
    /// Whether the issuer's host key (canonical Base64) signed this link.
    pub fn verify(&self, public_key: &str) -> bool {
        let Ok(key) = canonical(public_key, 32) else {
            return false;
        };
        let Ok(key) = VerifyingKey::from_bytes(&key.try_into().expect("checked length")) else {
            return false;
        };
        let Ok(signature) = canonical(&self.signature, 64) else {
            return false;
        };
        let signature = Signature::from_bytes(&signature.try_into().expect("checked length"));
        key.verify_strict(self.statement().as_bytes(), &signature)
            .is_ok()
    }
    /// The field shapes, independent of any other link.
    fn well_formed(&self) -> bool {
        let hex64 = |v: &str| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        self.network_id.strip_prefix("net_").is_some_and(hex64)
            && (self.previous == NONE || hex64(&self.previous))
            && valid_id(&self.issuer_host_id, "host", 32)
            && valid_id(&self.audience_host_id, "host", 32)
            && valid_id(&self.task_id, "task", 16)
            && valid_id(&self.originator_agent_id, "agent", 16)
            && principals(&self.principals).is_ok()
            && self.deadline.ends_with('Z')
            && DateTime::parse_from_rfc3339(&self.deadline).is_ok()
            && canonical(&self.signature, 64).is_ok()
    }
}

/// A principal: `network`, `person:<person ID>`, or `host:<host ID>`.
pub fn principal(value: &str) -> bool {
    value == NETWORK
        || value
            .strip_prefix("person:")
            .is_some_and(crate::policy::person_id_shape)
        || value
            .strip_prefix("host:")
            .is_some_and(|h| valid_id(h, "host", 32))
}
/// A link's principals: 1 to 16, sorted and without duplicates.
pub fn principals(values: &[String]) -> Result<(), Error> {
    if values.is_empty()
        || values.len() > MAX_PRINCIPALS
        || !values.iter().all(|p| principal(p))
        || !values.windows(2).all(|w| w[0] < w[1])
    {
        return Err(Error::Invalid(
            "delegation principals are 1 to 16 of network, person:<person ID>, or host:<host ID>, sorted and without duplicates".into(),
        ));
    }
    Ok(())
}
/// Sorts and deduplicates requested principals, defaulting to `network`.
pub fn normalized_principals(given: Option<Vec<String>>) -> Result<Vec<String>, Error> {
    let mut values = given.unwrap_or_else(|| vec![NETWORK.into()]);
    values.sort();
    values.dedup();
    principals(&values)?;
    Ok(values)
}
/// Whether principal `a` covers principal `b`, given the person each host is
/// bound to.
pub(crate) fn covers(a: &str, b: &str, bound: &dyn Fn(&str) -> Option<String>) -> bool {
    if a == NETWORK || a == b {
        return true;
    }
    match (a.strip_prefix("person:"), b.strip_prefix("host:")) {
        (Some(person), Some(host)) => bound(host).as_deref() == Some(person),
        _ => false,
    }
}
/// Whether any of `set` covers `b`.
pub(crate) fn covered(set: &[String], b: &str, bound: &dyn Fn(&str) -> Option<String>) -> bool {
    set.iter().any(|a| covers(a, b, bound))
}
/// The shape of a carried chain: 1 to 3 well-formed links. A malformed
/// chain is a 400.
pub(crate) fn validate(chain: &[Link]) -> Result<(), Error> {
    if chain.is_empty() || chain.len() > MAX_LINKS || !chain.iter().all(Link::well_formed) {
        return Err(Error::Invalid("malformed delegation chain".into()));
    }
    Ok(())
}

/// What a verified chain establishes about a task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Verified {
    pub originator_host_id: String,
    pub originator_agent_id: String,
    /// The person the originator host is bound to in the chain's network.
    pub originator_person_id: Option<String>,
    /// Every issuer, in order.
    pub chain_hosts: Vec<String>,
    /// How many further hops the receiver may create.
    pub depth: u64,
}

/// A task's request fields that a chain must agree with.
pub(crate) struct Carried<'a> {
    pub chain: &'a [Link],
    pub task_id: &'a str,
    pub deadline: &'a str,
    pub origin_agent_id: Option<&'a str>,
}

/// The member record of `host` in `network`, if current.
pub(crate) fn member(
    conn: &Connection,
    network: &str,
    host: &str,
) -> Result<Option<Member>, Error> {
    conn.query_row(
        "SELECT record FROM network_members WHERE network_id = ?1 AND host_id = ?2",
        params![network, host],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(json)
    .transpose()
}

impl Store {
    /// The bound person of each host in a network, from the current view.
    pub(crate) fn bindings(
        &self,
        conn: &Connection,
        network: &str,
    ) -> Result<std::collections::HashMap<String, String>, Error> {
        Ok(self
            .stored_members(conn, network)?
            .into_iter()
            .filter_map(|m| m.person_id.map(|p| (m.host_id, p)))
            .collect())
    }
    /// Verifies a chain carried by a request from the authenticated `sender`
    /// to this host. Shape failures are `Invalid` (400); every other failed
    /// check is `Forbidden` (403). `require_deadline` also refuses a chain
    /// whose deadlines have passed.
    pub(crate) fn verify_chain(
        &self,
        conn: &Connection,
        sender: &str,
        carried: &Carried<'_>,
        require_deadline: bool,
    ) -> Result<Verified, Error> {
        let chain = carried.chain;
        validate(chain)?;
        let me = self.identity().id;
        let network = &chain[0].network_id;
        // 1. Signatures, and current membership of every party.
        if member(conn, network, &me)?.is_none() {
            return Err(Error::Forbidden);
        }
        for link in chain {
            if link.network_id != *network {
                return Err(Error::Forbidden);
            }
            let Some(issuer) = member(conn, network, &link.issuer_host_id)? else {
                return Err(Error::Forbidden);
            };
            if !link.verify(&issuer.public_key)
                || member(conn, network, &link.audience_host_id)?.is_none()
            {
                return Err(Error::Forbidden);
            }
        }
        let bindings = self.bindings(conn, network)?;
        let bound = |host: &str| bindings.get(host).cloned();
        let at = Utc::now();
        let first = &chain[0];
        for (k, link) in chain.iter().enumerate() {
            // 2. Positions and hashes.
            let previous = match k {
                0 => NONE.to_owned(),
                _ => chain[k - 1].digest(),
            };
            if link.index != k as u64 || link.previous != previous {
                return Err(Error::Forbidden);
            }
            let deadline = crate::task::time(&link.deadline).map_err(|_| Error::Forbidden)?;
            if require_deadline && deadline <= at {
                return Err(Error::Forbidden);
            }
            if link.originator_agent_id != first.originator_agent_id {
                return Err(Error::Forbidden);
            }
            if k == 0 {
                continue;
            }
            // 3. Each link narrows the one before it.
            let before = &chain[k - 1];
            let narrowed = link.issuer_host_id == before.audience_host_id
                && covered(
                    &before.principals,
                    &format!("host:{}", link.audience_host_id),
                    &bound,
                )
                && link
                    .principals
                    .iter()
                    .all(|p| covered(&before.principals, p, &bound))
                && deadline <= crate::task::time(&before.deadline).map_err(|_| Error::Forbidden)?
                && before.depth >= 1
                && link.depth == before.depth - 1;
            if !narrowed {
                return Err(Error::Forbidden);
            }
        }
        // 4. The last link names this hop.
        let last = chain.last().expect("validated length");
        if last.issuer_host_id != sender
            || last.audience_host_id != me
            || last.task_id != carried.task_id
            || last.deadline != carried.deadline
        {
            return Err(Error::Forbidden);
        }
        // 5. Link 0 names the originator.
        if !(1..=MAX_DEPTH).contains(&first.depth)
            || (chain.len() == 1 && carried.origin_agent_id != Some(&first.originator_agent_id))
        {
            return Err(Error::Forbidden);
        }
        // 6. No participant is blocked: every issuer, and by binding the
        // originator's person.
        for link in chain {
            if self.blocked(conn, &link.issuer_host_id)? {
                return Err(Error::Forbidden);
            }
        }
        let originator_person_id = bound(&first.issuer_host_id);
        if let Some(person) = &originator_person_id {
            let blocked: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM access_blocks WHERE kind = 'person' AND subject = ?1)",
                [person],
                |r| r.get(0),
            )?;
            if blocked {
                return Err(Error::Forbidden);
            }
        }
        Ok(Verified {
            originator_host_id: first.issuer_host_id.clone(),
            originator_agent_id: first.originator_agent_id.clone(),
            originator_person_id,
            chain_hosts: chain.iter().map(|l| l.issuer_host_id.clone()).collect(),
            depth: last.depth,
        })
    }
    /// The first network, by ID, that this host and `peer` are both current
    /// members of.
    pub(crate) fn shared_network(&self, conn: &Connection, peer: &str) -> Result<String, Error> {
        let network: Option<String> = conn
            .query_row(
                "SELECT a.network_id FROM network_members a JOIN network_members b ON a.network_id = b.network_id WHERE a.host_id = ?1 AND b.host_id = ?2 ORDER BY a.network_id LIMIT 1",
                params![self.identity().id, peer],
                |r| r.get(0),
            )
            .optional()?;
        network.ok_or_else(|| {
            Error::Invalid(format!(
                "delegation needs a network shared with host {peer}"
            ))
        })
    }
    /// Signs a link as this host.
    pub(crate) fn sign_link(&self, fields: Unsigned<'_>) -> Link {
        Link::sign(&self.signing_key, fields)
    }
}

#[cfg(test)]
mod tests;
