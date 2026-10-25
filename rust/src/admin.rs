//! Signer choice for administration commands. When this host holds the
//! current root seed, the daemon signs as before. Otherwise the CLI signs
//! with the person key (administrator actions) or `--root-key` (root-only
//! actions) and hands the daemon the signed statement; the daemon never sees
//! the key.
use crate::{
    call,
    cli::{Command, GroupCommand, NetworkCommand, encoded, resolved},
};
use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use hyper::Method;
use peerspan_host::{
    admins::{AdminDelegation, AdminRemoval, Group},
    coordinator_move::{CoordinatorMove, ROOT_SIGNER},
    membership::{self, HostRevocation, InviteRevocation, KeySigner, Rotation},
    network::{AdminRemovalPlan, RotationPlan},
    persons::{
        self, HostAdmission, MemberInviteToken, PersonAdmission, PersonInviteToken, PersonRemoval,
        PersonSigner,
    },
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub(crate) struct Local<'a>(pub(crate) &'a Path);
impl Local<'_> {
    async fn call(
        &self,
        method: Method,
        path: String,
        body: Option<Value>,
    ) -> anyhow::Result<Value> {
        tokio::time::timeout(
            crate::LOCAL_TIMEOUT,
            call(self.0.to_path_buf(), method, path, body),
        )
        .await
        .context("local host daemon request timed out")?
    }
    pub(crate) async fn get(&self, path: String) -> anyhow::Result<Value> {
        self.call(Method::GET, path, None).await
    }
    pub(crate) async fn post(&self, path: String, body: Value) -> anyhow::Result<Value> {
        self.call(Method::POST, path, Some(body)).await
    }
    pub(crate) async fn put(&self, path: String, body: Value) -> anyhow::Result<Value> {
        self.call(Method::PUT, path, Some(body)).await
    }
    async fn network(&self, id: &str) -> anyhow::Result<Value> {
        self.get("/v1/networks".into())
            .await?
            .as_array()
            .into_iter()
            .flatten()
            .find(|n| n["id"].as_str() == Some(id))
            .cloned()
            .context("network not found")
    }
}

fn at() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field].as_str().unwrap_or_default()
}
fn failed(e: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

/// The network's network ID path segment.
fn under(network: &str, rest: &str) -> String {
    format!("/v1/networks/{}/{rest}", encoded(network))
}

/// Runs a command that this host cannot sign itself. Returns None when the
/// daemon signs, so the command goes through its plain local API request.
pub async fn command(command: &Command, socket: &Path) -> anyhow::Result<Option<Value>> {
    let local = Local(socket);
    let Command::Network(command) = command else {
        return Ok(None);
    };
    let network_id = match command {
        NetworkCommand::Invite { network, .. }
        | NetworkCommand::InvitePerson { network, .. }
        | NetworkCommand::Admit { network, .. }
        | NetworkCommand::RevokeInvite { network, .. }
        | NetworkCommand::RemovePerson { network, .. }
        | NetworkCommand::DelegateAdmin { network, .. }
        | NetworkCommand::Move { network, .. }
        | NetworkCommand::Group(GroupCommand::Set { network, .. }) => resolved(network),
        NetworkCommand::Revoke { network, .. } | NetworkCommand::RemoveAdmin { network, .. } => {
            network.as_str()
        }
        NetworkCommand::RotateRoot {
            id, to_ssh: true, ..
        } => id.as_str(),
        _ => return Ok(None),
    };
    let network = local.network(network_id).await?;
    let to_ssh = matches!(command, NetworkCommand::RotateRoot { .. });
    if network["administrator"] == json!(true) && !to_ssh {
        return Ok(None);
    }
    let id = network_id;
    let epoch = network["root_epoch"].as_u64().unwrap_or_default();
    let value = match command {
        NetworkCommand::DelegateAdmin {
            person, root_key, ..
        } => {
            let root = root_signer(&network, root_key.as_deref())?;
            let key = person_key(&local, id, person).await?;
            let delegation = AdminDelegation::sign(&KeySigner::Ssh(&root), id, epoch, &key, &at())
                .map_err(failed)?;
            local
                .post(under(id, "admins"), json!({"delegation": delegation}))
                .await?
        }
        NetworkCommand::RemoveAdmin {
            person,
            revoke_admitted,
            root_key,
            ..
        } => {
            let root = root_signer(&network, root_key.as_deref())?;
            match local.get(under(id, "link-catalog")).await {
                Ok(_) => {
                    let plan = local
                        .get(format!(
                            "{}?person={}&format=2",
                            under(id, "admin-removal-plan"),
                            encoded(person)
                        ))
                        .await?;
                    let key = text(&plan, "person_public_key");
                    let kept: Vec<String> = if *revoke_admitted {
                        Vec::new()
                    } else {
                        serde_json::from_value(plan["kept"].clone())?
                    };
                    let time = at();
                    let mut parts = vec![
                        "peerspan-admin-remove-v2".to_owned(),
                        id.into(),
                        key.into(),
                        revoke_admitted.to_string(),
                        time.clone(),
                        kept.len().to_string(),
                    ];
                    parts.extend(kept.clone());
                    let signature = root
                        .sign(&parts.iter().map(String::as_str).collect::<Vec<_>>())
                        .map_err(failed)?;
                    let removal = json!({"format":2,"network_id":id,"person_public_key":key,"revoke_admitted":revoke_admitted,"removed_at":time,"kept":kept,"signature":signature});
                    return Ok(Some(local.post(under(id,"admin-removals"),json!({"removal_base64":STANDARD.encode(serde_json::to_vec(&removal)?)})).await?));
                }
                Err(e)
                    if e.downcast_ref::<crate::integration::DaemonError>()
                        .is_some_and(|d| d.status == 426) => {}
                Err(e) => return Err(e),
            }
            // The daemon resolves the administrator (also one no longer a
            // current person) and lists what a plain removal keeps.
            let plan: AdminRemovalPlan = serde_json::from_value(
                local
                    .get(format!(
                        "{}?person={}",
                        under(id, "admin-removal-plan"),
                        encoded(person)
                    ))
                    .await?,
            )?;
            let kept = if *revoke_admitted {
                Vec::new()
            } else {
                plan.kept
            };
            let removal = AdminRemoval::sign(
                &KeySigner::Ssh(&root),
                id,
                &plan.person_public_key,
                *revoke_admitted,
                &kept,
                &at(),
            )
            .map_err(failed)?;
            local
                .post(under(id, "admin-removals"), json!({"removal": removal}))
                .await?
        }
        NetworkCommand::RotateRoot { root_key, .. } => {
            rotate_to_ssh(&local, &network, root_key.as_deref()).await?
        }
        command => {
            if person_key_of(command).is_none() && matches!(command, NetworkCommand::Move { .. }) {
                match local.get(under(id, "link-signer")).await {
                    Ok(_) => bail!(
                        "coordinator moves require the current network root or an explicitly selected original administrator key (--person-key PATH); selected devices cannot sign a move"
                    ),
                    Err(e)
                        if e.downcast_ref::<crate::integration::DaemonError>()
                            .is_some_and(|d| d.status == 404) => {}
                    Err(e) => {
                        return Err(e)
                            .context("repair selected authority before moving the coordinator");
                    }
                }
            }
            if person_key_of(command).is_none() && !matches!(command, NetworkCommand::Move { .. }) {
                match local.get(under(id, "link-signer")).await {
                    Ok(selected) => {
                        return Ok(Some(
                            administer_device(&local, &network, command, &selected).await?,
                        ));
                    }
                    Err(e)
                        if e.downcast_ref::<crate::integration::DaemonError>()
                            .is_some_and(|d| d.status == 404) => {}
                    Err(e) => {
                        return Err(e)
                            .context("repair selected device authority before administration");
                    }
                }
            }
            let signer = PersonSigner::open(person_key_of(command)).map_err(|e| {
                anyhow::anyhow!(
                    "this host does not hold the root seed, and signing as an administrator needs your person key: {e}"
                )
            })?;
            administer(&local, &network, command, &KeySigner::Ssh(&signer)).await?
        }
    };
    Ok(Some(value))
}

/// The `--person-key` of an administrator-signed command, if given.
fn person_key_of(command: &NetworkCommand) -> Option<&Path> {
    match command {
        NetworkCommand::Invite { person_key, .. }
        | NetworkCommand::InvitePerson { person_key, .. }
        | NetworkCommand::Admit { person_key, .. }
        | NetworkCommand::Revoke { person_key, .. }
        | NetworkCommand::RevokeInvite { person_key, .. }
        | NetworkCommand::RemovePerson { person_key, .. }
        | NetworkCommand::Move { person_key, .. }
        | NetworkCommand::Group(GroupCommand::Set { person_key, .. }) => person_key.as_deref(),
        _ => None,
    }
}

/// The root's SSH key for a root-only command on a host without the seed.
fn root_signer(network: &Value, path: Option<&Path>) -> anyhow::Result<PersonSigner> {
    let Some(path) = path else {
        bail!("this host does not hold the root seed; give --root-key PATH");
    };
    let signer = PersonSigner::open(Some(path)).map_err(failed)?;
    if signer.public_key_b64() != text(network, "current_root_public_key") {
        bail!("--root-key is not the network's current root");
    }
    Ok(signer)
}

/// Resolves a person ID or label to its public key, erroring on ambiguity.
pub(crate) async fn person_key(local: &Local<'_>, id: &str, given: &str) -> anyhow::Result<String> {
    let persons = local.get(under(id, "persons")).await?;
    let persons: Vec<&Value> = persons.as_array().into_iter().flatten().collect();
    if let Some(p) = persons
        .iter()
        .find(|p| text(p, "person_id") == given || text(p, "public_key") == given)
    {
        return Ok(text(p, "public_key").to_owned());
    }
    let matches: Vec<&&Value> = persons
        .iter()
        .filter(|p| text(p, "member").eq_ignore_ascii_case(given))
        .collect();
    match matches.as_slice() {
        [one] => Ok(text(one, "public_key").to_owned()),
        [] => {
            // A person ID that is no longer current (for example, removed)
            // cannot be resolved to a key here.
            bail!("no current person {given:?} in this network")
        }
        many => bail!(
            "label {given:?} is ambiguous: {}",
            many.iter()
                .map(|p| format!("{} ({})", text(p, "member"), text(p, "person_id")))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Signs an administrator-capable statement with `signer` and submits it.
async fn administer(
    local: &Local<'_>,
    network: &Value,
    command: &NetworkCommand,
    signer: &KeySigner<'_>,
) -> anyhow::Result<Value> {
    let id = text(network, "id");
    let epoch = network["root_epoch"].as_u64().unwrap_or_default();
    let root = text(network, "current_root_public_key");
    let name = text(network, "name");
    let coordinator = text(network, "coordinator_address");
    let coordinator_key = text(network, "coordinator_public_key");
    Ok(match command {
        NetworkCommand::Invite {
            member,
            expires_at,
            host_only,
            ..
        } => {
            let expiry = invite_expiry(local, id, resolved(expires_at)).await?;
            let invite = invite_key()?;
            let token = if *host_only {
                let signed = membership::sign_invite_with(id, signer, &invite, member, &expiry)
                    .map_err(failed)?;
                membership::InviteToken {
                    network_id: id.into(),
                    network_name: name.into(),
                    root_public_key: root.into(),
                    coordinator_address: coordinator.into(),
                    coordinator_public_key: coordinator_key.into(),
                    member: signed.member,
                    invite_public_key: signed.invite_public_key,
                    invite_seed: STANDARD.encode(invite.to_bytes()),
                    invite_expires_at: signed.invite_expires_at,
                    invite_signature: signed.invite_signature,
                }
                .encode()
            } else {
                MemberInviteToken::issue_with(
                    signer,
                    root,
                    &invite,
                    id,
                    name,
                    epoch,
                    member,
                    &expiry,
                    coordinator,
                    coordinator_key,
                )
                .map_err(failed)?
                .encode()
            };
            let token = wrap_original_invite(local, network, &token, signer).await?;
            local
                .post(under(id, "invites"), json!({"token": token}))
                .await?
        }
        NetworkCommand::InvitePerson {
            member, expires_at, ..
        } => {
            let expiry = invite_expiry(local, id, resolved(expires_at)).await?;
            let token = PersonInviteToken::issue_with(
                signer,
                root,
                &invite_key()?,
                id,
                name,
                epoch,
                member,
                &expiry,
                coordinator,
                coordinator_key,
            )
            .map_err(failed)?
            .encode();
            let token = wrap_original_invite(local, network, &token, signer).await?;
            local
                .post(under(id, "person-invites"), json!({"token": token}))
                .await?
        }
        NetworkCommand::Admit {
            person,
            host,
            member,
            ..
        } => match (person, host) {
            (Some(person), _) => {
                let line = std::fs::read_to_string(person)
                    .map(|text| text.trim().to_owned())
                    .unwrap_or_else(|_| person.clone());
                let key = persons::normalize_person_key(&line).map_err(failed)?;
                let admission = PersonAdmission::sign_with(signer, id, epoch, &key, member, &at())
                    .map_err(failed)?;
                local
                    .post(under(id, "persons"), json!({"admission": admission}))
                    .await?
            }
            (None, host) => {
                let host = host.clone().unwrap_or_default();
                let admission = HostAdmission::sign_with(signer, id, epoch, &host, member, &at())
                    .map_err(failed)?;
                local
                    .post(under(id, "hosts"), json!({"admission": admission}))
                    .await?
            }
        },
        NetworkCommand::Revoke { host, .. } => {
            let members = local.get(under(id, "members")).await?;
            let key = members
                .as_array()
                .into_iter()
                .flatten()
                .find(|m| text(m, "host_id") == host)
                .map(|m| text(m, "public_key").to_owned())
                .context("that host is not a member of this network")?;
            let revocation = HostRevocation::sign_with(signer, id, &key, &at()).map_err(failed)?;
            local
                .post(under(id, "revocations"), json!({"revocation": revocation}))
                .await?
        }
        NetworkCommand::RevokeInvite { invite, .. } => {
            let revocation =
                InviteRevocation::sign_with(signer, id, invite, &at()).map_err(failed)?;
            local
                .post(under(id, "revocations"), json!({"revocation": revocation}))
                .await?
        }
        NetworkCommand::RemovePerson { person, .. } => {
            let key = person_key(local, id, person).await?;
            let removal = PersonRemoval::sign_with(signer, id, &key, &at()).map_err(failed)?;
            local
                .post(under(id, "person-removals"), json!({"removal": removal}))
                .await?
        }
        NetworkCommand::Group(GroupCommand::Set { group, person, .. }) => {
            let mut members = Vec::new();
            for given in person {
                members.push(
                    persons::person_id_of(&person_key(local, id, given).await?).map_err(failed)?,
                );
            }
            let groups = local
                .get(format!("{}?all=true", under(id, "groups")))
                .await?;
            let mut prior = groups
                .as_array()
                .into_iter()
                .flatten()
                .find(|g| text(g, "name") == group)
                .and_then(|g| g["version"].as_u64())
                .unwrap_or(0);
            match local.get(under(id, "link-access-versions")).await {
                Ok(v) => {
                    prior = v["groups"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .find(|g| text(g, "name") == group)
                        .and_then(|g| g["version"].as_u64())
                        .unwrap_or(0)
                }
                Err(e)
                    if e.downcast_ref::<crate::integration::DaemonError>()
                        .is_some_and(|d| d.status == 426) => {}
                Err(e) => return Err(e),
            }
            let version = prior.checked_add(1).context("access version exhausted")?;
            let group = Group::sign(signer, id, group, version, &members, &at()).map_err(failed)?;
            local
                .post(under(id, "groups"), json!({"group": group}))
                .await?
        }
        NetworkCommand::Move {
            coordinator,
            coordinator_key,
            ..
        } => {
            let held = local.get(under(id, "move")).await?;
            let sequence = held["next_sequence"]
                .as_u64()
                .unwrap_or_else(|| held["move"]["sequence"].as_u64().unwrap_or_default() + 1);
            let key = signer.public_key_b64();
            let as_signer = if key == root {
                ROOT_SIGNER
            } else {
                key.as_str()
            };
            let pending = held
                .get("move")
                .filter(|m| m["sequence"].as_u64() == Some(sequence));
            let signed = if let Some(value) = pending {
                let m: CoordinatorMove = serde_json::from_value(value.clone())?;
                anyhow::ensure!(
                    m.address == *coordinator && m.public_key == *coordinator_key,
                    "an unresolved move already names another target"
                );
                m
            } else {
                CoordinatorMove::sign(
                    signer,
                    as_signer,
                    id,
                    sequence,
                    coordinator,
                    coordinator_key,
                    &at(),
                )
                .map_err(failed)?
            };
            local
                .post(
                    under(id, "move"),
                    json!({
                        "coordinator_address": coordinator,
                        "coordinator_public_key": coordinator_key,
                        "move": signed,
                    }),
                )
                .await?
        }
        _ => unreachable!("not an administrator command"),
    })
}

fn invite_key() -> anyhow::Result<SigningKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("random source: {e}"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Rotates the root to the SSH key at `path`. The new root signs the
/// daemon's rotation plan here; the daemon signs the rotation with its root
/// seed, or, from an SSH root, the agent's current root key signs it here.
async fn rotate_to_ssh(
    local: &Local<'_>,
    network: &Value,
    path: Option<&Path>,
) -> anyhow::Result<Value> {
    let id = text(network, "id");
    let path: PathBuf = path.context("--to-ssh needs --root-key PATH")?.into();
    let next = PersonSigner::open(Some(&path)).map_err(failed)?;
    let next_key = next.public_key_b64();
    let plan: RotationPlan = serde_json::from_value(local.get(under(id, "rotation-plan")).await?)?;
    if next_key == plan.current_root_public_key {
        bail!("--root-key is already the network's root");
    }
    let now = at();
    let signed = plan.sign(&KeySigner::Ssh(&next), &now).map_err(failed)?;
    let rotation = if network["administrator"] == json!(true) {
        None
    } else {
        let previous = PersonSigner::agent_with(&plan.current_root_public_key).map_err(|e| {
            anyhow::anyhow!(
                "this host does not hold the root seed, and the current root key is not in the ssh-agent: {e}"
            )
        })?;
        Some(
            Rotation::sign_with(&KeySigner::Ssh(&previous), id, plan.epoch, &next_key, &now)
                .map_err(failed)?,
        )
    };
    local
        .post(
            under(id, "rotate"),
            json!({
                "root_public_key": next_key,
                "rotation": rotation,
                "attestations": signed.attestations,
                "admissions": signed.admissions,
                "groups": signed.groups,
            }),
        )
        .await
}

fn descriptor(n: &Value) -> Value {
    json!({"network_id":n["id"],"name":n["name"],"genesis_root_public_key":n["root_public_key"],"coordinator_address":n["coordinator_address"],"coordinator_public_key":n["coordinator_public_key"]})
}
async fn typed_action(
    local: &Local<'_>,
    id: &str,
    selected: &Value,
    kind: &str,
    payload: Value,
) -> anyhow::Result<Value> {
    local.post(under(id,"link-actions"),json!({"kind":kind,"certificate_id":selected["certificate_id"],"payload_base64":STANDARD.encode(serde_json::to_vec(&payload)?)})).await
}
async fn wrap_original_invite(
    local: &Local<'_>,
    n: &Value,
    inner: &str,
    signer: &KeySigner<'_>,
) -> anyhow::Result<String> {
    let id = text(n, "id");
    let full = match local.get(under(id, "link-catalog")).await {
        Ok(v) => serde_json::to_vec(&v["catalog"])?,
        Err(e)
            if e.downcast_ref::<crate::integration::DaemonError>()
                .is_some_and(|d| d.status == 426) =>
        {
            return Ok(inner.into());
        }
        Err(e) => return Err(e),
    };
    let network = serde_json::to_vec(&descriptor(n))?;
    let (mode, host, person, expires) = peerspan_host::link_runtime::invite::legacy_parts(inner)?;
    let key = signer.public_key_b64();
    let unsigned = peerspan_host::link_runtime::invite::binding_intent(
        &network, &full, &mode, &host, &person, "person", &key, "root", &key, &expires,
    )?;
    let epoch = unsigned["epoch"].as_u64().context("invalid epoch")?;
    let lf = unsigned["feature_id"].as_str().context("invalid feature")?;
    let evidence = peerspan_host::linking::verify_stored_invite_feature_intent(
        peerspan_host::linking::CatalogFactContext {
            network: &network,
            epoch,
            known_feature_id: lf,
            now: peerspan_host::link_runtime::support::now()?,
        },
        &full,
        &serde_json::to_vec(&unsigned)?,
    )?;
    let signature = signer
        .sign(
            &std::str::from_utf8(&evidence.message)?
                .split('\n')
                .collect::<Vec<_>>(),
        )
        .map_err(failed)?;
    peerspan_host::link_runtime::invite::finish(&network, &full, inner, &unsigned, signature)
}
async fn administer_device(
    local: &Local<'_>,
    n: &Value,
    command: &NetworkCommand,
    selected: &Value,
) -> anyhow::Result<Value> {
    let id = text(n, "id");
    let epoch = n["root_epoch"].as_u64().context("invalid root epoch")?;
    let at = at();
    match command {
        NetworkCommand::Admit {person,host,member,..}=> {
            if let Some(person)=person {
                let line=std::fs::read_to_string(person).map(|s|s.trim().to_owned()).unwrap_or_else(|_|person.clone());
                typed_action(local,id,selected,"peerspan-person-admit-v1",json!({"network_id":id,"epoch":epoch,"person_public_key":persons::normalize_person_key(&line).map_err(failed)?,"member":member,"admitted_at":at})).await
            }else{typed_action(local,id,selected,"peerspan-host-admit-v1",json!({"network_id":id,"epoch":epoch,"host_public_key":host,"member":member,"admitted_at":at})).await}
        }
        NetworkCommand::Revoke {host,..}=> {
            let members=local.get(under(id,"members")).await?;
            let key=members.as_array().into_iter().flatten().find(|m|text(m,"host_id")==host).map(|m|text(m,"public_key")).context("that host is not a member")?;
            typed_action(local,id,selected,"peerspan-revoke-host-v1",json!({"network_id":id,"host_public_key":key,"revoked_at":at})).await
        }
        NetworkCommand::RevokeInvite {invite,..}=>typed_action(local,id,selected,"peerspan-revoke-invite-v1",json!({"network_id":id,"invite_public_key":invite,"revoked_at":at})).await,
        NetworkCommand::RemovePerson {person,..}=>typed_action(local,id,selected,"peerspan-person-remove-v1",json!({"network_id":id,"person_public_key":person_key(local,id,person).await?,"removed_at":at})).await,
        NetworkCommand::Group(GroupCommand::Set {group,person,..})=> {
            let versions=local.get(under(id,"link-access-versions")).await?;
            let prior=versions["groups"].as_array().into_iter().flatten().find(|g|text(g,"name")==group).and_then(|g|g["version"].as_u64()).unwrap_or(0);
            let version=prior.checked_add(1).context("access version exhausted")?;
            let mut members=Vec::new();for who in person {members.push(persons::person_id_of(&person_key(local,id,who).await?).map_err(failed)?);}members.sort();members.dedup();
            typed_action(local,id,selected,"peerspan-group-v1",json!({"network_id":id,"name":group,"version":version,"defined_at":at,"members":members})).await
        }
        NetworkCommand::Invite {member,expires_at,host_only,..}=>device_invite(local,n,selected,if *host_only{"host"}else{"member"},member,resolved(expires_at)).await,
        NetworkCommand::InvitePerson {member,expires_at,..}=>device_invite(local,n,selected,"person",member,resolved(expires_at)).await,
        _=>bail!("this action requires the original person or current network root"),
    }
}
async fn device_invite(
    local: &Local<'_>,
    n: &Value,
    selected: &Value,
    mode: &str,
    member: &str,
    expires: &str,
) -> anyhow::Result<Value> {
    let id = text(n, "id");
    let epoch = n["root_epoch"].as_u64().context("invalid epoch")?;
    let expires = membership::time(expires)
        .map_err(failed)?
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let seed = invite_key()?;
    let key = STANDARD.encode(seed.verifying_key().as_bytes());
    let mut halves = [json!("-"), json!("-")];
    for (i, kind, needed) in [
        (0, "peerspan-invite-v1", mode != "person"),
        (1, "peerspan-person-invite-v1", mode != "host"),
    ] {
        if needed {
            let mut payload = json!({"network_id":id,"invite_public_key":key,"member":member,"invite_expires_at":expires});
            if i == 1 {
                payload["invite_epoch"] = json!(epoch);
            }
            let signed = typed_action(local, id, selected, kind, payload).await?;
            halves[i] = serde_json::from_slice(
                &STANDARD.decode(
                    signed["record_base64"]
                        .as_str()
                        .context("missing invite record")?,
                )?,
            )?;
        }
    }
    let full = local.get(under(id, "link-catalog")).await?["catalog"].clone();
    let network = descriptor(n);
    let inner=format!("{}{}",peerspan_host::link_runtime::invite::AUTHORIZED_PREFIX,base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"format":1,"network":network,"mode":mode,"invite_seed":STANDARD.encode(seed.to_bytes()),"host_invite":halves[0],"person_invite":halves[1],"catalog":full}))?));
    let host = if mode != "person" {
        serde_json::to_vec(&halves[0])?
    } else {
        Vec::new()
    };
    let person = if mode != "host" {
        serde_json::to_vec(&halves[1])?
    } else {
        Vec::new()
    };
    let unsigned = peerspan_host::link_runtime::invite::binding_intent(
        &serde_json::to_vec(&network)?,
        &serde_json::to_vec(&full)?,
        mode,
        &host,
        &person,
        "person",
        text(selected, "person_public_key"),
        text(selected, "certificate_id"),
        text(selected, "device_public_key"),
        &expires,
    )?;
    let signed = typed_action(local, id, selected, "invite_feature", unsigned.clone()).await?;
    let binding: Value = serde_json::from_slice(
        &STANDARD.decode(
            signed["record_base64"]
                .as_str()
                .context("missing feature binding")?,
        )?,
    )?;
    let token = peerspan_host::link_runtime::invite::finish(
        &serde_json::to_vec(&network)?,
        &serde_json::to_vec(&signed["catalog"])?,
        &inner,
        &unsigned,
        text(&binding, "signature").into(),
    )?;
    local
        .post(
            under(
                id,
                if mode == "person" {
                    "person-invites"
                } else {
                    "invites"
                },
            ),
            json!({"token":token}),
        )
        .await
}

async fn invite_expiry(local: &Local<'_>, id: &str, value: &str) -> anyhow::Result<String> {
    match local.get(under(id, "link-catalog")).await {
        Ok(_) => Ok(membership::time(value)
            .map_err(failed)?
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()),
        Err(e)
            if e.downcast_ref::<crate::integration::DaemonError>()
                .is_some_and(|d| d.status == 426) =>
        {
            Ok(value.into())
        }
        Err(e) => Err(e),
    }
}
