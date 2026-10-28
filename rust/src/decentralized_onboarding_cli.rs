//! Private contact introductions carry discovery and review pins. They never
//! admit a person, replace an original key or supply requester consent.
use crate::{
    admin::Local,
    cli::{Command, NetworkCommand, encoded},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Args;
use peerspan_host::decentralized::{Invitation, local_decision_time};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{self, IsTerminal, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAX_TOKEN: usize = 32 << 10;

async fn confirm_identity(question: &str) -> Result<bool> {
    let answer = crate::up::prompt(&format!("{question}? (y/N)"), "no", false).await?;
    Ok(matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes"))
}

#[derive(Debug, Default, Args)]
pub struct InvitationInput {
    /// Read one private psi2 introduction from standard input
    #[arg(long, conflicts_with = "invite_file")]
    invite_stdin: bool,
    /// Read one private introduction from an owner-only regular file
    #[arg(long, value_name = "PATH")]
    invite_file: Option<PathBuf>,
}
impl InvitationInput {
    pub(crate) fn explicit(&self) -> bool {
        self.invite_stdin || self.invite_file.is_some()
    }
    pub(crate) async fn read(&self) -> Result<String> {
        let raw = if let Some(path) = &self.invite_file {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(path)
                .context("cannot open the private introduction file")?;
            let m = file.metadata()?;
            // SAFETY: geteuid has no arguments or memory side effects.
            let uid = unsafe { libc::geteuid() };
            ensure!(
                m.is_file() && m.mode() & 0o077 == 0 && m.uid() == uid,
                "the private introduction file must be an owner-only regular file"
            );
            let mut raw = String::new();
            file.take((MAX_TOKEN + 2) as u64).read_to_string(&mut raw)?;
            raw
        } else if self.invite_stdin {
            let mut raw = String::new();
            io::stdin()
                .lock()
                .take((MAX_TOKEN + 2) as u64)
                .read_to_string(&mut raw)?;
            raw
        } else {
            crate::up::prompt_bounded("Private introduction (hidden)", "", true, MAX_TOKEN).await?
        };
        let token = raw.strip_suffix('\n').unwrap_or(&raw);
        ensure!(
            token.len() <= MAX_TOKEN && !token.contains(['\n', '\r']),
            "give one exact bounded private introduction"
        );
        Ok(token.into())
    }
}

/// Used by guided setup only after private input; validation precedes key choice.
pub(crate) async fn create_join(
    local: &Local<'_>,
    token: &str,
    person_key: &Option<PathBuf>,
) -> Result<Value> {
    let intro = Invitation::read_token(token, &local_decision_time()?)?;
    let genesis = STANDARD.decode(&intro.descriptor.genesis_root_public_key)?;
    eprintln!(
        "Introduction: network {} ({}), context {}, genesis fingerprint SHA256:{}, inviter host {}, proposed member {}, person-key pin {}. An administrator must approve this exact machine.",
        intro.descriptor.name,
        intro.descriptor.network_id,
        intro.descriptor.context_id(),
        hex::encode(Sha256::digest(&genesis)),
        intro.inviter_host_public_key,
        intro.member,
        intro.expected_person_public_key
    );
    let choice = if person_key.is_some() {
        // The exact file option is an explicit identity selection. Opening it
        // does not save a key, create a request or admit this person.
        crate::choose_key(person_key)?
    } else if let Some((signer, path)) =
        peerspan_host::persons::PersonSigner::discover().map_err(|e| anyhow::anyhow!("{e}"))?
    {
        let public = signer.public_key_b64();
        ensure!(
            intro.expected_person_public_key == "-" || intro.expected_person_public_key == public,
            "the existing original key differs from the introduction; select its exact --person-key on its own machine"
        );
        ensure!(
            confirm_identity(&format!("Use existing original person {public}")).await?,
            "original identity not selected; use --person-key for an explicit noninteractive selection"
        );
        crate::KeyChoice {
            signer,
            source: if path.is_some() { "generated" } else { "agent" },
            path,
            new: None,
        }
    } else {
        ensure!(
            intro.expected_person_public_key == "-",
            "the pinned original key is unavailable; select its exact --person-key on its own machine"
        );
        ensure!(
            confirm_identity("Create a new original person on this machine").await?,
            "new original identity not approved; use --person-key for an existing original"
        );
        // The complete contact review and explicit creation approval precede
        // even in-memory key generation. Saving still precedes publication.
        let choice = crate::choose_key(person_key)?;
        ensure!(
            choice.new.is_some(),
            "an existing original appeared during review; select its exact --person-key"
        );
        choice
    };
    let person = choice.signer.public_key_b64();
    ensure!(
        intro.expected_person_public_key == "-" || intro.expected_person_public_key == person,
        "the selected original key differs from the introduction; keep it on its own original machine"
    );
    eprintln!("Selected original person: {person}");
    // Persist before a request can escape; a daemon failure cannot lose the key
    // or make a later retry silently choose a different original identity.
    choice.save(&intro.member)?;
    let v = local
        .post(
            "/v2/link/requests".into(),
            json!({
                "mode":"new", "network_id":intro.descriptor.network_id,
                "person_public_key":person, "migration_proposal_id":"-",
                "contact_invitation":token, "helpers":intro.helpers
            }),
        )
        .await?;
    ensure!(
        v["network_id"] == intro.descriptor.network_id
            && v["context_id"] == intro.descriptor.context_id()
            && v["person_public_key"] == person
            && v["role"] == "requester",
        "request creation changed the reviewed introduction or original identity"
    );
    eprintln!(
        "The request was sent to the inviting machine through the invite's return path when it was reachable; otherwise return the private reply code to it. Owner and administrator approval follow there. Membership remains pending."
    );
    Ok(v)
}

#[allow(clippy::too_many_arguments)]
async fn join(
    socket: &Path,
    token: &Option<String>,
    descriptor: Option<&str>,
    input: &InvitationInput,
    person_key: &Option<PathBuf>,
    no_person: bool,
    trusted: bool,
    untrusted: bool,
) -> Result<()> {
    ensure!(
        token.is_none() && descriptor.is_none() && !no_person,
        "join needs a private psi2 introduction before choosing --person-key; use --invite-stdin or --invite-file and explicit machine approval"
    );
    let token = input.read().await?;
    let v = create_join(&Local(socket), &token, person_key).await?;
    let mut v = crate::decentralized_link_cli::guide(socket, v, io::stdin().is_terminal()).await?;
    let network = v["network_id"].as_str().unwrap_or_default().to_owned();
    let linked = v["state"] == "linked";
    // The output stays the exact LINK_VIEW (spec 15, wire formats 16.8)
    // unless a trust answer was given or asked for: a flag, or the question
    // at a terminal once the link is applied.
    if trusted || untrusted || linked && io::stdin().is_terminal() {
        crate::capability_cli::dec_trust_outcome(
            &mut v,
            socket,
            &network,
            person_key.as_deref(),
            trusted,
            untrusted,
            linked,
        )
        .await;
    }
    crate::decentralized_link_cli::output(v, true)
}
async fn invite(
    local: &Local<'_>,
    network: &Option<String>,
    member: &str,
    expires_at: &Option<String>,
    expires_in: &Option<String>,
    person_key: &Option<PathBuf>,
    host_only: bool,
) -> Result<()> {
    ensure!(
        person_key.is_none() && !host_only,
        "an invite grants no authority; the joining machine is approved explicitly"
    );
    ensure!(
        expires_at.is_none() || expires_in.is_none(),
        "--expires-at and --expires-in are mutually exclusive"
    );
    let all = local.get("/v2/networks".into()).await?;
    let all = all
        .as_array()
        .context("invalid coordinator-free networks")?;
    let n = all
        .iter()
        .find(|n| match network {
            Some(name) => n["id"] == *name || n["name"] == *name,
            None => all.len() == 1,
        })
        .context("choose the exact coordinator-free network with --network")?;
    ensure!(
        n["mode"] == "decentralized",
        "this network needs explicit migration"
    );
    let id = n["id"].as_str().context("invalid network ID")?;
    // Spec 8.1: valid for 1 hour by default, at least 60 seconds and at most
    // 24 hours; the daemon checks the bounds against its decision time. A
    // relative lifetime is fixed just before the request, and the minimum
    // gets a few seconds of allowance for the request's own latency.
    let expiry = match (expires_at, expires_in) {
        (Some(at), _) => Some(at.clone()),
        (None, Some(duration)) => {
            let at = crate::integration::relative_expiry(duration)?;
            let floor = peerspan_host::clock::now() + chrono::TimeDelta::seconds(70);
            Some(
                if chrono::DateTime::parse_from_rfc3339(&at)?.with_timezone(&chrono::Utc) < floor {
                    floor.format("%Y-%m-%dT%H:%M:%SZ").to_string()
                } else {
                    at
                },
            )
        }
        (None, None) => None,
    };
    let v = local
        .post(
            format!("/v2/networks/{}/invitations", encoded(id)),
            match &expiry {
                Some(at) => {
                    json!({"member":member,"expected_person_public_key":"-","expires_at":at})
                }
                None => json!({"member":member,"expected_person_public_key":"-"}),
            },
        )
        .await?;
    let intro = Invitation::read_token(
        v["invitation"]
            .as_str()
            .context("invalid private introduction")?,
        &local_decision_time()?,
    )?;
    ensure!(
        intro.descriptor.network_id == id
            && intro.descriptor.context_id() == n["context_id"]
            && intro.inviter_host_public_key == n["host_public_key"]
            && intro.member == member
            && intro.expected_person_public_key == "-"
            && v["network_id"] == id
            && v["context_id"] == n["context_id"]
            && v["invitation_id"] == intro.id
            && v["expires_at"] == intro.expires_at,
        "the introduction changed the reviewed network/member pins"
    );
    eprintln!(
        "This private invite grants no membership. The joining machine returns a private reply code for explicit owner and administrator approval."
    );
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub(crate) async fn run(command: &Command, state: Option<&Path>) -> Result<bool> {
    if !matches!(
        command,
        Command::Join { .. }
            | Command::Invite { .. }
            | Command::Network(
                NetworkCommand::Join { .. }
                    | NetworkCommand::Invite { .. }
                    | NetworkCommand::Reinvite(_)
            )
    ) {
        return Ok(false);
    }
    let directory = state
        .map(Path::to_path_buf)
        .map(Ok)
        .unwrap_or_else(crate::default_directory)?;
    let socket = directory.join("admin.sock");
    let local = Local(&socket);
    match command {
        Command::Join {
            token,
            invitation,
            person_key,
            no_person,
            trusted,
            untrusted,
            ..
        } => {
            join(
                &socket, token, None, invitation, person_key, *no_person, *trusted, *untrusted,
            )
            .await?
        }
        Command::Network(NetworkCommand::Join {
            token,
            descriptor,
            invitation,
            person_key,
            no_person,
            trusted,
            untrusted,
            ..
        }) => {
            join(
                &socket,
                token,
                descriptor.as_deref(),
                invitation,
                person_key,
                *no_person,
                *trusted,
                *untrusted,
            )
            .await?
        }
        Command::Invite {
            label,
            network,
            expires_at,
            expires_in,
            person_key,
        } => {
            invite(
                &local, network, label, expires_at, expires_in, person_key, false,
            )
            .await?
        }
        Command::Network(NetworkCommand::Invite {
            member,
            network,
            expires_at,
            expires_in,
            person_key,
            host_only,
        }) => {
            invite(
                &local, network, member, expires_at, expires_in, person_key, *host_only,
            )
            .await?
        }
        Command::Network(NetworkCommand::Reinvite(a)) => {
            reinvite(&local, &a.old, &a.new, &a.expires_at, &a.expires_in).await?
        }
        _ => unreachable!(),
    }
    Ok(true)
}
fn text<'a>(v: &'a Value, name: &str) -> Result<&'a str> {
    v[name]
        .as_str()
        .with_context(|| format!("invalid daemon response field {name}"))
}
/// Every host a coordinator-free catalog names in a host grant (also inside
/// an activation), with its latest label and the person of its latest
/// binding, minus revoked hosts and removed persons. `catalog` is
/// `{"parsed":[{kind,payload}]}` from the parsed catalog's statements.
fn stored_members(catalog: &Value) -> Result<Vec<(String, String, String)>> {
    let objects = catalog["parsed"].as_array().context("invalid catalog")?;
    let mut hosts = std::collections::BTreeMap::<String, (u64, String)>::new();
    let mut bindings = std::collections::BTreeMap::<String, (u64, String)>::new();
    let mut revoked = std::collections::BTreeSet::new();
    let mut removed = std::collections::BTreeSet::new();
    for object in objects {
        let (kind, p) = (object["kind"].clone(), object["payload"].clone());
        let body = json!({ "kind": kind });
        let sequence = p["sequence"].as_u64().unwrap_or(0);
        let subject = &p["subject"];
        match body["kind"].as_str().unwrap_or_default() {
            "host_lease" => {
                let host = subject["host_public_key"]
                    .as_str()
                    .unwrap_or("-")
                    .to_owned();
                let label = subject["member"].as_str().unwrap_or("member").to_owned();
                if hosts.get(&host).is_none_or(|(s, _)| *s < sequence) {
                    hosts.insert(host, (sequence, label));
                }
            }
            "binding_lease" => {
                let host = subject["host_public_key"]
                    .as_str()
                    .unwrap_or("-")
                    .to_owned();
                let person = subject["person_public_key"]
                    .as_str()
                    .unwrap_or("-")
                    .to_owned();
                if bindings.get(&host).is_none_or(|(s, _)| *s < sequence) {
                    bindings.insert(host, (sequence, person));
                }
            }
            "host_revoke" => {
                revoked.insert(
                    p["target"]["host_public_key"]
                        .as_str()
                        .unwrap_or("-")
                        .to_owned(),
                );
            }
            "person_remove" => {
                removed.insert(
                    p["target"]["person_public_key"]
                        .as_str()
                        .unwrap_or("-")
                        .to_owned(),
                );
            }
            _ => {}
        }
    }
    Ok(hosts
        .into_iter()
        .filter(|(host, _)| !revoked.contains(host))
        .map(|(host, (_, label))| {
            let person = bindings
                .get(&host)
                .map(|(_, p)| p.clone())
                .unwrap_or_else(|| "-".into());
            (host, label, person)
        })
        .filter(|(_, _, person)| !removed.contains(person))
        .collect())
}
/// `network reinvite OLD NEW` (spec 14.2, DEC-Q16): one invite into NEW for
/// each member machine of OLD, through the ordinary invitation route.
async fn reinvite(
    local: &Local<'_>,
    old: &str,
    new: &str,
    expires_at: &Option<String>,
    expires_in: &Option<String>,
) -> Result<()> {
    let all = local.get("/v2/networks".into()).await?;
    let all = all.as_array().context("invalid networks")?;
    let find = |name: &str| {
        all.iter()
            .find(|n| n["id"] == name || n["name"] == name)
            .cloned()
    };
    let target =
        find(new).context("NEW must be a coordinator-free network this host belongs to")?;
    let target_id = text(&target, "id")?.to_owned();
    ensure!(
        target["mode"] == "decentralized" && target["root_state_id"] != "-",
        "NEW must be a current coordinator-free network"
    );
    let own = text(&target, "host_public_key")?.to_owned();
    // OLD: a coordinator-free network frozen by a root split, or a legacy
    // network kept as history.
    let (old_id, members) = if let Some(n) = find(old) {
        let id = text(&n, "id")?.to_owned();
        ensure!(id != target_id, "OLD and NEW are the same network");
        ensure!(
            n["root_state_id"] == "-",
            "OLD is a current network; reinvite moves members only from a legacy or root-split network"
        );
        // The stored records, not the live member view: hosts whose grants
        // have lapsed or whose path is unavailable in the split still count
        // (spec 14.2). Revoked hosts and removed persons are skipped.
        // The parsed catalog also yields grants carried inside activations
        // (members admitted through a join).
        let (plan, _, catalog) = crate::decentralized_policy_cli::planning(local, &id).await?;
        // Only bans this host admitted count; an inert one in the catalog
        // removes nobody.
        let admitted: std::collections::BTreeSet<&str> = plan["restriction_ids"]
            .as_array()
            .context("invalid planning restrictions")?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let grants: std::collections::BTreeSet<&str> = plan["admitted_ids"]
            .as_array()
            .context("invalid planning admissions")?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let objects: Vec<Value> = catalog
            .statements
            .values()
            .filter(|st| match st.kind.as_str() {
                "host_revoke" | "person_remove" => admitted.contains(st.id.as_str()),
                // Grants this host admitted, including expired ones; an inert
                // grant (one received after the split) is not a member.
                "host_lease" | "binding_lease" => grants.contains(st.id.as_str()),
                _ => true,
            })
            .map(|st| json!({"kind": st.kind, "payload": Value::Object(st.payload.clone())}))
            .collect();
        (id, stored_members(&json!({"parsed": objects}))?)
    } else {
        let v = local
            .get(format!("/v1/networks/{}/members", encoded(old)))
            .await
            .context("OLD is neither a legacy network nor a root-split network known here")?;
        let members = v.as_array().cloned().unwrap_or_default();
        // Legacy members name their person by ID; the stored person records
        // give the person key to pin (spec 14.2).
        let persons = local
            .get(format!("/v1/networks/{}/persons", encoded(old)))
            .await
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        let key_of = |id: &str| {
            persons
                .iter()
                .find(|p| p["person_id"] == id)
                .and_then(|p| p["person_public_key"].as_str())
                .unwrap_or("-")
                .to_owned()
        };
        (
            old.to_owned(),
            members
                .into_iter()
                .filter(|m| m["revoked"] != true)
                .map(|m| {
                    Ok((
                        text(&m, "public_key")
                            .or_else(|_| text(&m, "host_public_key"))?
                            .to_owned(),
                        m["member"].as_str().unwrap_or("member").to_owned(),
                        m["person_id"]
                            .as_str()
                            .map(key_of)
                            .unwrap_or_else(|| "-".into()),
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
        )
    };
    let expiry = match (expires_at, expires_in) {
        (Some(at), _) => at.clone(),
        (None, Some(duration)) => {
            // Each invite needs at least 60 seconds left when the daemon
            // makes it; allow for the whole sequential batch.
            let at = crate::integration::relative_expiry(duration)?;
            let floor = peerspan_host::clock::now()
                + chrono::TimeDelta::seconds(70 + 2 * members.len() as i64);
            if chrono::DateTime::parse_from_rfc3339(&at)?.with_timezone(&chrono::Utc) < floor {
                floor.format("%Y-%m-%dT%H:%M:%SZ").to_string()
            } else {
                at
            }
        }
        // 24 hours by default (spec 14.2), a little under so the daemon's
        // later decision time keeps it within the 24-hour maximum.
        (None, None) => (peerspan_host::clock::now() + chrono::TimeDelta::seconds(86_340))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string(),
    };
    let mut out = Vec::new();
    for (host, member, person) in members {
        if host == own {
            continue;
        }
        let raw = STANDARD.decode(&host).context("invalid member host key")?;
        let host_id = format!("host_{}", hex::encode(Sha256::digest(&raw)));
        let v = local
            .post(
                format!("/v2/networks/{}/invitations", encoded(&target_id)),
                json!({"member":member,"expected_person_public_key":person,"expires_at":expiry}),
            )
            .await?;
        out.push(json!({"member":member,"host_id":host_id,"person_public_key":person,
            "invitation_id":v["invitation_id"],"invitation":v["invitation"],"expires_at":v["expires_at"]}));
    }
    let _ = old_id;
    println!("{}", serde_json::to_string_pretty(&Value::Array(out))?);
    Ok(())
}
