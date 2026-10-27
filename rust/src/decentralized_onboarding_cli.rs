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
        "Return the private reply code to the inviting machine for explicit owner and administrator approval. Membership remains pending."
    );
    Ok(v)
}

async fn join(
    socket: &Path,
    token: &Option<String>,
    descriptor: Option<&str>,
    input: &InvitationInput,
    person_key: &Option<PathBuf>,
    no_person: bool,
    trusted: bool,
) -> Result<()> {
    ensure!(
        token.is_none() && descriptor.is_none() && !no_person,
        "join needs a private psi2 introduction before choosing --person-key; use --invite-stdin or --invite-file and explicit machine approval"
    );
    ensure!(
        !trusted,
        "review a separate typed trust policy after linking"
    );
    let token = input.read().await?;
    let v = create_join(&Local(socket), &token, person_key).await?;
    let v = crate::decentralized_link_cli::guide(socket, v, io::stdin().is_terminal()).await?;
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
        expires_at.is_none() && expires_in.is_none() && person_key.is_none() && !host_only,
        "a contact introduction has a fixed five-minute window and grants no authority; use explicit machine approval"
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
    let v = local
        .post(
            format!("/v2/networks/{}/invitations", encoded(id)),
            json!({"member":member,"expected_person_public_key":"-"}),
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
        "This private introduction grants no membership. The joining machine returns a private reply code for explicit owner and administrator approval."
    );
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub(crate) async fn run(command: &Command, state: Option<&Path>) -> Result<bool> {
    if !matches!(
        command,
        Command::Join { .. }
            | Command::Invite { .. }
            | Command::Network(NetworkCommand::Join { .. } | NetworkCommand::Invite { .. })
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
            ..
        } => {
            join(
                &socket, token, None, invitation, person_key, *no_person, *trusted,
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
        _ => unreachable!(),
    }
    Ok(true)
}
