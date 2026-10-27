//! Explicit whole-network migration. Public files are bounded and typed;
//! original keys sign only fixed, reviewed roles on this machine.
use crate::{admin::Local, cli::encoded};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Args, Subcommand};
use peerspan_host::{
    decentralized::{
        Descriptor, FixedStatement, Statement, local_decision_time, migration_inherited_bans,
        migration_person_labels,
    },
    persons::PersonSigner,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, IsTerminal, Read},
    path::{Path, PathBuf},
};

#[derive(Debug, Args)]
pub struct MigrationArgs {
    #[command(subcommand)]
    command: MigrationCommand,
}
#[derive(Debug, Args)]
struct Target {
    /// Exact existing legacy network ID; migration never creates a network.
    network_id: String,
    /// Exact retained proposal; omission uses this host's retained proposal.
    #[arg(long)]
    proposal: Option<String>,
}
#[derive(Debug, Args)]
struct Consent {
    #[command(flatten)]
    target: Target,
    /// Approve the displayed exact operation; omission previews or asks y/N.
    #[arg(long)]
    approve: bool,
}
#[derive(Debug, Subcommand)]
enum MigrationCommand {
    /// Review this host's preserved original person and owned device identity.
    Identity {
        #[command(flatten)]
        consent: Consent,
        /// Owned device scopes; use 0 for an unbound host.
        #[arg(long, default_value_t = 7)]
        scopes: u64,
    },
    /// Review the complete roster and current-root source endorsement.
    Prepare {
        #[command(flatten)]
        consent: Consent,
        /// Exact complete JSON roster; - reads bounded public input from stdin.
        #[arg(long)]
        roster_file: PathBuf,
        #[arg(long)]
        root_key: Option<PathBuf>,
    },
    /// Review this host's participation in the exact retained proposal.
    Review(Consent),
    /// Consent to only this unbound host's exact root-signed finite lease.
    HostLease {
        #[command(flatten)]
        consent: Consent,
        #[arg(long)]
        host_lease_file: PathBuf,
    },
    /// Copy required inherited device bans using that exact original person.
    DeviceBans {
        #[command(flatten)]
        consent: Consent,
        #[arg(long)]
        person: String,
        #[arg(long, alias = "person-key-file")]
        person_key: Option<PathBuf>,
    },
    /// Create this host's explicit staged request; no active membership results.
    Link(Target),
    /// Acknowledge the exact complete prepared catalog and durably fence legacy use.
    Ack {
        #[command(flatten)]
        consent: Consent,
        #[arg(long)]
        prepared_catalog: Option<String>,
    },
    /// Approve the current root's exact all-host commit.
    Commit {
        #[command(flatten)]
        consent: Consent,
        #[arg(long)]
        prepared_catalog: Option<String>,
        /// Exact ACK IDs, repeatable; omission uses all retained public ACKs.
        #[arg(long = "acknowledgment")]
        acknowledgments: Vec<String>,
        #[arg(long)]
        root_key: Option<PathBuf>,
    },
    /// Apply only the exact complete transition already approved by this host's ACK.
    Adopt {
        #[command(flatten)]
        consent: Consent,
        #[arg(long)]
        commit: Option<String>,
    },
    /// Resume only previously approved work; never supplies new consent.
    Resume {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        root_key: Option<PathBuf>,
        #[arg(long)]
        person_key: Option<PathBuf>,
    },
    /// Read migration progress without signing or changing authority.
    Status { network_id: String },
    /// Export exact public evidence, or import a bounded file without approval.
    Evidence {
        network_id: String,
        /// Exact public evidence carrier; - reads stdin. Omit to export.
        #[arg(long)]
        evidence_file: Option<PathBuf>,
    },
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RosterRow {
    host_public_key: String,
    member: String,
    person_public_key: String,
    device_public_key: String,
    scopes: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    proposal_base64: String,
    source_catalog_base64: String,
    source_state_base64: String,
    prepared_catalog_base64: String,
    acknowledgments_base64: Vec<String>,
    commit_base64: String,
}
fn text<'a>(v: &'a Value, field: &str) -> Result<&'a str> {
    v[field]
        .as_str()
        .with_context(|| format!("invalid migration {field}"))
}
fn shape(v: &Value, fields: &str) -> Result<()> {
    let o = v.as_object().context("invalid migration object")?;
    let names: Vec<_> = fields.split_whitespace().collect();
    ensure!(
        o.len() == names.len() && names.iter().all(|f| o.contains_key(*f)),
        "unexpected migration fields"
    );
    Ok(())
}
fn ident(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 64
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn decode(value: &str, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        value.len() <= limit.div_ceil(3) * 4,
        "public migration input exceeds bound"
    );
    let raw = STANDARD.decode(value)?;
    ensure!(
        raw.len() <= limit && STANDARD.encode(&raw) == value,
        "noncanonical public migration input"
    );
    Ok(raw)
}
fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    let reader: Box<dyn Read> = if path == Path::new("-") {
        Box::new(io::stdin())
    } else {
        Box::new(std::fs::File::open(path)?)
    };
    reader.take(limit as u64 + 1).read_to_end(&mut raw)?;
    ensure!(raw.len() <= limit, "public migration file exceeds bound");
    Ok(raw)
}
fn output(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
fn view(v: &Value, network: &str) -> Result<()> {
    shape(
        v,
        "network_id proposal_id context_id state source_catalog_sha256 source_state_sha256 prepared_catalog_sha256 root_state_id local_acknowledgment_id root_commit_id missing_host_keys required_proof_ids approved fenced expires_at",
    )?;
    ensure!(
        v["network_id"] == network && v["approved"].is_boolean() && v["fenced"].is_boolean(),
        "migration view changes network or consent shape"
    );
    Ok(())
}
fn review(v: &Value, network: &str) -> Result<()> {
    view(&v["migration"], network)?;
    ensure!(
        v["signing_requests"]
            .as_array()
            .is_some_and(|s| s.len() <= 16),
        "invalid migration signing batch"
    );
    let r = &v["review"];
    match text(r, "stage")? {
        "identity" => shape(v, "migration identity review signing_requests")?,
        "host_membership" => {
            shape(v, "migration host_lease_base64 review signing_requests")?;
            shape(
                r,
                "stage network_id proposal_id host_public_key member root_state_id host_lease_id issued_at not_before not_after authority_warning",
            )?;
        }
        "inherited_device_bans" => {
            shape(v, "migration review signing_requests")?;
            shape(
                r,
                "stage network_id proposal_id new_context_id person_public_key root_state_id person_lease_id source_catalog_sha256 source_state_sha256 copies access_maxima authority_warning",
            )?;
        }
        "proposal" | "participation" | "acknowledgment" | "root_commit" | "adoption" => {
            shape(v, "migration review signing_requests")?;
        }
        _ => bail!("unknown migration review stage"),
    }
    ensure!(
        r["network_id"] == network && !text(r, "authority_warning")?.is_empty(),
        "migration review changes selected network"
    );
    if r["stage"] != "identity" {
        ensure!(
            r["proposal_id"] == v["migration"]["proposal_id"],
            "migration review changes proposal"
        );
    }
    if r["stage"] != "identity" && r["stage"] != "host_membership" {
        ensure!(
            r["new_context_id"] == v["migration"]["context_id"],
            "migration review changes proposal or context"
        );
    }
    Ok(())
}
fn comparable(mut review: Value) -> Value {
    if let Some(object) = review.as_object_mut() {
        object.remove("authority_warning");
    }
    review
}
fn same_approval_review(before: &Value, after: &Value) -> Result<()> {
    let before = comparable(before.clone());
    let mut after = comparable(after.clone());
    let pending = match text(&before, "stage")? {
        "identity" => Some(("roster", "device_public_key")),
        "inherited_device_bans" => Some(("copies", "statement_id")),
        _ => None,
    };
    if let Some((list, field)) = pending {
        let old = before[list]
            .as_array()
            .context("invalid pending migration review")?;
        let new = after[list]
            .as_array_mut()
            .context("invalid approved migration review")?;
        ensure!(
            old.len() == new.len(),
            "approval changes reviewed migration rows"
        );
        for (old, new) in old.iter().zip(new) {
            // Only an actually unknown preview pin may become fixed. Once a
            // device/template ID exists, every approval and signature keeps it.
            if old[field] == "-" {
                if field == "device_public_key" && old["person_public_key"] == "-" {
                    ensure!(
                        new[field] == "-",
                        "unbound migration identity gained a device"
                    );
                    continue;
                }
                let fixed = text(new, field)?;
                ensure!(
                    if field == "statement_id" {
                        ident(fixed, "ds_")
                    } else {
                        decode(fixed, 32)?.len() == 32
                    },
                    "approval did not fix the pending migration identity"
                );
                new[field] = json!("-");
            }
        }
    }
    ensure!(before == after, "approval changes exact migration review");
    Ok(())
}
async fn consent(
    local: &Local<'_>,
    base: &str,
    operation: &str,
    mut body: Value,
    network: &str,
    approve: bool,
) -> Result<Value> {
    body["approve"] = json!(false);
    let before = local
        .post(format!("{base}/{operation}"), body.clone())
        .await?;
    if operation == "adopt" {
        shape(&before, "migration network")?;
        view(&before["migration"], network)?;
        eprintln!(
            "Adopt exact migration {} commit {}. Prior host acknowledgment is irreversible; expired grants stay expired.",
            text(&body, "proposal_id")?,
            text(&body, "commit_id")?
        );
    } else {
        review(&before, network)?;
        eprintln!("{}", serde_json::to_string_pretty(&before["review"])?);
    }
    let approved = approve
        || io::stdin().is_terminal()
            && matches!(
                crate::up::prompt("Approve this exact migration operation? (y/N)", "no", false)
                    .await?
                    .trim()
                    .to_ascii_lowercase()
                    .as_str(),
                "y" | "yes"
            );
    if !approved {
        return Ok(before);
    }
    body["approve"] = json!(true);
    let after = local.post(format!("{base}/{operation}"), body).await?;
    if operation == "adopt" {
        view(&after["migration"], network)?;
        ensure!(
            after["migration"]["proposal_id"] == before["migration"]["proposal_id"],
            "adoption changes exact proposal"
        );
    } else {
        review(&after, network)?;
        same_approval_review(&before["review"], &after["review"])?;
        if operation == "identity" && before["identity"]["device_public_key"] != "-" {
            ensure!(
                after["identity"]["device_public_key"] == before["identity"]["device_public_key"],
                "identity approval replaces an existing owned device"
            );
        }
    }
    Ok(after)
}
fn descriptor(raw: &[u8]) -> Result<Descriptor> {
    let outer: Value = serde_json::from_slice(raw)?;
    let payload: Value =
        serde_json::from_slice(&decode(text(&outer, "payload_base64")?, 256 << 10)?)?;
    Ok(Descriptor::read(&serde_json::to_vec(
        &payload["new_descriptor"],
    )?)?)
}
async fn evidence(local: &Local<'_>, base: &str) -> Result<Evidence> {
    Ok(serde_json::from_value(
        local.get(format!("{base}/evidence")).await?,
    )?)
}
struct SourceFacts {
    people: BTreeMap<String, String>,
    bans: Vec<Value>,
    maxima: Value,
}
async fn source_facts(local: &Local<'_>, base: &str, d: &Descriptor) -> Result<SourceFacts> {
    let carrier = evidence(local, base).await?;
    let value = serde_json::to_value(&carrier)?;
    // These pure readers authenticate the signed proposal, exact source hashes,
    // complete legacy source and roster before any source-derived signature.
    let people = migration_person_labels(d, &value)?;
    let bans = migration_inherited_bans(d, &value)?;
    let state: Value = serde_json::from_slice(&decode(&carrier.source_state_base64, 256 << 10)?)?;
    Ok(SourceFacts {
        people,
        bans,
        maxima: state["access_maxima"].clone(),
    })
}
fn root_statement(
    s: &Statement,
    r: &Value,
    migration: &Value,
    root: &str,
    source: Option<&SourceFacts>,
) -> Result<()> {
    let p = Value::Object(s.payload.clone());
    match s.kind.as_str() {
        "migration_proposal" => ensure!(
            s.id == text(r, "proposal_id")?
                && p["legacy_root_public_key"] == root
                && p["legacy_epoch"] == r["legacy_epoch"]
                && p["roster"] == r["roster"]
                && p["source_catalog_sha256"] == r["source_catalog_sha256"]
                && p["source_state_sha256"] == r["source_state_sha256"],
            "proposal differs from reviewed source and roster"
        ),
        "root_state" => ensure!(
            p["epoch"] == r["legacy_epoch"]
                && p["root_public_key"] == root
                && p["migration_proposal_id"] == r["proposal_id"]
                && p["predecessors"] == json!([])
                && p["resolves"] == json!([])
                && p["retained_statement_ids"] == json!([]),
            "initial root differs from reviewed migration"
        ),
        "person_lease" | "host_lease" => {
            ensure!(
                p["root_state_id"] == migration["root_state_id"]
                    && p["sequence"] == 1
                    && p["predecessors"] == json!([])
                    && p["resolves"] == json!([])
                    && p["retained_statement_ids"] == json!([])
                    && p["parents"] == json!([])
                    && p["issuer"] == json!({"kind":"root","person_public_key":"-"})
                    && p["subject"]["scopes"] == 0,
                "finite migration lease changes reviewed authority"
            );
            if s.kind == "host_lease" {
                ensure!(
                    p["operation_id"] == r["proposal_id"]
                        && p["subject"]["person_public_key"] == "-"
                        && p["subject"]["device_public_key"] == "-"
                        && r["roster"].as_array().is_some_and(|rows| rows.iter().any(
                            |row| row["person_public_key"] == "-"
                                && row["host_public_key"] == p["subject"]["host_public_key"]
                                && row["member"] == p["subject"]["member"]
                        )),
                    "finite host lease is outside unbound roster"
                );
            } else {
                let source =
                    source.context("signed endorsed source is required before person issuance")?;
                ensure!(
                    p["operation_id"] == "-"
                        && p["subject"]["host_public_key"] == "-"
                        && p["subject"]["device_public_key"] == "-"
                        && source
                            .people
                            .get(text(&p["subject"], "person_public_key")?)
                            .is_some_and(|member| p["subject"]["member"] == member.as_str()),
                    "invalid shared person lease"
                );
            }
            let start = chrono::DateTime::parse_from_rfc3339(text(&p, "not_before")?)?;
            let end = chrono::DateTime::parse_from_rfc3339(text(&p, "not_after")?)?;
            ensure!(
                end > start && end - start <= chrono::Duration::days(7),
                "migration lease is not finite within seven days"
            );
        }
        "person_remove" | "host_revoke" => {
            let source =
                source.context("signed endorsed source is required before root ban copies")?;
            ensure!(
                p["root_state_id"] == migration["root_state_id"]
                    && p["issuer"] == json!({"kind":"root","person_public_key":"-"})
                    && p["parents"] == json!([])
                    && p["kept_statement_ids"] == json!([])
                    && p["ratifies"] == "-"
                    && p["target"]["statement_id"] == "-"
                    && source.bans.iter().any(|ban| {
                        ban["kind"] == s.kind
                            && ban["person_public_key"] == p["target"]["person_public_key"]
                            && ban["host_public_key"] == p["target"]["host_public_key"]
                            && ban["device_public_key"] == p["target"]["device_public_key"]
                    }),
                "root copy is outside exact verified inherited person/host bans"
            );
        }
        "migration_commit" => ensure!(
            p["proposal_id"] == r["proposal_id"]
                && p["root_state_id"] == migration["root_state_id"]
                && p["prepared_catalog_sha256"] == r["prepared_catalog_sha256"],
            "root commit changes reviewed prepared state"
        ),
        _ => bail!("unreviewed migration root statement kind"),
    }
    Ok(())
}
fn ban_statement(s: &Statement, r: &Value, person: &str, source: &SourceFacts) -> Result<()> {
    let p = Value::Object(s.payload.clone());
    ensure!(
        r["stage"] == "inherited_device_bans"
            && r["person_public_key"] == person
            && s.kind == "device_revoke"
            && p["root_state_id"] == r["root_state_id"]
            && p["issuer"] == json!({"kind":"person","person_public_key":person})
            && p["target"]["person_public_key"] == person
            && p["target"]["host_public_key"] == "-"
            && p["target"]["statement_id"] == "-"
            && p["kept_statement_ids"] == json!([])
            && p["ratifies"] == "-",
        "inherited ban changes reviewed original-person authority"
    );
    ensure!(
        r["copies"].as_array().is_some_and(|copies| copies
            .iter()
            .any(|copy| copy["statement_id"] == s.id
                && copy["device_public_key"] == p["target"]["device_public_key"])),
        "device ban is outside exact reviewed copies"
    );
    ensure!(
        s.parents()?.len() == 1
            && s.parents()?.get("issuer_person").map(String::as_str)
                == Some(text(r, "person_lease_id")?),
        "inherited ban changes shared pending person lease"
    );
    let expected = source
        .bans
        .iter()
        .filter(|ban| ban["kind"] == "device_revoke" && ban["person_public_key"] == person)
        .collect::<Vec<_>>();
    let copies = r["copies"]
        .as_array()
        .context("missing exact inherited copies")?;
    ensure!(
        copies.len() == expected.len()
            && r["access_maxima"] == source.maxima
            && expected.iter().all(|ban| copies.iter().any(|copy| {
                copy["device_public_key"] == ban["device_public_key"]
                    && copy["source_proof_ids"] == ban["source_proof_ids"]
            })),
        "inherited copy review changes complete source targets, proofs or maxima"
    );
    Ok(())
}
fn commit_acknowledgments(d: &Descriptor, carrier: &Evidence, result: &Value) -> Result<Value> {
    let review = &result["review"];
    let mut hosts = BTreeSet::new();
    let mut ids = Vec::new();
    ensure!(
        carrier.acknowledgments_base64.len() <= 4096,
        "too many migration ACKs"
    );
    for raw in &carrier.acknowledgments_base64 {
        let ack = Statement::read(d, &decode(raw, 1 << 20)?)?;
        let payload = Value::Object(ack.payload.clone());
        ensure!(
            ack.kind == "migration_ack"
                && payload["proposal_id"] == review["proposal_id"]
                && payload["root_state_id"] == result["migration"]["root_state_id"]
                && payload["prepared_catalog_sha256"] == review["prepared_catalog_sha256"]
                && hosts.insert(text(&payload, "host_public_key")?.to_owned()),
            "commit evidence changes exact proposal, root, prepared state or host set"
        );
        ids.push(ack.id);
    }
    let roster = review["roster"]
        .as_array()
        .context("missing exact migration roster")?;
    let expected = roster
        .iter()
        .map(|row| text(row, "host_public_key").map(str::to_owned))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        hosts == expected && ids.len() == roster.len(),
        "root commit needs every exact roster ACK"
    );
    ids.sort();
    Ok(json!(ids))
}
async fn sign(
    local: &Local<'_>,
    base: &str,
    network: &str,
    mut result: Value,
    root_key: Option<&Path>,
    person_key: Option<&Path>,
) -> Result<Value> {
    if result["signing_requests"]
        .as_array()
        .is_none_or(Vec::is_empty)
    {
        return Ok(result);
    }
    review(&result, network)?;
    let reviewed = comparable(result["review"].clone());
    let mut proposal_raw = None;
    for slot in result["signing_requests"]
        .as_array()
        .context("missing migration slots")?
    {
        if slot["object_type"] == "migration_proposal" {
            proposal_raw = Some(decode(text(slot, "template_base64")?, 1 << 20)?);
            break;
        }
    }
    let proposal_raw = match proposal_raw {
        Some(raw) => raw,
        None => decode(&evidence(local, base).await?.proposal_base64, 1 << 20)?,
    };
    let d = descriptor(&proposal_raw)?;
    ensure!(
        d.network_id == network && d.context_id() == text(&result["review"], "new_context_id")?,
        "migration descriptor changes reviewed context"
    );
    let proposal = FixedStatement::read(&d, &proposal_raw)?;
    let p = Value::Object(proposal.typed().payload.clone());
    ensure!(
        proposal.typed().kind == "migration_proposal"
            && proposal.statement_id() == text(&result["review"], "proposal_id")?,
        "migration proposal changes reviewed identity"
    );
    let commit_ids = if result["review"]["stage"] == "root_commit" {
        Some(commit_acknowledgments(
            &d,
            &evidence(local, base).await?,
            &result,
        )?)
    } else {
        None
    };
    let mut keys = BTreeMap::new();
    for path in [root_key, person_key].into_iter().flatten() {
        let key = PersonSigner::open(Some(path))?;
        keys.insert(key.public_key_b64(), key);
    }
    let mut fixed_templates = BTreeMap::<(String, u64), String>::new();
    let mut signing_migration = result["migration"].clone();
    let mut source = None;
    for _ in 0..4096 {
        review(&result, network)?;
        ensure!(
            comparable(result["review"].clone()) == reviewed,
            "migration review changed between signature batches"
        );
        let slots = result["signing_requests"]
            .as_array()
            .context("invalid migration slots")?;
        if slots.is_empty() {
            return Ok(result);
        }
        let proposal_pending = slots
            .iter()
            .any(|slot| slot["object_type"] == "migration_proposal");
        if !proposal_pending && source.is_none() {
            source = Some(source_facts(local, base, &d).await?);
        }
        let now = local_decision_time()?;
        ensure!(
            now.as_str() >= text(&p, "issued_at")? && now.as_str() < text(&p, "expires_at")?,
            "expired: retain exact migration preparation without new signatures"
        );
        let mut intent = None;
        let mut batch = Vec::new();
        let mut seen = BTreeSet::new();
        for slot in slots {
            shape(
                slot,
                "intent_id slot_id object_id object_type role public_key format message_base64 template_base64",
            )?;
            let id = text(slot, "intent_id")?;
            ensure!(
                intent.is_none_or(|old| old == id),
                "mixed migration intents"
            );
            intent = Some(id);
            let number = slot["slot_id"]
                .as_u64()
                .filter(|n| *n > 0)
                .context("invalid migration slot")?;
            let role = text(slot, "role")?;
            ensure!(
                seen.insert((number, role)),
                "duplicate migration signing slot"
            );
            let template = text(slot, "template_base64")?;
            let raw = decode(template, 1 << 20)?;
            let typed = FixedStatement::read(&d, &raw)?;
            ensure!(
                typed.statement_id() == text(slot, "object_id")?
                    && typed.typed().kind == text(slot, "object_type")?,
                "migration signing object changed"
            );
            // Endorse the exact reviewed proposal first. Its signed public
            // source can then be independently verified before any P/H/ban.
            if proposal_pending && typed.typed().kind != "migration_proposal" {
                continue;
            }
            // Host roles are completed only by the daemon that owns that host.
            if role == "host" && typed.typed().kind == "host_lease" {
                continue;
            }
            if let Some(previous) =
                fixed_templates.insert((id.to_owned(), number), template.to_owned())
            {
                ensure!(
                    previous == template,
                    "fixed migration template changed between batches"
                );
            }
            ensure!(
                role == "issuer" && slot["format"] == "sshsig",
                "migration external signer is not an exact original SSHSIG issuer"
            );
            let public = text(slot, "public_key")?;
            if result["review"]["stage"] == "inherited_device_bans" {
                ban_statement(
                    typed.typed(),
                    &result["review"],
                    public,
                    source
                        .as_ref()
                        .context("missing verified inherited source")?,
                )?;
            } else {
                ensure!(
                    result["review"]["legacy_root_public_key"] == public,
                    "migration slot changes exact current legacy root"
                );
                if typed.typed().kind == "root_state" {
                    ensure!(
                        signing_migration["root_state_id"] == "-"
                            || signing_migration["root_state_id"] == typed.statement_id(),
                        "migration initial root template changed"
                    );
                    signing_migration["root_state_id"] = json!(typed.statement_id());
                }
                root_statement(
                    typed.typed(),
                    &result["review"],
                    &signing_migration,
                    public,
                    source.as_ref(),
                )?;
                if typed.typed().kind == "migration_commit" {
                    ensure!(
                        typed.typed().payload.get("acknowledgment_ids") == commit_ids.as_ref(),
                        "root commit changes the exact verified all-host ACK IDs"
                    );
                }
            }
            let declared = typed
                .pending()
                .into_iter()
                .find(|s| s.role == role)
                .context("migration slot is already filled")?;
            ensure!(
                declared.public_key == public
                    && declared.signature_format == "sshsig"
                    && declared.message_base64 == text(slot, "message_base64")?,
                "migration signing message differs from typed role"
            );
            let key=keys.get(public).with_context(||format!("signer_unavailable: retain intent {id}; select exact original {public} with --root-key or --person-key on its original machine"))?;
            let message = String::from_utf8(decode(&declared.message_base64, 4096)?)?;
            let signature = key.sign(&message.split('\n').collect::<Vec<_>>())?;
            typed.fill(&d, role, &signature)?;
            batch.push(json!({"slot_id":number,"role":role,"signature":signature}));
            if typed.typed().kind == "migration_proposal" {
                break;
            }
        }
        if batch.is_empty() {
            return Ok(result);
        }
        result = local
            .post(
                format!("{base}/signed"),
                json!({"intent_id":intent.context("missing migration intent")?,"signatures":batch}),
            )
            .await?;
    }
    bail!("migration signature batch bound exceeded; retain exact pending work")
}
async fn proposal(local: &Local<'_>, base: &str, target: &Target) -> Result<String> {
    let view_value = local.get(base.into()).await?;
    view(&view_value, &target.network_id)?;
    let retained = text(&view_value, "proposal_id")?;
    if let Some(expected) = &target.proposal {
        ensure!(
            expected == retained,
            "retained migration differs from --proposal"
        );
    }
    ensure!(
        ident(retained, "ds_"),
        "prepare or import the exact proposal first"
    );
    Ok(retained.into())
}
async fn prepared(local: &Local<'_>, base: &str, given: Option<String>) -> Result<String> {
    let view = local.get(base.into()).await?;
    let retained = text(&view, "prepared_catalog_sha256")?;
    let hash = given.unwrap_or_else(|| retained.into());
    ensure!(
        ident(&hash, "") && hash == retained,
        "supply the exact retained prepared catalog hash"
    );
    Ok(hash)
}
pub async fn run(args: MigrationArgs, state: Option<PathBuf>) -> Result<()> {
    let directory = state.map(Ok).unwrap_or_else(crate::default_directory)?;
    let socket = directory.join("admin.sock");
    let local = Local(&socket);
    let network = match &args.command {
        MigrationCommand::Identity { consent, .. }
        | MigrationCommand::Prepare { consent, .. }
        | MigrationCommand::HostLease { consent, .. }
        | MigrationCommand::DeviceBans { consent, .. }
        | MigrationCommand::Ack { consent, .. }
        | MigrationCommand::Commit { consent, .. }
        | MigrationCommand::Adopt { consent, .. }
        | MigrationCommand::Review(consent) => &consent.target.network_id,
        MigrationCommand::Link(target) | MigrationCommand::Resume { target, .. } => {
            &target.network_id
        }
        MigrationCommand::Status { network_id } | MigrationCommand::Evidence { network_id, .. } => {
            network_id
        }
    }
    .clone();
    ensure!(
        ident(&network, "net_"),
        "an exact existing legacy network ID is required"
    );
    let base = format!("/v2/networks/{}/migration", encoded(&network));
    let result = match args.command {
        MigrationCommand::Status { .. } => {
            let v = local.get(base).await?;
            view(&v, &network)?;
            v
        }
        MigrationCommand::Evidence { evidence_file, .. } => {
            if let Some(path) = evidence_file {
                let carrier: Evidence = serde_json::from_slice(&read_file(&path, 20 << 20)?)?;
                decode(&carrier.proposal_base64, 1 << 20)?;
                decode(&carrier.source_catalog_base64, 512 << 10)?;
                decode(&carrier.source_state_base64, 256 << 10)?;
                ensure!(
                    carrier.acknowledgments_base64.len() <= 4096,
                    "too many migration acknowledgments"
                );
                for raw in &carrier.acknowledgments_base64 {
                    decode(raw, 1 << 20)?;
                }
                for raw in [&carrier.prepared_catalog_base64, &carrier.commit_base64] {
                    if raw != "-" {
                        decode(raw, 1 << 20)?;
                    }
                }
                local
                    .post(format!("{base}/evidence"), serde_json::to_value(carrier)?)
                    .await?
            } else {
                serde_json::to_value(evidence(&local, &base).await?)?
            }
        }
        MigrationCommand::Identity { consent: c, scopes } => {
            ensure!(
                c.target.proposal.is_none(),
                "identity selection precedes proposal preparation; omit --proposal"
            );
            consent(
                &local,
                &base,
                "identity",
                json!({"scopes":scopes}),
                &network,
                c.approve,
            )
            .await?
        }
        MigrationCommand::Prepare {
            consent: c,
            roster_file,
            root_key,
        } => {
            if c.target.proposal.is_some() {
                proposal(&local, &base, &c.target).await?;
            }
            let roster: Vec<RosterRow> =
                serde_json::from_slice(&read_file(&roster_file, 1 << 20)?)?;
            ensure!(
                !roster.is_empty() && roster.len() <= 4096,
                "invalid complete migration roster"
            );
            let v=consent(&local,&base,"prepare",json!({"roster":roster,"signature_format":if root_key.is_some(){"sshsig"}else{"auto"}}),&network,c.approve).await?;
            if let Some(pin) = c.target.proposal {
                ensure!(
                    v["migration"]["proposal_id"] == pin,
                    "prepared proposal differs from --proposal"
                );
            }
            sign(&local, &base, &network, v, root_key.as_deref(), None).await?
        }
        MigrationCommand::Review(c) => {
            let p = proposal(&local, &base, &c.target).await?;
            consent(
                &local,
                &base,
                "review",
                json!({"proposal_id":p}),
                &network,
                c.approve,
            )
            .await?
        }
        MigrationCommand::HostLease {
            consent: c,
            host_lease_file,
        } => {
            let p = proposal(&local, &base, &c.target).await?;
            let raw = read_file(&host_lease_file, 1 << 20)?;
            let carrier = evidence(&local, &base).await?;
            let d = descriptor(&decode(&carrier.proposal_base64, 1 << 20)?)?;
            let typed = FixedStatement::read(&d, &raw)?;
            let own = local.get("/v1/host".into()).await?;
            ensure!(
                typed.typed().kind == "host_lease"
                    && typed.typed().payload.get("operation_id") == Some(&json!(p))
                    && typed.typed().subject()?.get("host_public_key") == Some(&own["public_key"]),
                "host lease does not name this exact proposal and host"
            );
            consent(
                &local,
                &base,
                "host-lease",
                json!({"proposal_id":p,"host_lease_base64":STANDARD.encode(raw)}),
                &network,
                c.approve,
            )
            .await?
        }
        MigrationCommand::DeviceBans {
            consent: c,
            person,
            person_key,
        } => {
            let p = proposal(&local, &base, &c.target).await?;
            let v = consent(
                &local,
                &base,
                "device-bans",
                json!({"proposal_id":p,"person_public_key":person}),
                &network,
                c.approve,
            )
            .await?;
            sign(&local, &base, &network, v, None, person_key.as_deref()).await?
        }
        MigrationCommand::Link(target) => {
            let p = proposal(&local, &base, &target).await?;
            let v = local
                .post(format!("{base}/link"), json!({"proposal_id":p}))
                .await?;
            output(&v)?;
            bail!(
                "migration request remains pending: review its separate original-person, administrator and requester consents; no agent attachment is ready"
            )
        }
        MigrationCommand::Ack {
            consent: c,
            prepared_catalog,
        } => {
            let p = proposal(&local, &base, &c.target).await?;
            let hash = prepared(&local, &base, prepared_catalog).await?;
            consent(
                &local,
                &base,
                "acknowledgment",
                json!({"proposal_id":p,"prepared_catalog_sha256":hash}),
                &network,
                c.approve,
            )
            .await?
        }
        MigrationCommand::Commit {
            consent: c,
            prepared_catalog,
            mut acknowledgments,
            root_key,
        } => {
            let p = proposal(&local, &base, &c.target).await?;
            let hash = prepared(&local, &base, prepared_catalog).await?;
            if acknowledgments.is_empty() {
                let carrier = evidence(&local, &base).await?;
                let d = descriptor(&decode(&carrier.proposal_base64, 1 << 20)?)?;
                for raw in carrier.acknowledgments_base64 {
                    let ack = Statement::read(&d, &decode(&raw, 1 << 20)?)?;
                    ensure!(ack.kind == "migration_ack", "non-ACK evidence");
                    acknowledgments.push(ack.id);
                }
            }
            acknowledgments.sort();
            ensure!(
                acknowledgments.windows(2).all(|v| v[0] < v[1]),
                "duplicate acknowledgment IDs"
            );
            let v=consent(&local,&base,"commit",json!({"proposal_id":p,"prepared_catalog_sha256":hash,"acknowledgment_ids":acknowledgments,"signature_format":if root_key.is_some(){"sshsig"}else{"auto"}}),&network,c.approve).await?;
            sign(&local, &base, &network, v, root_key.as_deref(), None).await?
        }
        MigrationCommand::Adopt { consent: c, commit } => {
            let p = proposal(&local, &base, &c.target).await?;
            let v = local.get(base.clone()).await?;
            let retained = text(&v, "root_commit_id")?;
            let commit = commit.unwrap_or_else(|| retained.into());
            ensure!(
                ident(&commit, "ds_") && commit == retained,
                "supply exact retained root commit"
            );
            consent(
                &local,
                &base,
                "adopt",
                json!({"proposal_id":p,"commit_id":commit}),
                &network,
                c.approve,
            )
            .await?
        }
        MigrationCommand::Resume {
            target,
            root_key,
            person_key,
        } => {
            proposal(&local, &base, &target).await?;
            let v = local.post(format!("{base}/resume"), json!({})).await?;
            sign(
                &local,
                &base,
                &network,
                v,
                root_key.as_deref(),
                person_key.as_deref(),
            )
            .await?
        }
    };
    output(&result)
}
