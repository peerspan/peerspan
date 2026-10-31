//! Native root management reviews exact retention and signs only fixed root roles.
//! Every branch remains explicit; SSH keys stay on their original machine.
use crate::{
    admin::Local,
    cli::{Command, NetworkCommand, encoded},
};
use anyhow::{Context, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::Signer;
use peerspan_host::{
    decentralized::{Catalog, Descriptor, FixedStatement, Statement},
    persons::PersonSigner,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

fn text<'a>(v: &'a Value, field: &str) -> anyhow::Result<&'a str> {
    v[field]
        .as_str()
        .with_context(|| format!("invalid root {field}"))
}
fn shape(v: &Value, fields: &str) -> anyhow::Result<()> {
    let o = v.as_object().context("invalid root object")?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    ensure!(
        o.len() == fields.len() && fields.iter().all(|f| o.contains_key(*f)),
        "unexpected root fields"
    );
    Ok(())
}
fn ident(id: &str, prefix: &str) -> bool {
    id.len() == prefix.len() + 64
        && id.starts_with(prefix)
        && id[prefix.len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn ids(v: &Value) -> anyhow::Result<Vec<String>> {
    let values = v.as_array().context("invalid root statement IDs")?;
    let mut output = Vec::new();
    for value in values {
        let id = value.as_str().context("invalid root statement ID")?;
        ensure!(
            ident(id, "ds_") && output.last().is_none_or(|old: &String| old.as_str() < id),
            "root IDs must be canonical, sorted and unique"
        );
        output.push(id.to_owned());
    }
    Ok(output)
}
fn decode(s: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = STANDARD.decode(s)?;
    ensure!(STANDARD.encode(&bytes) == s, "noncanonical root template");
    Ok(bytes)
}
fn descriptor(network: &Value, id: &str) -> anyhow::Result<Descriptor> {
    ensure!(
        network["mode"] == "decentralized" && network["id"] == id,
        "root management requires the exact decentralized network"
    );
    let d = Descriptor::read(&serde_json::to_vec(
        &json!({"format":1,"protocol":"peerspan-decentralized-v1","network_id":id,"name":network["name"],"genesis_root_public_key":network["genesis_root_public_key"]}),
    )?)?;
    ensure!(
        d.context_id() == text(network, "context_id")?,
        "root context mismatch"
    );
    Ok(d)
}
struct Plan {
    value: Value,
    descriptor: Descriptor,
    catalog: Catalog,
    heads: Vec<String>,
    epoch: u64,
}
async fn plan(local: &Local<'_>, network: &str) -> anyhow::Result<Plan> {
    let view = local
        .get(format!("/v2/networks/{}", encoded(network)))
        .await?;
    let d = descriptor(&view, network)?;
    let v = local
        .get(format!("/v2/networks/{}/root-retention", encoded(network)))
        .await?;
    shape(
        &v,
        "network_id context_id decision_time root_head_ids catalog candidates excluded",
    )?;
    ensure!(
        v["network_id"] == network && v["context_id"] == d.context_id(),
        "root preview context mismatch"
    );
    chrono::DateTime::parse_from_rfc3339(text(&v, "decision_time")?)?;
    let catalog = Catalog::read(&d, &serde_json::to_vec(&v["catalog"])?)?;
    let heads = ids(&v["root_head_ids"])?;
    ensure!(!heads.is_empty(), "root proof required before signing");
    let mut epoch = 0;
    for id in &heads {
        let s = catalog.get(id)?;
        ensure!(
            s.kind == "root_state",
            "root preview contains a non-root head"
        );
        epoch = epoch.max(s.sequence()?);
    }
    let epoch = epoch.checked_add(1).context("root epoch is exhausted")?;
    for (name, fields) in [
        (
            "candidates",
            "statement_id kind required_retained_ids effective_scopes effective_not_after",
        ),
        ("excluded", "statement_id code required_ids"),
    ] {
        let mut previous = None;
        for entry in v[name]
            .as_array()
            .context("invalid root retention preview")?
        {
            shape(entry, fields)?;
            let id = text(entry, "statement_id")?;
            ensure!(
                ident(id, "ds_") && previous.is_none_or(|old: &str| old < id),
                "unordered retention preview"
            );
            previous = Some(id);
            if name == "candidates" {
                let required = ids(&entry["required_retained_ids"])?;
                ensure!(
                    required.iter().any(|s| s == id),
                    "retention preview omits its own contribution"
                );
                let statement = catalog.get(id)?;
                ensure!(
                    entry["kind"] == statement.kind
                        && matches!(
                            statement.kind.as_str(),
                            "admin_lease"
                                | "person_lease"
                                | "host_lease"
                                | "binding_lease"
                                | "device_lease"
                                | "policy"
                                | "group"
                        ),
                    "invalid finite retention candidate"
                );
                ensure!(
                    entry["effective_scopes"].as_u64().is_some_and(|s| s <= 15),
                    "invalid retention power"
                );
                chrono::DateTime::parse_from_rfc3339(text(entry, "effective_not_after")?)?;
                for id in required {
                    catalog.get(&id)?;
                }
            } else {
                text(entry, "code")?;
                ids(&entry["required_ids"])?;
            }
        }
    }
    Ok(Plan {
        value: v,
        descriptor: d,
        catalog,
        heads,
        epoch,
    })
}
fn stable(v: &Value) -> Value {
    let mut v = v.clone();
    v.as_object_mut()
        .expect("checked preview")
        .remove("decision_time");
    v
}
fn selection(p: &Plan, requested: &[String], empty: bool) -> anyhow::Result<Vec<String>> {
    if empty {
        return Ok(Vec::new());
    }
    if !requested.is_empty() {
        let selected: BTreeSet<_> = requested.iter().cloned().collect();
        ensure!(
            selected.len() == requested.len() && selected.iter().all(|id| ident(id, "ds_")),
            "--retain requires unique canonical statement IDs"
        );
        return Ok(selected.into_iter().collect());
    }
    let excluded = p.value["excluded"]
        .as_array()
        .context("invalid exclusions")?;
    ensure!(
        !excluded.iter().any(|e| e["code"] == "proof_required"),
        "retention eligibility is unknown; run network sync and repair the listed proofs before rotating"
    );
    let mut selected = BTreeSet::new();
    for candidate in p.value["candidates"]
        .as_array()
        .context("invalid candidates")?
    {
        selected.extend(ids(&candidate["required_retained_ids"])?);
    }
    Ok(selected.into_iter().collect())
}
fn review(v: &Value, p: &Plan, target: &str) -> anyhow::Result<String> {
    shape(
        v,
        "action_id review signing_requests statement_base64 proof_id catalog committed delivery",
    )?;
    let r = &v["review"];
    shape(
        r,
        "kind statement_id provider subject sequence not_after authority_warning",
    )?;
    let statement = text(r, "statement_id")?;
    let expected = format!(
        "act_{:x}",
        Sha256::digest(
            [
                "peerspan-decentralized-action-intent-v1",
                &p.descriptor.context_id(),
                "root_state",
                statement,
                "network_root"
            ]
            .join("\n")
        )
    );
    ensure!(
        ident(statement, "ds_")
            && text(v, "action_id")? == expected
            && r["kind"] == "root_state"
            && r["sequence"] == p.epoch
            && r["not_after"] == "-",
        "root intent does not match reviewed epoch/pins"
    );
    shape(&r["subject"], "root_public_key epoch")?;
    ensure!(
        r["subject"]["epoch"] == p.epoch,
        "root subject epoch mismatch"
    );
    let next = text(&r["subject"], "root_public_key")?;
    ensure!(
        decode(next)?.len() == 32 && (target == "-" || target == next),
        "root target mismatch"
    );
    shape(
        &r["provider"],
        "kind person_public_key host_public_key device_public_key lease_id root_state_id scopes not_after",
    )?;
    let provider = &r["provider"];
    ensure!(
        provider["kind"] == "network_root"
            && provider["person_public_key"] == "-"
            && provider["host_public_key"] == "-"
            && provider["device_public_key"] == "-"
            && provider["lease_id"] == "-"
            && provider["not_after"] == "-"
            && provider["root_state_id"]
                == if p.heads.len() == 1 {
                    json!(p.heads[0])
                } else {
                    json!("-")
                }
            && provider["scopes"]
                == if p.heads.len() == 1 {
                    json!(8)
                } else {
                    json!(0)
                },
        "root review selects an unreviewed branch/provider"
    );
    Ok(expected)
}
fn payload(v: &Value, p: &Plan, selected: &[String], root: &str) -> anyhow::Result<()> {
    shape(
        v,
        "epoch predecessors resolves migration_proposal_id root_public_key issued_at retained_statement_ids",
    )?;
    ensure!(
        v["epoch"] == p.epoch
            && ids(&v["predecessors"])? == p.heads
            && ids(&v["resolves"])?
                == if p.heads.len() > 1 {
                    p.heads.clone()
                } else {
                    Vec::new()
                }
            && v["migration_proposal_id"] == "-"
            && v["root_public_key"] == root
            && ids(&v["retained_statement_ids"])? == selected,
        "root payload changes the reviewed branches, target or retained set"
    );
    chrono::DateTime::parse_from_rfc3339(text(v, "issued_at")?)?;
    Ok(())
}
fn envelope(
    outer: &Value,
    p: &Plan,
    next_format: &str,
    old_format: &str,
    frozen: &mut Option<Value>,
) -> anyhow::Result<()> {
    let mut identity = outer.clone();
    let roles = identity["signatures"]
        .as_array_mut()
        .context("invalid fixed root roles")?;
    let mut current_format = None;
    for role in roles {
        let name = text(role, "role")?;
        let format = text(role, "format")?;
        if name == "new_root" {
            ensure!(format == next_format, "new root signature format changed");
        } else {
            ensure!(
                (old_format == "auto" || old_format == format)
                    && current_format.is_none_or(|old: &str| old == format),
                "current root signature format changed"
            );
            current_format = Some(format);
        }
    }
    // The semantic ID excludes signature aliases. Freeze the declared role
    // keys/formats and exact payload bytes as well as the displayed DS pin.
    for role in identity["signatures"]
        .as_array_mut()
        .expect("checked roles")
    {
        role["signature"] = Value::from("-");
    }
    ensure!(
        identity["context_id"] == p.descriptor.context_id(),
        "root template context changed"
    );
    if let Some(previous) = frozen {
        ensure!(
            *previous == identity,
            "fixed root template changed between signature batches"
        );
    } else {
        *frozen = Some(identity);
    }
    Ok(())
}
fn signatures(
    v: &Value,
    p: &Plan,
    selected: &[String],
    keys: &BTreeMap<String, PersonSigner>,
    formats: (&str, &str),
    frozen: &mut Option<Value>,
) -> anyhow::Result<Value> {
    let requests = v["signing_requests"]
        .as_array()
        .context("invalid root signing slots")?;
    ensure!(
        !requests.is_empty() && requests.len() <= 16,
        "root signing slots unavailable; repair the exact pending intent"
    );
    let mut intent = None;
    let mut previous = None;
    let mut output = Vec::new();
    let mut template = None;
    for entry in requests {
        shape(
            entry,
            "intent_id slot_id object_type object_id role public_key format template_base64 message_base64",
        )?;
        ensure!(
            entry["slot_id"] == 1
                && entry["object_type"] == "root_state"
                && entry["object_id"] == v["review"]["statement_id"],
            "unreviewed root signing object"
        );
        let id = text(entry, "intent_id")?;
        ensure!(intent.is_none_or(|old| old == id), "mixed root intents");
        intent = Some(id);
        let role = text(entry, "role")?;
        ensure!(
            previous.is_none_or(|old: &str| old < role),
            "unordered root roles"
        );
        previous = Some(role);
        let bytes = decode(text(entry, "template_base64")?)?;
        ensure!(
            template.as_ref().is_none_or(|old| old == &bytes),
            "different root templates in one batch"
        );
        template = Some(bytes.clone());
        let fixed = FixedStatement::read(&p.descriptor, &bytes)?;
        ensure!(
            fixed.statement_id() == text(entry, "object_id")?,
            "root statement pin mismatch"
        );
        let outer: Value = serde_json::from_slice(&bytes)?;
        envelope(&outer, p, formats.0, formats.1, frozen)?;
        ensure!(
            outer["kind"] == "root_state",
            "unexpected root signature kind"
        );
        let body: Value = serde_json::from_slice(&decode(text(&outer, "payload_base64")?)?)?;
        let next = text(&v["review"]["subject"], "root_public_key")?;
        payload(&body, p, selected, next)?;
        let expected_key = if role == "new_root" {
            next
        } else {
            let branch = if p.heads.len() == 1 {
                ensure!(role == "issuer", "unexpected root role");
                p.heads[0].as_str()
            } else {
                let branch = role
                    .strip_prefix("root_branch:")
                    .context("unexpected fork role")?;
                ensure!(
                    p.heads.iter().any(|id| id == branch),
                    "unreviewed fork branch"
                );
                branch
            };
            p.catalog.get(branch)?.payload["root_public_key"]
                .as_str()
                .context("invalid root key")?
        };
        let pending = fixed.pending();
        let slot = pending
            .iter()
            .find(|s| s.role == role)
            .context("root role already signed")?;
        ensure!(
            slot.public_key == expected_key
                && slot.public_key == text(entry, "public_key")?
                && slot.signature_format == text(entry, "format")?
                && slot.message_base64 == text(entry, "message_base64")?,
            "root signature message/role/key mismatch"
        );
        let agent;
        let signer = if let Some(signer) = keys.get(expected_key) {
            signer
        } else if role == "issuer" && slot.signature_format == "sshsig" {
            // --to-ssh names the NEW key. Select the existing current root
            // from the agent by its exact reviewed key, never by discovery or
            // a first available identity. Fork branch keys remain explicit.
            agent = PersonSigner::agent_with(expected_key).with_context(|| {
                format!("the current root {expected_key} must be available in ssh-agent to rotate to the separately supplied new SSH root")
            })?;
            &agent
        } else {
            bail!(
                "missing exact root key for role {role}, public key {expected_key}; supply its --root-key PATH without selecting another branch"
            )
        };
        let message = decode(&slot.message_base64)?;
        let signature = match slot.signature_format.as_str() {
            "sshsig" => signer.sign(
                &std::str::from_utf8(&message)?
                    .split('\n')
                    .collect::<Vec<_>>(),
            )?,
            "ed25519" => match signer {
                PersonSigner::File(key) => STANDARD.encode(key.sign(&message).to_bytes()),
                PersonSigner::Agent { .. } => {
                    bail!("raw root role {role} requires its unencrypted private key file")
                }
            },
            _ => bail!("unsupported root signature format"),
        };
        fixed.fill(&p.descriptor, role, &signature)?;
        output.push(json!({"slot_id":1,"role":role,"signature":signature}));
    }
    Ok(json!({"intent_id":intent.context("missing root intent")?,"signatures":output}))
}
fn committed(
    v: &Value,
    p: &Plan,
    selected: &[String],
    formats: (&str, &str),
    frozen: &mut Option<Value>,
) -> anyhow::Result<()> {
    let raw = decode(text(v, "statement_base64")?)?;
    let s = Statement::read(&p.descriptor, &raw)?;
    envelope(
        &serde_json::from_slice(&raw)?,
        p,
        formats.0,
        formats.1,
        frozen,
    )?;
    ensure!(
        s.kind == "root_state"
            && s.id == text(&v["review"], "statement_id")?
            && s.proof_id == text(v, "proof_id")?,
        "committed root differs from reviewed statement"
    );
    payload(
        &serde_json::to_value(&s.payload)?,
        p,
        selected,
        text(&v["review"]["subject"], "root_public_key")?,
    )?;
    for branch in &p.heads {
        let role = if p.heads.len() == 1 {
            "issuer".to_owned()
        } else {
            format!("root_branch:{branch}")
        };
        ensure!(
            s.signatures
                .get(&role)
                .is_some_and(|sig| Some(sig.public_key.as_str())
                    == p.catalog
                        .get(branch)
                        .ok()
                        .and_then(|old| old.payload["root_public_key"].as_str())),
            "committed root branch signature mismatch"
        );
    }
    let c = Catalog::read(&p.descriptor, &serde_json::to_vec(&v["catalog"])?)?;
    ensure!(
        c.proofs
            .get(&s.proof_id)
            .is_some_and(|proof| proof.body == raw),
        "committed catalog omits the original root proof"
    );
    Ok(())
}
pub(crate) async fn command(command: &Command, socket: &Path) -> anyhow::Result<Option<Value>> {
    // Retention is automatic (spec 13.1, DEC-Q13), and a root fork is not
    // resolved by command (DEC-Q19: `network resolve-root` is removed).
    let (network, target_path, old_paths) = match command {
        Command::Network(NetworkCommand::RotateRoot {
            id,
            to_ssh,
            root_key,
        }) => (
            id,
            if *to_ssh { root_key.as_ref() } else { None },
            if *to_ssh {
                Vec::new()
            } else {
                root_key.iter().cloned().collect::<Vec<_>>()
            },
        ),
        _ => return Ok(None),
    };
    let (requested, empty, resolution): (&[String], bool, bool) = (&[], false, false);
    ensure!(ident(network, "net_"), "invalid network ID");
    let mut keys = BTreeMap::new();
    for path in &old_paths {
        let signer = PersonSigner::open(Some(path))?;
        keys.insert(signer.public_key_b64(), signer);
    }
    let target = if let Some(path) = target_path {
        let signer = PersonSigner::open(Some(path))?;
        let key = signer.public_key_b64();
        keys.insert(key.clone(), signer);
        key
    } else {
        "-".into()
    };
    let local = Local(socket);
    let p = plan(&local, network).await?;
    ensure!(
        resolution || p.heads.len() == 1,
        "the root is forked (a root split); rotation is refused until the network is reinvited"
    );
    let selected = selection(&p, requested, empty)?;
    let mut request = json!({"new_root_public_key":target,"new_root_signature_format":if target_path.is_some(){"sshsig"}else{"ed25519"},"signature_format":if old_paths.is_empty(){"auto"}else{"sshsig"},"retained_statement_ids":selected,"approve":false});
    let path = format!("/v2/networks/{}/root-transitions", encoded(network));
    let mut value = local.post(path.clone(), request.clone()).await?;
    let action = review(&value, &p, &target)?;
    let fixed_review = value["review"].clone();
    eprintln!("Root heads: {}", p.heads.join(", "));
    eprintln!(
        "Preserve these exact finite authority contributions: {}",
        serde_json::to_string(&selected)?
    );
    for candidate in p.value["candidates"]
        .as_array()
        .context("invalid candidates")?
    {
        let s = p.catalog.get(text(candidate, "statement_id")?)?;
        eprintln!(
            "{}",
            serde_json::to_string(
                &json!({"candidate":candidate,"subject":s.payload.get("subject").cloned().unwrap_or(Value::Null),"selected":selected.iter().any(|id|candidate["statement_id"] == *id)})
            )?
        );
    }
    eprintln!("Excluded finite heads: {}", p.value["excluded"]);
    eprintln!(
        "Next root: {}",
        serde_json::to_string_pretty(&fixed_review)?
    );
    if !crate::up::prompt(
        "Approve this exact root and retained authority set?",
        "no",
        false,
    )
    .await?
    .eq_ignore_ascii_case("yes")
    {
        bail!("root transition not approved; exact pending preview retained");
    }
    let latest = plan(&local, network).await?;
    ensure!(
        stable(&latest.value) == stable(&p.value),
        "root or retention state changed during review; inspect the pending exact intent before approving again"
    );
    request["approve"] = Value::Bool(true);
    value = local.post(path, request).await?;
    let mut frozen = None;
    let formats = (
        if target_path.is_some() {
            "sshsig"
        } else {
            "ed25519"
        },
        if old_paths.is_empty() {
            "auto"
        } else {
            "sshsig"
        },
    );
    for _ in 0..257 {
        ensure!(
            review(&value, &p, &target)? == action && value["review"] == fixed_review,
            "root review changed after approval"
        );
        if value["committed"] == true {
            committed(&value, &p, &selected, formats, &mut frozen)?;
            return Ok(Some(value));
        }
        let signed = signatures(&value, &p, &selected, &keys, formats, &mut frozen)?;
        value = local
            .post(
                format!(
                    "/v2/networks/{}/actions/{}/signed",
                    encoded(network),
                    encoded(&action)
                ),
                signed,
            )
            .await?;
    }
    bail!("root has too many pending signature batches; resume the exact action {action}")
}
