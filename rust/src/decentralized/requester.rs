//! The two requester confirmations are separate durable owner-local actions.
//! Neither incoming packets nor a device possession proof supplies approval.
use super::{
    bootstrap::Frame,
    codec::*,
    requests::{self, Pending},
};
use crate::store::Store;
use rusqlite::Connection;
use serde_json::json;

fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn bytes(value: &impl serde::Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error::new("internal"))
}
pub(crate) fn retain_outbound(
    c: &Connection,
    store: &Store,
    p: &mut Pending,
    role: &str,
    packet: &[u8],
    catalog: &str,
    now: &str,
) -> Result<()> {
    retain_with_contacts(c, store, p, role, packet, catalog, now, Vec::new())
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn retain_with_contacts(
    c: &Connection,
    store: &Store,
    p: &mut Pending,
    role: &str,
    packet: &[u8],
    catalog: &str,
    now: &str,
    contacts: Vec<serde_json::Value>,
) -> Result<()> {
    let secret = p.secret.ok_or_else(|| Error::new("recovery_required"))?;
    let old = requests::frames(c, p)?;
    require(old.len() < 64, "quota_exceeded")?;
    let created = text(&p.packet()?.payload, "created_at")?.to_owned();
    let frame = Frame::seal(
        &secret,
        &p.id,
        role,
        &store.signing_key,
        (&created, &p.deadline),
        now,
        &json!({"packet_base64":if role == "proofs" {"-".into()}else{encode(packet)},"catalog_base64":catalog,"contacts":contacts}),
    )?;
    require(
        old.iter().map(|f| f.ciphertext.len()).sum::<usize>() + frame.ciphertext.len() <= 32 << 20,
        "quota_exceeded",
    )?;
    c.execute(
        "INSERT INTO dec_frames(request_id,role,writer_key,frame_id,record) VALUES(?1,?2,?3,?4,?5)",
        rusqlite::params![
            p.id,
            role,
            frame.writer_host_public_key,
            frame.frame_id,
            json!({"frame_base64":encode(&frame.body)}).to_string()
        ],
    )
    .map_err(db)?;
    p.record.outbound_frames.push(json!({"role":role,"writer_public_key":frame.writer_host_public_key,"frame_id":frame.frame_id,"acknowledged_by":[]}));
    Ok(())
}
pub(crate) fn select(store: &Store, id: &str, input: &Obj) -> Result<Vec<u8>> {
    approval::select(store, id, input)
}
#[path = "requester_intents.rs"]
mod approval;
pub(crate) use approval::validate_references;
pub(crate) use commitment::inspect_machine as inspect_machine_requester_commit;
pub(crate) use commitment::resume_guarded as resume_commit_guarded;
pub(crate) use commitment::{activation_bytes, catalog_delta_components, retain_catalog};
pub(crate) use commitment::{
    consent_in as commit_in, consent_live as commit_live, consent_proposal as commit_proposal,
};
#[path = "requester_commit.rs"]
mod commitment;
pub(crate) fn commit(store: &Store, id: &str, input: &Obj) -> Result<Vec<u8>> {
    // The async dispatcher attempts exact sealed commit/catalog publication
    // before local application retires the secret and nonterminal frames.
    commitment::approve(store, id, input)
}
pub(crate) fn resume_approved(store: &Store, id: &str) -> Result<()> {
    super::ceremony::resume_offer(store, id)?;
    super::ceremony_admin::resume_owned(store, id)?;
    super::ceremony_admin::resume(store, id)?;
    super::ceremony_finalization::resume(store, id)?;
    approval::resume_approved(store, id)?;
    commitment::resume(store, id)?;
    Ok(())
}
