//! Signed contact refresh distributes transport hints, never authority or an
//! implicit lease renewal. Helpers are not contacted by this peer exchange.
use super::*;
pub(super) fn own(
    c: &Connection,
    store: &Store,
    view: &repair::View,
    now: &str,
    current: bool,
) -> Result<Option<Arc<Vec<u8>>>> {
    if !current {
        return Ok(None);
    }
    let host = &store.identity().public_key;
    let settings = store
        .bootstrap_settings
        .read()
        .map_err(|_| Error::new("internal"))?
        .clone();
    let payload = json!({"bootstrap_addresses":settings.bootstrap,"quic_addresses":settings.quic,"relays":settings.relays});
    let old:Option<(rusqlite::types::Value,String)>=c.query_row("SELECT sequence,record FROM dec_contacts WHERE network_id=?1 AND context_id=?2 AND host_key=?3",params![view.descriptor.network_id,view.network.context_id,host],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(db)?;
    if let Some((sequence, raw)) = old {
        let record = contact_record(sequence, &raw, &view.network.context_id, host)?;
        if !record.conflicted {
            for contact in record.contacts {
                if contact.valid_at(now).is_ok()
                    && contact.payload == payload
                    && (stamp(&contact.expires_at)? - stamp(now)?).num_seconds() > 60
                {
                    return Ok(Some(Arc::new(contact_body(&contact.body)?)));
                }
            }
        }
    }
    let contact = super::super::bootstrap_io::own_contact(
        c,
        store,
        now,
        &view.descriptor.network_id,
        &view.network.context_id,
    )?;
    Ok(Some(Arc::new(contact_body(&contact.body)?)))
}
fn learn(store: &Store, network: &str, source: &str, bytes: &[u8]) -> Result<()> {
    let value = parse(bytes, 1 << 20)?;
    fields(object(&value)?, "contacts")?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        contacts: Vec<Box<serde_json::value::RawValue>>,
    }
    let input: Input = serde_json::from_slice(bytes).map_err(|_| Error::new("invalid"))?;
    require(input.contacts.len() <= MAX_ITEMS, "quota_exceeded")?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let snapshot = Snapshot::load(&tx, network, &store.identity().public_key)?;
    let now = super::super::controls::local_decision_time()?;
    authorize(&snapshot, source, &now)?;
    let mut previous: Option<(String, u64)> = None;
    for raw in input.contacts {
        let contact = Contact::read(raw.get().as_bytes())?;
        let order = (contact.host_public_key.clone(), contact.sequence);
        check(previous.as_ref().is_none_or(|old| old < &order))?;
        previous = Some(order);
        check(contact.context_id == snapshot.network.context_id)?;
        remember_pairing_contact(
            &tx,
            network,
            &snapshot.network.context_id,
            &contact.host_public_key,
            raw.get().as_bytes(),
            &now,
        )?;
    }
    authorize(
        &snapshot,
        source,
        &super::super::controls::local_decision_time()?,
    )?;
    tx.commit().map_err(db)?;
    Ok(())
}
pub(super) async fn exchange(
    store: Arc<Store>,
    network: &str,
    target: &crate::peer_store::Peer,
    own: Option<&[u8]>,
) {
    if let Some(body) = own {
        let path = format!("/peer/v2/networks/{network}/contact");
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            crate::quic::request(store.clone(), target, "POST", &path, body),
        )
        .await;
    }
    let path = format!("/peer/v2/networks/{network}/contacts");
    if let Ok(Ok((200, body))) = tokio::time::timeout(
        Duration::from_secs(5),
        crate::quic::request(store.clone(), target, "GET", &path, b""),
    )
    .await
    {
        let network = network.to_owned();
        let source = target.public_key.clone();
        let _ = tokio::task::spawn_blocking(move || learn(&store, &network, &source, &body)).await;
    }
}
