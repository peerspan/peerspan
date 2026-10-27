//! Bounded untrusted relay source hints for a single completion connection.
//! The inner certificate must derive the claimed host digest before any HTTP.
use super::*;
use crate::decentralized::bootstrap_admission;
use std::{net::IpAddr, time::Instant};
pub(super) struct Provisional {
    started: Instant,
    verified: bool,
    claimed: bool,
    helper: Vec<u8>,
    source: IpAddr,
    _pending: bootstrap_admission::Permit,
    _wire: crate::decentralized::mailbox::TransportBuffers,
}
pub(crate) struct Inbound {
    owner: Arc<Relays>,
    host: Option<[u8; HOST_ID]>,
    started: Instant,
    provisional: bool,
    _pending: Option<bootstrap_admission::Permit>,
    pub(crate) source: String,
}
impl Inbound {
    pub(crate) fn has_transport_buffers(&self) -> bool {
        self.provisional
    }
    pub(crate) fn handshake_deadline(&self) -> tokio::time::Instant {
        tokio::time::Instant::from_std(self.started + Duration::from_secs(5))
    }
    pub(crate) fn request_deadline(&self) -> tokio::time::Instant {
        tokio::time::Instant::from_std(self.started + Duration::from_secs(30))
    }
    pub(crate) fn verify(&self, key: &[u8], completion: bool) -> bool {
        if let Some(host) = self.host {
            if raw_host(&crate::peer_store::key_id(key)) != Some(host) {
                return false;
            }
            if self.provisional {
                if !completion {
                    return false;
                }
                let Ok(mut s) = self.owner.state.lock() else {
                    return false;
                };
                let Some(p) = s.provisional.get_mut(&host) else {
                    return false;
                };
                if p.started != self.started || p.started.elapsed() >= Duration::from_secs(5) {
                    return false;
                }
                p.verified = true;
            }
        }
        true
    }
}
impl Drop for Inbound {
    fn drop(&mut self) {
        if self.provisional
            && let Some(host) = self.host
            && let Ok(mut s) = self.owner.state.lock()
            && s.provisional
                .get(&host)
                .is_some_and(|p| p.started == self.started)
        {
            remove(&mut s, &host);
        }
    }
}
fn remove(s: &mut State, host: &[u8; HOST_ID]) {
    s.provisional.remove(host);
    s.routes.remove(host);
    s.route_sources.remove(host);
    let address = synthetic(host);
    if s.hosts.get(&address) == Some(host) {
        s.hosts.remove(&address);
    }
}
fn collect(s: &mut State) {
    let expired: Vec<_> = s
        .provisional
        .iter()
        .filter(|(_, p)| {
            p.started.elapsed() >= Duration::from_secs(if p.verified { 30 } else { 5 })
        })
        .map(|(h, _)| *h)
        .collect();
    for h in expired {
        remove(s, &h);
    }
}
impl Relays {
    pub(crate) fn retire_completion(&self, store: &Store, host: &[u8; HOST_ID]) {
        let id = format!("host_{}", hex::encode(host));
        if store.member_pins.read().is_ok_and(|p| p.contains_key(&id))
            || store.peer_pins.read().is_ok_and(|p| p.contains_key(&id))
        {
            return;
        }
        if let Ok(mut s) = self.state.lock() {
            remove(&mut s, host);
        }
    }
    pub(crate) fn collect_provisional(&self) {
        if let Ok(mut s) = self.state.lock() {
            collect(&mut s);
        }
    }
    pub(crate) fn incoming(self: &Arc<Self>, store: &Store, remote: SocketAddr) -> Option<Inbound> {
        if !is_synthetic(remote) {
            let source = bootstrap_admission::source(remote.ip());
            return Some(Inbound {
                owner: self.clone(),
                host: None,
                started: Instant::now(),
                provisional: false,
                _pending: Some(
                    store
                        .dec_bootstrap_admission
                        .acquire(vec![source.clone()])?,
                ),
                source,
            });
        }
        let mut s = self.state.lock().ok()?;
        collect(&mut s);
        let SocketAddr::V4(address) = normalize(remote) else {
            return None;
        };
        let host = *s.hosts.get(&address)?;
        if let Some(p) = s.provisional.get_mut(&host) {
            if p.claimed {
                return None;
            };
            p.claimed = true;
            return Some(Inbound {
                owner: self.clone(),
                host: Some(host),
                started: p.started,
                provisional: true,
                _pending: None,
                source: bootstrap_admission::source(p.source),
            });
        }
        let helper = s.routes.get(&host)?;
        let source = s
            .route_sources
            .get(&host)
            .map(|ip| bootstrap_admission::source(*ip))
            .unwrap_or_else(|| format!("relay:{}", hex::encode(&helper.key)));
        let pending = store.dec_bootstrap_admission.acquire(vec![
            source.clone(),
            format!("helper:{}", hex::encode(&helper.key)),
        ])?;
        Some(Inbound {
            owner: self.clone(),
            host: Some(host),
            started: Instant::now(),
            provisional: false,
            _pending: Some(pending),
            source,
        })
    }
    pub(crate) fn receive_resource(
        self: &Arc<Self>,
        store: &Store,
        host: [u8; HOST_ID],
        datagram: Vec<u8>,
        helper: &Coordinator,
        source: IpAddr,
    ) {
        if datagram.is_empty() || datagram.len() > MAX_DATAGRAM {
            return;
        }
        let id = format!("host_{}", hex::encode(host));
        let known = store.member_pins.read().is_ok_and(|p| p.contains_key(&id))
            || store.peer_pins.read().is_ok_and(|p| p.contains_key(&id));
        let address = synthetic(&host);
        let Ok(mut s) = self.state.lock() else { return };
        collect(&mut s);
        if s.hosts
            .get(&address)
            .is_some_and(|existing| existing != &host)
        {
            return;
        }
        if !known {
            if let Some(p) = s.provisional.get(&host) {
                if p.helper != helper.key
                    || bootstrap_admission::source(p.source) != bootstrap_admission::source(source)
                {
                    return;
                }
            } else {
                let Some(pending) = store.dec_bootstrap_admission.acquire(vec![
                    bootstrap_admission::source(source),
                    format!("helper:{}", hex::encode(&helper.key)),
                ]) else {
                    return;
                };
                let Some(wire) = store
                    .bootstrap_mailboxes
                    .read()
                    .ok()
                    .and_then(|m| m.upgrade())
                    .and_then(|m| m.transport_buffers())
                else {
                    return;
                };
                s.provisional.insert(
                    host,
                    Provisional {
                        started: Instant::now(),
                        verified: false,
                        claimed: false,
                        helper: helper.key.clone(),
                        source,
                        _pending: pending,
                        _wire: wire,
                    },
                );
            }
        }
        s.hosts.insert(address, host);
        s.routes.insert(host, helper.clone());
        s.route_sources.insert(host, source);
        let _ = self.inbound.try_send((address, datagram));
    }
    /// A locally pinned outgoing completion handshake has already verified TLS.
    pub(crate) fn outgoing_completion(
        self: &Arc<Self>,
        store: &Store,
        remote: SocketAddr,
        key: &[u8],
    ) -> Option<Inbound> {
        let inbound = self.incoming(store, remote)?;
        inbound.verify(key, true).then_some(inbound)
    }
}
