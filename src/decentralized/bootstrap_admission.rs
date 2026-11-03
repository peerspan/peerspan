//! One bounded pre-authentication pool for TCP, QUIC and opaque relay sources.
//! Route hints never establish a host key or authorize an application stream.
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};
#[derive(Default)]
pub(crate) struct Admission(Mutex<Counts>);
#[derive(Default)]
struct Counts {
    total: usize,
    sources: BTreeMap<String, usize>,
}
pub(crate) struct Permit {
    owner: Arc<Admission>,
    sources: Vec<String>,
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut c) = self.owner.0.lock() {
            c.total -= 1;
            for source in &self.sources {
                if let Some(n) = c.sources.get_mut(source) {
                    *n -= 1;
                    if *n == 0 {
                        c.sources.remove(source);
                    }
                }
            }
        }
    }
}
pub(crate) fn source(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(v) => v
            .to_ipv4_mapped()
            .map(|v| v.to_string())
            .unwrap_or_else(|| {
                let mut s = v.segments();
                s[4..].fill(0);
                format!("{}/64", std::net::Ipv6Addr::from(s))
            }),
    }
}
impl Admission {
    pub(crate) fn acquire(self: &Arc<Self>, mut sources: Vec<String>) -> Option<Permit> {
        sources.sort();
        sources.dedup();
        let mut c = self.0.lock().ok()?;
        if c.total >= 128
            || sources
                .iter()
                .any(|s| c.sources.get(s).copied().unwrap_or(0) >= 16)
        {
            return None;
        }
        c.total += 1;
        for source in &sources {
            *c.sources.entry(source.clone()).or_default() += 1;
        }
        Some(Permit {
            owner: self.clone(),
            sources,
        })
    }
}
