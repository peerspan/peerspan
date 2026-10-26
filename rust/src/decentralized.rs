//! Coordinator-free signed authority. Public proof bytes and caller-owned prior
//! admission are distinct inputs; neither transport nor a signature is a grant.
mod catalog;
mod codec;
mod probe;
mod state;
mod statement;
mod transcript;

pub use catalog::{Catalog, Proof};
pub use codec::{Error, Result, decision_clock};
pub use probe::{MAX_PROBE_LINE, probe};
pub use statement::{Descriptor, SignatureEntry, Statement};

pub use state::{Maximum, Prior, Projection, Stream};
