//! Coordinator-free signed authority. Public proof bytes and caller-owned prior
//! admission are distinct inputs; neither transport nor a signature is a grant.
mod actions;
pub mod bootstrap;
pub(crate) mod bootstrap_admission;
pub mod bootstrap_io;
mod capability_claim;
mod catalog;
mod ceremony;
mod ceremony_admin;
mod ceremony_finalization;
pub(crate) mod codec;
pub(crate) mod completion;
mod controls;
mod creation;
mod edits;
pub(crate) mod history;
mod intents;
pub mod mailbox;
mod migration;
mod migration_ack;
mod migration_adopt;
mod migration_commit;
mod migration_device_bans;
mod migration_evidence;
mod migration_host;
mod migration_link;
mod migration_local;
mod migration_prefix;
mod migration_prepare;
mod observer;
pub(crate) mod peer;
mod probe;
pub(crate) mod product;
mod provider;
mod renewal;
mod requester;
mod requests;
mod requests_io;
mod roots;
pub(crate) mod runtime;
mod state;
mod statement;
pub(crate) mod storage;
mod template;
mod transcript;
mod views;

pub(crate) use capability_claim::{apply_capability_claim, check_capability_claim};
pub use catalog::{Catalog, Proof};
pub use codec::{Error, Result, decision_clock};
pub use controls::local_decision_time;
pub use migration::{migration_inherited_bans, migration_person_labels};
pub use peer::state_worker;
pub use probe::{MAX_PROBE_LINE, probe};
pub use statement::{Descriptor, SignatureEntry, Statement};

pub use state::{CurrentMember, Maximum, Prior, Projection, Stream};

pub use storage::{
    ContextRecord, MigrationRecord, NetworkRecord, OwnIdentity, ProviderSelection, Snapshot,
    check_outbox_capacity, decode_u64, encode_u64,
};

pub use bootstrap::{Contact, Frame, Invitation, PairingToken};
pub use template::{FixedPacket, FixedStatement, StatementSigningSlot};
