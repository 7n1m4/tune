//! Unified error types for tuned.

use std::path::PathBuf;

/// All errors that can occur in the tuned system.
#[derive(Debug, thiserror::Error)]
pub enum TunedError {
    #[error("sysfs I/O error on {path}: {source}")]
    Sysfs {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("procfs parse error for PID {pid}: {detail}")]
    Procfs { pid: u32, detail: String },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("ptrace error for PID {pid}: {source}")]
    Ptrace {
        pid: u32,
        #[source]
        source: nix::Error,
    },

    #[error("syscall injection failed for PID {pid}: {detail}")]
    Injection { pid: u32, detail: String },

    #[error("KSM snapshot error: {0}")]
    Snapshot(String),

    #[error("capability error: {0}")]
    Capability(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("nix error: {0}")]
    Nix(#[from] nix::Error),
}

pub type Result<T> = std::result::Result<T, TunedError>;
