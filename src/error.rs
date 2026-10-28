//! Error type and exit codes.

use std::fmt;

/// Process exit codes, identical across all Slash Mark suites.
pub mod exit {
    /// Ran successfully, nothing at or above `--fail-on`.
    pub const OK: i32 = 0;
    /// Ran successfully, at least one finding at or above `--fail-on`.
    pub const FINDINGS: i32 = 1;
    /// Bad command line.
    pub const USAGE: i32 = 2;
    /// Could not complete: network, missing toolchain, unreadable project.
    pub const ERROR: i32 = 3;
}

#[derive(Debug)]
pub enum Error {
    /// The command line was invalid.
    Usage(String),
    /// A network request failed.
    Network(String),
    /// A crate, version or resource does not exist.
    NotFound(String),
    /// `--offline` was given and the data is not cached.
    Offline(String),
    /// A required external program (cargo, nightly, git, strace...) is missing or failed.
    Env(String),
    /// Data could not be parsed.
    Parse(String),
    Io(std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Usage(_) => exit::USAGE,
            _ => exit::ERROR,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Usage(m) => write!(f, "{m}"),
            Error::Network(m) => write!(f, "network error: {m}"),
            Error::NotFound(m) => write!(f, "not found: {m}"),
            Error::Offline(m) => write!(f, "offline: {m} is not cached (run once without --offline)"),
            Error::Env(m) => write!(f, "{m}"),
            Error::Parse(m) => write!(f, "parse error: {m}"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Parse(e.to_string())
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Error::Parse(e.to_string())
    }
}
