use std::fmt;
use std::io;

pub type Result<T> = std::result::Result<T, GytError>;

#[derive(Debug)]
pub enum GytError {
    Io(io::Error),
    Parse(String),
    Repo(String),
    Object(String),
    Index(String),
    Refs(String),
    Net(String),
    NotFound(String),
    InvalidArgument(String),
    Unsupported(String),
    Ci(String),
}

impl fmt::Display for GytError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Parse(s) => write!(f, "parse: {s}"),
            Self::Repo(s) => write!(f, "repo: {s}"),
            Self::Object(s) => write!(f, "object: {s}"),
            Self::Index(s) => write!(f, "index: {s}"),
            Self::Refs(s) => write!(f, "refs: {s}"),
            Self::Net(s) => write!(f, "net: {s}"),
            Self::NotFound(s) => write!(f, "not found: {s}"),
            Self::InvalidArgument(s) => write!(f, "invalid argument: {s}"),
            Self::Unsupported(s) => write!(f, "unsupported: {s}"),
            Self::Ci(s) => write!(f, "ci: {s}"),
        }
    }
}

impl std::error::Error for GytError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for GytError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
