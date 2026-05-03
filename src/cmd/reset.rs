use crate::errors::{GytError, Result};

pub fn run(_args: &[String]) -> Result<()> {
    Err(GytError::Unsupported("reset: not yet implemented".into()))
}
