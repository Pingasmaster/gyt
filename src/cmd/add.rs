use crate::errors::{GytError, Result};

pub fn run(_args: &[String]) -> Result<()> {
    Err(GytError::Unsupported("add: not yet implemented".into()))
}
