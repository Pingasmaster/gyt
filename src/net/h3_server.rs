// HTTP/3-over-QUIC listener for `gyt serve`. Wired in a follow-up
// commit. This stub exists so the CLI / dispatch surface compiles
// today and the only thing we need to add is the actual h3+quinn
// glue when that commit lands.

use std::path::Path;
use std::sync::Arc;

use crate::errors::Result;
use crate::net::server::ServerState;

pub(crate) fn run_h3(
    _listen_addr: &str,
    _cert_path: &Path,
    _key_path: &Path,
    _state: Arc<ServerState>,
) -> Result<()> {
    Err(crate::errors::GytError::Net(
        "HTTP/3 listener is not yet enabled in this build".into(),
    ))
}
