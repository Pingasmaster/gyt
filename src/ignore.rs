// .gytignore parser + matcher (gitignore-compatible semantics).
// Real implementation lands in Phase 3b.

#[derive(Debug, Default)]
pub struct IgnoreSet;

impl IgnoreSet {
    pub fn new() -> Self {
        Self
    }
    pub fn matched(&self, _path: &str, _is_dir: bool) -> bool {
        false
    }
}
