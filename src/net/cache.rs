// Tiny in-memory response cache for cheap-to-build-but-still-hot
// endpoints (info/refs, api/repos, api/repos/:o/:n/refs). Anything
// that walks the on-disk refs/ tree or scans the repos_root directory
// on every request is fair game.
//
// Cache shape: per-key (bytes, expiry-instant) tuple. Reads grab the
// Mutex, copy out if not expired, drop. Writes drop expired entries
// past a high-water mark to keep memory bounded.
//
// Invalidation: refs/update calls invalidate_repo(repo); a fresh push
// is reflected within one TTL anyway, but explicit invalidation
// matters when the operator pushes via CLI rather than the server.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct Entry {
    body: Vec<u8>,
    content_type: String,
    expires: Instant,
}

pub struct ResponseCache {
    inner: Mutex<HashMap<String, Entry>>,
    ttl: Duration,
    max_entries: usize,
}

impl ResponseCache {
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
        }
    }

    /// Look up a cached response. Returns `Some((body, content-type))`
    /// when fresh, `None` on miss or expiry.
    pub fn get(&self, key: &str) -> Option<(Vec<u8>, String)> {
        // TTL=0 disables the cache entirely. Tests use this to make
        // direct-FS ref manipulations observable on the next fetch.
        if self.ttl.is_zero() {
            return None;
        }
        let now = Instant::now();
        let g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (body, ctype) = {
            let e = g.get(key)?;
            if e.expires <= now {
                return None;
            }
            (e.body.clone(), e.content_type.clone())
        };
        drop(g);
        Some((body, ctype))
    }

    /// Insert a fresh response. If the cache is at capacity, drop one
    /// expired entry first; if nothing is expired, drop an arbitrary
    /// entry (HashMap iteration order is randomized, which is fine for
    /// eviction). We avoid LRU bookkeeping because the access pattern
    /// for these endpoints is near-uniform anyway — every repo
    /// listing is roughly equally hot.
    pub fn insert(&self, key: String, body: Vec<u8>, content_type: String) {
        let now = Instant::now();
        let mut g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if g.len() >= self.max_entries {
            // Try to evict an expired entry first.
            let stale = g
                .iter()
                .find(|(_, e)| e.expires <= now)
                .map(|(k, _)| k.clone());
            if let Some(k) = stale {
                g.remove(&k);
            } else {
                // Nothing expired; drop one arbitrary entry to make room.
                if let Some(k) = g.keys().next().cloned() {
                    g.remove(&k);
                }
            }
        }
        g.insert(
            key,
            Entry {
                body,
                content_type,
                expires: now + self.ttl,
            },
        );
    }

    /// Invalidate every cache entry whose key starts with the given
    /// prefix. Used by refs/update to flush per-repo entries.
    pub fn invalidate_prefix(&self, prefix: &str) {
        let mut g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.retain(|k, _| !k.starts_with(prefix));
    }

    /// Invalidate the global list cache (the /api/repos response).
    /// Called when a repo is added or removed; in this server the
    /// only writer is human ops (`mkdir` on the host) so this is
    /// rarely needed at runtime — but it's wired up so admin tools
    /// can poke it.
    pub fn invalidate_all(&self) {
        let mut g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_then_miss_after_ttl() {
        let c = ResponseCache::new(Duration::from_millis(50), 10);
        c.insert("k".into(), b"v".to_vec(), "text/plain".into());
        assert_eq!(c.get("k"), Some((b"v".to_vec(), "text/plain".into())));
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(c.get("k"), None);
    }

    #[test]
    fn invalidate_prefix_drops_matching() {
        let c = ResponseCache::new(Duration::from_mins(1), 10);
        c.insert("repo:alice/x".into(), b"a".to_vec(), "x".into());
        c.insert("repo:alice/y".into(), b"b".to_vec(), "x".into());
        c.insert("repo:bob/z".into(), b"c".to_vec(), "x".into());
        c.invalidate_prefix("repo:alice/");
        assert!(c.get("repo:alice/x").is_none());
        assert!(c.get("repo:alice/y").is_none());
        assert!(c.get("repo:bob/z").is_some());
    }

    #[test]
    fn eviction_at_capacity() {
        let c = ResponseCache::new(Duration::from_mins(1), 2);
        c.insert("a".into(), b"1".to_vec(), "x".into());
        c.insert("b".into(), b"2".to_vec(), "x".into());
        c.insert("c".into(), b"3".to_vec(), "x".into());
        // At capacity 2; one of {a,b} must have been evicted.
        let n = ["a", "b", "c"].iter().filter(|k| c.get(k).is_some()).count();
        assert_eq!(n, 2);
    }
}
