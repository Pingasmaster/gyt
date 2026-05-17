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
    /// H9: hard cap on cumulative body bytes across all entries. Without
    /// this, the pack_cache (256 entries × hundreds of MiB per pack)
    /// could pin tens of GiB of resident memory under attacker churn.
    /// 0 means "no byte cap" (fall back to entry-count limit only).
    max_bytes: usize,
    /// Current total body bytes resident in the cache.
    bytes: Mutex<usize>,
}

impl ResponseCache {
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
            max_bytes: 0,
            bytes: Mutex::new(0),
        }
    }

    /// Like `new` but with an explicit cumulative byte cap (H9).
    pub fn new_with_bytes(ttl: Duration, max_entries: usize, max_bytes: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
            max_bytes,
            bytes: Mutex::new(0),
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
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the bytes_held lock is intentionally held across the eviction loop to keep `bytes_val` in sync with the entry map; releasing it earlier would race a concurrent insert"
    )]
    pub fn insert(&self, key: String, body: Vec<u8>, content_type: String) {
        let now = Instant::now();
        let body_len = body.len();
        // H9: refuse single entries that would be more than a quarter
        // of the byte cap. A small number of huge entries shouldn't be
        // able to evict every other useful entry on their own.
        if self.max_bytes > 0 && body_len * 4 > self.max_bytes {
            return;
        }
        let mut g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut bytes_held = self
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut bytes_val: usize = *bytes_held;
        // If overwriting, the old body's bytes are released.
        if let Some(prev) = g.get(&key) {
            bytes_val = bytes_val.saturating_sub(prev.body.len());
        }
        // Evict to make room in entry count.
        while g.len() >= self.max_entries {
            let stale = g
                .iter()
                .find(|(_, e)| e.expires <= now)
                .map(|(k, _)| k.clone());
            let evict_key = stale.or_else(|| g.keys().next().cloned());
            let Some(k) = evict_key else { break };
            if let Some(e) = g.remove(&k) {
                bytes_val = bytes_val.saturating_sub(e.body.len());
            }
        }
        // Evict to make room in bytes (H9).
        if self.max_bytes > 0 {
            while bytes_val.saturating_add(body_len) > self.max_bytes {
                let stale = g
                    .iter()
                    .find(|(_, e)| e.expires <= now)
                    .map(|(k, _)| k.clone());
                let evict_key = stale.or_else(|| g.keys().next().cloned());
                let Some(k) = evict_key else { break };
                if let Some(e) = g.remove(&k) {
                    bytes_val = bytes_val.saturating_sub(e.body.len());
                } else {
                    break;
                }
            }
        }
        bytes_val = bytes_val.saturating_add(body_len);
        *bytes_held = bytes_val;
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
    #[expect(
        clippy::significant_drop_tightening,
        reason = "both guards held across retain to keep `bytes` in sync with the map"
    )]
    pub fn invalidate_prefix(&self, prefix: &str) {
        let mut g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut bytes_held = self
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut freed = 0usize;
        g.retain(|k, e| {
            let keep = !k.starts_with(prefix);
            if !keep {
                freed = freed.saturating_add(e.body.len());
            }
            keep
        });
        *bytes_held = bytes_held.saturating_sub(freed);
    }

    /// Invalidate the global list cache (the /api/repos response).
    /// Called when a repo is added or removed; in this server the
    /// only writer is human ops (`mkdir` on the host) so this is
    /// rarely needed at runtime — but it's wired up so admin tools
    /// can poke it.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "both guards held together to keep `bytes` in sync with the map"
    )]
    pub fn invalidate_all(&self) {
        let mut g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut bytes_held = self
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.clear();
        *bytes_held = 0;
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
