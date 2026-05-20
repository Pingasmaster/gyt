// Token-bucket rate limiter shared by every accepted connection.
// One bucket per IP and one bucket per bearer-token actor; whichever
// runs out first denies the request with HTTP 429. The bucket cap +
// refill rate are operator-tunable via CLI flags; the defaults are
// generous enough that legitimate clones / CI runs never hit them
// but a misbehaving loop running a clone-in-a-while loop will.
//
// Implementation notes:
//
// - The map is a `Mutex<HashMap<Key, Bucket>>` — fine up to a few
//   thousand active actors. Past that we'd want a sharded map; we'll
//   sharded-ize when /metrics shows the mutex is hot.
// - We GC buckets that have been full and idle for >5 minutes so a
//   server seeing a million distinct IPs over its lifetime doesn't
//   leak unbounded memory.
// - Bucket arithmetic is in millitokens to give per-second refills
//   sub-token precision without floats.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Identity a rate-limit decision is made against. Per-IP and per-actor
/// share the same bucket map but with disjoint key prefixes so they
/// can never collide.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub enum Key {
    Ip(IpAddr),
    Actor(String),
}

#[derive(Clone, Copy)]
pub struct LimitConfig {
    /// Bucket capacity in tokens. A burst of `capacity` requests is
    /// accepted before any throttling kicks in.
    pub capacity: u32,
    /// Tokens added per second.
    pub refill_per_sec: u32,
}

impl LimitConfig {
    pub const DEFAULT_IP: Self = Self {
        capacity: 60,
        refill_per_sec: 10,
    };
    pub const DEFAULT_ACTOR: Self = Self {
        capacity: 600,
        refill_per_sec: 100,
    };
}

struct Bucket {
    /// Tokens × 1000. Lets us refill at a per-millisecond granularity
    /// without floats.
    millitokens: u64,
    last_refill: Instant,
    /// Last time this bucket was accessed. Used by `gc_idle`.
    last_seen: Instant,
}

pub struct RateLimiter {
    inner: Mutex<HashMap<Key, Bucket>>,
    ip_cfg: LimitConfig,
    actor_cfg: LimitConfig,
}

impl RateLimiter {
    pub fn new(ip_cfg: LimitConfig, actor_cfg: LimitConfig) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ip_cfg,
            actor_cfg,
        }
    }

    /// Try to take one token from each of the (ip, actor) buckets the
    /// caller provides. Returns true iff *both* succeed. We always
    /// charge both regardless of which side denies, so a noisy IP
    /// with a valid token can't bypass per-IP throttling by spending
    /// against the actor bucket.
    pub fn allow(&self, ip: Option<IpAddr>, actor: Option<&str>) -> bool {
        let now = Instant::now();
        let mut g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Charge both sides. We require both to succeed; the function
        // is allowed to refund nothing on the loser because the cost
        // of the partial charge is at most one token — and the next
        // call will refill it from now.last_refill.
        //
        // Capacity-zero disables that side entirely. This is the
        // operator escape hatch for reverse-proxy deployments (every
        // request appears to come from 127.0.0.1, so the per-IP bucket
        // becomes a global cap) and for test environments that fire
        // hundreds of requests in burst.
        let ip_ok = if self.ip_cfg.capacity == 0 {
            true
        } else if let Some(ip) = ip {
            Self::take(&mut g, Key::Ip(ip), self.ip_cfg, now)
        } else {
            true
        };
        let actor_ok = if self.actor_cfg.capacity == 0 {
            true
        } else if let Some(a) = actor {
            Self::take(&mut g, Key::Actor(a.to_string()), self.actor_cfg, now)
        } else {
            true
        };

        ip_ok && actor_ok
    }

    fn take(
        map: &mut HashMap<Key, Bucket>,
        key: Key,
        cfg: LimitConfig,
        now: Instant,
    ) -> bool {
        // H8: cap the bucket map's total size. Without this, an
        // IPv6 /64 attacker rotating source addresses creates millions
        // of `Key::Ip` entries before the time-based GC sweeps (5min);
        // each entry is ~80 bytes resident → multi-GiB OOM. When the
        // map is full, treat new-key inserts as denials (fail-closed).
        const MAX_RATE_LIMIT_ENTRIES: usize = 65_536;
        if !map.contains_key(&key) && map.len() >= MAX_RATE_LIMIT_ENTRIES {
            return false;
        }
        let cap = u64::from(cfg.capacity) * 1000;
        let entry = map.entry(key).or_insert(Bucket {
            millitokens: cap,
            last_refill: now,
            last_seen: now,
        });
        // Refill.
        let elapsed_ms = now.duration_since(entry.last_refill).as_millis() as u64;
        if elapsed_ms > 0 {
            let added = elapsed_ms * u64::from(cfg.refill_per_sec);
            entry.millitokens = entry.millitokens.saturating_add(added).min(cap);
            entry.last_refill = now;
        }
        entry.last_seen = now;
        if entry.millitokens >= 1000 {
            entry.millitokens -= 1000;
            true
        } else {
            false
        }
    }

    /// Drop buckets that have been idle longer than `max_idle`. Call
    /// occasionally (e.g., once per minute) — leaving idle buckets
    /// around forever would leak under a million-unique-clients
    /// workload.
    pub fn gc_idle(&self, max_idle: Duration) {
        let now = Instant::now();
        let mut g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.retain(|_, b| now.duration_since(b.last_seen) < max_idle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
    }

    #[test]
    fn allow_then_deny_after_burst() {
        let rl = RateLimiter::new(
            LimitConfig {
                capacity: 3,
                refill_per_sec: 0,
            },
            LimitConfig::DEFAULT_ACTOR,
        );
        let a = ip(1);
        for _ in 0..3 {
            assert!(rl.allow(Some(a), None));
        }
        // 4th in the burst is over capacity.
        assert!(!rl.allow(Some(a), None));
    }

    #[test]
    fn separate_ips_dont_share() {
        let rl = RateLimiter::new(
            LimitConfig {
                capacity: 1,
                refill_per_sec: 0,
            },
            LimitConfig::DEFAULT_ACTOR,
        );
        let a = ip(1);
        let b = ip(2);
        assert!(rl.allow(Some(a), None));
        assert!(!rl.allow(Some(a), None));
        // b is unaffected.
        assert!(rl.allow(Some(b), None));
    }

    #[test]
    fn actor_bucket_also_charged() {
        let rl = RateLimiter::new(
            LimitConfig::DEFAULT_IP,
            LimitConfig {
                capacity: 2,
                refill_per_sec: 0,
            },
        );
        let a = ip(1);
        assert!(rl.allow(Some(a), Some("tok")));
        assert!(rl.allow(Some(a), Some("tok")));
        // Actor bucket empty even though IP bucket has plenty.
        assert!(!rl.allow(Some(a), Some("tok")));
        // Different actor: independent.
        assert!(rl.allow(Some(a), Some("other")));
    }

    #[test]
    fn gc_idle_drops_buckets() {
        let rl = RateLimiter::new(
            LimitConfig {
                capacity: 1,
                refill_per_sec: 0,
            },
            LimitConfig::DEFAULT_ACTOR,
        );
        let a = ip(1);
        let _ = rl.allow(Some(a), None);
        rl.gc_idle(Duration::ZERO);
        // After GC the bucket map is empty: a fresh allow() must
        // see a full bucket again.
        assert!(rl.allow(Some(a), None));
    }

    // ── H8 cap: bucket-map size is bounded; new inserts deny ──────
    //
    // Without the cap, an IPv6 /64 attacker rotating source addresses
    // would fill the map with millions of `Key::Ip` entries before the
    // 5-minute idle GC sweeps. The 65_536 ceiling pins memory at ~5
    // MiB even in the worst case and fails closed (new addrs are
    // denied at the door) so the per-IP bucket is never a path to
    // unbounded growth.
    #[test]
    fn cap_full_fail_closed() {
        let rl = RateLimiter::new(
            LimitConfig {
                capacity: 1,
                refill_per_sec: 0,
            },
            LimitConfig {
                // Disable the actor side so the IP path is the only gate.
                capacity: 0,
                refill_per_sec: 0,
            },
        );
        // 65_536 distinct IPv4 addresses fits cleanly in a /16: 256 ×
        // 256 = 65_536 unique (b, c) pairs over 10.0.b.c.
        for n in 0u32..65_536 {
            let b = ((n >> 8) & 0xff) as u8;
            let c = (n & 0xff) as u8;
            let addr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, b, c));
            // Every fill request consumes the bucket's only token but
            // creates a new entry — all 65_536 must succeed.
            assert!(rl.allow(Some(addr), None), "fill {n}");
        }
        // The 65_537th distinct IP cannot get an entry: map is full and
        // the cap inserts a deny instead of growing the map further.
        let overflow = IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 0, 0));
        assert!(!rl.allow(Some(overflow), None));
    }

    // Verify the refill arithmetic by feeding a synthetic `now`
    // directly to `take` — no sleep needed, so the test is fast and
    // deterministic. `Instant` supports `+ Duration`, which is the only
    // way to advance "now" without actually waiting.
    #[test]
    fn refill_advances_with_time() {
        let cfg = LimitConfig {
            capacity: 1,
            refill_per_sec: 1,
        };
        let mut map: HashMap<Key, Bucket> = HashMap::new();
        let t0 = Instant::now();
        let key = Key::Ip(ip(1));
        // Burst of 1 token: first take succeeds, second at the same
        // instant is denied (no time has elapsed → no refill).
        assert!(RateLimiter::take(&mut map, key.clone(), cfg, t0));
        assert!(!RateLimiter::take(&mut map, key.clone(), cfg, t0));
        // Advance 1.1 s. refill_per_sec=1 ⇒ 1100 millitokens added,
        // capped at `capacity * 1000 = 1000`, so the bucket is full
        // again and the next take must succeed.
        let t1 = t0 + Duration::from_millis(1100);
        assert!(RateLimiter::take(&mut map, key, cfg, t1));
    }

    // Both buckets are charged on every `allow`, but each bucket
    // denies independently — exhausting one must NOT spend or shield
    // the other. This is the property the "we charge both regardless"
    // comment in `allow` claims.
    #[test]
    fn actor_and_ip_charged_independently() {
        // Case 1: IP bucket exhausted, actor bucket plenty. Result:
        // request denied even though the actor has tokens.
        let rl = RateLimiter::new(
            LimitConfig {
                capacity: 1,
                refill_per_sec: 0,
            },
            LimitConfig {
                capacity: 1000,
                refill_per_sec: 0,
            },
        );
        let a = ip(1);
        assert!(rl.allow(Some(a), Some("tok")));
        assert!(!rl.allow(Some(a), Some("tok")), "IP empty → deny");

        // Case 2: actor bucket exhausted, IP bucket plenty (fresh IP).
        // Result: still denied — sharing an actor across IPs is the
        // intended throttle vector for a noisy authenticated client.
        let rl = RateLimiter::new(
            LimitConfig {
                capacity: 1000,
                refill_per_sec: 0,
            },
            LimitConfig {
                capacity: 1,
                refill_per_sec: 0,
            },
        );
        assert!(rl.allow(Some(ip(2)), Some("tok")));
        // Same actor, different IP — actor bucket is the gate.
        assert!(!rl.allow(Some(ip(3)), Some("tok")), "actor empty → deny");
        // Different actor, same fresh IP — independent: succeeds.
        assert!(rl.allow(Some(ip(3)), Some("other")));
    }
}
