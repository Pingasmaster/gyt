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
}
