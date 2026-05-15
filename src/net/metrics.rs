// Process-wide HTTP server counters, exported in Prometheus text format
// at GET /metrics. Histograms aren't included — adding bucketed
// histograms with no external metrics dep is enough hand-rolled code to
// be its own change; counters and gauges cover the saturation /
// throughput questions you actually ask in an incident.
//
// Every counter is an AtomicU64 with Relaxed ordering: we tolerate
// brief inter-counter inconsistency in exchange for not paying for a
// Mutex on every request. No counter is part of a correctness
// invariant — they exist for observability.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    /// Connections that successfully made it past `accept` (TLS may
    /// still fail after this).
    pub accepts_total: AtomicU64,
    /// Connections rejected with a 503 because the worker pool was
    /// at capacity. The single most important number to look at when
    /// the server starts dropping load.
    pub pool_exhausted_total: AtomicU64,
    /// Requests received (counted after request-line parsed).
    pub requests_total: AtomicU64,
    /// Requests rejected with 401 because they presented no token,
    /// an unknown token, or a token without the required perm.
    pub requests_unauthorized_total: AtomicU64,
    /// Requests rejected with 429 by the rate limiter (item #7,
    /// wired separately).
    pub requests_rate_limited_total: AtomicU64,
    /// Bytes written back to clients across all responses.
    pub response_bytes_total: AtomicU64,
    /// Bytes received in request bodies.
    pub request_body_bytes_total: AtomicU64,
    /// Successful ref-update lines (refs/update). One per ref, not per
    /// request, since one request can update many refs at once.
    pub refs_updated_total: AtomicU64,
    /// Loose objects stored via objects/have.
    pub objects_stored_total: AtomicU64,
    /// Objects served back via objects/want.
    pub objects_served_total: AtomicU64,
    /// Per-handler request count, keyed by `Handler` variant name.
    /// Kept as 14 named fields rather than a HashMap to avoid
    /// touching a Mutex on every request.
    pub h_repo_list: AtomicU64,
    pub h_repo_info: AtomicU64,
    pub h_commit_list: AtomicU64,
    pub h_commit_detail: AtomicU64,
    pub h_tree_browse: AtomicU64,
    pub h_refs_list: AtomicU64,
    pub h_diff_revs: AtomicU64,
    pub h_search: AtomicU64,
    pub h_info_refs: AtomicU64,
    pub h_objects_want: AtomicU64,
    pub h_objects_have: AtomicU64,
    pub h_refs_update: AtomicU64,
    pub h_static: AtomicU64,
    pub h_other: AtomicU64,
}

impl Metrics {
    pub fn record_handler(&self, handler: crate::net::router::Handler) {
        use crate::net::router::Handler::{
            AdminShutdown, CommitDetail, CommitList, DiffRevs, Healthz, InfoRefs, Metrics as MH,
            NotFound, ObjectsHave, ObjectsWant, Readyz, RefsList, RefsUpdate, RepoInfo, RepoList,
            Search, StaticFile, TreeBrowse,
        };
        let counter = match handler {
            RepoList => &self.h_repo_list,
            RepoInfo => &self.h_repo_info,
            CommitList => &self.h_commit_list,
            CommitDetail => &self.h_commit_detail,
            TreeBrowse => &self.h_tree_browse,
            RefsList => &self.h_refs_list,
            DiffRevs => &self.h_diff_revs,
            Search => &self.h_search,
            InfoRefs => &self.h_info_refs,
            ObjectsWant => &self.h_objects_want,
            ObjectsHave => &self.h_objects_have,
            RefsUpdate => &self.h_refs_update,
            StaticFile => &self.h_static,
            Healthz | Readyz | MH | AdminShutdown | NotFound => &self.h_other,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Render Prometheus text-format. Every counter is `# TYPE` +
    /// metric name + value. No HELP lines — they bloat the response
    /// and the metric names are self-explanatory.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);
        let mut g = |name: &str, v: u64| {
            out.push_str("# TYPE ");
            out.push_str(name);
            out.push_str(" counter\n");
            out.push_str(name);
            out.push(' ');
            out.push_str(&v.to_string());
            out.push('\n');
        };
        g("gyt_accepts_total", self.accepts_total.load(Ordering::Relaxed));
        g(
            "gyt_pool_exhausted_total",
            self.pool_exhausted_total.load(Ordering::Relaxed),
        );
        g("gyt_requests_total", self.requests_total.load(Ordering::Relaxed));
        g(
            "gyt_requests_unauthorized_total",
            self.requests_unauthorized_total.load(Ordering::Relaxed),
        );
        g(
            "gyt_requests_rate_limited_total",
            self.requests_rate_limited_total.load(Ordering::Relaxed),
        );
        g(
            "gyt_response_bytes_total",
            self.response_bytes_total.load(Ordering::Relaxed),
        );
        g(
            "gyt_request_body_bytes_total",
            self.request_body_bytes_total.load(Ordering::Relaxed),
        );
        g(
            "gyt_refs_updated_total",
            self.refs_updated_total.load(Ordering::Relaxed),
        );
        g(
            "gyt_objects_stored_total",
            self.objects_stored_total.load(Ordering::Relaxed),
        );
        g(
            "gyt_objects_served_total",
            self.objects_served_total.load(Ordering::Relaxed),
        );
        // Per-handler counts share a single label key.
        let mut h = |label: &str, v: u64| {
            out.push_str("# TYPE gyt_requests_by_handler_total counter\n");
            out.push_str("gyt_requests_by_handler_total{handler=\"");
            out.push_str(label);
            out.push_str("\"} ");
            out.push_str(&v.to_string());
            out.push('\n');
        };
        h("repo_list", self.h_repo_list.load(Ordering::Relaxed));
        h("repo_info", self.h_repo_info.load(Ordering::Relaxed));
        h("commit_list", self.h_commit_list.load(Ordering::Relaxed));
        h("commit_detail", self.h_commit_detail.load(Ordering::Relaxed));
        h("tree_browse", self.h_tree_browse.load(Ordering::Relaxed));
        h("refs_list", self.h_refs_list.load(Ordering::Relaxed));
        h("diff_revs", self.h_diff_revs.load(Ordering::Relaxed));
        h("search", self.h_search.load(Ordering::Relaxed));
        h("info_refs", self.h_info_refs.load(Ordering::Relaxed));
        h("objects_want", self.h_objects_want.load(Ordering::Relaxed));
        h("objects_have", self.h_objects_have.load(Ordering::Relaxed));
        h("refs_update", self.h_refs_update.load(Ordering::Relaxed));
        h("static", self.h_static.load(Ordering::Relaxed));
        h("other", self.h_other.load(Ordering::Relaxed));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::router::Handler;

    #[test]
    fn metrics_render_includes_all_counters() {
        let m = Metrics::default();
        m.accepts_total.fetch_add(7, Ordering::Relaxed);
        m.record_handler(Handler::RepoList);
        m.record_handler(Handler::RepoList);
        m.record_handler(Handler::Healthz);
        let out = m.render_prometheus();
        assert!(out.contains("gyt_accepts_total 7"));
        assert!(out.contains("gyt_requests_by_handler_total{handler=\"repo_list\"} 2"));
        assert!(out.contains("gyt_requests_by_handler_total{handler=\"other\"} 1"));
    }
}
