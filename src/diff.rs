//! Hand-rolled Myers' line-based diff. No external dependencies.
//!
//! Reference: https://blog.jcoglan.com/2017/02/12/the-myers-diff-algorithm-part-1/
//! We implement the basic O(ND) variant; the linear-space refinement is not
//! needed at this scale. Inputs are split on `\n`; a trailing line without a
//! newline is retained as its own line.
//!
//! ## `diff --stat`
//! The `render_stat` function provides a compact summary of changes per file:
//! how many insertions and deletions, shown as a proportional bar.

use crate::term;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffOp<'a> {
    /// Line present in both `a` and `b` (no trailing `\n`).
    Equal(&'a [u8]),
    /// Line present in `a` only.
    Delete(&'a [u8]),
    /// Line present in `b` only.
    Insert(&'a [u8]),
}

/// Split a buffer on `\n`. A trailing line without a newline is included.
/// An empty input yields an empty Vec (no spurious empty line).
#[expect(
    clippy::indexing_slicing,
    reason = "buf[start..i] and buf[start..] use indices that are themselves yielded by enumerate() over buf — they are by construction valid offsets into buf"
)]
pub fn split_lines(buf: &[u8]) -> Vec<&[u8]> {
    if buf.is_empty() {
        return Vec::new();
    }
    let mut lines = Vec::new();
    let mut start = 0usize;
    for (i, &b) in buf.iter().enumerate() {
        if b == b'\n' {
            lines.push(&buf[start..i]);
            start = i + 1;
        }
    }
    if start < buf.len() {
        lines.push(&buf[start..]);
    }
    lines
}

/// Max sum-of-line-counts at which we still run the proper Myers
/// trace. Above this, the algorithm's `Vec<Vec<i32>>` `trace`
/// allocation is Θ((n+m)²) — for two 50k-line files that's ~80 GB.
/// Closes F-D6-03: instead of OOM-ing the process on a malicious or
/// huge blob diff, we degrade gracefully to a coarse delete-all /
/// insert-all diff that still renders correctly in `gyt diff/log/show`
/// and produces a valid (if maximally-conflicted) merge3 input.
pub const MAX_DIFF_LINES: usize = 50_000;

/// Myers' diff between two slices of lines. Returns a flat ordered op list.
#[expect(clippy::many_single_char_names, reason = "single-letter names are conventional shorthand in this algorithm")]
#[expect(
    clippy::indexing_slicing,
    reason = "all v[idx(k)], a[x], b[y], trace[d] indexing is bounded: x∈[0,n_i] and y∈[0,m_i] are checked by `x < n_i && y < m_i`; idx(k) returns k+offset which stays inside v_size=2*max+1 by Myers algorithm invariants"
)]
pub fn myers<'a>(a: &[&'a [u8]], b: &[&'a [u8]]) -> Vec<DiffOp<'a>> {
    let n = a.len();
    let m = b.len();

    // Trivial cases.
    if n == 0 && m == 0 {
        return Vec::new();
    }
    if n == 0 {
        return b.iter().map(|l| DiffOp::Insert(l)).collect();
    }
    if m == 0 {
        return a.iter().map(|l| DiffOp::Delete(l)).collect();
    }

    // F-D6-03: degrade to a coarse delete-all / insert-all diff for
    // inputs above MAX_DIFF_LINES. The trace allocation is the
    // expensive part — Θ((n+m)²) — and a malicious or pathologically
    // large blob diff would OOM the process otherwise.
    if n.saturating_add(m) > MAX_DIFF_LINES {
        let mut ops: Vec<DiffOp<'a>> = Vec::with_capacity(n + m);
        for l in a {
            ops.push(DiffOp::Delete(l));
        }
        for l in b {
            ops.push(DiffOp::Insert(l));
        }
        return ops;
    }

    let max = n + m;
    // V is indexed by k in [-max, max]; we offset by `max`.
    let offset = max;
    let v_size = 2 * max + 1;
    let mut v = vec![0i32; v_size];
    // trace[d][k+offset] = x for that step
    let mut trace: Vec<Vec<i32>> = Vec::with_capacity(max + 1);

    let n_i = n as i32;
    let m_i = m as i32;

    let idx = |k: i32| -> usize { (k + offset as i32) as usize };

    'outer: for d in 0..=(max as i32) {
        let mut k = -d;
        while k <= d {
            let down = k == -d || (k != d && v[idx(k - 1)] < v[idx(k + 1)]);
            let mut x = if down {
                v[idx(k + 1)]
            } else {
                v[idx(k - 1)] + 1
            };
            let mut y = x - k;
            // Follow the diagonal (snake). The cast indices are non-negative
            // by construction (we just initialized x ≥ 0 and y = x − k where
            // both bounds are checked above), so a usize cast is safe.
            #[expect(clippy::suspicious_operation_groupings, reason = "Myers' algorithm uses two independent dimension indices; not interchangeable")] // Reason: Myers' algorithm checks (x < n) && (y < m) with x = a-index, y = b-index — they are independent dimensions, not interchangeable.
            while x < n_i && y < m_i && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[idx(k)] = x;
            if x >= n_i && y >= m_i {
                trace.push(v.clone());
                break 'outer;
            }
            k += 2;
        }
        trace.push(v.clone());
    }

    // Backtrack from (n, m).
    let mut ops_rev: Vec<DiffOp<'a>> = Vec::new();
    let mut x = n_i;
    let mut y = m_i;
    for d in (0..trace.len() as i32).rev() {
        let v_d = &trace[d as usize];
        let k = x - y;
        let prev_k = if k == -d || (k != d && v_d[idx(k - 1)] < v_d[idx(k + 1)]) {
            k + 1
        } else {
            k - 1
        };
        let prev_x = v_d[idx(prev_k)];
        let prev_y = prev_x - prev_k;

        // Walk the diagonal back (these are Equal lines).
        while x > prev_x && y > prev_y {
            ops_rev.push(DiffOp::Equal(a[(x - 1) as usize]));
            x -= 1;
            y -= 1;
        }

        if d > 0 {
            if x == prev_x {
                // came from above: insertion in b
                ops_rev.push(DiffOp::Insert(b[(prev_y) as usize]));
            } else {
                // came from left: deletion in a
                ops_rev.push(DiffOp::Delete(a[(prev_x) as usize]));
            }
            x = prev_x;
            y = prev_y;
        }
    }

    ops_rev.reverse();
    ops_rev
}

pub fn diff_lines<'a>(a: &'a [u8], b: &'a [u8]) -> Vec<DiffOp<'a>> {
    let la = split_lines(a);
    let lb = split_lines(b);
    myers(&la, &lb)
}

fn is_binary(buf: &[u8]) -> bool {
    buf.contains(&0u8)
}

/// One contiguous diff hunk.
struct Hunk<'a> {
    a_start: usize, // 1-based line number in a
    a_len: usize,
    b_start: usize, // 1-based line number in b
    b_len: usize,
    ops: Vec<DiffOp<'a>>,
}

#[expect(
    clippy::indexing_slicing,
    reason = "every ops[N] / ops[hunk_op_start..trail_end] is gated by an explicit length check (i < n, run_end < n, trail_end < n) on the same line"
)]
fn group_hunks<'a>(ops: &[DiffOp<'a>], context: usize) -> Vec<Hunk<'a>> {
    // Walk ops once, tracking 0-based positions in a/b. Emit hunks
    // around runs of non-equal ops with up to `context` Equal lines on
    // either side. Adjacent change-runs whose context windows overlap
    // are merged.
    let mut hunks: Vec<Hunk<'a>> = Vec::new();
    let n = ops.len();
    let mut i = 0usize;
    let mut a_pos: usize = 0; // 0-based position in a, advances on Equal/Delete
    let mut b_pos: usize = 0; // 0-based position in b, advances on Equal/Insert

    while i < n {
        // Skip Equal ops while they aren't part of a hunk.
        while i < n && matches!(ops[i], DiffOp::Equal(_)) {
            a_pos += 1;
            b_pos += 1;
            i += 1;
        }
        if i >= n {
            break;
        }

        // First change at index i.
        // Leading context: take up to `context` immediately preceding
        // Equal ops by walking back from i.
        let mut lead = 0usize;
        while lead < context && i > lead {
            if let DiffOp::Equal(_) = ops[i - lead - 1] {
                lead += 1;
            } else {
                break;
            }
        }
        let hunk_op_start = i - lead;
        // Adjust positions to the start of leading context.
        let hunk_a_start_0 = a_pos - lead;
        let hunk_b_start_0 = b_pos - lead;

        // Now consume changes; allow up to (2 * context) consecutive Equal
        // ops to be absorbed into the hunk before splitting.
        let mut j = i;
        let mut last_change = i;
        while j < n {
            match ops[j] {
                DiffOp::Equal(_) => {
                    // Look ahead: how long is this equal run?
                    let mut run_end = j;
                    while run_end < n && matches!(ops[run_end], DiffOp::Equal(_)) {
                        run_end += 1;
                    }
                    let run_len = run_end - j;
                    // If there are more changes after this run AND the run is
                    // short enough to be absorbed (<= 2*context), keep going.
                    let has_more_changes = run_end < n;
                    if has_more_changes && run_len <= 2 * context {
                        j = run_end;
                        continue;
                    }
                    break;
                }
                _ => {
                    last_change = j;
                    j += 1;
                }
            }
        }

        // Trailing context: up to `context` Equal ops past `last_change`.
        let mut trail_end = last_change + 1;
        let mut trail = 0usize;
        while trail < context && trail_end < n && matches!(ops[trail_end], DiffOp::Equal(_)) {
            trail_end += 1;
            trail += 1;
        }

        // Extract the hunk's ops and compute lengths.
        let hunk_ops: Vec<DiffOp<'a>> = ops[hunk_op_start..trail_end].to_vec();
        let mut a_len = 0usize;
        let mut b_len = 0usize;
        for op in &hunk_ops {
            match op {
                DiffOp::Equal(_) => {
                    a_len += 1;
                    b_len += 1;
                }
                DiffOp::Delete(_) => a_len += 1,
                DiffOp::Insert(_) => b_len += 1,
            }
        }

        hunks.push(Hunk {
            a_start: hunk_a_start_0 + 1,
            a_len,
            b_start: hunk_b_start_0 + 1,
            b_len,
            ops: hunk_ops,
        });

        // Advance scanner past the trailing context that we consumed.
        // Update a_pos / b_pos to reflect everything from i .. trail_end.
        for op in &ops[i..trail_end] {
            match op {
                DiffOp::Equal(_) => {
                    a_pos += 1;
                    b_pos += 1;
                }
                DiffOp::Delete(_) => a_pos += 1,
                DiffOp::Insert(_) => b_pos += 1,
            }
        }
        i = trail_end;
    }

    hunks
}

/// Append a single line of `payload` to `out` with its prefix, optionally
/// colored. The line is followed by a `\n`.
fn write_line(out: &mut String, prefix: char, color: &str, payload: &[u8], use_color: bool) {
    let prefix_str = prefix.to_string();
    // We render bytes lossily; this is a developer-facing diff view.
    let body = String::from_utf8_lossy(payload);
    let combined = format!("{prefix_str}{body}");
    if use_color {
        out.push_str(&term::paint_when(use_color, color, &combined));
    } else {
        out.push_str(&combined);
    }
    out.push('\n');
}

pub fn render_unified(
    a: &[u8],
    b: &[u8],
    header_a: &str,
    header_b: &str,
    context: usize,
    use_color: bool,
) -> String {
    if is_binary(a) || is_binary(b) {
        return "Binary files differ\n".to_string();
    }

    let ops = diff_lines(a, b);

    // If everything is Equal, no output (matches `git diff` for identical content).
    if ops.iter().all(|op| matches!(op, DiffOp::Equal(_))) {
        return String::new();
    }

    let hunks = group_hunks(&ops, context);
    let mut out = String::new();

    let head_a_line = format!("--- a/{header_a}");
    let head_b_line = format!("+++ b/{header_b}");
    if use_color {
        out.push_str(&term::paint_when(use_color, term::BOLD, &head_a_line));
        out.push('\n');
        out.push_str(&term::paint_when(use_color, term::BOLD, &head_b_line));
    } else {
        out.push_str(&head_a_line);
        out.push('\n');
        out.push_str(&head_b_line);
    }
    out.push('\n');

    for h in &hunks {
        let header = format!(
            "@@ -{},{} +{},{} @@",
            h.a_start, h.a_len, h.b_start, h.b_len
        );
        out.push_str(&term::paint_when(use_color, term::CYAN, &header));
        out.push('\n');

        for op in &h.ops {
            match op {
                DiffOp::Equal(l) => write_line(&mut out, ' ', "", l, false),
                DiffOp::Delete(l) => write_line(&mut out, '-', term::RED, l, use_color),
                DiffOp::Insert(l) => write_line(&mut out, '+', term::GREEN, l, use_color),
            }
        }
    }

    out
}

/// Compute a stat summary for a single file diff: returns (insertions, deletions).
pub fn count_changes(a: &[u8], b: &[u8]) -> (usize, usize) {
    if is_binary(a) || is_binary(b) {
        return (0, 0);
    }
    let ops = diff_lines(a, b);
    let mut ins = 0usize;
    let mut del = 0usize;
    for op in &ops {
        match op {
            DiffOp::Insert(_) => ins += 1,
            DiffOp::Delete(_) => del += 1,
            DiffOp::Equal(_) => {}
        }
    }
    (ins, del)
}

/// Render a `--stat` line for one file:  `filename | N +++++---`
/// Bar width max 20 chars. Shows inserts as `+`, deletes as `-`.
#[expect(
    clippy::integer_division,
    reason = "intentional truncating integer division"
)]
pub fn render_stat(filename: &str, ins: usize, del: usize) -> String {
    let total = ins + del;
    if total == 0 {
        return format!(" {filename} | 0\n");
    }
    let bar_width = total.min(20);
    let ins_bar = if ins > 0 && bar_width > 0 {
        let ins_chars = (ins * bar_width + total / 2) / total;
        let ins_chars = ins_chars.max(1.min(ins));
        "+".repeat(ins_chars)
    } else {
        String::new()
    };
    let del_bar = if del > 0 && bar_width > ins_bar.len() {
        let del_chars = bar_width - ins_bar.len();
        "-".repeat(del_chars)
    } else if del > 0 && ins_bar.is_empty() {
        "-".repeat(bar_width.max(1))
    } else {
        String::new()
    };
    format!(" {filename} | {total} {ins_bar}{del_bar}\n")
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::indexing_slicing,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;

    #[test]
    fn equal_inputs_produce_only_equal() {
        let ops = diff_lines(b"a\nb\n", b"a\nb\n");
        assert_eq!(ops.len(), 2);
        assert!(matches!(ops[0], DiffOp::Equal(b"a")));
        assert!(matches!(ops[1], DiffOp::Equal(b"b")));
    }

    #[test]
    fn pure_insert() {
        let ops = diff_lines(b"", b"x\n");
        assert_eq!(ops.len(), 1);
        assert!(matches!(ops[0], DiffOp::Insert(b"x")));
    }

    #[test]
    fn pure_delete() {
        let ops = diff_lines(b"x\n", b"");
        assert_eq!(ops.len(), 1);
        assert!(matches!(ops[0], DiffOp::Delete(b"x")));
    }

    #[test]
    fn mixed_change() {
        // change one middle line: a/B/c -> a/X/c
        let ops = diff_lines(b"a\nB\nc\n", b"a\nX\nc\n");
        // Expect: Equal(a), Delete(B), Insert(X), Equal(c)
        // (The exact order of Delete vs Insert may vary depending on the
        // path Myers picks; they must be adjacent and surrounded by Equals.)
        assert_eq!(ops.len(), 4);
        assert!(matches!(ops[0], DiffOp::Equal(b"a")));
        assert!(matches!(ops[3], DiffOp::Equal(b"c")));
        // The two middle ops must be one Delete(B) and one Insert(X).
        let mids = (&ops[1], &ops[2]);
        let has_del =
            matches!(mids.0, DiffOp::Delete(b"B")) || matches!(mids.1, DiffOp::Delete(b"B"));
        let has_ins =
            matches!(mids.0, DiffOp::Insert(b"X")) || matches!(mids.1, DiffOp::Insert(b"X"));
        assert!(
            has_del && has_ins,
            "expected del(B) and ins(X), got {ops:?}"
        );
    }

    #[test]
    fn unified_renders_hunk_headers() {
        let out = render_unified(b"a\nb\nc\n", b"a\nB\nc\n", "f", "f", 3, false);
        assert!(out.contains("--- a/f"), "missing --- header: {out}");
        assert!(out.contains("+++ b/f"), "missing +++ header: {out}");
        assert!(out.contains("@@ "), "missing hunk header: {out}");
        assert!(out.contains("-b"), "missing delete line: {out}");
        assert!(out.contains("+B"), "missing insert line: {out}");
    }

    #[test]
    fn binary_input_emits_binary_message() {
        let a = b"hello\nworld\n";
        let b: &[u8] = &[b'h', 0, b'i', b'\n'];
        let out = render_unified(a, b, "f", "f", 3, false);
        assert_eq!(out, "Binary files differ\n");
    }

    #[test]
    fn split_lines_handles_no_trailing_newline() {
        let lines = split_lines(b"a\nb");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"a");
        assert_eq!(lines[1], b"b");
    }

    #[test]
    fn split_lines_empty_is_empty() {
        let lines = split_lines(b"");
        assert!(lines.is_empty());
    }

    #[test]
    fn identical_content_renders_empty() {
        let out = render_unified(b"a\nb\n", b"a\nb\n", "f", "f", 3, false);
        assert!(out.is_empty(), "expected empty diff, got: {out}");
    }
}
