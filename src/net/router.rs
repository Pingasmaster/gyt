// URL routing + handler dispatch for the gith1b API server.

#[derive(Debug, Clone)]
pub struct RouteMatch {
    pub handler: Handler,
    pub params: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handler {
    RepoList,
    RepoInfo,
    CommitList,
    CommitDetail,
    TreeBrowse,
    RefsList,
    DiffRevs,
    Search,
    StaticFile,
    NotFound,
}

pub fn route(method: &str, path: &str) -> RouteMatch {
    if method != "GET" {
        return RouteMatch {
            handler: Handler::NotFound,
            params: vec![],
        };
    }

    let segments = split_path(path);

    // /api/repos
    if segments == ["api", "repos"] {
        return RouteMatch {
            handler: Handler::RepoList,
            params: vec![],
        };
    }

    // /api/repos/:owner/:name
    if segments.len() >= 4 && segments[0] == "api" && segments[1] == "repos" {
        let owner = segments[2].clone();
        let name = segments[3].clone();

        if segments.len() == 4 {
            return RouteMatch {
                handler: Handler::RepoInfo,
                params: vec![("owner".to_string(), owner), ("name".to_string(), name)],
            };
        }

        let sub = &segments[4..];

        // /api/repos/:owner/:name/commits
        if sub == ["commits"] {
            return RouteMatch {
                handler: Handler::CommitList,
                params: vec![("owner".to_string(), owner), ("name".to_string(), name)],
            };
        }

        // /api/repos/:owner/:name/commits/:sha
        if sub.len() == 2 && sub[0] == "commits" {
            return RouteMatch {
                handler: Handler::CommitDetail,
                params: vec![
                    ("owner".to_string(), owner),
                    ("name".to_string(), name),
                    ("sha".to_string(), sub[1].clone()),
                ],
            };
        }

        // /api/repos/:owner/:name/tree/:ref[/*path]
        if sub.len() >= 2 && sub[0] == "tree" {
            let r#ref = sub[1].clone();
            let rest = if sub.len() > 2 {
                sub[2..].join("/")
            } else {
                String::new()
            };
            return RouteMatch {
                handler: Handler::TreeBrowse,
                params: vec![
                    ("owner".to_string(), owner),
                    ("name".to_string(), name),
                    ("ref".to_string(), r#ref),
                    ("path".to_string(), rest),
                ],
            };
        }

        // /api/repos/:owner/:name/refs
        if sub == ["refs"] {
            return RouteMatch {
                handler: Handler::RefsList,
                params: vec![("owner".to_string(), owner), ("name".to_string(), name)],
            };
        }

        // /api/repos/:owner/:name/diff/:base..:head
        if sub.len() == 2
            && sub[0] == "diff"
            && let Some((base, head)) = sub[1].split_once("..")
        {
            return RouteMatch {
                handler: Handler::DiffRevs,
                params: vec![
                    ("owner".to_string(), owner),
                    ("name".to_string(), name),
                    ("base".to_string(), base.to_string()),
                    ("head".to_string(), head.to_string()),
                ],
            };
        }

        // /api/repos/:owner/:name/search
        if sub == ["search"] {
            return RouteMatch {
                handler: Handler::Search,
                params: vec![("owner".to_string(), owner), ("name".to_string(), name)],
            };
        }
    }

    // If it doesn't match an API route, try serving a static file.
    RouteMatch {
        handler: Handler::StaticFile,
        params: vec![("path".to_string(), path.to_string())],
    }
}

fn split_path(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

pub fn query_params(query: Option<&str>) -> Vec<(String, String)> {
    let Some(q) = query else {
        return vec![];
    };
    q.split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((
                k.to_string(),
                url_decode(v).unwrap_or_else(|()| v.to_string()),
            ))
        })
        .collect()
}

fn url_decode(s: &str) -> std::result::Result<String, ()> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_nibble(bytes[i + 1])?;
            let lo = hex_nibble(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

fn hex_nibble(b: u8) -> std::result::Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

pub fn get_param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_repo_list() {
        let m = route("GET", "/api/repos");
        assert_eq!(m.handler, Handler::RepoList);
    }

    #[test]
    fn route_repo_info() {
        let m = route("GET", "/api/repos/alice/myrepo");
        assert_eq!(m.handler, Handler::RepoInfo);
        assert_eq!(get_param(&m.params, "owner"), Some("alice"));
        assert_eq!(get_param(&m.params, "name"), Some("myrepo"));
    }

    #[test]
    fn route_commit_list() {
        let m = route("GET", "/api/repos/alice/myrepo/commits");
        assert_eq!(m.handler, Handler::CommitList);
    }

    #[test]
    fn route_commit_detail() {
        let m = route("GET", "/api/repos/alice/myrepo/commits/abc123");
        assert_eq!(m.handler, Handler::CommitDetail);
        assert_eq!(get_param(&m.params, "sha"), Some("abc123"));
    }

    #[test]
    fn route_tree_root() {
        let m = route("GET", "/api/repos/alice/myrepo/tree/main");
        assert_eq!(m.handler, Handler::TreeBrowse);
        assert_eq!(get_param(&m.params, "ref"), Some("main"));
        assert_eq!(get_param(&m.params, "path"), Some(""));
    }

    #[test]
    fn route_tree_subpath() {
        let m = route("GET", "/api/repos/alice/myrepo/tree/main/src/lib.rs");
        assert_eq!(m.handler, Handler::TreeBrowse);
        assert_eq!(get_param(&m.params, "ref"), Some("main"));
        assert_eq!(get_param(&m.params, "path"), Some("src/lib.rs"));
    }

    #[test]
    fn route_refs() {
        let m = route("GET", "/api/repos/alice/myrepo/refs");
        assert_eq!(m.handler, Handler::RefsList);
    }

    #[test]
    fn route_diff() {
        let m = route("GET", "/api/repos/alice/myrepo/diff/main..feature");
        assert_eq!(m.handler, Handler::DiffRevs);
        assert_eq!(get_param(&m.params, "base"), Some("main"));
        assert_eq!(get_param(&m.params, "head"), Some("feature"));
    }

    #[test]
    fn route_search() {
        let m = route("GET", "/api/repos/alice/myrepo/search");
        assert_eq!(m.handler, Handler::Search);
    }

    #[test]
    fn route_non_get_returns_not_found() {
        let m = route("POST", "/api/repos/alice/myrepo");
        assert_eq!(m.handler, Handler::NotFound);
    }

    #[test]
    fn route_unknown_falls_to_static() {
        let m = route("GET", "/css/base.css");
        assert_eq!(m.handler, Handler::StaticFile);
    }

    #[test]
    fn query_params_parse() {
        let params = query_params(Some("page=2&per_page=50&q=hello+world"));
        assert_eq!(get_param(&params, "page"), Some("2"));
        assert_eq!(get_param(&params, "per_page"), Some("50"));
        assert_eq!(get_param(&params, "q"), Some("hello world"));
    }

    #[test]
    fn query_params_none() {
        assert!(query_params(None).is_empty());
    }

    #[test]
    fn url_decode_works() {
        assert_eq!(url_decode("hello%20world").unwrap(), "hello world");
        assert_eq!(url_decode("a+b").unwrap(), "a b");
        assert_eq!(url_decode("100%25").unwrap(), "100%");
    }
}
