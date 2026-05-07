// Hand-rolled HTTP/1.1 client. Phase 6a.
//
// Each request opens a fresh connection (no keepalive). HTTPS uses
// `tls::connect_tls`; plain HTTP uses `TcpStream` and is gated behind
// `HttpClient::new_plain` (test/local-server use only — `HttpClient::new`
// rejects non-https schemes).
//
// Body framing: we honour `Content-Length` and `Transfer-Encoding: chunked`.
// If neither header is present we read until EOF (server closes connection).

use crate::errors::{GytError, Result};
use crate::net::tls;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

const USER_AGENT: &str = concat!("gyt/", env!("CARGO_PKG_VERSION"));

/// A parsed HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Https,
    Http,
}

/// HTTPS-by-default HTTP/1.1 client.
pub struct HttpClient {
    scheme: Scheme,
    host: String,
    port: u16,
    base_path: String,
    base_query: Option<String>,
    auth: Option<String>,
}

impl HttpClient {
    /// Build a client over HTTPS. `base_url` must start with `https://`.
    pub fn new(base_url: &str) -> Result<Self> {
        Self::new_inner(base_url, false)
    }

    /// Build a client over plain HTTP. For tests and local servers.
    pub fn new_plain(base_url: &str) -> Result<Self> {
        Self::new_inner(base_url, true)
    }

    fn new_inner(base_url: &str, allow_plain: bool) -> Result<Self> {
        let (scheme, rest) = if let Some(rest) = base_url.strip_prefix("https://") {
            (Scheme::Https, rest)
        } else if let Some(rest) = base_url.strip_prefix("http://") {
            if !allow_plain {
                return Err(GytError::Net(
                    "plain http:// is not allowed; use HttpClient::new_plain for tests".into(),
                ));
            }
            (Scheme::Http, rest)
        } else {
            return Err(GytError::Net(format!(
                "unsupported url scheme: {base_url:?}"
            )));
        };

        // Split off path/query.
        let (authority, path_and_query) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(GytError::Net(format!("missing host in url: {base_url:?}")));
        }

        // Split path/query.
        let (path, query) = match path_and_query.find('?') {
            Some(i) => (
                path_and_query[..i].to_string(),
                Some(path_and_query[i + 1..].to_string()),
            ),
            None => (path_and_query.to_string(), None),
        };

        // Split host:port.
        let (host, port) = parse_authority(authority, scheme)?;

        Ok(Self {
            scheme,
            host,
            port,
            base_path: path,
            base_query: query,
            auth: None,
        })
    }

    pub fn with_basic_auth(mut self, username: &str, password: &str) -> Self {
        let raw = format!("{username}:{password}");
        let encoded = base64_encode(raw.as_bytes());
        self.auth = Some(format!("Basic {encoded}"));
        self
    }

    pub fn get(&self, path_suffix: &str, extra_headers: &[(&str, &str)]) -> Result<HttpResponse> {
        self.request("GET", path_suffix, None, extra_headers)
    }

    pub fn post(
        &self,
        path_suffix: &str,
        body: &[u8],
        extra_headers: &[(&str, &str)],
    ) -> Result<HttpResponse> {
        self.request("POST", path_suffix, Some(body), extra_headers)
    }

    fn request(
        &self,
        method: &str,
        path_suffix: &str,
        body: Option<&[u8]>,
        extra_headers: &[(&str, &str)],
    ) -> Result<HttpResponse> {
        let target = self.build_target(path_suffix);
        let request_bytes = self.build_request(method, &target, body, extra_headers);

        match self.scheme {
            Scheme::Https => {
                let mut stream = tls::connect_tls(&self.host, self.port)?;
                stream.write_all(&request_bytes)?;
                stream.flush()?;
                read_response(&mut stream)
            }
            Scheme::Http => {
                let mut stream = TcpStream::connect((self.host.as_str(), self.port))
                    .map_err(|e| GytError::Net(format!("tcp connect: {e}")))?;
                stream.write_all(&request_bytes)?;
                stream.flush()?;
                read_response(&mut stream)
            }
        }
    }

    fn build_target(&self, path_suffix: &str) -> String {
        // Concatenate base_path with suffix. base_path already starts with `/`.
        // Suffix is treated relative; do not double up the slash.
        let mut t = String::with_capacity(self.base_path.len() + path_suffix.len() + 1);
        t.push_str(&self.base_path);
        if !t.ends_with('/') && !path_suffix.starts_with('/') {
            t.push('/');
        }
        // If suffix begins with `/` and base ends with `/`, drop one.
        if t.ends_with('/') && path_suffix.starts_with('/') {
            t.push_str(&path_suffix[1..]);
        } else {
            t.push_str(path_suffix);
        }
        if let Some(q) = &self.base_query {
            // If the suffix already has a `?`, append with `&`; otherwise `?`.
            if t.contains('?') {
                t.push('&');
            } else {
                t.push('?');
            }
            t.push_str(q);
        }
        t
    }

    fn build_request(
        &self,
        method: &str,
        target: &str,
        body: Option<&[u8]>,
        extra_headers: &[(&str, &str)],
    ) -> Vec<u8> {
        let mut req = Vec::with_capacity(256 + body.map(<[u8]>::len).unwrap_or(0));
        let _ = write!(req, "{method} {target} HTTP/1.1\r\n");
        let host_header = if (self.scheme == Scheme::Https && self.port == 443)
            || (self.scheme == Scheme::Http && self.port == 80)
        {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        };
        let _ = write!(req, "Host: {host_header}\r\n");
        let _ = write!(req, "User-Agent: {USER_AGENT}\r\n");
        let _ = write!(req, "Connection: close\r\n");
        let _ = write!(req, "Accept: */*\r\n");
        if let Some(auth) = &self.auth {
            let _ = write!(req, "Authorization: {auth}\r\n");
        }
        if let Some(b) = body {
            let _ = write!(req, "Content-Length: {}\r\n", b.len());
        } else if method == "POST" || method == "PUT" {
            let _ = write!(req, "Content-Length: 0\r\n");
        }
        for (k, v) in extra_headers {
            let _ = write!(req, "{k}: {v}\r\n");
        }
        req.extend_from_slice(b"\r\n");
        if let Some(b) = body {
            req.extend_from_slice(b);
        }
        req
    }
}

fn parse_authority(authority: &str, scheme: Scheme) -> Result<(String, u16)> {
    if let Some((h, p)) = authority.rsplit_once(':') {
        let port: u16 = p
            .parse()
            .map_err(|_| GytError::Net(format!("invalid port in authority: {authority:?}")))?;
        Ok((h.to_string(), port))
    } else {
        let port = match scheme {
            Scheme::Https => 443,
            Scheme::Http => 80,
        };
        Ok((authority.to_string(), port))
    }
}

// ---------- response parsing ----------

fn read_response<R: Read>(stream: &mut R) -> Result<HttpResponse> {
    let mut reader = BufReader::new(stream);
    let header_bytes = read_until_crlf_crlf(&mut reader)?;
    let header_str = std::str::from_utf8(&header_bytes)
        .map_err(|_| GytError::Net("non-utf8 response headers".into()))?;
    let mut lines = header_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| GytError::Net("empty response".into()))?;
    let (status, reason) = parse_status_line(status_line)?;
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        headers.push(parse_header_line(line)?);
    }

    // Determine framing.
    let is_chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && contains_token(v, "chunked"));
    let content_length: Option<usize> = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok());

    let body = if is_chunked {
        chunked_decode(&mut reader)?
    } else if let Some(n) = content_length {
        let mut buf = vec![0u8; n];
        reader.read_exact(&mut buf)?;
        buf
    } else {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        buf
    };

    Ok(HttpResponse {
        status,
        reason,
        headers,
        body,
    })
}

fn read_until_crlf_crlf<R: BufRead>(reader: &mut R) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    loop {
        let n_before = buf.len();
        let read = reader.read_until(b'\n', &mut buf)?;
        if read == 0 {
            return Err(GytError::Net("unexpected EOF while reading headers".into()));
        }
        // Strip the trailing CRLF for the empty-line check.
        if buf.ends_with(b"\r\n\r\n") {
            // trim the last \r\n so the caller sees just header text.
            buf.truncate(buf.len() - 2);
            return Ok(buf);
        }
        if buf.ends_with(b"\n\n") {
            buf.truncate(buf.len() - 1);
            return Ok(buf);
        }
        if buf.len() == n_before {
            return Err(GytError::Net("no progress reading headers".into()));
        }
        if buf.len() > 64 * 1024 {
            return Err(GytError::Net("response headers too large".into()));
        }
    }
}

fn parse_status_line(line: &str) -> Result<(u16, String)> {
    // HTTP/1.1 200 OK
    let mut parts = line.splitn(3, ' ');
    let _version = parts
        .next()
        .ok_or_else(|| GytError::Net(format!("bad status line: {line:?}")))?;
    let status_s = parts
        .next()
        .ok_or_else(|| GytError::Net(format!("bad status line: {line:?}")))?;
    let reason = parts.next().unwrap_or("").trim_end().to_string();
    let status: u16 = status_s
        .parse()
        .map_err(|_| GytError::Net(format!("non-numeric status: {status_s:?}")))?;
    Ok((status, reason))
}

fn parse_header_line(line: &str) -> Result<(String, String)> {
    let (k, v) = line
        .split_once(':')
        .ok_or_else(|| GytError::Net(format!("bad header line: {line:?}")))?;
    Ok((k.trim().to_string(), v.trim().to_string()))
}

fn contains_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

fn chunked_decode<R: BufRead>(reader: &mut R) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut size_line = String::new();
        let n = reader
            .read_line(&mut size_line)
            .map_err(|e| GytError::Net(format!("chunked: read size: {e}")))?;
        if n == 0 {
            return Err(GytError::Net(
                "chunked: unexpected EOF before final chunk".into(),
            ));
        }
        // Trim CRLF and any chunk-extension after `;`.
        let trimmed = size_line.trim_end_matches(['\r', '\n']);
        let hex = trimmed.split(';').next().unwrap_or("").trim();
        if hex.is_empty() {
            return Err(GytError::Net(format!(
                "chunked: empty size line: {size_line:?}"
            )));
        }
        let size = usize::from_str_radix(hex, 16)
            .map_err(|_| GytError::Net(format!("chunked: bad hex size: {hex:?}")))?;
        if size == 0 {
            // Read trailers until empty line.
            loop {
                let mut t = String::new();
                let n = reader
                    .read_line(&mut t)
                    .map_err(|e| GytError::Net(format!("chunked: read trailer: {e}")))?;
                if n == 0 {
                    break;
                }
                if t.trim_end_matches(['\r', '\n']).is_empty() {
                    break;
                }
            }
            return Ok(out);
        }
        let mut chunk = vec![0u8; size];
        reader
            .read_exact(&mut chunk)
            .map_err(|e| GytError::Net(format!("chunked: read body: {e}")))?;
        out.extend_from_slice(&chunk);
        // Consume trailing CRLF after the chunk data.
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .map_err(|e| GytError::Net(format!("chunked: trailing crlf: {e}")))?;
        if &crlf != b"\r\n" {
            return Err(GytError::Net(format!(
                "chunked: missing CRLF after chunk, got {crlf:?}"
            )));
        }
    }
}

// ---------- minimal base64 encoder for basic-auth ----------
//
// We don't have a base64 dep; basic-auth credentials are short, so a tiny
// encoder is fine. Standard alphabet, with padding.

fn base64_encode(input: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let b0 = u32::from(input[i]);
        let b1 = u32::from(input[i + 1]);
        let b2 = u32::from(input[i + 2]);
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TBL[((n >> 18) & 0x3f) as usize] as char);
        out.push(TBL[((n >> 12) & 0x3f) as usize] as char);
        out.push(TBL[((n >> 6) & 0x3f) as usize] as char);
        out.push(TBL[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let b0 = u32::from(input[i]);
        let n = b0 << 16;
        out.push(TBL[((n >> 18) & 0x3f) as usize] as char);
        out.push(TBL[((n >> 12) & 0x3f) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let b0 = u32::from(input[i]);
        let b1 = u32::from(input[i + 1]);
        let n = (b0 << 16) | (b1 << 8);
        out.push(TBL[((n >> 18) & 0x3f) as usize] as char);
        out.push(TBL[((n >> 12) & 0x3f) as usize] as char);
        out.push(TBL[((n >> 6) & 0x3f) as usize] as char);
        out.push('=');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_line_ok() {
        assert_eq!(
            parse_status_line("HTTP/1.1 200 OK").unwrap(),
            (200, "OK".to_string())
        );
        assert_eq!(
            parse_status_line("HTTP/1.1 404 Not Found").unwrap(),
            (404, "Not Found".to_string())
        );
        // Empty reason is fine.
        assert_eq!(
            parse_status_line("HTTP/1.1 204 ").unwrap(),
            (204, String::new())
        );
    }

    #[test]
    fn parse_header_line_ok() {
        let (k, v) = parse_header_line("Content-Length: 42").unwrap();
        assert_eq!(k, "Content-Length");
        assert_eq!(v, "42");
    }

    #[test]
    fn b64_encode_examples() {
        // RFC 4648 test vectors.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base_url_rejects_plain_in_new() {
        assert!(HttpClient::new("http://example.com/").is_err());
        assert!(HttpClient::new("ftp://example.com/").is_err());
        assert!(HttpClient::new("https://example.com/").is_ok());
    }

    #[test]
    fn build_target_joins_correctly() {
        let c = HttpClient::new("https://example.com/repo/").unwrap();
        assert_eq!(c.build_target("info/refs"), "/repo/info/refs");
        let c = HttpClient::new("https://example.com/repo").unwrap();
        assert_eq!(c.build_target("info/refs"), "/repo/info/refs");
        let c = HttpClient::new("https://example.com/repo/?force=1").unwrap();
        assert_eq!(c.build_target("info/refs"), "/repo/info/refs?force=1");
    }

    #[test]
    fn chunked_decode_round_trip() {
        // 5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n  -> "hello world"
        let input: &[u8] = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut cur = std::io::Cursor::new(input);
        let out = chunked_decode(&mut cur).unwrap();
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn chunked_decode_handles_extensions() {
        let input: &[u8] = b"3;name=foo\r\nabc\r\n0\r\n\r\n";
        let mut cur = std::io::Cursor::new(input);
        let out = chunked_decode(&mut cur).unwrap();
        assert_eq!(out, b"abc");
    }
}
