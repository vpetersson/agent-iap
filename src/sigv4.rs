//! AWS Signature Version 4 — the scheme S3 and every S3-compatible store speaks.
//!
//! Every other scheme in this proxy attaches a value. This one cannot: the
//! credential is an HMAC key, and what goes on the wire is a signature over the
//! method, the path, the query, a chosen set of headers and the body. So it is
//! computed here, after the ACL has said yes and after the request has its final
//! shape, and nothing the agent sent is allowed to contribute a signature of
//! its own.
//!
//! Cloudflare R2, Backblaze B2, MinIO, Wasabi, DigitalOcean Spaces, Ceph RGW,
//! SeaweedFS and Google Cloud Storage's interoperability endpoint all verify
//! exactly this, which is why it is one scheme with a `region` and a `service`
//! rather than one per vendor.

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use ring::{digest, hmac};

/// The `service` S3 and its imitators sign for, and the default.
pub const S3: &str = "s3";

const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// What S3 accepts in place of a body hash. Only used for a body this process
/// never held in full — the proxy buffers every request, so in practice that
/// is a body-less request built somewhere else.
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// Chunked uploads whose chunks are *not* individually signed. The body is the
/// agent's aws-chunked framing, the seed signature is ours, and nothing inside
/// the body refers to a key — so it survives being re-signed here untouched.
const STREAMING_UNSIGNED: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";

/// Headers the signer owns. Whatever the agent sent under these names was
/// computed with a key that is not the real one, or is a credential of its own
/// (`x-amz-security-token`); either way it does not reach the upstream.
pub const SIGNER_HEADERS: &[&str] = &[
    "authorization",
    "x-amz-date",
    "x-amz-content-sha256",
    "x-amz-security-token",
];

/// RFC 3986 unreserved characters are the only ones SigV4 leaves alone.
const STRICT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// The same, keeping `/` — for a path, encoded whole.
const PATH: &AsciiSet = &STRICT.remove(b'/');

/// A request this scheme cannot carry safely, refused before the ACL is asked.
///
/// Returned as the sentence the agent is shown: each of these is something the
/// agent can change, and "could not resolve the credential" — what a failure in
/// the signer would otherwise surface as — names none of them.
pub fn refusal(headers: &http::HeaderMap) -> Option<String> {
    // CopyObject and UploadPartCopy name a *second* object in a header, read
    // with the proxy's credential. The ACL only ever sees the path being
    // written, so a grant to write `/scratch/**` would read any key in any
    // bucket the access key can reach and drop it where the agent can fetch it.
    for name in ["x-amz-copy-source", "x-amz-copy-source-range"] {
        if headers.contains_key(name) {
            return Some(format!(
                "`{name}` is refused: a server-side copy reads an object the ACL never \
                 saw. GET the source and PUT it to the destination instead, so both \
                 halves are checked"
            ));
        }
    }
    let declared = headers
        .get("x-amz-content-sha256")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    // Each chunk of a signed stream carries a signature chained from the seed
    // signature, which the agent computed with a key that is not the real one.
    // Re-signing the seed here would leave every chunk signature wrong, so the
    // upload would fail at the upstream with nothing pointing back at why.
    if declared.starts_with("STREAMING-") && declared != STREAMING_UNSIGNED {
        return Some(format!(
            "`x-amz-content-sha256: {declared}` signs each chunk with the client's own key, \
             which the proxy cannot re-sign. Send the body whole, or unsigned chunks \
             (`{STREAMING_UNSIGNED}`) — boto3 does with `request_checksum_calculation = \
             when_required`"
        ));
    }
    None
}

/// `refusal`, for whichever scheme an upstream uses — `None` for every scheme
/// but this one. The proxy and the MCP gateway both ask it, before the gate,
/// so neither a human nor the audit log is troubled with a request that was
/// never going to be sent.
pub fn refusal_for(auth: &crate::config::AuthConfig, headers: &http::HeaderMap) -> Option<String> {
    match auth {
        crate::config::AuthConfig::AwsSigv4 { .. } => refusal(headers),
        _ => None,
    }
}

/// Sign `request` in place for `region` and `service`, as of `now`.
///
/// Replaces anything the agent put in the signer's own headers, then signs
/// `host`, `content-type`, `content-md5` and every `x-amz-*` header present:
/// S3 refuses a request carrying an `x-amz-*` header it was not told was
/// signed, and those are the headers that change what a request does.
pub fn sign(
    request: &mut reqwest::Request,
    access_key_id: &str,
    secret: &str,
    region: &str,
    service: &str,
    now: DateTime<Utc>,
) -> Result<()> {
    let declared = request
        .headers()
        .get("x-amz-content-sha256")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    for name in SIGNER_HEADERS {
        request.headers_mut().remove(*name);
    }

    let payload = match request.body() {
        None => hex(digest::digest(&digest::SHA256, b"").as_ref()),
        // A body still framed as unsigned aws-chunked is hashed by nobody; the
        // upstream reads the framing and checks the trailing checksum.
        Some(_) if declared.as_deref() == Some(STREAMING_UNSIGNED) => {
            STREAMING_UNSIGNED.to_string()
        }
        Some(body) => match body.as_bytes() {
            Some(bytes) => hex(digest::digest(&digest::SHA256, bytes).as_ref()),
            None if service == S3 => UNSIGNED_PAYLOAD.to_string(),
            None => bail!("a streamed body cannot be signed for `{service}`, only for `s3`"),
        },
    };

    // The path goes out in exactly the encoding it is signed in. Whether a
    // store canonicalises the bytes it received or re-encodes the key it
    // decoded from them, it then arrives at the same string — a `+` or a `(`
    // left raw is where those two readings part.
    let path = encoded_path(request.url().path());
    request.url_mut().set_path(&path);
    let url = request.url().clone();
    let Some(host) = url.host_str() else {
        bail!("the upstream URL has no host to sign");
    };
    let host = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };

    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    insert(request, "x-amz-date", &amz_date, false)?;
    insert(request, "x-amz-content-sha256", &payload, false)?;

    // Lower-cased, sorted, values trimmed and inner runs of spaces collapsed,
    // repeats joined by commas — the canonical header form.
    let mut signed: Vec<(String, String)> = vec![("host".to_string(), host)];
    for name in request.headers().keys() {
        let key = name.as_str();
        if !(key.starts_with("x-amz-") || key == "content-type" || key == "content-md5") {
            continue;
        }
        let values: Vec<String> = request
            .headers()
            .get_all(name)
            .iter()
            .map(|value| {
                String::from_utf8_lossy(value.as_bytes())
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect();
        signed.push((key.to_string(), values.join(",")));
    }
    signed.sort();
    signed.dedup_by(|a, b| a.0 == b.0);

    let canonical_headers: String = signed
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();
    let signed_headers = signed
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_request = format!(
        "{}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{payload}",
        request.method().as_str(),
        canonical_uri(&path, service),
        canonical_query(url.query()),
    );

    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
        hex(digest::digest(&digest::SHA256, canonical_request.as_bytes()).as_ref())
    );

    let key = [date.as_str(), region, service, "aws4_request"]
        .iter()
        .fold(format!("AWS4{secret}").into_bytes(), |key, part| {
            mac(&key, part.as_bytes())
        });
    let signature = hex(&mac(&key, string_to_sign.as_bytes()));

    insert(
        request,
        "authorization",
        &format!(
            "{ALGORITHM} Credential={access_key_id}/{scope}, \
             SignedHeaders={signed_headers}, Signature={signature}"
        ),
        true,
    )
}

/// The path decoded, then encoded with SigV4's own rules: everything but the
/// unreserved characters and `/`. Decoding first is what makes the client's
/// spelling irrelevant — `~` and `%7E` are the same key to S3, and now the same
/// bytes on the wire. Decoding cannot change what the ACL approved: it matched
/// the decoded path.
fn encoded_path(path: &str) -> String {
    let path = if path.is_empty() { "/" } else { path };
    let decoded = percent_decode_str(path).collect::<Vec<u8>>();
    percent_encoding::percent_encode(&decoded, PATH).to_string()
}

/// The path as it is signed, from `encoded_path`'s output. S3 signs it as it
/// is; every other AWS service encodes the encoded path a second time.
fn canonical_uri(path: &str, service: &str) -> String {
    match service {
        S3 => path.to_string(),
        _ => utf8_percent_encode(path, PATH).to_string(),
    }
}

/// Query pairs decoded, re-encoded strictly, and sorted by name then value.
/// A bare `?uploads` is the pair `uploads=`.
///
/// `+` is a literal plus here, not a space: SigV4 never form-decodes, and a
/// client that meant a space sent `%20`.
fn canonical_query(query: Option<&str>) -> String {
    let Some(query) = query.filter(|query| !query.is_empty()) else {
        return String::new();
    };
    let encode = |raw: &str| {
        let bytes = percent_decode_str(raw).collect::<Vec<u8>>();
        percent_encoding::percent_encode(&bytes, STRICT).to_string()
    };
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (encode(name), encode(value))
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn insert(
    request: &mut reqwest::Request,
    name: &'static str,
    value: &str,
    sensitive: bool,
) -> Result<()> {
    let mut value: http::HeaderValue = value.parse()?;
    value.set_sensitive(sensitive);
    request.headers_mut().insert(name, value);
    Ok(())
}

fn mac(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data)
        .as_ref()
        .to_vec()
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// The credentials every published SigV4 example uses.
    const KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    fn at(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    fn signed(request: &reqwest::Request) -> &str {
        request.headers()["authorization"].to_str().unwrap()
    }

    /// "GET Bucket (List Objects)" from the same page: no extra headers, a
    /// query string that has to be sorted and encoded. Published signature
    /// `34b48302…`.
    #[test]
    fn the_s3_documentation_listing_example_matches_exactly() {
        let mut request = reqwest::Request::new(
            http::Method::GET,
            "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J"
                .parse()
                .unwrap(),
        );
        sign(
            &mut request,
            KEY_ID,
            SECRET,
            "us-east-1",
            S3,
            at(2013, 5, 24),
        )
        .unwrap();
        assert_eq!(
            signed(&request),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        );
    }

    /// "PUT Object" from the same page — a body, its hash, and `x-amz-*`
    /// headers the agent chose — with its published signature `98ad721…`.
    #[test]
    fn the_s3_documentation_put_example_matches_exactly() {
        let mut request = reqwest::Request::new(
            http::Method::PUT,
            "https://examplebucket.s3.amazonaws.com/test$file.text"
                .parse()
                .unwrap(),
        );
        request
            .headers_mut()
            .insert("date", "Fri, 24 May 2013 00:00:00 GMT".parse().unwrap());
        request
            .headers_mut()
            .insert("x-amz-storage-class", "REDUCED_REDUNDANCY".parse().unwrap());
        *request.body_mut() = Some(reqwest::Body::from("Welcome to Amazon S3."));
        sign(
            &mut request,
            KEY_ID,
            SECRET,
            "us-east-1",
            S3,
            at(2013, 5, 24),
        )
        .unwrap();
        // The documented request also signs `date`, which this signer does not
        // (it carries `x-amz-date`), so the signature differs from the page's;
        // what must match is the hash of the body, which S3 recomputes.
        assert_eq!(
            request.headers()["x-amz-content-sha256"],
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        assert!(signed(&request)
            .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,"));
    }

    /// Cases the documentation does not cover, each signed independently by
    /// botocore (`S3SigV4Auth`, or `SigV4Auth` for `sts`) at the same instant:
    /// a key with reserved characters, a query to sort and encode, `x-amz-*`
    /// and `content-type` headers with untidy whitespace, a valueless query
    /// key, and a non-S3 service that double-encodes its path.
    #[test]
    fn signatures_agree_with_botocore() {
        let when = Utc.with_ymd_and_hms(2026, 10, 14, 12, 34, 56).unwrap();
        // method, url, headers, body, region, service, botocore's signature
        type Case<'a> = (
            &'a str,
            &'a str,
            &'a [(&'a str, &'a str)],
            &'a [u8],
            &'a str,
            &'a str,
            &'a str,
        );
        let cases: [Case; 5] = [
            (
                "GET",
                "https://acct.r2.cloudflarestorage.com/my-bucket/dir/a%20file%2B%28v2%29~.txt",
                &[],
                b"",
                "auto",
                S3,
                "6ccf633fa150c9ae6a70dfa24bf771f8ace5b08e201d481375cb69e79a512aa0",
            ),
            (
                "GET",
                "https://acct.r2.cloudflarestorage.com/my-bucket?list-type=2&prefix=a%2Fb%20c&delimiter=%2F",
                &[],
                b"",
                "auto",
                S3,
                "c354984d4206854c555544c974595075f692273b7d04eeb02b649afc621cdd08",
            ),
            (
                "PUT",
                "http://127.0.0.1:8333/bkt/k%C3%A9y.json",
                &[
                    ("content-type", "application/json"),
                    ("x-amz-meta-owner", "  agent   one "),
                    ("x-amz-acl", "private"),
                ],
                br#"{"a":1}"#,
                "us-east-1",
                S3,
                "f9be79bd39211f0536320f97012bdae8a6015fb8d1f177f348965a9594ed736b",
            ),
            (
                "POST",
                "https://s3.eu-west-1.amazonaws.com/bkt?uploads",
                &[],
                b"",
                "eu-west-1",
                S3,
                "a01db09deeffdb5ec43ef777f924f77d1631be9955c1502635f8b5296c48955e",
            ),
            (
                "POST",
                "https://sts.amazonaws.com/a%20b/",
                &[("content-type", "application/x-www-form-urlencoded")],
                b"Action=GetCallerIdentity&Version=2011-06-15",
                "us-east-1",
                "sts",
                "70e9732f8797ace836d52f523f2f93cb80e3ffcf3eea879be51758d4181d3385",
            ),
        ];
        for (method, url, headers, body, region, service, expected) in cases {
            let mut request = reqwest::Request::new(method.parse().unwrap(), url.parse().unwrap());
            for (name, value) in headers {
                request.headers_mut().insert(*name, value.parse().unwrap());
            }
            if method != "GET" {
                *request.body_mut() = Some(reqwest::Body::from(body.to_vec()));
            }
            sign(&mut request, KEY_ID, SECRET, region, service, when).unwrap();
            assert!(
                signed(&request).ends_with(&format!("Signature={expected}")),
                "{method} {url}: {}",
                signed(&request)
            );
        }
    }

    #[test]
    fn whatever_the_agent_signed_with_is_replaced() {
        let mut request = reqwest::Request::new(
            http::Method::GET,
            "https://example.r2.cloudflarestorage.com/bucket/key"
                .parse()
                .unwrap(),
        );
        for (name, value) in [
            ("authorization", "AWS4-HMAC-SHA256 Credential=FAKE/…"),
            ("x-amz-date", "19700101T000000Z"),
            ("x-amz-security-token", "someone-elses-session"),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        ] {
            request.headers_mut().insert(name, value.parse().unwrap());
        }
        sign(&mut request, KEY_ID, SECRET, "auto", S3, at(2026, 10, 14)).unwrap();
        let headers = request.headers();
        assert!(signed(&request).contains("Credential=AKIAIOSFODNN7EXAMPLE/20261014/auto/s3/"));
        assert_eq!(headers["x-amz-date"], "20261014T000000Z");
        assert!(headers.get("x-amz-security-token").is_none());
        // A request with no body hashes the empty string, whatever was claimed.
        assert_eq!(
            headers["x-amz-content-sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(headers["authorization"].is_sensitive());
    }

    #[test]
    fn a_path_is_canonical_however_the_client_spelled_it() {
        assert_eq!(encoded_path("/b/a%20b~c"), "/b/a%20b~c");
        assert_eq!(encoded_path("/b/a%7Eb"), "/b/a~b");
        assert_eq!(encoded_path("/b/a+(v2)"), "/b/a%2B%28v2%29");
        assert_eq!(encoded_path("/b/test$file.text"), "/b/test%24file.text");
        assert_eq!(encoded_path(""), "/");
        // Everyone but S3 double-encodes.
        assert_eq!(canonical_uri("/a%20b", "execute-api"), "/a%2520b");
    }

    /// The path that is signed is the path that is sent.
    #[test]
    fn the_wire_path_is_the_signed_path() {
        let mut request = reqwest::Request::new(
            http::Method::GET,
            "https://example.com/b/a+(v2)%7E.txt".parse().unwrap(),
        );
        sign(&mut request, KEY_ID, SECRET, "auto", S3, at(2026, 1, 1)).unwrap();
        assert_eq!(request.url().path(), "/b/a%2B%28v2%29~.txt");
    }

    #[test]
    fn a_query_is_sorted_strictly_encoded_and_valueless_keys_get_an_equals() {
        assert_eq!(
            canonical_query(Some("uploads&prefix=a%2Fb&list-type=2")),
            "list-type=2&prefix=a%2Fb&uploads="
        );
        assert_eq!(canonical_query(Some("k=a+b")), "k=a%2Bb");
        assert_eq!(canonical_query(None), "");
    }

    #[test]
    fn a_server_side_copy_is_refused_before_anything_is_signed() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-copy-source", "/secrets/key".parse().unwrap());
        assert!(refusal(&headers).unwrap().contains("x-amz-copy-source"));
    }

    #[test]
    fn signed_chunks_are_refused_and_unsigned_chunks_pass_through() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
        assert!(refusal(&headers).is_some());

        headers.insert("x-amz-content-sha256", STREAMING_UNSIGNED.parse().unwrap());
        assert_eq!(refusal(&headers), None);

        let mut request = reqwest::Request::new(
            http::Method::PUT,
            "https://s3.example.com/b/k".parse().unwrap(),
        );
        *request.headers_mut() = headers;
        *request.body_mut() = Some(reqwest::Body::from("0\r\n\r\n"));
        sign(
            &mut request,
            KEY_ID,
            SECRET,
            "us-east-1",
            S3,
            at(2026, 1, 1),
        )
        .unwrap();
        assert_eq!(
            request.headers()["x-amz-content-sha256"],
            STREAMING_UNSIGNED
        );
    }
}
