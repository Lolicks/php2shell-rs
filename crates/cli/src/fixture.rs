//! Loads captured HTTP responses for fully offline diagnostics.

use bytes::Bytes;
use php2shell_core::{Error, Result};
use php2shell_http_client::HttpResponse;

#[derive(serde::Deserialize)]
struct JsonFixture {
    #[serde(default = "default_url")]
    url: String,
    #[serde(default = "default_status")]
    status: u16,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    body: String,
}

fn default_url() -> String {
    "fixture://captured-response".to_owned()
}
fn default_status() -> u16 {
    200
}

pub fn parse_fixture(text: &str) -> Result<HttpResponse> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        let fixture: JsonFixture = serde_json::from_str(trimmed)
            .map_err(|err| Error::Config(format!("invalid JSON fixture: {err}")))?;
        return Ok(HttpResponse {
            url: fixture.url,
            status: fixture.status,
            headers: fixture.headers,
            body: Bytes::from(fixture.body),
        });
    }

    let (head, body) = if let Some(index) = text.find("\r\n\r\n") {
        (&text[..index], &text[index + 4..])
    } else if let Some(index) = text.find("\n\n") {
        (&text[..index], &text[index + 2..])
    } else {
        (text, "")
    };
    let mut lines = head.lines().map(str::trim_end);
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(200);
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    let url = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-observed-url"))
        .map(|(_, value)| value.clone())
        .unwrap_or_else(default_url);
    Ok(HttpResponse {
        url,
        status,
        headers,
        body: Bytes::from(body.to_owned()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_raw_http_fixture() {
        let fixture = parse_fixture(
            "HTTP/1.1 200 OK\r\nServer: Apache/2.4.69 (Debian)\r\nX-Powered-By: PHP/8.4.26\r\nX-Observed-Url: http://lab.local/index.php\r\n\r\nOK\n",
        )
        .unwrap();
        assert_eq!(fixture.status, 200);
        assert_eq!(fixture.header("x-powered-by"), Some("PHP/8.4.26"));
        assert_eq!(fixture.url, "http://lab.local/index.php");
        assert_eq!(fixture.body_text(), "OK\n");
    }

    #[test]
    fn parses_json_fixture() {
        let fixture =
            parse_fixture(r#"{"status":404,"headers":[["Server","nginx"]],"body":"missing"}"#)
                .unwrap();
        assert_eq!(fixture.status, 404);
        assert_eq!(fixture.header("server"), Some("nginx"));
    }
}
