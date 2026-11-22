use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures::{StreamExt, stream};
use php2shell_config::Config;
use php2shell_core::{Error, Result};
use reqwest::{Client, Url};
use tracing::{debug, info, warn};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

#[derive(Clone, Debug)]
pub struct SafeClient {
    config: Arc<Config>,
    inner: Client,
}

impl SafeClient {
    pub fn new(config: Arc<Config>) -> Result<Self> {
        config.validate()?;
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(config.http.timeout_secs))
            .connect_timeout(Duration::from_secs(config.http.connect_timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(
                config.http.max_redirects,
            ))
            .pool_max_idle_per_host(config.http.pool_max_idle_per_host)
            .user_agent(config.http.user_agent.clone());

        if !config.http.tls_verify {
            warn!("TLS verification disabled by configuration; lab mode only");
            builder = builder.danger_accept_invalid_certs(true);
        }

        let inner = builder
            .build()
            .map_err(|err| Error::Http(err.to_string()))?;
        Ok(Self { config, inner })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub async fn fetch(&self, target: &str) -> Result<HttpResponse> {
        self.fetch_with(target, reqwest::Method::GET, Vec::new(), Vec::new())
            .await
    }

    /// Explicit request helper for laboratory diagnostics. The caller supplies
    /// every header and body byte; nothing is generated or guessed.
    pub async fn fetch_with(
        &self,
        target: &str,
        method: reqwest::Method,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<HttpResponse> {
        let url = normalize_url(target)?;
        let host = url.host_str().unwrap_or_default();
        if !self.config.is_host_allowed(host) {
            warn!(host, "blocked HTTP request to a non-allowed host");
            return Err(Error::HostNotAllowed(host.to_owned()));
        }
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(Error::Http(format!(
                "unsupported URL scheme: {}",
                url.scheme()
            )));
        }

        info!(
            url = url.as_str(),
            method = method.as_str(),
            "fetching explicitly supplied URL"
        );
        let mut request = self.inner.request(method, url.clone());
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let response = request
            .body(body)
            .send()
            .await
            .map_err(|err| Error::Http(format!("request to {url} failed: {err}")))?;

        let status = response.status().as_u16();
        let final_url = response.url().to_string();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();

        let mut body = BytesMut::new();
        let limit = self.config.http.max_response_bytes;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|err| Error::Http(format!("reading response body: {err}")))?;
            if body.len().saturating_add(chunk.len()) > limit {
                return Err(Error::Http(format!(
                    "response exceeded the configured limit of {limit} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        debug!(status, bytes = body.len(), "response received");
        Ok(HttpResponse {
            url: final_url,
            status,
            headers,
            body: body.freeze(),
        })
    }

    /// Fetches a small explicitly supplied list of URLs with bounded
    /// concurrency. This is not a scanner: the caller provides every URL.
    pub async fn fetch_many(
        &self,
        targets: &[String],
        concurrency: usize,
    ) -> Vec<Result<HttpResponse>> {
        let concurrency = concurrency.clamp(1, 16);
        stream::iter(targets.iter().map(|target| self.fetch(target)))
            .buffer_unordered(concurrency)
            .collect()
            .await
    }
}

fn normalize_url(target: &str) -> Result<Url> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err(Error::Http("empty URL".into()));
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_owned()
    } else {
        format!("http://{trimmed}")
    };
    Url::parse(&with_scheme).map_err(|err| Error::Http(format!("invalid URL `{target}`: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn serve_once(response: &'static [u8]) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let _ = socket.read(&mut buffer).await.unwrap();
            socket.write_all(response).await.unwrap();
        });
        (format!("http://{addr}/index.php"), handle)
    }

    #[tokio::test]
    async fn fetches_and_parses_an_explicit_local_url() {
        let (url, server) = serve_once(
            b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.69 (Debian)\r\nX-Powered-By: PHP/8.4.26\r\nContent-Length: 4\r\n\r\nOK\n\n",
        )
        .await;
        let client = SafeClient::new(Arc::new(Config::default())).unwrap();
        let response = client.fetch(&url).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.header("x-powered-by"), Some("PHP/8.4.26"));
        assert_eq!(response.body_text(), "OK\n\n");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn refuses_a_non_allowed_host_before_any_request() {
        let client = SafeClient::new(Arc::new(Config::default())).unwrap();
        let err = client.fetch("https://example.org/").await.unwrap_err();
        assert!(matches!(err, Error::HostNotAllowed(_)));
    }

    #[tokio::test]
    async fn enforces_the_response_size_limit() {
        let (url, server) = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .await;
        let mut config = Config::default();
        config.http.max_response_bytes = 1024;
        let client = SafeClient::new(Arc::new(config)).unwrap();
        assert!(client.fetch(&url).await.is_err());
        server.await.unwrap();
    }
}
