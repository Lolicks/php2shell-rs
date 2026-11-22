//! Tiny local-only HTTP service used for laboratory smoke checks and for the
//! offline fingerprint integration tests. It never binds a non-loopback
//! interface and serves fixed, harmless responses.

use std::net::SocketAddr;

use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use php2shell_core::{Error, Result};
use serde_json::json;

pub async fn serve_mock_lab(address: &str) -> Result<()> {
    let address: SocketAddr = address
        .parse()
        .map_err(|err| Error::Config(format!("invalid mock lab address `{address}`: {err}")))?;
    if !address.ip().is_loopback() {
        return Err(Error::LabOnly);
    }

    let router = Router::new()
        .route("/health", get(health))
        .route("/index.php", get(index))
        .route("/ready", get(ready));
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|err| Error::other(format!("cannot bind mock lab: {err}")))?;
    axum::serve(listener, router)
        .await
        .map_err(|err| Error::other(format!("mock lab server failed: {err}")))
}

async fn health() -> &'static str {
    "OK\n"
}

async fn ready() -> Json<serde_json::Value> {
    Json(json!({ "status": "ready", "mode": "local-mock" }))
}

async fn index() -> impl IntoResponse {
    (
        [
            ("server", "Apache/2.4.69 (Debian)"),
            ("x-powered-by", "PHP/8.4.26"),
            ("content-type", "text/plain; charset=utf-8"),
        ],
        "OK\n",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use php2shell_config::Config;
    use php2shell_http_client::SafeClient;
    use std::sync::Arc;

    #[tokio::test]
    async fn mock_lab_is_reachable_only_on_loopback() {
        assert!(serve_mock_lab("0.0.0.0:0").await.is_err());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let server = tokio::spawn(async move {
            let _ = serve_mock_lab(&address.to_string()).await;
        });

        let client = SafeClient::new(Arc::new(Config::default())).unwrap();
        let mut response = None;
        for _ in 0..50 {
            if let Ok(result) = client.fetch(&format!("http://{address}/index.php")).await {
                response = Some(result);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let response = response.expect("mock lab should start");
        assert_eq!(response.header("x-powered-by"), Some("PHP/8.4.26"));
        assert_eq!(response.body_text(), "OK\n");
        server.abort();
    }
}
