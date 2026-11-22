//! Deliberately narrow asynchronous HTTP client.
//!
//! It fetches only URLs the operator supplied and that pass the configured
//! allow-list. There is no discovery, crawling or address generation.

mod client;

pub use client::{HttpResponse, SafeClient};
