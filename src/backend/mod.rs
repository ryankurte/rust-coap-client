//! Backend module provides swappable CoAP client backends
// https://github.com/ryankurte/rust-coap-client
// Copyright 2021 ryan kurte <ryan@kurte.nz>

use coap_lite::Packet;

use crate::RequestOptions;

#[cfg(feature = "backend-tokio")]
pub mod backend_tokio;

#[cfg(feature = "backend-tokio")]
pub use backend_tokio::Tokio;

/// Generic transport trait for implementing CoAP client backends
// TODO: swap this to an associated future type so it's box-free,
// requires re-working the tokio driver to a future object
#[async_trait::async_trait]
pub trait Backend {
    type Error;

    async fn request(&mut self, req: Packet, opts: RequestOptions) -> Result<Packet, Self::Error>;
}
