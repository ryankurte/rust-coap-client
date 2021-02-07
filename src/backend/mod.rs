//! Backend module provides swappable CoAP client backends

use coap_lite::Packet;

use crate::RequestOptions;

pub mod tokio_transport;
pub use tokio_transport::Tokio;

/// Generic transport trait for implementing CoAP client backends
// TODO: swap this to an associated future type so it's box-free,
// requires re-working the tokio driver to a future object
#[async_trait::async_trait]
pub trait Backend {
    type Error;

    async fn request(&mut self, req: Packet, opts: RequestOptions) -> Result<Packet, Self::Error>;
}
