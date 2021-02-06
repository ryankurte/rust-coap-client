

use coap_lite::{CoapResponse, Packet};

use crate::{RequestOptions};

pub mod tokio_transport;
pub use tokio_transport::Tokio;

#[async_trait::async_trait]
pub trait Transport {
    type Error;

    async fn request(&mut self, req: Packet, opts: RequestOptions) -> Result<CoapResponse, Self::Error>;
}

