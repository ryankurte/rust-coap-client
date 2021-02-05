
use std::net::SocketAddr;

use futures::prelude::*;

use coap_lite::{CoapRequest, CoapResponse};

pub mod transport;
pub use transport::Transport;

pub const COAP_MTU: usize = 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct RequestOptions {
    ack: bool,
    retries: usize,
}

impl Default for RequestOptions {
    fn default() -> Self {
        Self {
            ack: true,
            retries: 3,
        }
    }
}

pub enum Error {

}

/// Generic (async) CoAP client
pub struct Client<T: Transport> {
    transport: T,
}

impl <T, E> Client<T>
where 
    T: Transport<Error=E>,
{
    /// Perform a basic CoAP request
    pub async fn request(&mut self, req: CoapRequest<&str>, opts: RequestOptions) -> Result<CoapResponse, E> {
        let resp = self.transport.request(req, opts).await?;
        Ok(resp)
    }

}


fn token_as_u64(token: &[u8]) -> u64 {
    let mut v = 0;
    for i in 0..token.len() {
        v |= (token[i] as u64) << (i * 8);
    }
    v
}

fn token_as_u32(token: &[u8]) -> u32 {
    let mut v = 0;
    for i in 0..token.len() {
        v |= (token[i] as u32) << (i * 8);
    }
    v
}
