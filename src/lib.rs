
use std::time::Duration;

use coap_lite::{CoapRequest, CoapResponse, Packet, MessageClass, MessageType};
pub use coap_lite::{RequestType as Method};

pub mod transport;
pub use transport::Transport;

pub const COAP_MTU: usize = 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct RequestOptions {
    confirmable: bool,
    retries: usize,
    timeout: Duration,
    backoff: Duration,
}

impl Default for RequestOptions {
    fn default() -> Self {
        Self {
            confirmable: true,
            retries: 3,
            timeout: Duration::from_secs(2),
            backoff: Duration::from_millis(500),
        }
    }
}

pub enum Error {

}

/// Generic (async) CoAP client
pub struct Client<T: Transport> {
    message_id: u16,
    transport: T,
}

pub type TokioClient = Client<transport::Tokio>;

impl TokioClient {
    async fn connect(host: &str) -> Result<Self, std::io::Error> {
        // Connect underlying transport
        let transport = transport::Tokio::new_udp(host).await?;
        // Return client object
        Ok(Self {
            message_id: rand::random(),
            transport,
        })
    }
}

impl <T, E> Client<T>
where 
    T: Transport<Error=E>,
{
    /// Perform a basic CoAP request
    pub async fn request(&mut self, method: Method, resource: &str, data: Option<&[u8]>, opts: RequestOptions) -> Result<CoapResponse, E> {

        // Update message ID
        let message_id = self.message_id;
        self.message_id += 1;

        // Build request object
        let mut request = CoapRequest::<&str>::new();

        request.message.header.message_id = self.message_id;
        self.message_id += 1;

        request.set_method(method);
        request.set_path(resource);

        match opts.confirmable {
            true => request.message.header.set_type(MessageType::Confirmable),
            false => request.message.header.set_type(MessageType::NonConfirmable),
        }

        if let Some(d) = data {
            request.message.payload = d.to_vec();
        }

        let t = rand::random::<u32>();
        let token = t.to_be_bytes().to_vec();
        request.message.set_token(token);

        let resp = self.transport.request(request.message, opts).await?;

        
        Ok(resp)
    }

    pub async fn get(&mut self, resource: &str, opts: RequestOptions) -> Result<Vec<u8>, ()> {
        unimplemented!()
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
