
use std::time::Duration;
use std::convert::{TryInto, TryFrom};
use std::str::FromStr;

use structopt::StructOpt;
use log::{debug, error};
use strum_macros::{Display, EnumString, EnumVariantNames};

use coap_lite::{CoapRequest, Packet, MessageType};
pub use coap_lite::{RequestType as Method};

pub mod backend;
pub use backend::Backend;

pub const COAP_MTU: usize = 1600;


#[derive(Debug, Clone, PartialEq, StructOpt)]
pub struct ClientOptions {
    #[structopt(long, parse(try_from_str = humantime::parse_duration), default_value = "500ms")]
    /// Client / Connection timeout
    pub connect_timeout: Duration,

    /// CA certificate for TLS/DTLS modes
    #[structopt(long)]
    pub tls_ca: Option<String>,

    /// Client certificate for TLS/DTLS modes with client-auth
    #[structopt(long)]
    pub tls_cert: Option<String>,

    /// Client key for TLS/DTLS modes with client-auth
    #[structopt(long)]
    pub tls_key: Option<String>,

    /// Skip verifying peer certificate
    #[structopt(long)]
    pub tls_skip_verify: bool,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(2),
            tls_ca: None,
            tls_cert: None,
            tls_key: None,
            tls_skip_verify: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, StructOpt)]
pub struct RequestOptions {
    #[structopt(long)]
    /// Disable message acknowlegement
    non_confirmable: bool,
    #[structopt(long, default_value = "3")]
    /// Number of retries (for acknowleged messages)
    retries: usize,
    #[structopt(long, parse(try_from_str = humantime::parse_duration), default_value = "2s")]
    /// Request -> response timeout
    timeout: Duration,
    #[structopt(long, parse(try_from_str = humantime::parse_duration), default_value = "500ms")]
    /// Base period for exponential backoff
    backoff: Duration,
}

impl Default for RequestOptions {
    fn default() -> Self {
        Self {
            non_confirmable: false,
            retries: 3,
            timeout: Duration::from_secs(2),
            backoff: Duration::from_millis(500),
        }
    }
}


/// Supported transports / schemes
#[derive(Clone, PartialEq, Debug, Display, EnumString, EnumVariantNames)]
pub enum Transport {
    #[strum(serialize = "udp", serialize = "coap")]
    Udp,
    #[strum(serialize = "dtls", serialize = "coaps")]
    Dtls,
    Tcp,
    Tls,
}

/// CoAP client errors
// TODO: impl std::error::Error via thiserror
#[derive(Debug, thiserror::Error)]
pub enum Error<T: std::fmt::Debug> {
    #[error("Transport / Backend error: {:?}", 0)]
    Transport(T),
    #[error("Invalid host specification")]
    InvalidHost,
    #[error("Invalid URL")]
    InvalidUrl,
    #[error("Invalid Scheme")]
    InvalidScheme,
}

/// Options for connecting client to hosts
#[derive(Clone, PartialEq, Debug)]
pub struct HostOptions {
    /// Transport / scheme for connection
    pub scheme: Transport,
    /// Host to connect to
    pub host: String,
    /// Port for connection
    pub port: u16,
    /// Resource path (if provided)
    pub resource: String,
}

impl Default for HostOptions {
    fn default() -> Self {
        Self {
            scheme: Transport::Udp,
            host: "localhost".to_string(),
            port: 5683,
            resource: "".to_string(),
        }
    }
}

impl ToString for HostOptions {
    fn to_string(&self) -> String {
        format!("{}://{}:{}", self.scheme, self.port, self.host)
    }
}

impl TryFrom<(&str, u16)> for HostOptions {
    type Error = std::io::Error;

    /// Convert from host and port
    fn try_from(v: (&str, u16)) -> Result<HostOptions, Self::Error> {
        Ok(Self {
            host: v.0.to_string(),
            port: v.1,
            ..Default::default()
        })
    }
}

impl TryFrom<(Transport, &str, u16)> for HostOptions {
    type Error = std::io::Error;

    /// Convert from scheme, host and port
    fn try_from(v: (Transport, &str, u16)) -> Result<HostOptions, Self::Error> {
        Ok(Self {
            scheme: v.0,
            host: v.1.to_string(),
            port: v.2,
            ..Default::default()
        })
    }
}

impl TryFrom<&str> for HostOptions {
    type Error = std::io::Error;

    /// Parse from string
    fn try_from(url: &str) -> Result<HostOptions, Self::Error> {
        // Split URL to parameters
        let params = match url::Url::from_str(url) {
            Ok(v) => v,
            Err(e) => {
                error!("Error parsing URL: {:?}", e);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "Invalid Url"));
            }
        };

        // Match transport (or default to UDP)
        let s = params.scheme();
        let scheme = match (s, Transport::from_str(s)) {
            ("", _) => Transport::Udp,
            (_, Ok(v)) => v,
            (_, Err(_e)) => {
                error!("Unrecognized or unsupported scheme: {}", params.scheme());
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "Invalid Scheme"));
            }
        };

        // Match port (or derive based on scheme default)
        let p = params.port();
        let port = match (p, &scheme) {
            (Some(p), _) => p,
            (None, Transport::Udp) => 5683,
            (None, Transport::Dtls) => 5684,
            (None, Transport::Tcp) => 5683,
            (None, Transport::Tls) => 5684,
        };

        Ok(HostOptions{
            scheme,
            host: params.host_str().unwrap_or("localhost").to_string(),
            port,
            resource: params.path().to_string(),
        })
    }
}
    

/// Generic (async) CoAP client
pub struct Client<T: Backend> {
    message_id: u16,
    transport: T,
}

#[cfg(feature = "backend-tokio")]
pub type TokioClient = Client<backend::Tokio>;

#[cfg(feature = "backend-tokio")]
impl TokioClient {
    /// Create a new client with the provided host and client options
    pub async fn connect<H>(host: H, opts: &ClientOptions) -> Result<Self, std::io::Error> 
    where
        H: TryInto<HostOptions>,
        <H as TryInto<HostOptions>>::Error: std::fmt::Debug,
    {
        // Convert provided host options
        let peer: HostOptions = match host.try_into() {
            Ok(v) => v,
            Err(e) => {
                error!("Error parsing host options: {:?}", e);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "Invalid host options"));
            }
        };
        let connect_str = format!("{}:{}", peer.host, peer.port);
        debug!("Using host options: {:?} (connect: {})", peer, connect_str);

        // Create appropriate transport
        let transport = match &peer.scheme {
            Transport::Udp => backend::Tokio::new_udp(&connect_str).await?,
            Transport::Dtls => backend::Tokio::new_dtls(&connect_str, opts).await?,
            _ => {
                error!("Transport '{}' not yet implemented", peer.scheme);
                unimplemented!()
            }
        };

       // Return client object
       Ok(Self {
            message_id: rand::random(),
            transport,
        })
    }

    /// Close the provided client, ending all existing sessions
    pub async fn close(self) -> Result<(), std::io::Error> {
        self.transport.close().await
    }
}

impl <T, E> Client<T>
where 
    T: Backend<Error=E>,
    E: std::fmt::Debug,
{
    /// Perform a basic CoAP request
    pub async fn request(&mut self, method: Method, resource: &str, data: Option<&[u8]>, opts: &RequestOptions) -> Result<Packet, Error<E>> {

        // Build request object
        let mut request = CoapRequest::<&str>::new();

        request.message.header.message_id = self.message_id;
        self.message_id += 1;

        request.set_method(method);
        request.set_path(resource);

        match !opts.non_confirmable {
            true => request.message.header.set_type(MessageType::Confirmable),
            false => request.message.header.set_type(MessageType::NonConfirmable),
        }

        if let Some(d) = data {
            request.message.payload = d.to_vec();
        }

        let t = rand::random::<u32>();
        let token = t.to_be_bytes().to_vec();
        request.message.set_token(token);

        // Send request via backing transport
        let resp = self.transport.request(request.message, opts.clone()).await
            .map_err(Error::Transport)?;

        // TODO: handle response error codes here...
        
        Ok(resp)
    }

    pub async fn get(&mut self, resource: &str, opts: &RequestOptions) -> Result<Vec<u8>, Error<E>> {
        let resp = self.request(Method::Get, resource, None, opts).await?;
        Ok(resp.payload)
    }

    pub async fn put(&mut self, resource: &str, data: Option<&[u8]>, opts: &RequestOptions) -> Result<Vec<u8>, Error<E>> {
        let resp = self.request(Method::Put, resource, data, opts).await?;
        Ok(resp.payload)
    }

    pub async fn post(&mut self, resource: &str, data: Option<&[u8]>, opts: &RequestOptions) -> Result<Vec<u8>, Error<E>> {
        let resp = self.request(Method::Post, resource, data, opts).await?;
        Ok(resp.payload)
    }
}

fn token_as_u32(token: &[u8]) -> u32 {
    let mut v = 0;
    for i in 0..token.len() {
        v |= (token[i] as u32) << (i * 8);
    }
    v
}

