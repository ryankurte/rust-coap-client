use std::net::SocketAddr;
use std::io::{Error, ErrorKind};
use std::collections::HashMap;
use std::time::{Instant};

use log::{debug, error};


use coap_lite::{CoapResponse, Packet, MessageType, MessageClass};
use tokio::sync::mpsc::{channel, Sender};

use super::Transport;
use crate::{RequestOptions, COAP_MTU};

pub struct Tokio {
    message_id: u16,
    raw_tx: Sender<Vec<u8>>,
    ctl_tx: Sender<Ctl>,
    listener: tokio::task::JoinHandle<Result<(), Error>>,
}

#[derive(Debug)]
enum Ctl {
    Register(u32, Sender<Packet>),
    Deregister(u32),
}

impl Tokio {
    // Helper to create a basic UDP socket
    pub async fn new_udp(peer: &str) -> Result<Self, Error> 
    {
        // Connect to UDP socket
        let udp_sock = Self::udp_connect(peer).await?;

        let (raw_tx, mut raw_rx) = channel::<Vec<u8>>(10);
        let (ctl_tx, mut ctl_rx) = channel::<Ctl>(1);

        // Run listener thread
        let listener_raw_tx = raw_tx.clone();
        let listener = tokio::task::spawn(async move {
            let mut buff = [0u8; COAP_MTU];
            let mut handles = HashMap::new();

            loop {
                tokio::select!(
                    // Receive from external sender channel
                    ctl = ctl_rx.recv() => {
                        match ctl {
                            Some(Ctl::Register(token, rx)) => {
                                debug!("Register handler");
                                handles.insert(token, rx);
                            },
                            Some(Ctl::Deregister(token)) => {
                                handles.remove(&token);
                            },
                            _ => (),
                        }
                    }
                    // Receive from the mounted socket
                    r = udp_sock.recv(&mut buff) => {
                        let data = match r {
                            Ok(n) => &buff[..n],
                            Err(e) => {
                                error!("net receive error: {:?}", e);
                                break;
                            }
                        };

                        // Handle received data
                        if let Err(e) = Self::handle_rx(&mut handles, data, listener_raw_tx.clone()).await {
                            error!("net handle error: {:?}", e);
                            break;
                        }
                    },
                    // Recieve from internal TX channel
                    Some(v) = raw_rx.recv() => {
                        debug!("net tx: {:?}", v);
                        if let Err(e) = udp_sock.send(&v[..]).await {
                            error!("net transmit error: {:?}", e);
                            break;
                        }
                    }
                );
            }

            debug!("Exit coap UDP handler");

            Ok(())
        });

        Ok(Self{
            message_id: rand::random(),
            raw_tx,
            ctl_tx,
            listener,
        })
    }

    async fn handle_rx(handles: &mut HashMap<u32, Sender<Packet>>, data: &[u8], tx: Sender<Vec<u8>>) -> Result<(), Error> {
        // Decode packet
        let packet = match Packet::from_bytes(&data) {
            Ok(p) => p,
            Err(e) => {
                debug!("packet decode error: {:?}", e);
                return Err(Error::new(ErrorKind::InvalidData, e));
            }
        };

        // Convert to response
        match packet.header.code {
            MessageClass::Response(_) => (),
            _ => {
                debug!("packet was not response type: {:?}", packet);
                return Err(Error::new(ErrorKind::InvalidData, "unexpected packet type"));
            }
        };

        // Fetch token from packet
        let token = crate::token_as_u32(packet.get_token());

        // Lookup response handle
        let handle = handles.get(&token).map(|v| v.clone() );

        // Return to caller or respond with failure
        match handle {
            Some(h) => {
                debug!("Handled response: {:?}, forwarding to caller", packet);

                // Forward to requester
                h.send(packet.clone()).await.unwrap();

                // Send acknowlegement if required
                if packet.header.get_type() == MessageType::Confirmable {

                    if let Some(mut ack) = CoapResponse::new(&packet) {
                        ack.message.header.code = MessageClass::Empty;

                        let encoded = ack.message.to_bytes().unwrap();
                        tx.send(encoded).await.unwrap();
                    }
                }
            },
            None => {
                debug!("Unhandled response: {:?}, sending reset", packet);

                // Send connection reset
                let mut request = Packet::new();
                request.header.message_id = packet.header.message_id;
                request.header.code = MessageClass::Empty;
                request.header.set_type(MessageType::Reset);
                request.set_token(packet.get_token().to_vec());

                let encoded = request.to_bytes().unwrap();
                tx.send(encoded).await.unwrap();
            }
        }

        Ok(())
    }

    /// Helper to create UDP connections
    async fn udp_connect(host: &str) -> Result<tokio::net::UdpSocket, Error> {

        // Resolve peer address to determine local socket type
        let peer_addr = tokio::net::lookup_host(host).await?.next();

        // Work out bind address
        let bind_addr = match peer_addr {
            Some(SocketAddr::V6(_)) => ":::0",
            Some(SocketAddr::V4(_)) => "0.0.0.0:0",
            None => {
                error!("No peer address found");
                return Err(Error::new(ErrorKind::NotFound, "no peer address found"));
            }
        };
        let peer_addr = peer_addr.unwrap();

        // Bind to local socket
        let udp_sock = tokio::net::UdpSocket::bind(bind_addr).await
            .map_err(|e| {
                error!("Error binding local socket: {:?}", e);
                e
            })?;

        debug!("Bound to local socket: {}", udp_sock.local_addr()?);

        // Connect to remote socket
        udp_sock.connect(peer_addr).await?;

        Ok(udp_sock)
    }
}

#[async_trait::async_trait]
impl Transport for Tokio {
    type Error = Error;

    async fn request(&mut self, req: Packet, opts: RequestOptions) -> Result<Packet, Self::Error> {
        // Create request handle
        let (tx, mut rx) = channel(10);
        let token = crate::token_as_u32(req.get_token());

        // Register handler
        if let Err(e) = self.ctl_tx.send(Ctl::Register(token, tx)).await {
            error!("Register send error: {:?}", e);
            return Err(Error::new(ErrorKind::Other, "Register send failed"));
        }

        // For the allowed number of retries
        let mut resp = Ok(None);

        for i in 0..opts.retries {
            // TODO: control / bump message_id each retry?

            // Encode data
            let data = req.to_bytes().unwrap();

            // Issue request
            if let Err(e) = self.raw_tx.send(data).await {
                error!("Raw send error: {:?}", e);
                break;
            }

            // Await response
            match tokio::time::timeout(opts.timeout, rx.recv()).await {
                Ok(Some(v)) => {
                    resp = Ok(Some(v));
                    break;
                },
                Ok(None) | Err(_) => {
                    debug!("Timeout awaiting response (retry {})", i);
                    // TODO: await backoff
                    continue;
                },
            };
        }

        // Remove handler
        if let Err(e) = self.ctl_tx.send(Ctl::Deregister(token)).await {
            error!("Deregister send error: {:?}", e);
            return Err(Error::new(ErrorKind::Other, "Deregister send failed"));
        }

        // Handle results
        match resp {
            Ok(Some(v)) => Ok(v),
            Ok(None) => Err(Error::new(ErrorKind::TimedOut, "Request timed out")),
            Err(e) => Err(e),
        }
    }
}


#[cfg(test)]
mod test {
    use simplelog::{SimpleLogger, Config, LevelFilter};
    use crate::{TokioClient, RequestOptions};

    #[tokio::test]
    async fn test_get() {
        let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());

        let mut client = TokioClient::connect("coap.me:5683").await.unwrap();

        let resp = client.get("hello", RequestOptions::default()).await.unwrap();
        assert_eq!(resp, b"world".to_vec());
    }

}