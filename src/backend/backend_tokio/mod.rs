//! Tokio based backend for coap-client.

use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;

use log::{debug, error};
use coap_lite::{CoapResponse, MessageClass, MessageType, Packet};

use tokio::sync::mpsc::{channel, Sender};


use super::Backend;
use crate::{RequestOptions};


mod udp;
mod dtls;

/// Tokio backend for coap-client
pub struct Tokio {
    ctl_tx: Sender<Ctl>,
    _listener: tokio::task::JoinHandle<Result<(), Error>>,
}

#[derive(Debug)]
enum Ctl {
    Register(u32, Sender<Packet>),
    Deregister(u32),
    Send(Vec<u8>),
    Exit,
}

impl Tokio {

    /// Helper for handling received data (transport-independent)
    async fn handle_rx(
        handles: &mut HashMap<u32, Sender<Packet>>,
        data: &[u8],
        tx: Sender<Ctl>,
    ) -> Result<(), Error> {
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
        let handle = handles.get(&token).map(|v| v.clone());

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
                        tx.send(Ctl::Send(encoded)).await.unwrap();
                    }
                }
            }
            None => {
                debug!("Unhandled response: {:?}, sending reset", packet);

                // Send connection reset
                let mut request = Packet::new();
                request.header.message_id = packet.header.message_id;
                request.header.code = MessageClass::Empty;
                request.header.set_type(MessageType::Reset);
                request.set_token(packet.get_token().to_vec());

                let encoded = request.to_bytes().unwrap();
                tx.send(Ctl::Send(encoded)).await.unwrap();
            }
        }

        Ok(())
    }

    /// Helper to create UDP connections
    async fn udp_connect(host: &str) -> Result<tokio::net::UdpSocket, Error> {
        // Resolve peer address to determine local socket type
        let peer_addr = tokio::net::lookup_host(host).await?.next();
        debug!("Using IP: {:?} for host: {}", peer_addr, host);

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
        let udp_sock = tokio::net::UdpSocket::bind(bind_addr).await.map_err(|e| {
            error!("Error binding local socket: {:?}", e);
            e
        })?;

        debug!("Bound to local socket: {}", udp_sock.local_addr()?);

        // Connect to remote socket
        udp_sock.connect(peer_addr).await?;

        Ok(udp_sock)
    }

    /// Close the CoAP client
    pub async fn close(self) -> Result<(), Error> {
        // TODO: disable observations when supported?

        // Send exit command
        match self.ctl_tx.send(Ctl::Exit).await {
            Ok(_) => {
                self._listener.await??;
            }
            Err(_) => self._listener.abort(),
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl Backend for Tokio {
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
            if let Err(e) = self.ctl_tx.send(Ctl::Send(data)).await {
                error!("Raw send error: {:?}", e);
                break;
            }

            // Await response
            match tokio::time::timeout(opts.timeout, rx.recv()).await {
                Ok(Some(v)) => {
                    resp = Ok(Some(v));
                    break;
                }
                Ok(None) | Err(_) => {
                    debug!("Timeout awaiting response (retry {})", i);
                    // TODO: await backoff
                    continue;
                }
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
    use crate::{ClientOptions, RequestOptions, TokioClient};
    use simplelog::{Config, LevelFilter, SimpleLogger};

    #[tokio::test]
    async fn test_get_udp() {
        let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());

        let mut client = TokioClient::connect("coap://coap.me:5683", &ClientOptions::default())
            .await
            .unwrap();

        let resp = client
            .get("hello", RequestOptions::default())
            .await
            .unwrap();
        assert_eq!(resp, b"world".to_vec());
    }

    #[tokio::test]
    #[ignore = "coap.me does not have DTLS support"]
    async fn test_get_dtls() {
        let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());

        let mut client = TokioClient::connect("coaps://coap.me:5683", &ClientOptions::default())
            .await
            .unwrap();

        let resp = client
            .get("hello", RequestOptions::default())
            .await
            .unwrap();
        assert_eq!(resp, b"world".to_vec());
    }
}
