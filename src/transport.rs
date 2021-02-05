use std::net::SocketAddr;
use std::io::{Error, ErrorKind};
use std::collections::HashMap;
use std::time::{SystemTime, Instant, Duration};
use std::task::{Poll, Context};
use std::pin::Pin;

use log::{debug, error};
use futures::Future;

use coap_lite::{CoapRequest, CoapResponse, Packet, RequestType, MessageType, MessageClass};
use tokio::sync::mpsc::{channel, Sender, Receiver};


use crate::{RequestOptions, COAP_MTU};


pub trait Transport {
    type Error;
    type Response: Future<Output = Result<CoapResponse, Self::Error>>;

    fn request(&mut self, req: CoapRequest<&str>, opts: RequestOptions) -> Self::Response;
}

pub struct Tokio {
    message_id: u16,
    sender_tx: Sender<Handle>,
    listener: tokio::task::JoinHandle<Result<(), Error>>,
}

struct Handle {
    token: u32,
    data: Vec<u8>,
    tx: Sender<Option<CoapResponse>>,
    observer: bool,
    expiry: Instant,
}

impl Tokio {
    // Helper to create a basic UDP socket
    pub async fn new_udp(peer: &str) -> Result<Self, Error> 
    {
        // Connect to UDP socket
        let udp_sock = Self::udp_connect(peer).await?;

        let (raw_tx, mut raw_rx) = channel::<(Vec<u8>)>(10);
        let (sender_tx, mut sender_rx) = channel::<Handle>(10);

        // Run listener thread
        let raw_tx = raw_tx.clone();
        let listener = tokio::task::spawn(async move {
            let mut buff = [0u8; COAP_MTU];
            let mut handles = HashMap::new();

            let mut upd = tokio::time::interval(Duration::from_secs(2));

            loop {
                tokio::select!(
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
                        if let Err(e) = Self::handle_rx(&mut handles, data, raw_tx.clone()).await {
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
                    // Receive from external sender channel
                    Some(h) = sender_rx.recv() => {
                        debug!("Register sender");
                        let data = h.data.clone();
                        
                        handles.insert(h.token, h);

                        raw_tx.send(data).await.unwrap();
                    }
                    // Check for request timeouts
                    _ = upd.tick() => {
                        let i = Instant::now();
                        // Send empty responses to signal expiry
                        for (_k, h) in &handles {
                            if h.expiry > i {
                                h.tx.send(None).await.unwrap();
                            }
                        }
                        // Remove expired entries
                        handles.retain(|_k, h| h.expiry < i );
                    }
                )
            }

            Ok(())
        });

        Ok(Self{
            message_id: 0,
            sender_tx,
            listener,
        })
    }

    async fn handle_rx(handles: &mut HashMap<u32, Handle>, data: &[u8], tx: Sender<Vec<u8>>) -> Result<(), Error> {
        // Decode packet
        let packet = match Packet::from_bytes(&data) {
            Ok(p) => p,
            Err(e) => {
                debug!("packet decode error: {:?}", e);
                return Err(Error::new(ErrorKind::InvalidData, e));
            }
        };

        // Convert to response
        let resp = match CoapResponse::new(&packet) {
            Some(r) => r,
            None => {
                debug!("packet was not response type");
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
                debug!("Handled response: {:?}, forwarding to caller", resp);

                // Forward to requester
                h.tx.send(Some(resp)).await.unwrap();

                // Send acknowlegement if required
                if packet.header.get_type() == MessageType::Confirmable {
                    let mut request = Packet::new();
                    request.header.message_id = packet.header.message_id;
                    request.header.code = MessageClass::Empty;
                    request.header.set_type(MessageType::Acknowledgement);
                    request.set_token(packet.get_token().to_vec());

                    let encoded = request.to_bytes().unwrap();
                    tx.send(encoded).await.unwrap();
                }

                // Remove from tracking if non-observing
                if !h.observer {
                    handles.remove(&token);
                }
            },
            None => {
                debug!("Unhandled response: {:?}, sending reset", resp);

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
    async fn udp_connect(peer: &str) -> Result<tokio::net::UdpSocket, Error> {

        // Resolve peer address to determine local socket type
        let peer_addr = tokio::net::lookup_host(peer).await?.next();

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

pub struct TokioRequest {
    tx: Sender<Handle>,
    rx: Receiver<Option<CoapResponse>>,
    retries: usize,
}

impl Future for TokioRequest {
    type Output = Result<CoapResponse, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Receive from the channel
        let r = match self.rx.poll_recv(cx) {
            Poll::Ready(Some(v)) => v,
            _ => return Poll::Pending,
        };

        match r {
            Some(r) => Poll::Ready(Ok(r)),
            None if self.retries > 0 => {


                Poll::Pending
            },
            None => {
                Poll::Ready(Err(Error::new(ErrorKind::TimedOut, "Request timed out")))
            }
        }
    }
}

impl Transport for Tokio {
    type Error = Error;
    type Response = TokioRequest;

    fn request(&mut self, req: CoapRequest<&str>, opts: RequestOptions) -> Self::Response {
        let (tx, rx) = channel(10);

        // Issue request

        // Await response

        // Retry if required
        
        TokioRequest{ tx: self.sender_tx.clone(), rx, retries: opts.retries }
    }
}
