//! Tokio based backends for coap-client.
// https://github.com/ryankurte/rust-coap-client
// Copyright 2021 ryan kurte <ryan@kurte.nz>

use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use coap_lite::{
    CoapOption, MessageClass, MessageType, ObserveOption, Packet, RequestType, ResponseType,
};
use futures::{Future, FutureExt, Stream};
use log::{debug, error};

use tokio::sync::mpsc::{channel, Receiver, Sender};

use super::{Backend, Observer};
use crate::{status_is_ok, RequestOptions};

mod dtls;
mod udp;

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
                //debug!("packet was not response type: {:?}", packet);
                //return Err(Error::new(ErrorKind::InvalidData, "unexpected packet type"));
            }
        };

        // Fetch token from packet
        let raw_token = packet.get_token();
        let token = crate::token_as_u32(raw_token);

        debug!("Received packet: {:x?}", packet);

        // Lookup response handle and send reset if no handle matches
        let handle = match handles.get(&token).map(|v| v.clone()) {
            Some(h) => h,
            None => {
                debug!("No registered handle for token: {:x}, sending reset", token);

                // Send connection reset
                let mut request = Packet::new();
                request.header.message_id = packet.header.message_id;
                request.header.code = MessageClass::Empty;
                request.header.set_type(MessageType::Reset);
                request.set_token(packet.get_token().to_vec());

                let encoded = request.to_bytes().unwrap();
                tx.send(Ctl::Send(encoded)).await.unwrap();

                return Ok(());
            }
        };

        // Send acknowlegement if required
        if packet.header.get_type() == MessageType::Confirmable {
            debug!("Sending ACK for message: {}", packet.header.message_id);

            let mut ack = Packet::new();
            ack.header.message_id = packet.header.message_id;
            ack.header.code = MessageClass::Response(ResponseType::Content);
            ack.header.set_type(MessageType::Acknowledgement);
            ack.set_token(packet.get_token().to_vec());

            let encoded = ack.to_bytes().unwrap();
            tx.send(Ctl::Send(encoded)).await.unwrap();
        }

        debug!(
            "Found response handler for packet: {:x}, forwarding to caller",
            token
        );

        // Forward to requester
        if let Err(_e) = handle.send(packet.clone()).await {
            debug!("Response channel dropped, removing handler");
            handles.remove(&token);

            // TODO: we could also send a reset here?
            // however, we'll get it next round anyway
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

    // Helper for running request / responses
    async fn do_send_retry(
        ctl_tx: Sender<Ctl>,
        rx: &mut Receiver<Packet>,
        req: Packet,
        opts: RequestOptions,
    ) -> Result<Option<Packet>, Error> {
        // Send request and await response for the allowed number of retries
        let mut resp = Ok(None);
        for i in 0..opts.retries {
            // TODO: control / bump message_id each retry?

            // Encode data
            let data = req.to_bytes().unwrap();

            // Issue request
            if let Err(e) = ctl_tx.send(Ctl::Send(data)).await {
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

        resp
    }

    // Helper for executing requests
    async fn do_request(
        ctl_tx: Sender<Ctl>,
        req: Packet,
        opts: RequestOptions,
    ) -> Result<Packet, Error> {
        // Create request handle
        let (tx, mut rx) = channel(10);
        let token = crate::token_as_u32(req.get_token());

        // Register handler
        if let Err(e) = ctl_tx.send(Ctl::Register(token, tx)).await {
            error!("Register send error: {:?}", e);
            return Err(Error::new(ErrorKind::Other, "Register send failed"));
        }

        // Send request and await response for the allowed number of retries
        let resp = Self::do_send_retry(ctl_tx.clone(), &mut rx, req, opts).await;

        // Remove handler
        if let Err(e) = ctl_tx.send(Ctl::Deregister(token)).await {
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

    // Helper for executing observations
    async fn do_observe(
        ctl_tx: Sender<Ctl>,
        resource: String,
        opts: RequestOptions,
    ) -> Result<(u32, Receiver<Packet>), Error> {
        debug!("Setup observe for resource: {}", resource);

        // Create response channel
        let (tx, mut rx) = channel(10);

        // Create token
        let token = rand::random::<u32>();

        // Register handler
        if let Err(e) = ctl_tx.send(Ctl::Register(token, tx.clone())).await {
            error!("Register send error: {:?}", e);
            return Err(Error::new(ErrorKind::Other, "Register send failed"));
        }

        // Build register packet
        let mut register = Packet::new();
        // TODO: message ID technically managed by higher level atm
        // probably should be consistent?
        register.header.message_id = rand::random();
        register.header.code = MessageClass::Request(RequestType::Get);
        register.header.set_type(MessageType::Confirmable);
        register.set_token(token.to_le_bytes().to_vec());

        let res = resource.trim_start_matches("/");
        register.add_option(CoapOption::UriPath, res.as_bytes().to_vec());
        register.set_observe(vec![ObserveOption::Register as u8]);

        // Execute register command

        // Send request and await response for the allowed number of retries
        let resp = Self::do_send_retry(ctl_tx.clone(), &mut rx, register, opts).await;

        // Handle responses
        match resp {
            Ok(Some(v)) => {
                // TODO: check response code is OK (2.xx)

                // Check observe response
                // Technically the server should respond with an empty observe...
                // however libcoap does not appear to do this
                // https://tools.ietf.org/html/rfc7641#section-3.1
                let obs = v.get_observe();
                debug!("Observe response: {:02x?}", obs);

                if obs.is_some() {
                    debug!("Registered observer!");

                    // TODO: Forward response if it's valid GET data

                    Ok((token, rx))
                } else {
                    debug!("Server refused observe request");
                    let _ = ctl_tx.send(Ctl::Deregister(token)).await;
                    Err(Error::new(
                        ErrorKind::ConnectionRefused,
                        "Observe request refused",
                    ))
                }
            }
            Ok(None) => {
                debug!("Timeout registering observer");
                let _ = ctl_tx.send(Ctl::Deregister(token)).await;
                Err(Error::new(ErrorKind::TimedOut, "Request timed out"))
            }
            Err(e) => {
                debug!("Error registering ovbserver: {:?}", e);
                let _ = ctl_tx.send(Ctl::Deregister(token)).await;
                Err(e)
            }
        }
    }

    async fn do_unobserve(
        ctl_tx: Sender<Ctl>,
        token: u32,
        resource: String,
        mut rx: Receiver<Packet>,
    ) -> Result<(), Error> {
        debug!("Deregister observer: {:x}", token);

        // Send de-register command
        // Note this is not -technically- required as the next observe
        // response will prompt a Reset, however, it's nice to do
        // https://tools.ietf.org/html/rfc7641#section-3.6

        let mut deregister = Packet::new();
        deregister.header.message_id = rand::random();
        deregister.header.code = MessageClass::Request(RequestType::Get);
        deregister.header.set_type(MessageType::Confirmable);
        deregister.set_token(token.to_le_bytes().to_vec());

        let res = resource.trim_start_matches("/");
        deregister.add_option(CoapOption::UriPath, res.as_bytes().to_vec());
        deregister.set_observe(vec![ObserveOption::Deregister as u8]);

        // Send de-register with retries
        let resp = Self::do_send_retry(
            ctl_tx.clone(),
            &mut rx,
            deregister,
            RequestOptions::default(),
        )
        .await;

        debug!("Deregister response: {:?}", resp);

        match resp {
            Ok(Some(v)) => {
                debug!("Deregister response: {:?}", v);

                match v.header.code {
                    MessageClass::Response(s) if !status_is_ok(s) => {
                        debug!("Deregister error (code: {:?})", s);
                        // TODO: propagate error
                    }
                    _ => {
                        debug!("Deregister OK!");
                    }
                }
            }
            Ok(None) => {
                debug!("Deregister request timed out");
            }
            Err(e) => {
                debug!("Error sending deregister request: {:?}", e);
            }
        }

        // De-register local handler
        if let Err(e) = ctl_tx.try_send(Ctl::Deregister(token)) {
            debug!("Error sending deregister command: {:?}", e)
        }

        Ok(())
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

/// Async request type for Tokio backend
// TODO: it'd be great to not have to box this?
// Unfortunately this would appear require unwrapping the future states in
// do_request, and because Tokio uses `async` functions the output of each
// of these is an opaque type, so we may always have to box </3
pub struct TokioRequest<T> {
    inner: Pin<Box<dyn Future<Output = Result<T, Error>>>>,
}

impl<T> Future for TokioRequest<T> {
    type Output = Result<T, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_unpin(cx)
    }
}

unsafe impl<T> Send for TokioRequest<T> {}

pub struct TokioObserve {
    token: u32,
    resource: String,
    rx: Receiver<Packet>,
}

unsafe impl Send for TokioObserve {}

impl Observer<Error> for TokioObserve {
    fn token(&self) -> u32 {
        self.token
    }

    fn resource(&self) -> &str {
        &self.resource
    }
}

impl Stream for TokioObserve {
    type Item = Result<Packet, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(p)) => Poll::Ready(Some(Ok(p))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[async_trait::async_trait]
impl Backend<std::io::Error> for Tokio {
    type Observe = TokioObserve;

    async fn request(
        &mut self,
        req: Packet,
        opts: RequestOptions,
    ) -> Result<Packet, std::io::Error> {
        Tokio::do_request(self.ctl_tx.clone(), req, opts).await
    }

    async fn observe(
        &mut self,
        resource: String,
        opts: RequestOptions,
    ) -> Result<Self::Observe, std::io::Error> {
        let (token, rx) = Tokio::do_observe(self.ctl_tx.clone(), resource.clone(), opts).await?;
        Ok(TokioObserve {
            token,
            resource,
            rx,
        })
    }

    async fn unobserve(&mut self, o: Self::Observe) -> Result<(), std::io::Error> {
        Tokio::do_unobserve(self.ctl_tx.clone(), o.token, o.resource, o.rx).await
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
            .get("hello", &RequestOptions::default())
            .await
            .unwrap();
        assert_eq!(resp, b"world".to_vec());

        client.close().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "separate responses not yet implemented"]
    async fn test_get_udp_separate() {
        let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());

        let mut client = TokioClient::connect("coap://coap.me:5683", &ClientOptions::default())
            .await
            .unwrap();

        let resp = client
            .get("separate", &RequestOptions::default())
            .await
            .unwrap();
        assert_eq!(resp, b"separate".to_vec());

        client.close().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "coap.me does not have DTLS support"]
    async fn test_get_dtls() {
        let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());

        let mut client = TokioClient::connect("coaps://coap.me:5683", &ClientOptions::default())
            .await
            .unwrap();

        let resp = client
            .get("hello", &RequestOptions::default())
            .await
            .unwrap();
        assert_eq!(resp, b"world".to_vec());
    }
}
