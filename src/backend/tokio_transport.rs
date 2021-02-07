use std::net::SocketAddr;
use std::io::{Error, ErrorKind};
use std::collections::HashMap;
use std::task::{Poll, Context};
use std::pin::Pin;

use log::{trace, debug, error};


use coap_lite::{CoapResponse, Packet, MessageType, MessageClass};

use tokio::io::{ReadBuf, AsyncWriteExt, AsyncReadExt};
use tokio::sync::mpsc::{channel, Sender};

use openssl::ssl::{SslMethod, SslVerifyMode, SslFiletype};

use super::Backend;
use crate::{COAP_MTU, ClientOptions, RequestOptions};

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
    // Helper for creating a UDP client instance
    pub(crate) async fn new_udp(peer: &str) -> Result<Self, Error> {
        debug!("Creating UDP listener");

        // Connect to UDP socket
        let udp_sock = Self::udp_connect(peer).await?;

        // Setup control channel
        let (ctl_tx, mut ctl_rx) = channel::<Ctl>(1000);

        // Run listener thread
        let l_ctl_tx = ctl_tx.clone();
        let _listener = tokio::task::spawn(async move {
            let mut buff = [0u8; COAP_MTU];
            let mut handles = HashMap::new();

            loop {
                tokio::select!(
                    // Receive from control channel
                    ctl = ctl_rx.recv() => {
                        match ctl {
                            Some(Ctl::Register(token, rx)) => {
                                debug!("Register handler: {}", token);
                                handles.insert(token, rx);
                            },
                            Some(Ctl::Deregister(token)) => {
                                debug!("Deregister handler: {}", token);
                                handles.remove(&token);
                            },
                            Some(Ctl::Send(data)) => {
                                trace!("Tx: {:02x?}", data);
                                if let Err(e) = udp_sock.send(&data[..]).await {
                                    error!("net transmit error: {:?}", e);
                                    break;
                                }
                            }
                            Some(Ctl::Exit) => {
                                debug!("Exiting client");
                                break;
                            },
                            _ => (),
                        }
                    }
                    // Receive from the bound socket
                    r = udp_sock.recv(&mut buff) => {
                        let data = match r {
                            Ok(n) => &buff[..n],
                            Err(e) => {
                                error!("net receive error: {:?}", e);
                                break;
                            }
                        };

                        trace!("Rx: {:02x?}", data);

                        // Handle received data
                        if let Err(e) = Self::handle_rx(&mut handles, data, l_ctl_tx.clone()).await {
                            error!("net handle error: {:?}", e);
                            break;
                        }
                    },
                );
            }

            debug!("Exit coap UDP handler");
            Ok(())
        });

        Ok(Self{
            ctl_tx,
            _listener,
        })
    }

    /// Helper for creating a DTLS client instance
    pub(crate) async fn new_dtls(peer: &str, opts: &ClientOptions) -> Result<Self, std::io::Error> {
        debug!("Creating DTLS listener");

        // Bind UDP socket and convert to a viable stream
        let udp_socket = Self::udp_connect(peer).await?;
        let udp_stream = UdpStream::from(udp_socket);

        // Setup openssl context
        let mut ssl_builder = openssl::ssl::SslContext::builder(SslMethod::dtls()).unwrap();

        // Load client options
        if opts.tls_skip_verify {
            ssl_builder.set_verify(SslVerifyMode::NONE);
        }
        if let Some(tls_ca) = &opts.tls_ca {
            ssl_builder.set_ca_file(tls_ca)?;
        }
        if let Some(tls_cert) = &opts.tls_cert {
            ssl_builder.set_certificate_file(tls_cert, SslFiletype::PEM)?;
        }
        if let Some(tls_key) = &opts.tls_key {
            ssl_builder.set_private_key_file(tls_key, SslFiletype::PEM)?;
        }
        let ssl_ctx = ssl_builder.build();

        // Create SSL connection
        let ssl_conn =  openssl::ssl::Ssl::new(&ssl_ctx).unwrap();

        // Wrap our socket stream in DTLS
        let mut dtls_stream = tokio_openssl::SslStream::new(ssl_conn, udp_stream).unwrap();

        // Initialise connection
        let connect = tokio_openssl::SslStream::connect(Pin::new(&mut dtls_stream));
        if let Err(e) = tokio::time::timeout(opts.connect_timeout, connect).await? {
            debug!("DTLS connect error: {:?}", e);
            return Err(Error::new(ErrorKind::Other, "DTLS connect failed"));
        };

        // Setup sockets
        let (mut udp_rx, mut udp_tx) = tokio::io::split(dtls_stream);
        let (ctl_tx, mut ctl_rx) = channel::<Ctl>(1000);

        // Run listener thread
        let l_ctl_tx = ctl_tx.clone();
        let _listener = tokio::task::spawn(async move {
            let mut buff = [0u8; COAP_MTU];
            let mut handles = HashMap::new();

            loop {
                tokio::select!(
                    // Receive from control channel
                    ctl = ctl_rx.recv() => {
                        match ctl {
                            Some(Ctl::Register(token, rx)) => {
                                debug!("Register handler: {}", token);
                                handles.insert(token, rx);
                            },
                            Some(Ctl::Deregister(token)) => {
                                debug!("Deregister handler: {}", token);
                                handles.remove(&token);
                            },
                            Some(Ctl::Send(data)) => {
                                trace!("Tx: {:02x?}", data);
                                if let Err(e) = udp_tx.write(&data[..]).await {
                                    error!("net transmit error: {:?}", e);
                                    break;
                                }
                            },
                            Some(Ctl::Exit) => {
                                debug!("Exiting client");
                                break;
                            },
                            _ => (),
                        }
                    }
                    // Receive from the bound socket
                    r = udp_rx.read(&mut buff) => {
                        let data = match r {
                            Ok(n) => &buff[..n],
                            Err(e) => {
                                error!("net receive error: {:?}", e);
                                break;
                            }
                        };

                        trace!("Rx: {:02x?}", data);

                        // Handle received data
                        if let Err(e) = Self::handle_rx(&mut handles, data, l_ctl_tx.clone()).await {
                            error!("net handle error: {:?}", e);
                            break;
                        }
                    },
                );
            }

            debug!("Exiting coap DTLS handler");

            // Shutdown DTLS connection
            let mut dtls_stream = udp_rx.unsplit(udp_tx);
            dtls_stream.shutdown().await?;

            Ok(())
        });

        Ok(Self{
            ctl_tx,
            _listener,
        })
    }

    /// Helper for handling received data (transport-independent)
    async fn handle_rx(handles: &mut HashMap<u32, Sender<Packet>>, data: &[u8], tx: Sender<Ctl>) -> Result<(), Error> {
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
                        tx.send(Ctl::Send(encoded)).await.unwrap();
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

    /// Close the CoAP client
    pub async fn close(self) -> Result<(), Error> {
        // TODO: disable observations when supported?

        // Send exit command
        match self.ctl_tx.send(Ctl::Exit).await {
            Ok(_) => {
                self._listener.await??;
            },
            Err(_) => {
                self._listener.abort()
            },
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

/// UdpStream wrapper for DTLS compatibility
pub struct UdpStream {
    socket: tokio::net::UdpSocket,
}

impl From<tokio::net::UdpSocket> for UdpStream {
    fn from(socket: tokio::net::UdpSocket) -> Self {
        Self{ socket }
    }
}

impl std::io::Read for UdpStream {
    fn read(&mut self, buff: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        self.socket.try_recv(buff)
    }
}

impl std::io::Write for UdpStream {
    fn write(&mut self, buff: &[u8]) -> std::result::Result<usize, std::io::Error> { 
        self.socket.try_send(buff)
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

impl tokio::io::AsyncRead for UdpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.socket.poll_recv(cx, buf) {
            Poll::Ready(Ok(_n)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for UdpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        self.socket.poll_send(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}


#[cfg(test)]
mod test {
    use simplelog::{SimpleLogger, Config, LevelFilter};
    use crate::{ClientOptions, RequestOptions, TokioClient};

    #[tokio::test]
    async fn test_get_udp() {
        let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());

        let mut client = TokioClient::connect("coap://coap.me:5683", &ClientOptions::default()).await.unwrap();

        let resp = client.get("hello", RequestOptions::default()).await.unwrap();
        assert_eq!(resp, b"world".to_vec());
    }

    #[tokio::test]
    #[ignore = "coap.me does not have DTLS support"]
    async fn test_get_dtls() {
        let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());

        let mut client = TokioClient::connect("coaps://coap.me:5683", &ClientOptions::default()).await.unwrap();

        let resp = client.get("hello", RequestOptions::default()).await.unwrap();
        assert_eq!(resp, b"world".to_vec());
    }
}