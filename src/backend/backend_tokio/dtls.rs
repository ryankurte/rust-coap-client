use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};


use log::{debug, error, trace};

use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc::channel;

use openssl::ssl::{SslFiletype, SslMethod, SslVerifyMode};


use crate::{ClientOptions, COAP_MTU};
use super::{Tokio, Ctl};


impl Tokio {
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
        let ssl_conn = openssl::ssl::Ssl::new(&ssl_ctx).unwrap();

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

        Ok(Self { ctl_tx, _listener })
    }
}


/// UdpStream wrapper for DTLS compatibility
pub struct UdpStream {
    socket: tokio::net::UdpSocket,
}

impl From<tokio::net::UdpSocket> for UdpStream {
    fn from(socket: tokio::net::UdpSocket) -> Self {
        Self { socket }
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
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.socket.poll_recv(cx, buf) {
            Poll::Ready(Ok(_n)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for UdpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.socket.poll_send(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}
