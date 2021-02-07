use std::collections::HashMap;
use std::io::Error;

use log::{debug, error, trace};

use tokio::sync::mpsc::channel;


use crate::{COAP_MTU};
use super::{Tokio, Ctl};


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

        Ok(Self { ctl_tx, _listener })
    }
}
