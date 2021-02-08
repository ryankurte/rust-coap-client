//! A simple async CoAP client
// https://github.com/ryankurte/rust-coap-client
// Copyright 2021 ryan kurte <ryan@kurte.nz>

use std::convert::{TryFrom, TryInto};

use futures::{StreamExt};
use log::{debug, info, error};
use simplelog::{LevelFilter, SimpleLogger, TermLogger, TerminalMode};
use structopt::StructOpt;

use coap_client::{ClientOptions, HostOptions, RequestOptions, TokioClient};

/// A simple utility to for interacting with CoAP services
#[derive(PartialEq, Clone, Debug, StructOpt)]
pub struct Options {
    #[structopt(flatten)]
    pub request_opts: RequestOptions,

    #[structopt(flatten)]
    pub client_opts: ClientOptions,

    #[structopt(parse(try_from_str = HostOptions::try_from))]
    /// Target (transport://hostname:port/resource) for CoAP operation
    pub target: HostOptions,

    #[structopt(subcommand)]
    pub command: Command,

    #[structopt(long, default_value = "1")]
    /// Repeat command N times
    pub repeat: usize,

    #[structopt(long = "log-level", default_value = "info")]
    /// Configure app logging levels (warn, info, debug, trace)
    pub log_level: LevelFilter,
}

/// Wrapper type for decoding data as hex under structopt
#[derive(Clone, Debug, PartialEq)]
pub struct HexData(pub Vec<u8>);

impl std::str::FromStr for HexData {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::decode(s).map(HexData)
    }
}

/// Helper type to flatten data options
#[derive(PartialEq, Clone, Debug, StructOpt)]
pub struct Data {
    /// File  to read/write
    #[structopt(long, group = "d")]
    pub file: Option<String>,

    /// UTF-8 String data to write
    #[structopt(long, group = "d")]
    pub string: Option<String>,

    /// Hex encoded data to write
    #[structopt(long, group = "d")]
    pub hex: Option<HexData>,
}

impl TryFrom<&Data> for Option<Vec<u8>> {
    type Error = std::io::Error;

    fn try_from(d: &Data) -> Result<Self, Self::Error> {
        let data = if let Some(f) = d.file.as_ref() {
            debug!("Loading file: {}", f);
            Some(std::fs::read(f)?)
        } else if let Some(s) = d.string.as_ref() {
            Some(s.as_bytes().to_vec())
        } else if let Some(h) = d.hex.as_ref() {
            Some(h.0.clone())
        } else {
            None
        };

        Ok(data)
    }
}

/// Commands to execute
#[derive(PartialEq, Clone, Debug, StructOpt)]
pub enum Command {
    /// Perform a GET request
    Get,
    /// Perform a PUT request
    Put(Data),
    /// Perform a POST request
    Post(Data),
    /// Register an observer on the provided topic
    Observe,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Load options from CLI
    let opts = Options::from_args();

    // Initialise logging w/ fallback to simple mode if no stderr available
    let log_config = simplelog::ConfigBuilder::new().build();
    if let Err(_e) = TermLogger::init(opts.log_level, log_config.clone(), TerminalMode::Mixed) {
        SimpleLogger::init(opts.log_level, log_config).unwrap();
    }

    debug!("Connecting client to target: '{}'", opts.target.to_string());

    // Setup client (this will bind a socket and connect if required)
    let mut client = match TokioClient::connect(opts.target.clone(), &opts.client_opts).await {
        Ok(c) => c,
        Err(e) => return Err(anyhow::anyhow!("Error connecting to client: {:?}", e)),
    };

    debug!("Connected, executing command");

    // Run observation
    if let Command::Observe = &opts.command {
        // Create observer
        let mut o = client.observe(&opts.target.resource, &opts.request_opts).await;

        // Await messages
        loop {
            tokio::select! {
                r = o.next() => {
                    match r {
                        Some(Ok(d)) => {
                            debug!("Observe RX: {:?}", d);
                            display_resp(&d.payload)
                        },
                        Some(Err(e)) => {
                            error!("Observe error: {:?}", e);
                            break;
                        },
                        None => {
                            info!("Observe channel closed");
                            break;
                        }
                    }
                },
                _ = tokio::signal::ctrl_c() => {
                    break;
                }
            }
        }

        // Destroy observer
        client.unobserve(o).await?;

    // Perform basic commands
    } else {
        for _i in 0..opts.repeat {
            match &opts.command {
                Command::Get => {
                    let r = client
                        .get(&opts.target.resource, &opts.request_opts)
                        .await?;
                    display_resp(&r);
                }
                Command::Put(data) => {
                    let d: Option<Vec<u8>> = data.try_into()?;
                    let r = client
                        .put(&opts.target.resource, d.as_deref(), &opts.request_opts)
                        .await?;
                    display_resp(&r);
                }
                Command::Post(data) => {
                    let d: Option<Vec<u8>> = data.try_into()?;
                    let r = client
                        .post(&opts.target.resource, d.as_deref(), &opts.request_opts)
                        .await?;
                    display_resp(&r);
                },
                _ => ()
            };
        }
    }

    // Close client
    if let Err(e) = client.close().await {
        return Err(anyhow::anyhow!("Error closing client: {:?}", e));
    }

    Ok(())
}

// Display response
// TODO: accept data options here (string, hex, write-to-file)
fn display_resp(d: &[u8]) {
    match std::str::from_utf8(&d) {
        Ok(s) if s.len() > 0 => println!("Received: {}", s),
        Err(_) if d.len() > 0 => println!("Received: {:02x?}", d),
        _ => (),
    }
}