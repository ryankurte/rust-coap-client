//! Backend module provides swappable CoAP client backends
// https://github.com/ryankurte/rust-coap-client
// Copyright 2021 ryan kurte <ryan@kurte.nz>

use coap_lite::Packet;
use futures::{Future, Stream};

use crate::RequestOptions;

#[cfg(feature = "backend-tokio")]
pub mod backend_tokio;

#[cfg(feature = "backend-tokio")]
pub use backend_tokio::{Tokio, TokioObserve};

pub trait Observer<E>: Stream<Item = Result<Packet, E>> + Send {
    /// Fetch the observer token
    fn token(&self) -> u32;
    /// Fetch the observer resource
    fn resource(&self) -> &str;
}

/// Generic transport trait for implementing CoAP client backends
pub trait Backend<E>: Send {
    type Request: Future<Output = Result<Packet, E>> + Send;
    type Observe: Observer<E>;
    type Unobserve: Future<Output = Result<(), E>> + Send;

    fn request(&mut self, req: Packet, opts: RequestOptions) -> Self::Request;

    fn observe(&mut self, resource: String, opts: RequestOptions) -> Self::Observe;

    fn unobserve(&mut self, o: Self::Observe) -> Self::Unobserve;
}
