# An(other) Asynchronous Rust CoAP Client

An asynchronous [CoAP](https://tools.ietf.org/html/rfc7252) client with pluggable backends, intended to provide a straightforward API, allow use with tokio/async-std/smolctp/anything else, to support all the standard UDP/DTLS/TCP/TLS transports, and eventually to work with `no_std`.

There's also a little client utility that may be useful for working on CoAP things, installable via `cargo install coap-client` or by downloading pre-built images from the [releases](https://github.com/ryankurte/rust-coap-client/releases/latest) page.

## Status

[![GitHub tag](https://img.shields.io/github/tag/ryankurte/rust-coap-client.svg)](https://github.com/ryankurte/rust-coap-client)
![Build Status](https://github.com/ryankurte/rust-coap-client/workflows/Rust/badge.svg)
[![Crates.io](https://img.shields.io/crates/v/coap-client.svg)](https://crates.io/crates/coap-client)
[![Docs.rs](https://docs.rs/coap-client/badge.svg)](https://docs.rs/coap-client)


This is very much a work in progress (but, hopefully a useful one!), check out the [Project Status](https://github.com/ryankurte/rust-coap-client/issues/1) meta-issue for where we're up to.

## Related Projects

- [martindisch/coap-lite](https://github.com/martindisch/coap-lite)
- [Covertness/coap-rs](https://github.com/Covertness/coap-rs)
- [google/rust-async-coap](https://github.com/google/rust-async-coap)
