//! Asynchronous SCUT DrCOM client and protocol implementation.
//!
//! EAP authentication gates the UDP session through a latest-state watch channel.
//! Wire codecs are kept separate from I/O so they can be checked against fixtures.
pub mod client;
pub mod control;
pub mod device;
pub mod eap;
pub mod hooks;
pub mod logger;
pub mod settings;
pub mod socket;
pub mod udp;
pub mod update;
mod update_schedule;
pub mod util;

pub use settings::Settings;

#[cfg(test)]
mod integration_tests;

pub mod service;

#[cfg(feature = "portal")]
pub mod portal;
