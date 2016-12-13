//! This crate will group network usage per process. It uses a method similar to `nethogs`:
//! All packets will be captured and their source/destination address are then used to
//! match them to a process.
//!
//! This matching process relies on the `/proc` file system, so it only works on Linux.
//!
//! Because capturing the network traffic is not permittet for normal programs, you
//! either have to run your binary as root or allow capturing with:
//!
//! ```bash
//! sudo setcap cap_net_raw,cap_net_admin=eip /path/to/your/bin
//! ```
#![deny(missing_docs,
        missing_debug_implementations, missing_copy_implementations,
        trivial_casts, trivial_numeric_casts,
        unsafe_code,
        unstable_features,
        unused_qualifications)]

#[macro_use] extern crate log;
#[macro_use] extern crate enum_primitive;
#[macro_use] extern crate error_chain;
extern crate pnet;
extern crate byteorder;

pub use netinfo::Netinfo;
pub use netinfo::NetStatistics;
pub use netinfo::InoutType;
pub use netinfo::TransportType;
pub use netinfo::error;
pub use pnet::datalink::NetworkInterface;

mod netinfo;
