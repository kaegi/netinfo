#![deny(missing_docs,
        missing_debug_implementations, missing_copy_implementations,
        trivial_casts, trivial_numeric_casts,
        unsafe_code,
        unstable_features,
        unused_qualifications)]

//! This binary will group network usage per process nethogs-like. See library documentation or 'lib.rs' for more information.

#[macro_use] extern crate log;
#[macro_use] extern crate enum_primitive;
#[macro_use] extern crate error_chain;
extern crate pnet;
extern crate byteorder;

mod netinfo;
pub use netinfo::*;

use std::time::Duration;
use std::thread::sleep;

static SEPARATOR: &'static str = "#####################";

fn main() {
    // Please use error handling instead of unwrap() in real applications - the functions heavily depend on network and thread IO, so they
    // CAN and WILL fail at some point!

    let net_interfaces = Netinfo::list_net_interfaces().unwrap();
    if net_interfaces.len() == 0 {
        println!("No up-and-running network interfaces found!");
        return;
    }

    print!("Please use applications that send data over following network interfaces to see statistics: ");
    print!("{}", net_interfaces[0].get_name_as_str());
    for i in &net_interfaces[1..] { print!(", {}", i.get_name_as_str()); }
    println!("");
    println!("{}", SEPARATOR);
    println!("");

    let mut netinfo = Netinfo::new(&net_interfaces[..]).unwrap();
    netinfo.start().unwrap();


    loop {
        let statistics = netinfo.get_net_statistics().unwrap();
        let mut printed_pid = false;
        for pid in statistics.get_all_pids() {
            let num_incoming_bytes = statistics.get_bytes_by_attr(Some(pid), Some(InoutType::Incoming), None);
            let num_outgoing_bytes = statistics.get_bytes_by_attr(Some(pid), Some(InoutType::Outgoing), None);
            println!("Pid: {}  i: {}kB   o: {}kB", pid, num_incoming_bytes / 1000, num_outgoing_bytes / 1000);
            printed_pid = true;
        }

        if printed_pid {
            let num_total_bytes = statistics.get_total();
            let num_unknown = statistics.get_unassigned_bytes();
            let num_tcp_bytes = statistics.get_bytes_by_transport_type(TransportType::Tcp);
            let num_udp_bytes = statistics.get_bytes_by_transport_type(TransportType::Udp);

            println!("");
            println!("Tcp/Udp: {}kB / {}kB", num_tcp_bytes / 1000, num_udp_bytes / 1000);
            println!("Unknown: {}kB", num_unknown / 1000);
            println!("Total: {}kB", num_total_bytes / 1000);
            println!("");
            println!("{}", SEPARATOR);
            println!("");
        }
        netinfo.clear().unwrap();
        sleep(Duration::new(1, 0));
    }
}
