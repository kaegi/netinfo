use std;
use std::net::{SocketAddr, IpAddr};
use std::collections::HashSet;
use pnet::datalink::{self, NetworkInterface, Channel, Config};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet};
use pnet::packet::ipv6::{Ipv6Packet};
use pnet::packet::tcp::{TcpPacket};
use pnet::packet::udp::{UdpPacket};
use pnet::packet::{Packet};
use netinfo::{ConnectionType, PacketInfo, TransportType};
use netinfo::error::*;
use std::os::raw::c_int;


// taken from https://github.com/rust-lang/libc/blob/454b32511f311b13b235562d98b6c591faa60af3/src/unix/notbsd/mod.rs#L433
pub const IFF_UP: c_int = 0x1;
pub const IFF_LOOPBACK: c_int = 0x8;
pub const IFF_RUNNING: c_int = 0x40;

//pub const IFF_BROADCAST: c_int = 0x2;
//pub const IFF_DEBUG: c_int = 0x4;
//pub const IFF_POINTOPOINT: c_int = 0x10;
//pub const IFF_NOTRAILERS: c_int = 0x20;
//pub const IFF_NOARP: c_int = 0x80;
//pub const IFF_PROMISC: c_int = 0x100;
//pub const IFF_ALLMULTI: c_int = 0x200;
//pub const IFF_MASTER: c_int = 0x400;
//pub const IFF_SLAVE: c_int = 0x800;
//pub const IFF_MULTICAST: c_int = 0x1000;
//pub const IFF_PORTSEL: c_int = 0x2000;
//pub const IFF_AUTOMEDIA: c_int = 0x4000;
//pub const IFF_DYNAMIC: c_int = 0x8000;



///! This module provides `CaptureHandle` which generates `PacketInfo`s from incoming and outgoing traffic.
///! What is done to these `PacketInfo`s is decided by a closure which is given to `CaptureHandle::new()`.

/// form a new packet like and use a function to handle it
///
///     handle!(ethernet_packet, Ipv6Packet, handle_ipv6_packet);
///
macro_rules! handle {
    ($_self:ident, $f:ident, $from:ident, $to_ty:ident, $($extra:ident),*) => {{
        match $to_ty::new($from.payload()) {
            Some(new_packet) => { $_self.$f(new_packet, $($extra),*) }
            /* Ignore error, packet errors seem to occur from time to time */
            /* Err(Error::from(ErrorKind::PacketConversionError)) */
            None => { warn!("package conversion error happend - ignoring packet"); Ok(()) }
        }
    }}
}

/// Test flags whether device is running
fn is_running(flags: u32) -> bool {
  !(flags & IFF_LOOPBACK as u32 != 0) && (flags & IFF_UP as u32 != 0) && (flags & IFF_RUNNING as u32 != 0)
}


struct ExtraPacketData {
    length: u64,
}

struct CaptureParser {
    /// Function that handles packet infos
    packet_info_handler: Box<FnMut(PacketInfo) -> Result<()> + Send>,

    /// Local IP addresses accociated with network interface. Organized in a
    /// HashSet so we can determine quickly, whether IpAddr is local IpAddr.
    local_net_ips: HashSet<IpAddr>
}

// `FnMut(X) -> Y` does not implement Debug
impl std::fmt::Debug for CaptureParser {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // TODO: wait until `FnMut(X) -> Y` implements Debug, then remove this `impl Debug`
        write!(f, "CaptureParser {{ packet_info_handler: ???, local_net_ips: {:?} }}", self.local_net_ips)
    }
}

impl CaptureParser {
    fn new(packet_info_handler: Box<FnMut(PacketInfo) -> Result<()> + Send>, local_net_ips_opt: Option<Vec<IpAddr>>) -> CaptureParser {
        let mut local_net_ips_hashset = HashSet::new();
        if let Some(local_net_ips) = local_net_ips_opt {
            for ip in local_net_ips { local_net_ips_hashset.insert(ip); }
        }
        CaptureParser { packet_info_handler: packet_info_handler, local_net_ips: local_net_ips_hashset }
    }

    fn handle_channel(&mut self, channel: &mut Channel) -> Result<()> {
		match channel {
			&mut Channel::Ethernet(_ /* ref tx */, ref mut rx) => {
                let mut iter = rx.iter();
                loop {
                    let packet = iter.next().chain_err(|| ErrorKind::EthernetReceiveError)?;
                    let extra_data = ExtraPacketData { length: packet.packet().len() as u64 };
                    self.handle_ethernet_packet(extra_data, packet)?;
				}
			}
			_ => {
                Err(ErrorKind::UnknownNetworkObject.into())
			}
		}
    }

    fn handle_ethernet_packet(&mut self, extra_data: ExtraPacketData, ethernet_packet: EthernetPacket) -> Result<()> {
        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => { handle!(self, handle_ipv4_packet, ethernet_packet, Ipv4Packet, extra_data)? }
            EtherTypes::Ipv6 => { handle!(self, handle_ipv6_packet, ethernet_packet, Ipv6Packet, extra_data)? }
            EtherTypes::Arp => { /* ignore */ }
            e => { warn!("Warning: Unhandled ethernet packet type: {:?}", e) }
        }

        Ok(())
    }

    fn handle_ipv4_packet(&mut self, ipv4_packet: Ipv4Packet, extra_data: ExtraPacketData) -> Result<()> {
        let source = IpAddr::V4(ipv4_packet.get_source());
        let dest = IpAddr::V4(ipv4_packet.get_destination());

        match ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => { handle!(self, handle_tcp_packet, ipv4_packet, TcpPacket, source, dest, extra_data)? }
            IpNextHeaderProtocols::Udp => { handle!(self, handle_udp_packet, ipv4_packet, UdpPacket, source, dest, extra_data)? }
            e => { warn!("Unhandled Ipv4 protocol: {:?}", e); }
        }
        Ok(())
    }

    fn handle_ipv6_packet(&mut self, ipv6_packet: Ipv6Packet, extra_data: ExtraPacketData) -> Result<()> {
        let source = IpAddr::V6(ipv6_packet.get_source());
        let dest = IpAddr::V6(ipv6_packet.get_destination());

        match ipv6_packet.get_next_header() {
            IpNextHeaderProtocols::Tcp => { handle!(self, handle_tcp_packet, ipv6_packet, TcpPacket, source, dest, extra_data)? }
            IpNextHeaderProtocols::Udp => { handle!(self, handle_udp_packet, ipv6_packet, UdpPacket, source, dest, extra_data)? }
            e => { warn!("Unhandled Ipv6 protocol: {:?}", e); }
        }
        Ok(())
    }

    fn handle_tcp_packet(&mut self, tcp_packet: TcpPacket, source_addr: IpAddr, dest_addr: IpAddr, extra_data: ExtraPacketData) -> Result<()> {
        let source = SocketAddr::new(source_addr, tcp_packet.get_source());
        let dest = SocketAddr::new(dest_addr, tcp_packet.get_destination());
        let inout_type = self.get_inout_type(source_addr, dest_addr)?;
        self.handle_packet_info(PacketInfo::new(source, dest, extra_data.length, TransportType::Tcp, inout_type))
    }

    fn handle_udp_packet(&mut self, udp_packet: UdpPacket, source_addr: IpAddr, dest_addr: IpAddr, extra_data: ExtraPacketData) -> Result<()> {
        let source = SocketAddr::new(source_addr, udp_packet.get_source());
        let dest = SocketAddr::new(dest_addr, udp_packet.get_destination());
        let inout_type = self.get_inout_type(source_addr, dest_addr)?;
        self.handle_packet_info(PacketInfo::new(source, dest, extra_data.length, TransportType::Udp, inout_type))
    }

    fn handle_packet_info(&mut self, packet_info: PacketInfo) -> Result<()> {
        (self.packet_info_handler)(packet_info)?;
        Ok(())
    }

    fn get_inout_type(&self, source_addr: IpAddr, dest_addr: IpAddr) -> Result<Option<ConnectionType>> {
        match (self.local_net_ips.contains(&source_addr), self.local_net_ips.contains(&dest_addr)) {
            // local to non-local
            (true, false) => { Ok(Some(ConnectionType::Outgoing)) }

            // non-local to local
            (false, true) => { Ok(Some(ConnectionType::Incoming)) }

            // it can happen that neither address is local.
            // Example: Incoming multicast can go from "remote -> 239.255.255.250".
            (false, false) => { Ok(None) }

            // these packages are supposed to land in loopback... This case should never happen...
            (true, true) => { Err(ErrorKind::LocalToLocalConnectionError.into()) }
        }
    }
}

/// This structure is used to capture all traffic on a network interface and pass it to a
/// closure which handles all `PacketInfo`s.
pub struct CaptureHandle {
	channel: Channel,
    capture_parser: CaptureParser,
}

impl std::fmt::Debug for CaptureHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // TODO: wait until pnet::datalink::Channel implements Debug, then remove this `impl Debug`
        write!(f, "CaptureHandle {{ channel: ???, capture_parser: {:?} }}", self.capture_parser)
    }
}


impl CaptureHandle {
    /// Lists all non-loopback, active network interfaces
    pub fn list_net_interfaces() -> Vec<NetworkInterface> {
        datalink::interfaces().into_iter().filter(|interface| is_running(interface.flags)).collect()
    }

    /// This function will block while capturing all packets.
    ///
    /// TODO: the pnet crate only allows single threaded pcap; `pcap_setnonblock` is currently (11 Nov 2016) not implemented.
    ///       in the future we might want to use that instead of another thread.
	pub fn handle_packets(&mut self) -> Result<()> {
        self.capture_parser.handle_channel(&mut self.channel)
    }

    /// Create a new `CaptureHandle` for a specific network interface. The interface can be obtained from `list_net_interfaces()`. The second
    /// argument is a closure where all packet infos are dealt with.
    pub fn new<F: FnMut(PacketInfo) -> Result<()> + Send + 'static>(interface: NetworkInterface, packet_info_handler: F) -> Result<CaptureHandle> {
        info!("CaptureHandle for interface: {:?}", interface);

        Ok(CaptureHandle {
            channel: datalink::channel(&interface, Config::default()).chain_err(|| ErrorKind::ChannelCreationError)?,
            capture_parser: CaptureParser::new(Box::new(packet_info_handler), interface.ips),
        })
    }
}
