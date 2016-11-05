use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr, IpAddr};

/// Udp, Tcp or other packet type on transport layer?
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum TransportType {
    /// Using Tcp on transport layer for packet
    Tcp,

    /// Using Udp on transport layer for packet
    Udp,

    // others might get added
}

/// Describes a network packet.
#[allow(missing_copy_implementations)]
#[derive(Debug, Clone)]
pub struct PacketInfo {

    /// Source IP
    pub sip: SocketAddr,

    /// Destination IP
    pub dip: SocketAddr,

    /// Number of nanoseconds (currently unused and set to 0)
    pub time: u64,

    /// Number of bytes in package (on datalink level)
    pub datalen: u64,

    /// Transport layer type
    pub transport_type: TransportType,

    /// Is Some(Incoming) or Some(Outgoing) if connection type can be determined, None if not
    pub inout_type: Option<ConnectionType>
}

impl PacketInfo {
    /// Constructor for `PacketInfo` type.
    pub fn new(sip: SocketAddr, dip: SocketAddr, datalen: u64, transport_type: TransportType, inout_type: Option<ConnectionType>) -> PacketInfo {
        PacketInfo { sip: sip, dip: dip, time: 0, datalen: datalen, transport_type: transport_type, inout_type: inout_type }
    }
}

/// Set IP to zero but leave type and port untouched.
pub fn reset_socket_addr_ip(s: SocketAddr) -> SocketAddr {
    let port = s.port();
    let mut new = reset_socket_addr(s);
    new.set_port(port);
    new
}


/// Set IP and port to zero but leave type untouched.
pub fn reset_socket_addr(s: SocketAddr) -> SocketAddr {
    match s {
        SocketAddr::V4(_) => { SocketAddr::new(IpAddr::V4(Ipv4Addr::from([0u8; 4])), 0) }
        SocketAddr::V6(_) => { SocketAddr::new(IpAddr::V6(Ipv6Addr::from([0u8; 16])), 0) }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[allow(missing_copy_implementations)]
/// Represents a network connection from one "ip-adress:port" to another. It can be
/// Ipv4 or Ipv6.
pub struct Connection {
    /// Local adress.
    pub local: SocketAddr,

    /// Remote adress.
    pub remote: SocketAddr,
}

impl Connection {
    /// Generate new `Connection` from Ipv4 or Ipv6 addressses.
    pub fn new(local: SocketAddr, remote: SocketAddr) -> Connection {
        Connection { local: local, remote: remote }
    }

    /*
    /// Generate new `Connection` from Ipv4 addressses.
    pub fn new_ip4(local: SocketAddrV4, remote: SocketAddrV4) -> Connection {
        Self::new(SocketAddr::V4(local), SocketAddr::V4(remote))
    }

    /// Generate new `Connection` from Ipv6 addressses.
    pub fn new_ip6(local: SocketAddrV6, remote: SocketAddrV6) -> Connection {
        Self::new(SocketAddr::V6(local), SocketAddr::V6(remote))
    }
    */

    /// Get the reverse connection.
    pub fn get_reverse(&self) -> Connection {
        Connection::new(self.remote, self.local)
    }

    /// Get connection with port but ip set to zero.
    pub fn get_resetted_ip(&self) -> Connection {
        Connection::new(reset_socket_addr_ip(self.local), reset_socket_addr_ip(self.remote))
    }

    /// Get connection with port and ip set to zero for remote (but same type).
    pub fn get_resetted_remote(&self) -> Connection {
        Connection::new(self.local, reset_socket_addr(self.remote))
    }
}

impl<'a> From<&'a PacketInfo> for Connection {
    fn from(p: &'a PacketInfo) -> Connection {
        Connection::new(p.sip, p.dip)
    }
}

impl From<PacketInfo> for Connection {
    fn from(p: PacketInfo) -> Connection {
        Connection::new(p.sip, p.dip)
    }
}


#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
/// ConnectionType can be Incoming or Outgoing (do we have to reverse Connection or not?).
pub enum ConnectionType {
    /// Local address -> Remote adress
    Incoming,

    /// Remote adress -> Local address
    Outgoing,
}
