use netinfo::{Inode, Connection, TransportType};
use std::collections::{HashMap};
use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;
use std::io::Cursor;
use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr, IpAddr};
use std::str::FromStr;
use byteorder::*;
use netinfo::error::*;


/// This structure uses the tables in `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp` and `/proc/net/udp6` files to generate a
/// `Connection -> Inode`-HashMap.
#[derive(Debug)]
pub struct ConnToInodeMap {
    /// Each transport type (tcp, udp) has their own `Connection -> Inode` HashMap,
    conn_to_inode_map: HashMap<(TransportType, Connection), Inode>,
}

impl ConnToInodeMap {
    /// Constructor for `ConnToInodeMap`.
    pub fn new() -> ConnToInodeMap {
        ConnToInodeMap { conn_to_inode_map: HashMap::new() }
    }

    /// This function parses an adress of the form "DDCCBBAA:XXXX" or "IIHHGGEEDDCCBBAA:XXXX".
    /// `bytes.len()` is the number of bytes in the adress (4 for ipv4; 16 for ipv6) and `bytes`
    /// is used for output. The returned value is the port (the XXXX in the input).
    ///
    /// Because the network format is big endian, the order of the bytes has to be reversed afterwards.
    fn parse_ip_addr_to_bytes(s: &str, bytes: &mut [u8]) -> Result<u16> {
        if s.len() != bytes.len() * 2 + 1 + 4           { return Err(ErrorKind::ProcNetFileHasWrongFormat)?; }
        if s.chars().nth(bytes.len() * 2) != Some(':')  { return Err(ErrorKind::ProcNetFileHasWrongFormat)?; }

        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i*2..i*2 + 2], 16).map_err(|_| ErrorKind::ProcNetFileHasWrongFormat)?;
        }
        let port_start = bytes.len() * 2 + 1;
        let port = u16::from_str_radix(&s[port_start..port_start+4], 16).map_err(|_| ErrorKind::ProcNetFileHasWrongFormat)?;

        Ok(port)
    }

    /// Fix endianess for every 4-byte package (network -> host; u32 big endian -> u32 little endian).
    fn fix_endianness(bytes: &mut [u8]) -> Result<()> {
        assert!(bytes.len() % 4 == 0);
        for i in 0..bytes.len() / 4 {
            let host = Cursor::new(&mut bytes[i*4..(i+1)*4]).read_u32::<NetworkEndian>()?;
            Cursor::new(&mut bytes[i*4..(i+1)*4]).write_u32::<NativeEndian>(host)?;
        }
        Ok(())
    }

    /// This function parses an adress of the form "DDCCBBAA:XXXX" or "IIHHGGEEDDCCBBAA:XXXX" to
    /// a `SocketAddr`. See `parse_ip_addr_to_bytes` for more details.
    fn parse_ip_addr(s: &str) -> Result<SocketAddr> {
        if s.len() == 4 * 2 + 1 + 4 {
            let mut addr = [0u8; 4];
            let port = Self::parse_ip_addr_to_bytes(s, &mut addr[..])?;
            Self::fix_endianness(&mut addr[..])?;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port))
        } else if s.len() == 16 * 2 + 1 + 4 {
            let mut addr = [0u8; 16];
            Self::fix_endianness(&mut addr[..])?;
            let port = Self::parse_ip_addr_to_bytes(s, &mut addr[..])?;
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port))
        } else {
            Err(ErrorKind::ProcNetFileHasWrongFormat)?
        }
    }

    /// Parse files like /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6 and return a "connection -> inode" hashmap.
    fn parse_net_file(&mut self, path: String) -> Result<HashMap<Connection, Inode>> {
        let file = File::open(path.clone()).map_err(|e| ErrorKind::ProcNetFileError(path, e))?;
        let reader = BufReader::new(&file);
        let mut hash_map = HashMap::new();
        for line_res in reader.lines().skip(1) {
            let line = line_res?;
            let words: Vec<_> = line.split_whitespace().collect();

            let local_addr_str = words[1];
            let remote_addr_str = words[2];

            let local_addr = Self::parse_ip_addr(local_addr_str)?;
            let remote_addr = Self::parse_ip_addr(remote_addr_str)?;

            let inode_res: Result<_> = Inode::from_str(words[9])
                                                .chain_err(|| ErrorKind::ProcNetFileHasWrongFormat);
            let inode = inode_res?;

            hash_map.insert(Connection::new(local_addr, remote_addr), inode);
        }

        Ok(hash_map)
    }

    /// Test whether connection already exists, then up
    fn add_conninode(&mut self, transport_type: TransportType, connection: Connection, inode: Inode) {
        self.conn_to_inode_map.insert((transport_type, connection), inode);
    }

    /// Discard current HashMap and rebuild from `/proc/net/tcp*`
    pub fn refresh(&mut self) -> Result<()> {
        self.conn_to_inode_map.clear();

        let tcp4_hash_map = self.parse_net_file("/proc/net/tcp".to_string())?;
        let tcp6_hash_map = self.parse_net_file("/proc/net/tcp6".to_string())?;
        let udp4_hash_map = self.parse_net_file("/proc/net/udp".to_string())?;
        let udp6_hash_map = self.parse_net_file("/proc/net/udp6".to_string())?;

        for (connection, inode) in tcp4_hash_map.into_iter().chain(tcp6_hash_map.into_iter()).filter(|&(_, inode)| inode != 0) {
            self.add_conninode(TransportType::Tcp, connection, inode);
        }

        for (connection, inode) in udp4_hash_map.into_iter().chain(udp6_hash_map.into_iter()).filter(|&(_, inode)| inode != 0) {
            self.add_conninode(TransportType::Udp, connection, inode);
        }

        Ok(())
    }


    /// Lookup connection in HashMap and return associated inode when found.
    fn find_inode_tcp(&self, tt: TransportType, c: Connection) -> Option<Inode> {
        self.conn_to_inode_map.get(&(tt, c)).map(|&x| x)
    }

    /// Lookup connection in HashMap and return associated inode when found.
    /// UDP "connections" do not seem to have a remote adress in /proc/net/udp (its always 0.0.0.0:0) -> onesided.
    /// UDP "connections" might claim a port but do not have an IP (0.0.0.0:53241) -> port_only.
    fn find_inode_udp(&self, tt: TransportType, mut c: Connection, onesided: bool, port_only: bool) -> Option<Inode> {
        if onesided { c = c.get_resetted_remote(); }
        if port_only { c = c.get_resetted_ip(); }
        self.conn_to_inode_map.get(&(tt, c)).map(|&x| x)
    }

    /// Lookup connection in HashMap and return associated inode when found
    pub fn find_inode(&self, tt: TransportType, c: Connection) -> Option<Inode> {
        match tt {
            TransportType::Udp => {
                // try progressively less stricter versions until we find a inode
                None
                    .or_else(|| self.find_inode_udp(tt, c, false, false)) // case 1: remote addr always was 0.0.0.0:0 in /proc/net/udp* so this will probably not work
                    .or_else(|| self.find_inode_udp(tt, c, true, false))  // case 2: remote is zero, but local has ip and port: this case really happens
                    .or_else(|| self.find_inode_udp(tt, c, false, true))  // case 3: ip is zero for both remote and local, but port is non-zero: this will probably not happen (see case 1)
                    .or_else(|| self.find_inode_udp(tt, c, true, true))   // case 4: we only compare local port => this will give the right inode in most cases, but a port can be claimed by two processes (can be ambigous)
            }
            TransportType::Tcp => {
                self.find_inode_tcp(tt, c)
            }
        }
    }
}
