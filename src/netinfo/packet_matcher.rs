use netinfo::{ConnToInodeMap, InodeToPidMap, Pid, Connection, ConnectionType, PacketInfo};
use netinfo::error::*;

/// `PacketMatcher` provides a function which allows matching
/// source/destination adresses for packet to a process.
#[derive(Debug)]
pub struct PacketMatcher {
    /// Matches a source/destination adress to a socket inode of a process.
    conn_to_inode_map: ConnToInodeMap,

    /// Matches a socket inode to its process.
    inode_to_pid_map: InodeToPidMap,
}


impl PacketMatcher {
    /// Constructor for `PacketMatcher`.
    pub fn new() -> PacketMatcher {
        PacketMatcher {
            conn_to_inode_map: ConnToInodeMap::new(),
            inode_to_pid_map: InodeToPidMap::new(),
        }
    }

    /// This function updates the tables that are used for the matching.
    pub fn refresh(&mut self) -> Result<()> {
        self.conn_to_inode_map.refresh()?;
        self.inode_to_pid_map.refresh()?;
        Ok(())
    }

    /// Find the process to which a packet belongs.
    pub fn find_pid(&mut self, packet_info: PacketInfo) -> Option<Pid> {
        let tt = packet_info.transport_type;
        let mut c = Connection::from(packet_info.clone());
        match packet_info.inout_type {
            // Incoming packets have a their address ordered as "remote addr -> local addr" but
            // our connection-to-inode table only contains "local addr -> remote addr" entries.
            // So we have to reverse the connection.
            Some(ConnectionType::Incoming) => { c = c.get_reverse(); }
            Some(ConnectionType::Outgoing) => {}

            // TODO: use heuristics to guess whether packet is incoming or outgoing - this is just a corner case though
            None => { return None; }
        }
        self.conn_to_inode_map
            .find_inode(tt, c)
            .and_then(|inode| self.inode_to_pid_map.find_pid(inode))
    }
}
