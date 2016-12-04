use netinfo::{ConnToInodeMap, InodeToPidMap, Inode, Pid, Connection, ConnectionType, TransportType, PacketInfo};
use netinfo::error::*;
use std::collections::HashMap;

/// `PacketMatcher` provides a function which allows matching
/// source/destination adresses for packet to a process.
#[derive(Debug)]
pub struct PacketMatcher {
    /// Matches a source/destination adress to a socket inode of a process.
    conn_to_inode_map: ConnToInodeMap,

    /// Matches a socket inode to its process.
    inode_to_pid_map: InodeToPidMap,

    /// Store all already-handled connections in HashMap so we can look them up
    /// without having to refresh the other maps (less cpu intensive)
    ///
    /// If the resulting value is None, the connection could not be associated with
    /// process and it is in most cases pointless to try again.
    known_connections: HashMap<(TransportType, Connection), Option<(Inode, Pid)>>,
}


impl PacketMatcher {
    /// Constructor for `PacketMatcher`.
    pub fn new() -> PacketMatcher {
        PacketMatcher {
            conn_to_inode_map: ConnToInodeMap::new(),
            inode_to_pid_map: InodeToPidMap::new(),
            known_connections: HashMap::new(),
        }
    }

    /// This function updates the tables that are used for the matching.
    pub fn refresh(&mut self) -> Result<()> {
        self.conn_to_inode_map.refresh()?;
        self.inode_to_pid_map.refresh()?;
        Ok(())
    }

    /// Find the process to which a packet belongs.
    pub fn find_pid(&mut self, packet_info: PacketInfo) -> Result<Option<Pid>> {
        let tt = packet_info.transport_type;
        let mut c = Connection::from(packet_info.clone());
        match packet_info.inout_type {
            // Incoming packets have a their address ordered as "remote addr -> local addr" but
            // our connection-to-inode table only contains "local addr -> remote addr" entries.
            // So we have to reverse the connection.
            Some(ConnectionType::Incoming) => { c = c.get_reverse(); }
            Some(ConnectionType::Outgoing) => {}

            // TODO: use heuristics to guess whether packet is incoming or outgoing - this is just a corner case though
            None => { return Ok(None); }
        }

        self.find_pid_in_table(tt, c)
    }


    /// Find the process by transport type and connection. The connection has to be
    /// already reversed for incoming packets.
    /// This functions uses the "self.known_connections"-HashMap or adds the new connection
    /// to it.
    fn find_pid_in_table(&mut self, tt: TransportType, c: Connection) -> Result<Option<Pid>> {
        if let Some(&res) = self.known_connections.get(&(tt, c)) {
            // Known connection! Does this connection have a process?
            Ok(res.map(|(_, pid)| pid))
        } else {
            // Unknown connection!
            let inode_pid_opt = self.get_new_connection(tt, c)?;
            self.known_connections.insert((tt, c), inode_pid_opt);
            Ok(inode_pid_opt.map(|(_, pid)| pid))
        }
    }

    /// Find the process by transport type and connection. The connection has to be
    /// already reversed for incoming packets.
    /// At the beginning the internal conn->inode->pid tables are refreshed, then the
    /// it tries to assign the connection to a pid.
    fn get_new_connection(&mut self, tt: TransportType, c: Connection) -> Result<Option<(Inode, Pid)>> {
        self.refresh()?;

        Ok(
            self.conn_to_inode_map
                .find_inode(tt, c)
                .and_then(|inode| self.inode_to_pid_map.find_pid(inode)
                                                        .map(|pid| (inode, pid)))
        )
    }
}
