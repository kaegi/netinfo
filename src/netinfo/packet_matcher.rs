use netinfo::{ConnToInodeMap, InodeToPidMap, Inode, Pid, Connection, InoutType, TransportType, PacketInfo};
use netinfo::error::*;
use std::collections::HashMap;

/// Provides the tables for PacketMatcher.
#[derive(Debug)]
struct PacketMatcherTables {
    /// Matches a source/destination adress to a socket inode of a process.
    conn_to_inode_map: ConnToInodeMap,

    /// Matches a socket inode to its process.
    inode_to_pid_map: InodeToPidMap,
}

/// `PacketMatcher` provides a function which allows matching
/// source/destination adresses for packet to a process.
#[derive(Debug)]
pub struct PacketMatcher {
    /// conn->inode->pid Tables
    tables: PacketMatcherTables,

    /// Store all already-handled connections in HashMap so we can look them up
    /// without having to refresh the other maps (less cpu intensive/caching)
    ///
    /// If the resulting value is None, the connection could not be associated with
    /// process and it is in most cases pointless to try again.
    known_connections: HashMap<(TransportType, Connection), Option<(Inode, Pid)>>,
}


impl PacketMatcherTables {
    /// Constructor for `PacketMatcherTables`.
    pub fn new() -> PacketMatcherTables {
        PacketMatcherTables {
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

    /// Maps connection from conn->inode->pid with internal tables.
    fn map_connection(&self, tt: TransportType, c: Connection) -> Option<(Inode, Pid)> {
        self.conn_to_inode_map
        .find_inode(tt, c)
        .and_then(|inode| self.inode_to_pid_map.find_pid(inode)
                                                .map(|pid| (inode, pid)))
    }
}

impl PacketMatcher {
    /// Constructor for `PacketMatcher`.
    pub fn new() -> PacketMatcher {
        PacketMatcher {
            tables: PacketMatcherTables::new(),
            known_connections: HashMap::new(),
        }
    }

    /// This function updates the tables that are used for the matching.
    fn refresh(&mut self) -> Result<()> {
        self.tables.refresh()?;
        self.update_known_connections()?;
        Ok(())
    }

    /// A process might end a connection and another might open the same connection.
    /// To prevent wrong assignment we have to update/purge the "self.known_connections"
    /// when connection is closed/reopened.
    fn update_known_connections(&mut self) -> Result<()> {
        self.known_connections =
                self.known_connections.iter()
                .filter_map(|(&(tt, c), &old)| {
                    let new = self.tables.map_connection(tt, c);
                    match (old, new) {
                        // Connection used to exist, but not anymore -> remove/drop so
                        // if reopened it will be assinged to a new program
                        (Some(_), None) => { None }

                        // in these cases the connection was changed/did not change/was created
                        (_, new) => { Some(((tt, c), new)) }
                    }

                })
                .collect();
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
            Some(InoutType::Incoming) => { c = c.get_reverse(); }
            Some(InoutType::Outgoing) => {}

            // TODO: use heuristics to guess whether packet is incoming or outgoing - this is just a corner case though
            None => { return Ok(None); }
        }

        self.find_pid_cached(tt, c)
    }

    /// Find the process by transport type and connection. The connection has to be
    /// already reversed for incoming packets.
    /// This functions uses the "self.known_connections"-HashMap or adds the new connection
    /// to it.
    fn find_pid_cached(&mut self, tt: TransportType, c: Connection) -> Result<Option<Pid>> {
        if let Some(&res) = self.known_connections.get(&(tt, c)) {
            // Known connection! Does this connection have a process?
            Ok(res.map(|(_, pid)| pid))
        } else {
            // Unknown connection!
            self.refresh()?;
            let inode_pid_opt = self.tables.map_connection(tt, c);
            self.known_connections.insert((tt, c), inode_pid_opt);
            Ok(inode_pid_opt.map(|(_, pid)| pid))
        }
    }
}
