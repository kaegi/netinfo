mod packet_capture;
mod inode_to_pid;
mod conn_to_inode;
mod packet_matcher;
mod types;
mod netinfo;

/// Contains netinfo-crate errors generated with "error-chain".
pub mod error;

pub use self::netinfo::Netinfo;
pub use self::netinfo::NetStatistics;
pub use self::types::InoutType;
pub use self::types::TransportType;
pub use self::packet_matcher::PacketMatcher;
pub use self::inode_to_pid::InodeToPidMap;
pub use self::conn_to_inode::ConnToInodeMap;
pub use self::packet_capture::CaptureHandle;
pub use self::types::Connection;
pub use self::types::PacketInfo;

/// Represents an Unix-Inode.
pub type Inode = u64;

/// Represents an Unix-Pid.
pub type Pid = u64;
