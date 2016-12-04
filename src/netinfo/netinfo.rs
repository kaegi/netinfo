use pnet::datalink::NetworkInterface;
use netinfo::{Pid, PacketInfo, CaptureHandle, PacketMatcher, ConnectionType, TransportType};
use std::sync::Arc;
use std::sync::Mutex;
use std::collections::HashMap;
use std::time::Duration;
use std::thread;
use std::thread::{sleep, JoinHandle};
use netinfo::error::*;

#[derive(Clone, Debug, Default)]
/// Contains detailed information on network usage on per attribute (pid, in/out, tcp/udp).
pub struct NetStatistics {
    /// Usage per "Pid | Inout | Udp/Tcp". Some values might not be known (we know a package is tcp-outgoing but can't
    /// figure out an associated process).
    map: HashMap<(Option<Pid>, Option<ConnectionType>, Option<TransportType>), u64>,
}

impl NetStatistics {
    fn add_bytes(&mut self, pid: Option<Pid>, c: Option<ConnectionType>, tt: Option<TransportType>, b: u64) {
        *self.map.entry((pid, c, tt)).or_insert(0) += b;
    }

    /// None for inout type and transport type means "this value can be arbitrary". This is much faster than "get_bytes_by_attr" when map contains many pids.
    fn get_bytes_by_pidopt_and_attr(&self, pid_opt: Option<Pid>, c: Option<ConnectionType>, tt: Option<TransportType>) -> u64 {
        let mut b = 0;
        for &c_attr in [None, Some(ConnectionType::Incoming), Some(ConnectionType::Outgoing)].into_iter() {
            if c != None && c != c_attr { continue }
            for &tt_attr in [None, Some(TransportType::Tcp), Some(TransportType::Udp)].into_iter() {
                if tt != None && tt != tt_attr { continue }

                b += self.map.get(&(pid_opt, c_attr, tt_attr)).map(|&x| x).unwrap_or(0);
            }
        }

        b
    }


    /// None means "this value can be arbitrary".
    fn get_bytes_by_attr(&self, pid: Option<Pid>, c: Option<ConnectionType>, tt: Option<TransportType>) -> u64 {
        self.map.iter()
                .filter(|&(&(kpid, kc, ktt), _)| (pid == None || pid == kpid) && (c == None || c == kc) && (tt == None || tt == ktt))
                .map(|(_, &b)| b)
                .fold(0, |b, acc| b + acc)
    }

    /// Get network usage per pid.
    pub fn get_bytes_by_pid(&self, pid: Pid) -> u64 {
        self.get_bytes_by_pidopt_and_attr(Some(pid), None, None)
    }

    /// Get network usage per pid or if None is used for pid_opt: all traffic that could not be assigned to pid.
    pub fn get_bytes_by_pid_opt(&self, pid_opt: Option<Pid>) -> u64 {
        self.get_bytes_by_pidopt_and_attr(pid_opt, None, None)
    }

    /// Get network usage per transport type (udp/tcp).
    pub fn get_bytes_by_transport_type(&self, tt: TransportType) -> u64 {
        self.get_bytes_by_attr(None, None, Some(tt))
    }

    /// Get network usage per connection type (udp/tcp).
    pub fn get_bytes_by_inout_type(&self, c: ConnectionType) -> u64 {
        self.get_bytes_by_attr(None, Some(c), None)
    }

    /// List all pids which have some data attached.
    pub fn get_all_pids(&self) -> Vec<Pid> {
        let mut pids: Vec<_> = self.map.keys().map(|&(pid_opt, _, _)| pid_opt)
                                                .filter_map(|pid_opt| pid_opt)
                                                .collect();
        pids.sort();
        pids.dedup();
        pids
    }

    /// None as pid means "traffic that could not be assinged to pid".
    /// None for inout_type or transport_type means "can be anything"
    pub fn get_bytes_per_pidopt_iot_tt(&self, pid: Option<Pid>, inout_type: Option<ConnectionType>, transport_type: Option<TransportType>) -> u64 {
        self.get_bytes_by_pidopt_and_attr(pid, inout_type, transport_type)
    }

    /// Get traffic that has direction "inout_type" and is assigned to "pid".
    pub fn get_bytes_per_pid_inout(&self, pid: Pid, inout_type: ConnectionType) -> u64 {
        self.get_bytes_by_pidopt_and_attr(Some(pid), Some(inout_type), None)
    }

    /// Get traffic that has specified transport type (udp/tcp) and is assigned to "pid".
    pub fn get_bytes_per_pid_ttype(&self, pid: Pid, tt: TransportType) -> u64 {
        self.get_bytes_by_pidopt_and_attr(Some(pid), None, Some(tt))
    }

    /// Total number of bytes that can't be assigned to pid.
    pub fn get_unassigned_bytes(&self) -> u64 {
        self.map.iter().filter(|&(&(pid_opt, _, _), _)| pid_opt.is_none()).fold(0, |acc, (_, bytes)| acc + bytes)
    }

    /// Total number of bytes that can be assigned to a pid.
    pub fn get_assigned_bytes(&self) -> u64 {
        self.map.iter().filter(|&(&(pid_opt, _, _), _)| pid_opt.is_some()).fold(0, |acc, (_, bytes)| acc + bytes)
    }

    /// Total number of bytes.
    pub fn get_total(&self) -> u64 {
        self.map.values().fold(0, |acc, bytes| acc + bytes)
    }
}

/// Current state of a thread (used for signaling between two threads).
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
enum ThreadState {
    /// Thread was not started.
    Inactive,

    /// Thread got signal to stop (but might be still running).
    Stopping,

    /// Thread is running.
    Running,

    // / Thread failed.
    //Dead
}

/// This structure allows you to group network traffic by pid.
#[allow(missing_debug_implementations)] // TODO
pub struct Netinfo {
    capture_handle: Arc<Mutex<CaptureHandle>>,

    packet_matcher: Arc<Mutex<PacketMatcher>>,

    /// This will be updated by the closure which is given to PacketCapture.
    statistics: Arc<Mutex<NetStatistics>>,

    thread_handle_opt: Option<JoinHandle<()>>,
    refresh_thread_opt: Option<JoinHandle<()>>,

    refresh_thread_state: Arc<Mutex<ThreadState>>,
}

impl Netinfo {
    /// Lists all non-loopback, active (= up and runnig) network interfaces
    pub fn list_net_interfaces() -> Vec<NetworkInterface> {
        CaptureHandle::list_net_interfaces()
    }

    /// Constructor for Netinfo.
    pub fn new(interface: NetworkInterface) -> Result<Netinfo> {
        // These variables are shared between the Netinfo object and the closure in CaptureHandle.
        let packet_matcher = Arc::new(Mutex::new(PacketMatcher::new()));
        let statistics = Arc::new(Mutex::new(NetStatistics::default()));
        let packet_handler_closure = {
            // copy required fields
            let mut statistics = statistics.clone();
            let mut packet_matcher = packet_matcher.clone();

            // The closure which redirects packet to Self::handle_packet().
            // This closure will be called every time a packet is captured by CaptureHandle.
            move |packet_info: PacketInfo| {
                /// TODO: let error bubble up in CaptureHandle
                Self::handle_packet(&mut packet_matcher, &mut statistics, packet_info).unwrap()
            }
        };

        Ok(Netinfo {
            capture_handle:
                Arc::new(Mutex::new(CaptureHandle::new(interface,
                                                       packet_handler_closure)?)),
            packet_matcher: packet_matcher,
            statistics: statistics,
            thread_handle_opt: None,
            refresh_thread_opt: None,
            refresh_thread_state: Arc::new(Mutex::new(ThreadState::Inactive)),
        })
    }

    fn handle_packet(packet_matcher: &mut Arc<Mutex<PacketMatcher>>,
                     statistics: &mut Arc<Mutex<NetStatistics>>,
                     packet_info: PacketInfo) -> Result<()> {
        let pid_opt = {
            packet_matcher.lock().unwrap().find_pid(packet_info.clone())?
        };
        statistics.lock().unwrap().add_bytes(pid_opt, packet_info.inout_type, Some(packet_info.transport_type), packet_info.datalen);
        Ok(())
    }

    /// Returns the statistics about traffic since last clear.
    pub fn get_net_statistics(&self) -> NetStatistics {
        self.statistics.lock().unwrap().clone()
    }

    /// Resets the statistics.
    pub fn clear(&mut self) {
        *self.statistics.lock().unwrap() = NetStatistics::default();
    }

    /// Refresh internal tables. This should be done in small time intervals (about 100ms). Every connection that is
    /// opened and closed within such an interval __can not be associated with an pid__. Calling this function too often
    /// will increase CPU usage.
    pub fn refresh(&mut self) -> Result<()> {
        self.packet_matcher.lock().unwrap().refresh()
    }

    /// Interval in which "refresh()" will automatically be called. "duration" as None means stopping the thread.
    pub fn set_autorefresh_interval(&mut self, duration: Option<Duration>) {
        if let Some(join_handle) = self.refresh_thread_opt.take() {
            *self.refresh_thread_state.lock().unwrap() = ThreadState::Stopping;
            join_handle.join().unwrap();
            *self.refresh_thread_state.lock().unwrap() = ThreadState::Inactive;
        }

        // only stop thread - do not start one
        let duration = if let Some(duration) = duration { duration } else { return };

        *self.refresh_thread_state.lock().unwrap() = ThreadState::Running;

        // clone shared object to send them to the thread
        let packet_matcher = self.packet_matcher.clone();
        let thread_state = self.refresh_thread_state.clone();

        // start thread
        self.refresh_thread_opt = Some(thread::spawn(move || {
            loop {
                // stop when told to do so
                if *thread_state.lock().unwrap() != ThreadState::Running { break }

                // refresh connection-to-pid map in "duration" intervals
                packet_matcher.lock().unwrap().refresh().unwrap();
                sleep(duration);
            }
        }));
    }

    /// Start capture in current thread. This function will block until an error occurs (may take a LOOOONG time).
    pub fn start(&mut self) -> Result<()> {
        self.capture_handle.lock().unwrap().handle_packets()
    }

    /// Start capture in different thread. This function will not block.
    pub fn start_async(&mut self) {
        let capture_handle = self.capture_handle.clone();
        self.thread_handle_opt = Some(thread::spawn(move || {
            capture_handle.lock().unwrap().handle_packets().unwrap();
        }));
    }
}
