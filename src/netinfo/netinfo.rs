use netinfo::{Pid, PacketInfo, CaptureHandle, PacketMatcher, InoutType, TransportType, NetworkInterface, StopRequest};
use pnet::datalink::NetworkInterface as PnetNetworkInterface;
use std::sync::Arc;
use std::sync::Mutex;
use std::collections::HashMap;
use std::thread;
use std::thread::{JoinHandle};
use netinfo::error::*;

#[derive(Clone, Debug, Default)]
/// Contains detailed information on network usage on per attribute (pid, in/out, tcp/udp).
pub struct NetStatistics {
    /// Usage per "Pid | Inout | Udp/Tcp". Some values might not be known (we know a package is tcp-outgoing but can't
    /// figure out an associated process).
    map: HashMap<(Option<Pid>, Option<InoutType>, Option<TransportType>), u64>,
}

impl NetStatistics {
    fn add_bytes(&mut self, pid: Option<Pid>, c: Option<InoutType>, tt: Option<TransportType>, b: u64) {
        *self.map.entry((pid, c, tt)).or_insert(0) += b;
    }

    /// None means "this value can be arbitrary".
    fn get_bytes_by_filter(&self, pid: Option<Pid>, c: Option<InoutType>, tt: Option<TransportType>) -> u64 {
        self.map.iter()
                .filter(|&(&(kpid, kc, ktt), _)| (pid == None || pid == kpid) && (c == None || c == kc) && (tt == None || tt == ktt))
                .map(|(_, &b)| b)
                .fold(0, |b, acc| b + acc)
    }

    /// Get network usage per pid.
    pub fn get_bytes_by_pid(&self, pid: Pid) -> u64 {
        self.get_bytes_by_attr(Some(pid), None, None)
    }

    /// Get network usage per transport type (udp/tcp).
    pub fn get_bytes_by_transport_type(&self, tt: TransportType) -> u64 {
        self.get_bytes_by_filter(None, None, Some(tt))
    }

    /// Get network usage per inout type (udp/tcp).
    pub fn get_bytes_by_inout_type(&self, i: InoutType) -> u64 {
        self.get_bytes_by_filter(None, Some(i), None)
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
    pub fn get_bytes_by_attr(&self, pid: Option<Pid>, inout_type: Option<InoutType>, transport_type: Option<TransportType>) -> u64 {
        let mut b = 0;
        for &io_attr in [None, Some(InoutType::Incoming), Some(InoutType::Outgoing)].into_iter() {
            if inout_type != None && inout_type != io_attr { continue }
            for &tt_attr in [None, Some(TransportType::Tcp), Some(TransportType::Udp)].into_iter() {
                if transport_type != None && transport_type != tt_attr { continue }

                b += self.map.get(&(pid, io_attr, tt_attr)).map(|&x| x).unwrap_or(0);
            }
        }

        b
    }

    /// Total number of bytes that couldn't be assigned to pid.
    pub fn get_unassigned_bytes(&self) -> u64 {
        self.get_bytes_by_attr(None, None, None)
    }

    /// Total number of bytes that can be assigned to a pid.
    pub fn get_assigned_bytes(&self) -> u64 {
        self.map.iter().filter(|&(&(pid_opt, _, _), _)| pid_opt.is_some()).fold(0, |acc, (_, bytes)| acc + bytes)
    }

    /// Total number of bytes.
    /// Some packets might dropped if they can't be handled fast enough. So this "total" value
    /// (and every other value) might not be the real value if CPU is working to capacity.
    ///
    /// Please use the information from the kernel for that purpose.
    pub fn get_total(&self) -> u64 {
        self.map.values().fold(0, |acc, bytes| acc + bytes)
    }
}

/// This structure allows you to group network traffic by pid.
#[allow(missing_debug_implementations)] // TODO
pub struct Netinfo {
    capture_handle: Arc<Mutex<CaptureHandle>>,

    /// This will be updated by the closure which is given to PacketCapture.
    statistics: Arc<Mutex<NetStatistics>>,

    /// will be set by `start*()` and `stop()`
    stop_request: Arc<Mutex<StopRequest>>,

    /// will be set by `start_async()` and `stop()`
    thread_error: Arc<Mutex<Option<Error>>>,

    thread_handle_opt: Option<JoinHandle<()>>,
}

impl Netinfo {
    /// Lists all non-loopback, active (= up and runnig) network interfaces
    pub fn list_net_interfaces() -> Result<Vec<NetworkInterface>> {
        Ok(CaptureHandle::list_net_interfaces().into_iter().map(|i| NetworkInterface::from(i)).collect())
    }

    /// Constructor for Netinfo. WARNING: this function will only handle the first NetworkInterface -
    /// tracking multiple interfaces at the same time will be implemented in the future. Until then
    /// this signature is there for API stability.
    pub fn new(interfaces: &[NetworkInterface]) -> Result<Netinfo> {
        // These variables are shared between the Netinfo object and the closure in CaptureHandle.
        let packet_matcher = Arc::new(Mutex::new(PacketMatcher::new()));
        let statistics = Arc::new(Mutex::new(NetStatistics::default()));
        let stop_request = Arc::new(Mutex::new(StopRequest::Continue));
        let packet_handler_closure = {
            // copy required fields
            let mut statistics = statistics.clone();
            let mut packet_matcher = packet_matcher.clone();
            let stop_request = stop_request.clone();

            // The closure which redirects packet to Self::handle_packet().
            // This closure will be called every time a packet is captured by CaptureHandle.
            move |packet_info: PacketInfo| -> Result<StopRequest> {
                Self::handle_packet(&mut packet_matcher, &mut statistics, packet_info)?;
                Ok(*stop_request.lock().unwrap())
            }
        };

        // convert from newtype to original type that libpnet can use
        let pnet_interfaces: Vec<PnetNetworkInterface> = interfaces.iter().map(|i| PnetNetworkInterface::from(i.clone())).collect();

        Ok(Netinfo {
            capture_handle:
                Arc::new(Mutex::new(CaptureHandle::new(&pnet_interfaces[0],
                                                       packet_handler_closure)?)),
            stop_request: stop_request,
            thread_error: Arc::new(Mutex::new(None)),
            statistics: statistics,
            thread_handle_opt: None,
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
    pub fn get_net_statistics(&self) -> Result<NetStatistics> {
        Ok(self.statistics.lock().unwrap().clone())
    }

    /// Resets the statistics.
    pub fn clear(&mut self) -> Result<()> {
        *self.statistics.lock().unwrap() = NetStatistics::default();
        Ok(())
    }

    /// Start capture in current thread. This function will block until an error occurs (may take a LOOOONG time). The error is then output with the
    /// return.
    pub fn start(&mut self) -> Result<()> {
        *self.stop_request.lock().unwrap() = StopRequest::Continue;
        self.capture_handle.lock().unwrap().handle_packets()
    }

    /// Stop capture in whether it was started by `start()` or `start*()` (function may be called from a different thread). Note that `start()` will
    /// not immediately unblock and the worker thread created by `start_async()` is not immediately ended - instead they will both stop on the next
    /// packet capture (this is due to a limitation in the packet capture library - as soon as it has non-blocking packet capturing this can be resolved).
    pub fn stop(&mut self) -> Result<()> {
        *self.stop_request.lock().unwrap() = StopRequest::Stop;
        Ok(())
    }

    /// Return the possible errors of the worker thread started by `start_async()`. Since there is no notification when errors occur (e.g. `get_net_statistics()` still resturns `Ok(())`), please check on this
    /// value regularly and before restarting a a new worker thread (check for `Ok(Some(some_error))`). A returned error means that the worker thread stopped.
    ///
    /// By calling this function, the error is cleared (so a subsequent call will return `None` if no other error occured in a new thread).
    ///
    /// The `Result` is there for general error handling, the enclosed `Option<Error>` is the actual return value.
    pub fn pop_thread_error(&mut self) -> Result<Option<Error>> {
        Ok(self.thread_error.lock().unwrap().take())
    }

    /// Start capture in different thread. This function will not block.
    ///
    /// Note: Starting a new thread while the old thread prior a `stop()` or `pop_thread_error()` with `Some(error)` results in
    /// undefined behavior.
    pub fn start_async(&mut self) -> Result<()> {
        *self.stop_request.lock().unwrap() = StopRequest::Continue;

        let capture_handle = self.capture_handle.clone();
        let thread_error = self.thread_error.clone();
        self.thread_handle_opt = Some(thread::spawn(move || {
            let result: Result<()> = capture_handle.lock().unwrap().handle_packets();

            // write errors but do not replace an `error` with `no error`
            if let Err(e) = result {
                *thread_error.lock().unwrap() = Some(e);
            }
        }));

        Ok(())
    }
}
