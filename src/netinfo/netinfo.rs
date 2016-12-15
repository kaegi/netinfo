use netinfo::{Pid, PacketInfo, CaptureHandle, PacketMatcher, InoutType, TransportType, NetworkInterface, StopRequest};
use pnet::datalink::NetworkInterface as PnetNetworkInterface;
use std::sync::Arc;
use std::sync::Mutex;
use std::collections::HashMap;
use std::thread;
use std::thread::{JoinHandle};
use netinfo::error::*;

#[derive(Clone, Debug)]
/// Contains detailed information on network usage on per attribute (pid, in/out, tcp/udp).
pub struct NetStatistics {
    /// Usage per "Pid | Inout | Udp/Tcp". Some values might not be known (we know a package is tcp-outgoing but can't
    /// figure out an associated process).
    map: HashMap<(Option<Pid>, Option<InoutType>, Option<TransportType>), u64>,
}

impl NetStatistics {
    fn new() -> NetStatistics {
        NetStatistics { map: HashMap::new() }
    }

    fn merge(net_stats: &[NetStatistics]) -> NetStatistics {
        let mut res = NetStatistics::new();
        for stat in net_stats {
            for (key, bytes) in &stat.map {
                *res.map.entry(*key).or_insert(0) += *bytes;
            }
        }
        res
    }

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

// this makes the multi-threaded types more readable
type Shared<T> = Arc<Mutex<T>>;
fn new_shared<T>(t: T) -> Shared<T> { Arc::new(Mutex::new(t)) }

pub struct PacketCaptureUnit {
    stop_request: Shared<StopRequest>,
    statistics: Shared<NetStatistics>,
    capture_handle: Shared<CaptureHandle>,
    thread_handle_opt: Option<JoinHandle<()>>,

    /// will be set by `start_async()` and `stop()`
    thread_error: Shared<Option<Error>>,
}

impl PacketCaptureUnit {
    /// Handle a PacketInfo: try to find PID for packet with PacketMatcher, then add the length to
    /// the right entry in the network statistics.
    fn handle_packet(packet_matcher: &mut Shared<PacketMatcher>,
                     statistics: &mut Shared<NetStatistics>,
                     packet_info: PacketInfo) -> Result<()> {
        let pid_opt = {
            packet_matcher.lock().unwrap().find_pid(packet_info.clone())?
        };
        statistics.lock().unwrap().add_bytes(pid_opt, packet_info.inout_type, Some(packet_info.transport_type), packet_info.datalen);
        Ok(())
    }

    /// Creates a fresh capture closure which will be called every time a packet is captured.
    /// This closure only calls Self::handle_packet().
    fn get_capture_closure(stop_request: &mut Shared<StopRequest>,
                        statistics: &mut Shared<NetStatistics>,
                        packet_matcher: &mut Shared<PacketMatcher>)
                        -> Box<FnMut(PacketInfo) -> Result<StopRequest> + Send> {
        let mut packet_matcher = packet_matcher.clone();
        let mut statistics = statistics.clone();
        let stop_request = stop_request.clone();

        // This closure will be called every time a packet is captured by CaptureHandle.
        let closure = move |packet_info: PacketInfo| -> Result<StopRequest> {
            Self::handle_packet(&mut packet_matcher, &mut statistics, packet_info)?;
            Ok(*stop_request.lock().unwrap())
        };

        Box::new(closure)
    }

    /// Create a new CaptureUnit for a specific NetworkInterface. Since the packet matcher does not
    /// contain network interface specific information, it is shared among all capture units.
    fn new(packet_matcher: &mut Shared<PacketMatcher>, i: &PnetNetworkInterface) -> Result<PacketCaptureUnit> {

        // copy required fields
        let mut stop_request = new_shared(StopRequest::Continue);
        let mut statistics = new_shared(NetStatistics::new());

        // The closure which redirects packet to Self::handle_packet().
        let boxed_closure = Self::get_capture_closure(&mut stop_request, &mut statistics, packet_matcher);

        // the capture handle which provides the capturing for one network interface
        let capture_handle = new_shared(CaptureHandle::new(i, boxed_closure)?);

        Ok(PacketCaptureUnit {
            capture_handle: capture_handle,
            statistics: statistics,
            stop_request: stop_request,
            thread_handle_opt: None,
            thread_error: new_shared(None)
        })
    }

    /// Get a fresh copy of the network statistics of this capture unit.
    fn get_net_statistics(&self) -> Result<NetStatistics> {
        Ok(self.statistics.lock().unwrap().clone())
    }

    /// Clear network statistics of this capture unit.
    fn clear(&self) -> Result<()> {
        *self.statistics.lock().unwrap() = NetStatistics::new();
        Ok(())
    }

    /// Request that thread is stopped. Note that the worker threads is not immediately stopped - instead they will stop on the next
    /// packet capture (this is due to a limitation in the packet capture library - as soon as it has non-blocking packet capturing this can be resolved).
    fn stop(&mut self) -> Result<()> {
        *self.stop_request.lock().unwrap() = StopRequest::Stop;
        Ok(())
    }

    fn start(&mut self) -> Result<()> {

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

    fn pop_thread_error(&mut self) -> Result<Option<Error>> {
        Ok(self.thread_error.lock().unwrap().take())
    }
}

/// This structure allows you to group network traffic by pid.
#[allow(missing_debug_implementations)] // TODO
pub struct Netinfo {
    // all network interfaces this Netinfo-object captures on
    network_interfaces: Vec<PnetNetworkInterface>,

    // there is only one packet matcher for all threads because the information
    // are from /proc/net/tcp, which gives information NOT by network interface
    packet_matcher: Shared<PacketMatcher>,

    // this vector contains a capture unit for each network inteface
    units: Vec<PacketCaptureUnit>,


}

impl Netinfo {
    /// Lists all non-loopback, active (= up and runnig) network interfaces
    pub fn list_net_interfaces() -> Result<Vec<NetworkInterface>> {
        Ok(CaptureHandle::list_net_interfaces().into_iter().map(|i| NetworkInterface::from(i)).collect())
    }

    /// Constructor for Netinfo. A Netinfo object can handle multple network interfaces at the same time.
    pub fn new(interfaces: &[NetworkInterface]) -> Result<Netinfo> {
        Ok(Netinfo {
            packet_matcher: new_shared(PacketMatcher::new()),
            network_interfaces: interfaces.iter().map(|i| PnetNetworkInterface::from(i.clone())).collect(),
            units: Vec::new(),
        })
    }

    /// Get a new batch of CaptureUnits - one for each network interfaces.
    fn get_new_capture_units(&mut self) -> Result<Vec<PacketCaptureUnit>> {
        // request for all old PacketCaptureUnits to be stopped
        let mut capture_units: Vec<PacketCaptureUnit> = Vec::new();
        let network_interfaces = self.network_interfaces.clone();
        for i in &network_interfaces { capture_units.push(PacketCaptureUnit::new(&mut self.packet_matcher, i)?); }

        Ok(capture_units)
    }

    /// Start capture in different thread for each network interface. This function will not block.
    ///
    /// Calling start() will automatically call stop() beforehand, so the old worker threads are automatically killed (see `stop()` for more information).
    pub fn start(&mut self) -> Result<()> {
        // stop "old" units (might still be running in background until next packet is provided by libpnet)
        self.stop()?;

        // recreate units
        self.units = self.get_new_capture_units()?;
        self.units.iter_mut().map(|u| u.start()).collect::<Result<Vec<()>>>()?;

        Ok(())
    }

    /// Stop capture in all threads.
    ///
    /// Note that the internal worker threads are not immediately ended - instead they will stop on the next
    /// packet capture (this is due to a limitation in the packet capture library - as soon as it has non-blocking packet capturing this can be resolved).
    /// Unless you do work that requires detailed thread information, you can safely ignore this implementation detail.
    pub fn stop(&mut self) -> Result<()> {
        self.units.iter_mut().map(|u| u.stop()).collect::<Result<Vec<()>>>()?;
        Ok(())
    }

    /// Return the possible errors of the worker threads. Since there is no notification when errors occur (e.g. `get_net_statistics()` still resturns `Ok(())`), please check on this
    /// value regularly. A returned error means that at least one worker thread has stopped.
    ///
    /// By calling this function, the errors are popped (so a subsequent call will return an empty vector if no other error occured in other thread).
    ///
    /// The `Result` is there for general error handling, the enclosed `Vec<Error>` is the actual return value.
    pub fn pop_thread_errors(&mut self) -> Result<Vec<Error>> {
        let temp = self.units.iter_mut().map(|u| u.pop_thread_error()).collect::<Result<Vec<Option<Error>>>>()?;
        Ok(temp.into_iter().filter_map(|err_opt| err_opt).collect())
    }

    /// Returns the statistics about traffic since last clear.
    pub fn get_net_statistics(&self) -> Result<NetStatistics> {
        let net_stats: Result<Vec<NetStatistics>> = self.units.iter().map(|u| u.get_net_statistics()).collect();
        Ok(NetStatistics::merge(&net_stats?))
    }

    /// Resets the statistics.
    pub fn clear(&mut self) -> Result<()> {
        self.units.iter_mut().map(|u| u.clear()).collect::<Result<Vec<()>>>()?;
        Ok(())
    }

}

/// Automatically stop threads when `Netinfo` object gets dropped/goes out of scope.
impl Drop for Netinfo {
    fn drop(&mut self) {
        self.stop().unwrap()
    }
}
