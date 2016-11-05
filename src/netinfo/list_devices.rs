use libc::{getifaddrs, freeifaddrs, ifaddrs, IFF_UP, IFF_RUNNING, IFF_LOOPBACK};
use std::ptr::null_mut;
use std::ffi::CStr;
use std::os::raw::c_uint;

/// Pcaps Device::list() returns many non-network devices (usb, bluetooth) but we only want to capture network interfaces


/// Test flags whether device is running
fn is_running(flags: c_uint) -> bool {
  !(flags & IFF_LOOPBACK as c_uint != 0) && (flags & IFF_UP as c_uint != 0) && (flags & IFF_RUNNING as c_uint != 0)
}

/// List all network interfaces by Tuple (name, is_running)
pub fn list_network() -> Result<Vec<(String, bool)>, ()> {
    unsafe {
        let mut ifaddrs: *mut ifaddrs = null_mut();
        if getifaddrs(&mut ifaddrs as *mut *mut ifaddrs) != 0 { return Err(()); }

        let mut devices = Vec::new();
        let mut ifa = ifaddrs;
        while ifa != null_mut() {
            let devname = CStr::from_ptr((*ifa).ifa_name).to_string_lossy().into_owned();
            devices.push((devname, is_running((*ifa).ifa_flags)));
            ifa = (*ifa).ifa_next;
        }


        freeifaddrs(ifaddrs);

        Ok(devices)
    }
}
