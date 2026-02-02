use anyhow::{bail, Result};
use std::io;

use crate::protocol::ETH_P_PAE;

pub struct RawSocket {
    fd: libc::c_int,
    ifindex: libc::c_int,
    mac: [u8; 6],
}

impl RawSocket {
    /// Open an AF_PACKET / SOCK_RAW socket bound to `interface`, filtering for
    /// EtherType 0x888E (802.1X).
    pub fn new(interface: &str) -> Result<Self> {
        if interface.len() >= libc::IFNAMSIZ {
            bail!("interface name too long (max {} bytes)", libc::IFNAMSIZ - 1);
        }

        // ---- create socket ------------------------------------------------
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (ETH_P_PAE as u16).to_be() as libc::c_int,
            )
        };
        if fd < 0 {
            bail!(
                "failed to create raw socket (need CAP_NET_RAW): {}",
                io::Error::last_os_error()
            );
        }

        // Helper: close fd and return error
        macro_rules! fail {
            ($fmt:expr $(, $arg:expr)*) => {{
                unsafe { libc::close(fd); }
                bail!($fmt $(, $arg)*)
            }};
        }

        // ---- build ifreq with interface name ------------------------------
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        for (i, &b) in interface.as_bytes().iter().enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }

        // ---- get interface index ------------------------------------------
        if unsafe { libc::ioctl(fd, libc::SIOCGIFINDEX as libc::c_ulong, &mut ifr) } < 0 {
            fail!(
                "ioctl SIOCGIFINDEX on '{}': {}",
                interface,
                io::Error::last_os_error()
            );
        }
        let ifindex: libc::c_int =
            unsafe { *(&ifr.ifr_ifru as *const _ as *const libc::c_int) };

        // ---- get hardware (MAC) address -----------------------------------
        if unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR as libc::c_ulong, &mut ifr) } < 0 {
            fail!(
                "ioctl SIOCGIFHWADDR on '{}': {}",
                interface,
                io::Error::last_os_error()
            );
        }
        let mut mac = [0u8; 6];
        unsafe {
            let sa = &*(&ifr.ifr_ifru as *const _ as *const libc::sockaddr);
            for i in 0..6 {
                mac[i] = sa.sa_data[i] as u8;
            }
        }

        // ---- bind to the interface ----------------------------------------
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (ETH_P_PAE as u16).to_be();
        sll.sll_ifindex = ifindex;

        if unsafe {
            libc::bind(
                fd,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        } < 0
        {
            fail!("bind: {}", io::Error::last_os_error());
        }

        // ---- set receive timeout (5 s) ------------------------------------
        let tv = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        Ok(RawSocket { fd, ifindex, mac })
    }

    pub fn mac(&self) -> &[u8; 6] {
        &self.mac
    }

    pub fn set_mac(&mut self, mac: [u8; 6]) {
        self.mac = mac;
    }

    #[allow(dead_code)]
    pub fn ifindex(&self) -> libc::c_int {
        self.ifindex
    }

    /// Send a raw Ethernet frame.
    pub fn send(&self, frame: &[u8]) -> Result<()> {
        let ret =
            unsafe { libc::send(self.fd, frame.as_ptr() as *const libc::c_void, frame.len(), 0) };
        if ret < 0 {
            bail!("send: {}", io::Error::last_os_error());
        }
        Ok(())
    }

    /// Receive a raw Ethernet frame.  Returns `Ok(None)` on timeout.
    pub fn recv(&self, buf: &mut [u8]) -> Result<Option<usize>> {
        let ret =
            unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock
                || err.kind() == io::ErrorKind::TimedOut
            {
                return Ok(None);
            }
            bail!("recv: {}", err);
        }
        Ok(Some(ret as usize))
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}
