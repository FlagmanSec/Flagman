//! Live capture from a network interface through libpcap.
//!
//! Opening an interface needs the `CAP_NET_RAW` capability (and
//! `CAP_NET_ADMIN` for promiscuous mode). The systemd unit in
//! `product/deploy/linux` grants exactly those two, and nothing else.

use crate::source::{CaptureError, CaptureStats, Frame, NextFrame, PacketSource, timestamp_of};
use flagman_core::packet::LinkType;
use rustix::event::{PollFd, PollFlags, Timespec};

#[derive(Clone, Debug)]
pub struct LiveOptions {
    pub interface: String,
    /// Bytes captured per packet. 160 bytes hold every header Flagman reads
    /// (Ethernet + IPv6 + TCP with options) and almost no payload, which
    /// protects the privacy of the people on the network.
    pub snaplen: i32,
    /// See every packet on the link, not only those addressed to this machine.
    pub promiscuous: bool,
    /// How long one read waits before returning [`NextFrame::Timeout`].
    pub read_timeout_ms: i32,
    /// Kernel buffer size. Bigger absorbs bursts without dropping packets.
    pub buffer_bytes: i32,
}

impl LiveOptions {
    pub fn for_interface(interface: &str) -> LiveOptions {
        LiveOptions {
            interface: interface.to_string(),
            snaplen: 160,
            promiscuous: true,
            read_timeout_ms: 250,
            buffer_bytes: 8 * 1024 * 1024,
        }
    }
}

/// The capture runs in non-blocking mode, and Flagman waits for packets with
/// `poll()` itself. libpcap's own read timeout is not enough on Linux: it
/// never fires while no packet arrives at all, which would stop timeouts
/// and shutdown on a quiet network.
pub struct LiveSource {
    capture: pcap::Capture<pcap::Active>,
    link: LinkType,
    interface: String,
    wait: Timespec,
    /// The last read found nothing: wait for the socket before reading again.
    must_wait: bool,
}

impl LiveSource {
    pub fn open(options: &LiveOptions) -> Result<LiveSource, CaptureError> {
        let open_error = |error: pcap::Error| CaptureError::Open {
            target: format!("interface {}", options.interface),
            message: error.to_string(),
        };
        let capture = pcap::Capture::from_device(options.interface.as_str())
            .map_err(open_error)?
            .promisc(options.promiscuous)
            .snaplen(options.snaplen)
            .timeout(options.read_timeout_ms)
            .buffer_size(options.buffer_bytes)
            .open()
            .and_then(pcap::Capture::setnonblock)
            .map_err(open_error)?;
        let dlt = capture.get_datalink().0;
        let link = LinkType::from_dlt(dlt).ok_or(CaptureError::UnsupportedLink(dlt))?;
        let wait_ms = i64::from(options.read_timeout_ms.max(1));
        Ok(LiveSource {
            capture,
            link,
            interface: options.interface.clone(),
            wait: Timespec {
                tv_sec: wait_ms / 1_000,
                tv_nsec: (wait_ms % 1_000) * 1_000_000,
            },
            must_wait: true,
        })
    }
}

impl PacketSource for LiveSource {
    fn link_type(&self) -> LinkType {
        self.link
    }

    fn next_frame(&mut self) -> Result<NextFrame<'_>, CaptureError> {
        if self.must_wait {
            let mut fds = [PollFd::new(&self.capture, PollFlags::IN)];
            match rustix::event::poll(&mut fds, Some(&self.wait)) {
                Ok(0) | Err(rustix::io::Errno::INTR) => return Ok(NextFrame::Timeout),
                Ok(_) => self.must_wait = false,
                Err(error) => return Err(CaptureError::Read(error.to_string())),
            }
        }
        match self.capture.next_packet() {
            Ok(packet) => Ok(NextFrame::Packet(Frame {
                ts: timestamp_of(packet.header),
                wire_len: packet.header.len,
                data: packet.data,
            })),
            // Non-blocking mode: nothing to read right now.
            Err(pcap::Error::TimeoutExpired) => {
                self.must_wait = true;
                Ok(NextFrame::Timeout)
            }
            Err(pcap::Error::NoMorePackets) => Ok(NextFrame::End),
            Err(error) => Err(CaptureError::Read(error.to_string())),
        }
    }

    fn stats(&mut self) -> Option<CaptureStats> {
        let stat = self.capture.stats().ok()?;
        Some(CaptureStats {
            received: u64::from(stat.received),
            dropped: u64::from(stat.dropped) + u64::from(stat.if_dropped),
        })
    }

    fn describe(&self) -> String {
        self.interface.clone()
    }
}

/// A network interface, as listed by `flagmand interfaces`.
#[derive(Clone, Debug)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
    pub is_up: bool,
    pub is_loopback: bool,
}

pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, CaptureError> {
    let devices = pcap::Device::list().map_err(|error| CaptureError::Open {
        target: "the interface list".to_string(),
        message: error.to_string(),
    })?;
    Ok(devices
        .into_iter()
        .map(|device| InterfaceInfo {
            addresses: device
                .addresses
                .iter()
                .map(|address| address.addr.to_string())
                .collect(),
            is_up: device.flags.is_up() && device.flags.is_running(),
            is_loopback: device.flags.is_loopback(),
            name: device.name,
            description: device.desc,
        })
        .collect())
}

/// The interface libpcap would pick by default (the first one that is up
/// and not loopback), if any.
pub fn default_interface() -> Option<String> {
    pcap::Device::lookup()
        .ok()
        .flatten()
        .map(|device| device.name)
}
