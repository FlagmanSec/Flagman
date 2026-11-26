//! Writes classic `.pcap` files, byte by byte.
//!
//! Used by tests to create small captures. The format is simple:
//! a 24-byte file header, then for each packet a 16-byte record header
//! followed by the captured bytes. All numbers are little-endian here.
//! Reference: <https://www.tcpdump.org/manpages/pcap-savefile.5.html>

use flagman_core::time::Timestamp;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

pub struct RecordedPacket {
    pub ts: Timestamp,
    /// Original size on the wire.
    pub wire_len: u32,
    /// The bytes that were captured (may be shorter than `wire_len`).
    pub data: Vec<u8>,
}

/// Writes `packets` to `path`. `link_type` is a LINKTYPE number (1 = Ethernet).
pub fn write_pcap(path: &Path, link_type: u32, packets: &[RecordedPacket]) -> io::Result<()> {
    let mut out = BufWriter::new(File::create(path)?);
    out.write_all(&0xa1b2_c3d4u32.to_le_bytes())?; // magic number, microsecond timestamps
    out.write_all(&2u16.to_le_bytes())?; // format version 2.4
    out.write_all(&4u16.to_le_bytes())?;
    out.write_all(&0i32.to_le_bytes())?; // time zone offset (always 0)
    out.write_all(&0u32.to_le_bytes())?; // timestamp accuracy (always 0)
    out.write_all(&65_535u32.to_le_bytes())?; // snapshot length
    out.write_all(&link_type.to_le_bytes())?;
    for packet in packets {
        let millis = packet.ts.millis();
        let seconds = u32::try_from(millis.div_euclid(1_000)).unwrap_or(0);
        let micros = u32::try_from(millis.rem_euclid(1_000) * 1_000).unwrap_or(0);
        let captured = u32::try_from(packet.data.len()).unwrap_or(u32::MAX);
        out.write_all(&seconds.to_le_bytes())?;
        out.write_all(&micros.to_le_bytes())?;
        out.write_all(&captured.to_le_bytes())?;
        out.write_all(&packet.wire_len.to_le_bytes())?;
        out.write_all(&packet.data)?;
    }
    out.flush()
}
