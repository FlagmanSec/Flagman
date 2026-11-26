//! Reading packets from a capture file (`.pcap` or `.pcapng`).
//!
//! Replay mode uses this to analyse a recorded attack exactly as if it were
//! happening live: the packet timestamps drive every timeout.

use crate::source::{CaptureError, CaptureStats, Frame, NextFrame, PacketSource, timestamp_of};
use flagman_core::packet::LinkType;
use std::path::Path;

pub struct FileSource {
    capture: pcap::Capture<pcap::Offline>,
    link: LinkType,
    name: String,
}

impl FileSource {
    pub fn open(path: &Path) -> Result<FileSource, CaptureError> {
        let capture = pcap::Capture::from_file(path).map_err(|error| CaptureError::Open {
            target: path.display().to_string(),
            message: error.to_string(),
        })?;
        let dlt = capture.get_datalink().0;
        let link = LinkType::from_dlt(dlt).ok_or(CaptureError::UnsupportedLink(dlt))?;
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        Ok(FileSource {
            capture,
            link,
            name,
        })
    }
}

impl PacketSource for FileSource {
    fn link_type(&self) -> LinkType {
        self.link
    }

    fn next_frame(&mut self) -> Result<NextFrame<'_>, CaptureError> {
        match self.capture.next_packet() {
            Ok(packet) => Ok(NextFrame::Packet(Frame {
                ts: timestamp_of(packet.header),
                wire_len: packet.header.len,
                data: packet.data,
            })),
            Err(pcap::Error::NoMorePackets) => Ok(NextFrame::End),
            Err(error) => Err(CaptureError::Read(error.to_string())),
        }
    }

    fn stats(&mut self) -> Option<CaptureStats> {
        None
    }

    fn describe(&self) -> String {
        self.name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap_writer::{RecordedPacket, write_pcap};
    use flagman_core::time::Timestamp;

    #[test]
    fn reads_back_the_packets_of_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("two.pcap");
        let packets = vec![
            RecordedPacket {
                ts: Timestamp(1_500),
                wire_len: 60,
                data: vec![0xaa; 60],
            },
            RecordedPacket {
                ts: Timestamp(2_250),
                wire_len: 1_514,
                data: vec![0xbb; 100],
            },
        ];
        write_pcap(&path, 1, &packets).unwrap();

        let mut source = FileSource::open(&path).unwrap();
        assert_eq!(source.link_type(), LinkType::Ethernet);
        assert_eq!(source.describe(), "two.pcap");
        let NextFrame::Packet(first) = source.next_frame().unwrap() else {
            panic!("expected a packet");
        };
        assert_eq!(first.ts, Timestamp(1_500));
        assert_eq!(first.data.len(), 60);
        let NextFrame::Packet(second) = source.next_frame().unwrap() else {
            panic!("expected a packet");
        };
        assert_eq!((second.wire_len, second.data.len()), (1_514, 100));
        assert!(matches!(source.next_frame().unwrap(), NextFrame::End));
    }

    #[test]
    fn a_missing_file_is_a_clear_error() {
        let error = FileSource::open(Path::new("/nonexistent/x.pcap"))
            .err()
            .unwrap();
        assert!(error.to_string().contains("/nonexistent/x.pcap"));
    }
}
