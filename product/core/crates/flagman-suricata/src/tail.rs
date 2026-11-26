//! Following a log file while another program appends to it (like `tail -F`).
//!
//! Suricata's log gets rotated (renamed and recreated) by logrotate. When the
//! file is replaced or truncated, the tailer starts again at the beginning of
//! the new file.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// A line longer than this is not a valid EVE event; it is skipped.
const MAX_LINE_BYTES: usize = 1024 * 1024;
/// Lines returned per call at most, so one call never blocks for long.
const MAX_LINES_PER_READ: usize = 10_000;

pub struct EveTailer {
    path: PathBuf,
    reader: Option<BufReader<File>>,
    /// Identity of the open file, to notice when it is replaced.
    file_id: Option<u64>,
    position: u64,
    /// The start of a line whose end has not been written yet.
    partial: String,
    start_at_end: bool,
}

impl EveTailer {
    /// `start_at_end`: skip what is already in the file (live mode), or read
    /// it all (replaying an old log).
    pub fn new(path: &Path, start_at_end: bool) -> EveTailer {
        EveTailer {
            path: path.to_path_buf(),
            reader: None,
            file_id: None,
            position: 0,
            partial: String::new(),
            start_at_end,
        }
    }

    /// Returns the complete lines appended since the last call.
    pub fn read_new_lines(&mut self) -> io::Result<Vec<String>> {
        let metadata = fs::metadata(&self.path)?;
        let replaced = self.reader.is_some()
            && (file_id(&metadata) != self.file_id || metadata.len() < self.position);
        if self.reader.is_none() || replaced {
            // The first open honours `start_at_end`; a replaced file is read from its start.
            let skip_existing = self.reader.is_none() && self.start_at_end;
            self.open(skip_existing)?;
        }
        let Some(reader) = self.reader.as_mut() else {
            return Ok(Vec::new());
        };

        let mut lines = Vec::new();
        let mut buffer = String::new();
        while lines.len() < MAX_LINES_PER_READ {
            buffer.clear();
            let read = reader.read_line(&mut buffer)?;
            if read == 0 {
                break;
            }
            self.position += read as u64;
            if !buffer.ends_with('\n') {
                // Suricata is still writing this line: keep it for next time.
                self.partial.push_str(&buffer);
                if self.partial.len() > MAX_LINE_BYTES {
                    self.partial.clear();
                }
                break;
            }
            let mut line = std::mem::take(&mut self.partial);
            line.push_str(buffer.trim_end_matches(['\n', '\r']));
            if line.len() <= MAX_LINE_BYTES {
                lines.push(line);
            }
        }
        Ok(lines)
    }

    fn open(&mut self, skip_existing: bool) -> io::Result<()> {
        let mut file = File::open(&self.path)?;
        let metadata = file.metadata()?;
        self.position = if skip_existing {
            file.seek(SeekFrom::End(0))?
        } else {
            0
        };
        self.file_id = file_id(&metadata);
        self.partial.clear();
        self.reader = Some(BufReader::new(file));
        Ok(())
    }
}

#[cfg(unix)]
fn file_id(metadata: &fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.ino())
}

#[cfg(not(unix))]
fn file_id(_metadata: &fs::Metadata) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn append(path: &Path, text: &str) {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        file.write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn returns_only_complete_new_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eve.json");
        append(&path, "old line\n");
        let mut tailer = EveTailer::new(&path, true);
        assert!(
            tailer.read_new_lines().unwrap().is_empty(),
            "existing content is skipped"
        );

        append(&path, "first\nsec");
        assert_eq!(tailer.read_new_lines().unwrap(), vec!["first"]);
        append(&path, "ond\n");
        assert_eq!(tailer.read_new_lines().unwrap(), vec!["second"]);
    }

    #[test]
    fn starts_over_when_the_file_is_rotated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eve.json");
        append(&path, "a\nb\n");
        let mut tailer = EveTailer::new(&path, false);
        assert_eq!(tailer.read_new_lines().unwrap(), vec!["a", "b"]);

        fs::rename(&path, dir.path().join("eve.json.1")).unwrap();
        append(&path, "c\n");
        assert_eq!(tailer.read_new_lines().unwrap(), vec!["c"]);
    }

    #[test]
    fn a_missing_file_is_an_error_that_can_be_retried() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eve.json");
        let mut tailer = EveTailer::new(&path, true);
        assert!(tailer.read_new_lines().is_err());
        append(&path, "x\n");
        assert!(tailer.read_new_lines().unwrap().is_empty());
        append(&path, "y\n");
        assert_eq!(tailer.read_new_lines().unwrap(), vec!["y"]);
    }
}
