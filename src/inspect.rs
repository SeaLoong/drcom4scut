//! Bounded local inspection, including files rotated while a command is reading.
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::Path,
};

const MAX_STATUS_BYTES: u64 = 16 * 1024;
const MAX_LOG_TAIL_BYTES: u64 = 1024 * 1024;

fn open_regular(path: &Path, label: &str) -> Result<(File, u64), String> {
    if !fs::metadata(path)
        .map_err(|_| format!("Cannot inspect {label}"))?
        .is_file()
    {
        return Err(format!("{label} must be a regular file"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // The path may become a FIFO after the metadata check. Never wait for
        // a writer; validate the opened handle before reading any bytes.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| format!("Cannot open {label}"))?;
    let metadata = file
        .metadata()
        .map_err(|_| format!("Cannot inspect {label}"))?;
    if !metadata.is_file() {
        return Err(format!("{label} must be a regular file"));
    }
    Ok((file, metadata.len()))
}

pub(crate) fn status(path: &Path) -> Result<serde_json::Value, String> {
    let (file, size) = open_regular(path, "status file")?;
    if size > MAX_STATUS_BYTES {
        return Err("Status file exceeds the 16 KiB size limit".into());
    }
    let mut data = Vec::new();
    file.take(MAX_STATUS_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|_| "Cannot read status file")?;
    if data.len() as u64 > MAX_STATUS_BYTES {
        return Err("Status file exceeds the 16 KiB size limit".into());
    }
    serde_json::from_slice(&data).map_err(|_| "Invalid status file".into())
}

pub(crate) fn logs(path: &Path) -> Result<Vec<String>, String> {
    let (mut file, size) = open_regular(path, "local log")?;
    let start = size.saturating_sub(MAX_LOG_TAIL_BYTES);
    // One preceding byte distinguishes a complete first line from a partial
    // line, including a UTF-8 character split at the tail boundary.
    let offset = start.saturating_sub(1);
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| "Cannot seek local log")?;
    let mut data = Vec::new();
    file.take(size - offset)
        .read_to_end(&mut data)
        .map_err(|_| "Cannot read local log")?;
    let retained = if start == 0 {
        data.as_slice()
    } else {
        let first = data
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or("No complete log line fits within the 1 MiB tail limit")?;
        if first + 1 == data.len() {
            return Err("No complete log line fits within the 1 MiB tail limit".into());
        }
        &data[first + 1..]
    };
    let text = std::str::from_utf8(retained).map_err(|_| "Local log must contain UTF-8 text")?;
    let mut lines = text
        .lines()
        .rev()
        .take(200)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    lines.reverse();
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn status_accepts_json_but_rejects_oversized_or_invalid_input_without_echoing_it() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(br#"{"schema":1,"phase":"online"}"#).unwrap();
        assert_eq!(status(file.path()).unwrap()["phase"], "online");
        file.as_file_mut().set_len(MAX_STATUS_BYTES + 1).unwrap();
        assert_eq!(
            status(file.path()).unwrap_err(),
            "Status file exceeds the 16 KiB size limit"
        );
        fs::write(file.path(), "synthetic-private-invalid-status").unwrap();
        assert_eq!(status(file.path()).unwrap_err(), "Invalid status file");
    }

    #[test]
    fn log_tail_preserves_order_blank_lines_and_crlf_without_reading_the_whole_file() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.as_file_mut().set_len(64 * 1024 * 1024).unwrap();
        file.seek(SeekFrom::End(0)).unwrap();
        writeln!(file).unwrap();
        for line in 0..250 {
            write!(file, "event-{line}\r\n").unwrap();
        }
        let tail = logs(file.path()).unwrap();
        assert_eq!(tail.len(), 200);
        assert_eq!(tail.first().unwrap(), "event-50");
        assert_eq!(tail.last().unwrap(), "event-249");
        fs::write(file.path(), "first\n\nlast\n").unwrap();
        assert_eq!(logs(file.path()).unwrap(), ["first", "", "last"]);
    }

    #[test]
    fn log_tail_omits_a_partial_utf8_line_and_bounds_a_single_huge_line() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            file.path(),
            "界".repeat(400_000) + "\nretained-α\nretained-β\n",
        )
        .unwrap();
        assert_eq!(logs(file.path()).unwrap(), ["retained-α", "retained-β"]);
        fs::write(file.path(), vec![b'x'; MAX_LOG_TAIL_BYTES as usize + 10]).unwrap();
        assert!(logs(file.path()).unwrap_err().contains("1 MiB"));
        OpenOptions::new()
            .append(true)
            .open(file.path())
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        assert!(logs(file.path()).unwrap_err().contains("1 MiB"));
    }

    #[test]
    fn inspection_rejects_directories_and_accepts_empty_logs() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            status(directory.path())
                .unwrap_err()
                .contains("regular file")
        );
        assert!(logs(directory.path()).unwrap_err().contains("regular file"));
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(logs(file.path()).unwrap().is_empty());
    }
}
