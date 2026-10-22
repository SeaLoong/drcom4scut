//! Private GUI control transport. It carries only a stop request, never secrets.
#[cfg(windows)]
use std::time::Duration;

pub fn validate_name(name: &str) -> Result<(), String> {
    let suffix = name
        .strip_prefix(r"\\.\pipe\drcom4scut-")
        .ok_or("Invalid private control pipe name")?;
    if suffix.len() < 16
        || suffix.len() > 80
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("Invalid private control pipe name".into());
    }
    Ok(())
}

/// GUI owns a CurrentUserOnly server; EOF also stops the core when its parent
/// crashes. No global named event or predictable process-wide stop handle exists.
pub async fn wait(name: Option<&str>) -> Result<(), String> {
    let Some(name) = name else {
        return std::future::pending().await;
    };
    validate_name(name)?;
    #[cfg(windows)]
    {
        use tokio::{
            io::AsyncReadExt,
            net::windows::named_pipe::ClientOptions,
            time::{Instant, sleep},
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut pipe = loop {
            match ClientOptions::new().read(true).write(false).open(name) {
                Ok(pipe) => break pipe,
                Err(error)
                    if matches!(error.raw_os_error(), Some(2 | 231))
                        && Instant::now() < deadline =>
                {
                    sleep(Duration::from_millis(25)).await
                }
                Err(_) => return Err("Cannot connect private GUI control pipe".into()),
            }
        };
        let mut message = [0u8; 5];
        match pipe.read_exact(&mut message).await {
            Ok(_) if &message == b"stop\n" => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                Ok(())
            }
            _ => Err("Invalid private GUI control request".into()),
        }
    }
    #[cfg(not(windows))]
    {
        Err("Private GUI control pipes require Windows".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_scoped_random_control_pipe_names() {
        assert!(validate_name(r"\\.\pipe\drcom4scut-12345678-1234-5678-1234-567812345678").is_ok());
        for invalid in [
            r"\\server\pipe\drcom4scut-1234567812345678",
            r"\\.\pipe\another-1234567812345678",
            r"\\.\pipe\drcom4scut-short",
            r"\\.\pipe\drcom4scut-1234567812345678\nested",
        ] {
            assert!(validate_name(invalid).is_err());
        }
    }
}
