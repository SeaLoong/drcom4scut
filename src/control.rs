//! Private GUI control transport. It carries only a stop request, never secrets.
use std::path::Path;
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

/// Keep Unix endpoints short enough for Darwin's sockaddr_un and unambiguous.
/// Ownership and permissions are checked again before connecting to the server.
pub fn validate_socket_path(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::path::Component;
        let bytes = path.as_os_str().as_bytes();
        if !path.is_absolute()
            || bytes.len() > 103
            || bytes.contains(&0)
            || path.file_name().is_none()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        {
            return Err("Invalid private GUI control socket path".into());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err("Private GUI control sockets require Unix".into())
    }
}

#[cfg(unix)]
fn validate_socket_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    validate_socket_path(path)?;
    // SAFETY: geteuid has no arguments or borrowed resources.
    let user = unsafe { libc::geteuid() };
    let parent = path
        .parent()
        .ok_or("Invalid private GUI control socket path")?;
    let directory = std::fs::symlink_metadata(parent)
        .map_err(|_| "Cannot inspect private GUI control directory")?;
    let socket =
        std::fs::symlink_metadata(path).map_err(|_| "Cannot inspect private GUI control socket")?;
    if !directory.is_dir() || directory.uid() != user || directory.mode() & 0o777 != 0o700 {
        return Err("GUI control directory must belong to the current user with mode 0700".into());
    }
    if !socket.file_type().is_socket() || socket.uid() != user || socket.mode() & 0o777 != 0o600 {
        return Err("GUI control socket must belong to the current user with mode 0600".into());
    }
    Ok(())
}

/// The GUI owns a private Unix-domain listener. A stop request or parent EOF
/// initiates the same bounded logout as Ctrl-C; no TCP port or secret is used.
pub async fn wait_socket(path: Option<&Path>) -> Result<(), String> {
    let Some(path) = path else {
        return std::future::pending().await;
    };
    validate_socket_path(path)?;
    #[cfg(unix)]
    {
        use tokio::{io::AsyncReadExt, net::UnixStream};
        validate_socket_permissions(path)?;
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            UnixStream::connect(path),
        )
        .await
        .map_err(|_| "Private GUI control socket connection timed out")?
        .map_err(|_| "Cannot connect private GUI control socket")?;
        // Verify the connected process as well as the endpoint's filesystem ACL.
        // SAFETY: geteuid does not access pointers or retain resources.
        if stream
            .peer_cred()
            .map_err(|_| "Cannot verify private GUI control peer")?
            .uid()
            != unsafe { libc::geteuid() }
        {
            return Err("Private GUI control peer belongs to another user".into());
        }
        let mut message = [0u8; 5];
        match stream.read_exact(&mut message).await {
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
    #[cfg(not(unix))]
    {
        Err("Private GUI control sockets require Unix".into())
    }
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

    #[cfg(unix)]
    mod unix {
        use super::*;
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        use std::path::PathBuf;
        use tokio::{io::AsyncWriteExt, net::UnixListener};

        struct Endpoint(PathBuf);
        impl Endpoint {
            fn new() -> Self {
                // Darwin's default TMPDIR can exceed sockaddr_un's 104 bytes.
                let directory =
                    Path::new("/tmp").join(format!("d4s-test-{:032x}", rand::random::<u128>()));
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&directory)
                    .unwrap();
                Self(directory)
            }
            fn path(&self) -> PathBuf {
                self.0.join("c.sock")
            }
            fn listen(&self) -> UnixListener {
                let listener = UnixListener::bind(self.path()).unwrap();
                std::fs::set_permissions(self.path(), std::fs::Permissions::from_mode(0o600))
                    .unwrap();
                listener
            }
        }
        impl Drop for Endpoint {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        #[test]
        fn unix_control_rejects_relative_traversing_and_overlong_paths() {
            assert!(validate_socket_path(Path::new("/tmp/d4s-test/c.sock")).is_ok());
            for path in [
                "relative/c.sock".to_owned(),
                "/tmp/../c.sock".into(),
                format!("/tmp/{}", "a".repeat(110)),
                "/tmp/bad\0socket".into(),
            ] {
                assert!(validate_socket_path(Path::new(&path)).is_err(), "{path:?}");
            }
        }

        #[tokio::test]
        async fn unix_control_stop_and_parent_eof_request_graceful_shutdown() {
            for stop in [true, false] {
                let endpoint = Endpoint::new();
                let listener = endpoint.listen();
                let path = endpoint.path();
                let (result, ()) = tokio::join!(wait_socket(Some(&path)), async {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    if stop {
                        stream.write_all(b"stop\n").await.unwrap();
                    }
                });
                assert_eq!(result, Ok(()));
            }
        }

        #[tokio::test]
        async fn unix_control_rejects_a_shared_directory_or_socket() {
            let endpoint = Endpoint::new();
            let _listener = endpoint.listen();
            let path = endpoint.path();
            std::fs::set_permissions(&endpoint.0, std::fs::Permissions::from_mode(0o750)).unwrap();
            assert!(wait_socket(Some(&path)).await.unwrap_err().contains("0700"));
            std::fs::set_permissions(&endpoint.0, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
            assert!(wait_socket(Some(&path)).await.unwrap_err().contains("0600"));
        }

        #[tokio::test]
        async fn unix_control_rejects_files_symlinks_and_unknown_messages() {
            let endpoint = Endpoint::new();
            let path = endpoint.path();
            std::fs::write(&path, b"not a socket").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(wait_socket(Some(&path)).await.is_err());
            std::fs::remove_file(&path).unwrap();
            let listener = endpoint.listen();
            let link = endpoint.0.join("link.sock");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(wait_socket(Some(&link)).await.is_err());
            let (result, ()) = tokio::join!(wait_socket(Some(&path)), async {
                let (mut stream, _) = listener.accept().await.unwrap();
                stream.write_all(b"oops\n").await.unwrap();
            });
            assert!(
                result
                    .unwrap_err()
                    .contains("Invalid private GUI control request")
            );
        }
    }
}
