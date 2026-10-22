//! Explicit local lifecycle hooks. No shell expansion and no credential variables.
use std::{net::IpAddr, process::Stdio, time::Duration};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Hooks {
    pub online: Vec<String>,
    pub offline: Vec<String>,
    pub timeout: u64,
}
impl Default for Hooks {
    fn default() -> Self {
        Self {
            online: Vec::new(),
            offline: Vec::new(),
            timeout: 10,
        }
    }
}

pub async fn run(
    arguments: &[String],
    state: &str,
    interface: &str,
    ip: Option<IpAddr>,
    timeout: u64,
) -> Result<(), String> {
    let Some(executable) = arguments.first() else {
        return Ok(());
    };
    let mut child = tokio::process::Command::new(executable)
        .args(&arguments[1..])
        .env("DRCOM_STATE", state)
        .env("DRCOM_INTERFACE", interface)
        .env("DRCOM_IP", ip.map(|ip| ip.to_string()).unwrap_or_default())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "Cannot start configured lifecycle hook")?;
    let status = match tokio::time::timeout(Duration::from_secs(timeout), child.wait()).await {
        Ok(result) => result.map_err(|_| "Cannot wait for lifecycle hook")?,
        Err(_) => {
            let _ = child.kill().await;
            return Err("Lifecycle hook timed out".into());
        }
    };
    if !status.success() {
        return Err("Lifecycle hook returned a failure status".into());
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn hook_receives_only_declared_connection_metadata() {
        run(&["/bin/sh".into(), "-c".into(), "test \"$DRCOM_STATE\" = online && test \"$DRCOM_INTERFACE\" = eth0 && test \"$DRCOM_IP\" = 192.0.2.3".into()], "online", "eth0", Some("192.0.2.3".parse().unwrap()), 1).await.unwrap();
    }
    #[tokio::test]
    async fn hook_failure_is_reported_without_stderr_or_args() {
        let error = run(
            &[
                "/bin/sh".into(),
                "-c".into(),
                "echo secret-on-stderr >&2; exit 3".into(),
            ],
            "offline",
            "eth0",
            None,
            1,
        )
        .await
        .unwrap_err();
        assert_eq!(error, "Lifecycle hook returned a failure status");
    }
    #[tokio::test]
    async fn hook_timeout_is_bounded() {
        assert_eq!(
            run(
                &["/bin/sleep".into(), "10".into()],
                "offline",
                "eth0",
                None,
                0
            )
            .await
            .unwrap_err(),
            "Lifecycle hook timed out"
        );
    }
}
