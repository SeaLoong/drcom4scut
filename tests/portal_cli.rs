#![cfg(feature = "portal")]
//! Real CLI lifecycle + loopback portal. No capture privileges or real account.
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PASSWORD: &str = "e2e-only-password";
static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "drcom-portal-cli-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, username: Option<&str>, extra: &str) {
        let account = username
            .map(|name| format!("username: '{name}'\n"))
            .unwrap_or_default();
        std::fs::write(self.0.join("config.yml"), format!("{account}hostname: test-pc\nheartbeat: {{udp_timeout: 1}}\nlog: {{enable_console: true, enable_file: false}}\n{extra}")).unwrap();
    }
    fn status(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.0.join("status.json")).unwrap()).unwrap()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Each connection has its own handler so an abandoned periodic status request
/// cannot block the separate shutdown/logout request.
struct PortalMock {
    base: String,
    stop: Arc<AtomicBool>,
    online: Arc<AtomicBool>,
    logins: Arc<AtomicUsize>,
    logouts: Arc<AtomicUsize>,
    queries: Arc<AtomicUsize>,
    #[cfg(unix)]
    pending_check: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<(String, IpAddr)>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl PortalMock {
    fn new(delay_periodic_check: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let online = Arc::new(AtomicBool::new(false));
        let logins = Arc::new(AtomicUsize::new(0));
        let logouts = Arc::new(AtomicUsize::new(0));
        let queries = Arc::new(AtomicUsize::new(0));
        let pending_check = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread = {
            let (stop, online, logins, logouts, queries, pending_check, requests) = (
                stop.clone(),
                online.clone(),
                logins.clone(),
                logouts.clone(),
                queries.clone(),
                pending_check.clone(),
                requests.clone(),
            );
            std::thread::spawn(move || {
                let mut handlers = Vec::new();
                while !stop.load(Ordering::SeqCst) {
                    let (mut stream, peer) = match listener.accept() {
                        Ok(value) => value,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                            continue;
                        }
                        Err(error) => panic!("mock accept failed: {error}"),
                    };
                    let (stop, online, logins, logouts, queries, pending_check, requests) = (
                        stop.clone(),
                        online.clone(),
                        logins.clone(),
                        logouts.clone(),
                        queries.clone(),
                        pending_check.clone(),
                        requests.clone(),
                    );
                    handlers.push(std::thread::spawn(move || {
                        stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                        let mut request = Vec::new();
                        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                            let mut buffer = [0; 1024];
                            match stream.read(&mut buffer) {
                                Ok(0) => return,
                                Ok(size) => request.extend_from_slice(&buffer[..size]),
                                Err(_) => return,
                            }
                            assert!(request.len() < 16384);
                        }
                        let text = String::from_utf8(request).unwrap();
                        let path = text.lines().next().unwrap().split_whitespace().nth(1).unwrap();
                        requests.lock().unwrap().push((path.to_owned(), peer.ip()));
                        let json = if path.starts_with("/drcom/chkstatus?") {
                            r#"{"result":1,"v46ip":"192.0.2.10","olmac":"020000000001"}"#
                        } else if path.starts_with("/eportal/portal/login?") {
                            online.store(true, Ordering::SeqCst);
                            logins.fetch_add(1, Ordering::SeqCst);
                            let parsed = reqwest::Url::parse(&format!("http://localhost{path}")).unwrap();
                            let query: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
                            assert_eq!(query["user_password"], PASSWORD);
                            r#"{"result":1}"#
                        } else if path.starts_with("/eportal/portal/logout?") {
                            online.store(false, Ordering::SeqCst);
                            logouts.fetch_add(1, Ordering::SeqCst);
                            r#"{"result":1}"#
                        } else {
                            assert!(path.starts_with("/eportal/portal/online_list?"));
                            let query = queries.fetch_add(1, Ordering::SeqCst) + 1;
                            if delay_periodic_check && query == 3 {
                                pending_check.store(true, Ordering::SeqCst);
                                let until = Instant::now() + Duration::from_secs(10);
                                while !stop.load(Ordering::SeqCst) && Instant::now() < until {
                                    std::thread::sleep(Duration::from_millis(5));
                                }
                            }
                            if online.load(Ordering::SeqCst) { r#"{"result":1,"list":[{"online_ip":"192.0.2.10","online_mac":"020000000001"}]}"# }
                            else { r#"{"result":1,"list":[]}"# }
                        };
                        let body = format!("drcom4scut({json});");
                        // Broken pipe is expected when a cancelled status request
                        // is abandoned while shutdown uses a new connection.
                        let _ = write!(stream, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
                    }));
                }
                for handler in handlers {
                    handler.join().unwrap();
                }
            })
        };
        Self {
            base,
            stop,
            online,
            logins,
            logouts,
            queries,
            #[cfg(unix)]
            pending_check,
            requests,
            thread: Some(thread),
        }
    }
    fn command(&self, directory: &Directory) -> Command {
        let mut command = executable();
        command.current_dir(&directory.0).args([
            "--mode",
            "portal",
            "--portal-base",
            &self.base,
            "--portal-api",
            &self.base,
            "--allow-insecure-portal",
            "--portal-ac-ip",
            "192.0.2.254",
            "--status-file",
            "status.json",
        ]);
        command
    }
}
impl Drop for PortalMock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
fn executable() -> Command {
    if let Some(runner) = std::env::var_os("DRCOM_TEST_RUNNER") {
        let mut command = Command::new(runner);
        command.arg(env!("CARGO_BIN_EXE_drcom4scut"));
        command
    } else {
        Command::new(env!("CARGO_BIN_EXE_drcom4scut"))
    }
}
struct Process(Option<Child>);
impl Process {
    fn start(mut command: Command, password: Option<&str>) -> Self {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        if let Some(password) = password {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(format!("{password}\n").as_bytes())
                .unwrap();
        } else {
            drop(child.stdin.take());
        }
        Self(Some(child))
    }
    fn finish(mut self) -> Output {
        let child = self.0.as_mut().unwrap();
        let exited = wait_until(Duration::from_secs(15), || {
            child.try_wait().unwrap().is_some()
        });
        if !exited {
            let _ = child.kill();
        }
        let output = self.0.take().unwrap().wait_with_output().unwrap();
        assert!(
            exited,
            "CLI process did not terminate: {}",
            output_text(&output)
        );
        output
    }
    #[cfg(unix)]
    fn terminate(&mut self) {
        unsafe extern "C" {
            fn kill(pid: i32, signal: i32) -> i32;
        }
        let pid = i32::try_from(self.0.as_ref().unwrap().id()).unwrap();
        // SAFETY: pid is the live child owned by this fixture; SIGTERM=15 is the
        // Unix termination signal. No foreign process or pointer is involved.
        assert_eq!(unsafe { kill(pid, 15) }, 0);
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + timeout;
    loop {
        if predicate() {
            return true;
        }
        if Instant::now() > until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
fn assert_private_success(output: &Output) {
    let text = output_text(output);
    assert!(output.status.success(), "{text}");
    assert!(!text.contains(PASSWORD));
}

#[test]
fn once_portal_cli_confirms_the_mock_session_without_exposing_stdin_password() {
    let directory = Directory::new();
    directory.config(Some("test-student"), "");
    let server = PortalMock::new(false);
    let mut command = server.command(&directory);
    command.args(["--password-stdin", "--once"]);
    let output = Process::start(command, Some(PASSWORD)).finish();
    assert_private_success(&output);
    assert!(output_text(&output).contains("Portal authorization confirmed online"));
    assert_eq!(server.logins.load(Ordering::SeqCst), 1);
    assert_eq!(server.queries.load(Ordering::SeqCst), 2);
    let text = std::fs::read_to_string(directory.0.join("status.json")).unwrap();
    assert!(!text.contains(PASSWORD));
    assert!(!text.contains("test-student"));
    assert_eq!(directory.status()["phase"], "online");
}

#[test]
fn portal_logoff_uses_configured_provider_without_credentials_or_capture() {
    let directory = Directory::new();
    let server = PortalMock::new(false);
    server.online.store(true, Ordering::SeqCst);
    directory.config(
        None,
        &format!(
            "mode: portal\nportal: {{base_url: '{}', api_url: '{}', allow_http: true}}\n",
            server.base, server.base
        ),
    );
    let mut command = executable();
    command
        .current_dir(&directory.0)
        .args(["--logoff", "--status-file", "status.json"]);
    let output = Process::start(command, None).finish();
    assert_private_success(&output);
    assert_eq!(server.logins.load(Ordering::SeqCst), 0);
    assert_eq!(server.logouts.load(Ordering::SeqCst), 1);
    assert_eq!(directory.status()["phase"], "offline");
}

#[test]
fn portal_account_length_is_not_limited_by_the_ethernet_wire_field() {
    let directory = Directory::new();
    let account = "test-long-account-with-an-operator-suffix@wifi";
    assert!(account.len() > 25);
    directory.config(Some(account), "");
    let server = PortalMock::new(false);
    let mut command = server.command(&directory);
    command.args(["--password-stdin", "--once"]);
    assert_private_success(&Process::start(command, Some(PASSWORD)).finish());
    let requests = server.requests.lock().unwrap();
    let (path, _) = requests
        .iter()
        .find(|(path, _)| path.starts_with("/eportal/portal/login?"))
        .unwrap();
    let url = reqwest::Url::parse(&format!("http://localhost{path}")).unwrap();
    assert!(
        url.query_pairs()
            .any(|(key, value)| key == "user_account" && value == account)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn portal_cli_binds_real_source_independently_from_authenticated_ip() {
    let directory = Directory::new();
    directory.config(Some("test-student"), "");
    let server = PortalMock::new(false);
    let mut command = server.command(&directory);
    command.args(["--password-stdin", "--once", "--ip", "127.0.0.2"]);
    assert_private_success(&Process::start(command, Some(PASSWORD)).finish());
    let source: IpAddr = "127.0.0.2".parse().unwrap();
    assert!(
        server
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|(_, peer)| *peer == source)
    );
    assert_eq!(directory.status()["local_ip"], "192.0.2.10");
}

#[cfg(unix)]
fn termination_lifecycle(delay_periodic_check: bool) {
    let directory = Directory::new();
    directory.config(Some("test-student"), "hooks:\n  online: ['/bin/sh', 'hook.sh']\n  offline: ['/bin/sh', 'hook.sh']\n  timeout: 2\n");
    std::fs::write(
        directory.0.join("hook.sh"),
        r#"printf '%s:%s:%s\n' "$DRCOM_STATE" "$DRCOM_INTERFACE" "$DRCOM_IP" >>hook-events
"#,
    )
    .unwrap();
    let server = PortalMock::new(delay_periodic_check);
    let mut command = server.command(&directory);
    command.arg("--password-stdin");
    let mut process = Process::start(command, Some(PASSWORD));
    assert!(wait_until(Duration::from_secs(8), || directory
        .0
        .join("hook-events")
        .exists()));
    if delay_periodic_check {
        assert!(wait_until(Duration::from_secs(8), || server
            .pending_check
            .load(Ordering::SeqCst)));
    } else {
        assert_eq!(server.queries.load(Ordering::SeqCst), 2);
    }
    process.terminate();
    let output = process.finish();
    assert_private_success(&output);
    assert_eq!(server.logins.load(Ordering::SeqCst), 1);
    assert_eq!(server.logouts.load(Ordering::SeqCst), 1);
    let status = directory.status();
    assert_eq!(status["phase"], "offline");
    assert_eq!(status["online"], false);
    let hooks = std::fs::read_to_string(directory.0.join("hook-events")).unwrap();
    assert_eq!(
        hooks.lines().collect::<Vec<_>>(),
        ["online:portal:192.0.2.10", "offline:portal:192.0.2.10"]
    );
}

#[cfg(unix)]
#[test]
fn sigterm_while_waiting_for_periodic_check_logs_out_and_runs_offline_hook() {
    termination_lifecycle(false);
}
#[cfg(unix)]
#[test]
fn sigterm_during_pending_http_check_logs_out_and_runs_offline_hook() {
    termination_lifecycle(true);
}
