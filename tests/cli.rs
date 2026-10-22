//! Process-level regression tests exercise the real CLI without raw sockets,
//! campus credentials or access to external services.
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "drcom4scut-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn command(dir: &TempDir) -> Command {
    let mut command = if let Some(runner) = std::env::var_os("DRCOM_TEST_RUNNER") {
        let mut command = Command::new(runner);
        command.arg(env!("CARGO_BIN_EXE_drcom4scut"));
        command
    } else {
        Command::new(env!("CARGO_BIN_EXE_drcom4scut"))
    };
    command.current_dir(dir.path());
    command
}
fn run(dir: &TempDir, args: &[&str]) -> Output {
    command(dir).args(args).output().unwrap()
}
fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
fn config(dir: &TempDir, extra: &str) {
    std::fs::write(
        dir.path().join("config.yml"),
        format!("username: student\npassword: e2e-private-password\nhostname: e2e-pc\n{extra}"),
    )
    .unwrap();
}

#[test]
fn help_and_version_do_not_create_config_or_open_device() {
    let dir = TempDir::new();
    let help = run(&dir, &["--help"]);
    assert!(help.status.success(), "{}", output_text(&help));
    assert!(output_text(&help).contains("--check-config"));
    assert!(output_text(&help).contains("--control-pipe"));
    assert!(output_text(&help).contains("--password-stdin"));
    let version = run(&dir, &["--version"]);
    assert!(version.status.success());
    assert!(output_text(&version).contains(env!("CARGO_PKG_VERSION")));
    assert!(!dir.path().join("config.yml").exists());
}

#[test]
fn first_run_creates_template_and_reports_missing_credentials() {
    let dir = TempDir::new();
    let output = run(&dir, &["--check-config"]);
    assert!(!output.status.success());
    assert!(output_text(&output).contains("Username is REQUIRED"));
    let template = std::fs::read_to_string(dir.path().join("config.yml")).unwrap();
    assert!(template.contains("host: s.scut.edu.cn"));
    assert!(!output_text(&output).contains("panicked"));
}

#[test]
fn valid_config_check_needs_no_device_and_does_not_echo_password() {
    let dir = TempDir::new();
    config(&dir, "");
    let before = std::fs::read(dir.path().join("config.yml")).unwrap();
    let output = run(&dir, &["--check-config"]);
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(!output_text(&output).contains("e2e-private-password"));
    assert!(!dir.path().join("logs").exists());
    assert_eq!(
        std::fs::read(dir.path().join("config.yml")).unwrap(),
        before
    );
}

#[test]
fn custom_path_and_legacy_gui_options_are_accepted() {
    let dir = TempDir::new();
    let output = run(
        &dir,
        &[
            "--check-config",
            "-c",
            "custom.yml",
            "-u",
            "student",
            "-p",
            "command-private-password",
            "-m",
            "02:00:00:00:00:01",
            "-i",
            "192.0.2.1",
            "-N",
            "pc",
            "-H",
            "example.test",
            "-t",
            "07:00",
            "-D",
        ],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(dir.path().join("custom.yml").exists());
    assert!(!dir.path().join("config.yml").exists());
    assert!(!output_text(&output).contains("command-private-password"));
}

#[test]
fn malformed_yaml_does_not_print_source_lines_or_panic() {
    let dir = TempDir::new();
    std::fs::write(
        dir.path().join("config.yml"),
        "password: [private-password\n",
    )
    .unwrap();
    let output = run(&dir, &["--check-config"]);
    assert!(!output.status.success());
    assert!(output_text(&output).contains("valid YAML"));
    assert!(!output_text(&output).contains("private-password"));
    assert!(!output_text(&output).contains("panicked"));
}

#[test]
fn invalid_config_is_rejected_before_network_initialization() {
    let dir = TempDir::new();
    for extra in [
        "retry: {interval: -1}",
        "heartbeat: {eap_timeout: 0}",
        "dns: ['[::1]:53']",
        "data: {misc_info: {version: 'zz'}}",
    ] {
        config(&dir, extra);
        let output = run(&dir, &["--check-config"]);
        assert!(!output.status.success(), "{extra}");
        let text = output_text(&output);
        assert!(text.contains("Invalid"), "{text}");
        assert!(!text.contains("panicked"));
        assert!(!text.contains("e2e-private-password"));
    }
}

#[test]
fn private_stdin_secret_is_not_in_args_config_or_output() {
    use std::{io::Write, process::Stdio};
    let dir = TempDir::new();
    let mut child = command(&dir)
        .args([
            "--check-config",
            "--password-stdin",
            "--username",
            "student",
            "--hostname",
            "pc",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"pipe-only-password  with spaces\r\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(!output_text(&output).contains("pipe-only-password"));
    assert!(
        !std::fs::read_to_string(dir.path().join("config.yml"))
            .unwrap()
            .contains("pipe-only-password")
    );
}

#[test]
fn stdin_rejects_empty_multiline_overlong_or_non_utf8_values() {
    use std::{io::Write, process::Stdio};
    let dir = TempDir::new();
    for value in [
        Vec::new(),
        b"one\ntwo\n".to_vec(),
        vec![b'a'; 4099],
        vec![0xff],
    ] {
        let mut child = command(&dir)
            .args([
                "--check-config",
                "--password-stdin",
                "--username",
                "student",
                "--hostname",
                "pc",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&value).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(!output_text(&output).contains("panicked"));
    }
}

#[test]
fn password_file_is_relative_to_config_and_never_echoed() {
    let dir = TempDir::new();
    std::fs::create_dir(dir.path().join("nested")).unwrap();
    let secret = dir.path().join("nested/secret");
    std::fs::write(&secret, "file-only-password\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(
        dir.path().join("nested/client.yml"),
        "username: student\npassword_file: secret\nhostname: pc\n",
    )
    .unwrap();
    let output = run(&dir, &["--check-config", "-c", "nested/client.yml"]);
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(!output_text(&output).contains("file-only-password"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(secret, std::fs::Permissions::from_mode(0o644)).unwrap();
        let output = run(&dir, &["--check-config", "-c", "nested/client.yml"]);
        assert!(!output.status.success());
        assert!(output_text(&output).contains("private permissions"));
    }
}

#[test]
fn inspection_and_initialization_do_not_need_account_data() {
    let dir = TempDir::new();
    let interfaces = run(&dir, &["--list-interfaces"]);
    assert!(interfaces.status.success());
    assert!(output_text(&interfaces).contains("NAME"));
    assert!(!dir.path().join("config.yml").exists());
    let template = run(&dir, &["init"]);
    assert!(template.status.success(), "{}", output_text(&template));
    assert!(dir.path().join("config.yml").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(dir.path().join("config.yml"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }
}

#[test]
fn doctor_returns_a_regular_prerequisite_result_without_credentials() {
    let dir = TempDir::new();
    let output = run(&dir, &["doctor"]);
    assert!(
        matches!(output.status.code(), Some(0 | 1)),
        "doctor must return an ordinary result: {}",
        output_text(&output)
    );
    assert!(output_text(&output).contains("diagnostics (no authentication)"));
    assert!(output_text(&output).contains("capture="));
    assert!(!dir.path().join("config.yml").exists());
}
