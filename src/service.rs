//! Optional Windows Service Control Manager integration.
//!
//! The service runs the same async client as the console. Installation never
//! transmits credentials in argv, starts authentication, or copies secret files.
//! Administrators must first place the executable and configuration under ACLs
//! that prevent an unprivileged user from reading the secret or replacing code.
use std::path::Path;

pub const SERVICE_NAME: &str = "drcom4scut";

/// Enter the blocking SCM dispatcher before creating a console Tokio runtime.
pub fn dispatch() -> Result<(), String> {
    #[cfg(windows)]
    return windows::dispatch();
    #[cfg(not(windows))]
    Err("Windows service mode is available only on Windows".into())
}

/// Manage this service only. `status` describes SCM state, not authentication.
pub fn manage(action: &str, config: &Path) -> Result<String, String> {
    if !matches!(
        action,
        "install" | "start" | "stop" | "status" | "uninstall"
    ) {
        return Err("Unknown service action".into());
    }
    #[cfg(windows)]
    return windows::manage(action, config);
    #[cfg(not(windows))]
    {
        let _ = config;
        Err("Windows service management is available only on Windows".into())
    }
}

#[cfg(any(windows, test))]
fn launch_arguments(config: &Path) -> Result<Vec<std::ffi::OsString>, String> {
    if !config.is_absolute() {
        return Err("Service configuration path must be absolute".into());
    }
    let parent = config
        .parent()
        .ok_or("Service configuration needs a parent directory")?;
    Ok(vec![
        "--service-run".into(),
        "--config".into(),
        config.as_os_str().to_owned(),
        "--status-file".into(),
        parent.join("status.json").into_os_string(),
    ])
}

/// Resolve the effective service credential file without opening it. The main
/// config has already passed the secret-path audit before this parser is used.
/// Match Settings precedence, but forbid interactive/argv secrets in SCM mode.
#[cfg(any(windows, test))]
fn service_password_file(
    config_path: &Path,
    config: &config::Config,
    matches: Option<&clap::ArgMatches>,
) -> Result<Option<std::path::PathBuf>, String> {
    use config::{ConfigError, Value, ValueKind};
    let text = |key: &str| -> Result<Option<String>, String> {
        match config.get::<Value>(key) {
            Err(ConfigError::NotFound(_)) => Ok(None),
            Ok(value) if value.kind == ValueKind::Nil => Ok(None),
            Ok(value) => match value.kind {
                ValueKind::String(value) => Ok(Some(value)),
                _ => Err(format!("Invalid service {key}: expected a string")),
            },
            Err(_) => Err(format!("Invalid service {key}")),
        }
    };
    let password = text("password")?;
    let configured_file = text("password_file")?;
    if password.is_some_and(|password| !password.is_empty()) && configured_file.is_some() {
        return Err(
            "Specify either password or password_file, not both, in service configuration".into(),
        );
    }
    if let Some(matches) = matches {
        if matches.get_flag("password-stdin") {
            return Err("Windows service cannot read a password from standard input".into());
        }
        if matches.get_one::<String>("password").is_some() {
            return Err("Windows service rejects plaintext password arguments; use a protected configuration or password_file".into());
        }
        if let Some(path) = matches.get_one::<String>("password-file") {
            if path.is_empty() {
                return Err("Invalid service password-file path".into());
            }
            let path = Path::new(path);
            // CLI --password-file is relative to the process working directory,
            // exactly as Settings::from_matches reads it. Do not accidentally
            // audit a similarly named file beside the config instead.
            let path = if path.is_absolute() {
                path.to_owned()
            } else {
                std::env::current_dir()
                    .map_err(|_| "Cannot resolve service password-file path")?
                    .join(path)
            };
            if !path.is_absolute() {
                return Err("Service password-file must resolve to an absolute path".into());
            }
            return Ok(Some(path));
        }
    }
    configured_file
        .map(|path| {
            if path.is_empty() {
                return Err("Invalid service password_file path".into());
            }
            let path = Path::new(&path);
            let path = if path.is_absolute() {
                path.to_owned()
            } else {
                config_path
                    .parent()
                    .ok_or("Service configuration needs a parent directory")?
                    .join(path)
            };
            if !path.is_absolute() {
                return Err("Service password_file must resolve to an absolute path".into());
            }
            Ok(path)
        })
        .transpose()
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::ffi::OsString;
    use std::os::windows::fs::MetadataExt;
    use std::path::{Component, PathBuf, Prefix};
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::watch;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
            ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
            ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
        service_dispatcher,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    pub(super) fn dispatch() -> Result<(), String> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .map_err(|error| format!("Cannot enter Windows service dispatcher: {error}"))
    }

    define_windows_service!(ffi_service_main, service_main);

    fn status(state: ServiceState, failed: bool) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(u32::from(failed)),
            checkpoint: u32::from(matches!(
                state,
                ServiceState::StartPending | ServiceState::StopPending
            )),
            wait_hint: if matches!(
                state,
                ServiceState::StartPending | ServiceState::StopPending
            ) {
                Duration::from_secs(10)
            } else {
                Duration::ZERO
            },
            process_id: None,
        }
    }

    fn service_main(_arguments: Vec<OsString>) {
        let (shutdown, receiver) = watch::channel(false);
        let handle_slot = Arc::new(Mutex::new(None::<ServiceStatusHandle>));
        let handler_slot = handle_slot.clone();
        // Register before parsing files or constructing the runtime, so SCM can
        // interrogate the service even if initialization fails.
        let handle = match service_control_handler::register(SERVICE_NAME, move |event| match event
        {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Ok(slot) = handler_slot.lock()
                    && let Some(handle) = *slot
                {
                    let _ = handle.set_service_status(status(ServiceState::StopPending, false));
                }
                shutdown.send_replace(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }) {
            Ok(handle) => handle,
            Err(_) => return,
        };
        if let Ok(mut slot) = handle_slot.lock() {
            *slot = Some(handle);
        }
        let _ = handle.set_service_status(status(ServiceState::StartPending, false));
        let result = run_client(handle, receiver);
        if let Err(ref error) = result {
            log::error!("Windows service stopped: {error}");
        }
        let _ = handle.set_service_status(status(ServiceState::Stopped, result.is_err()));
    }

    #[cfg(feature = "log4rs")]
    fn run_client(
        handle: ServiceStatusHandle,
        receiver: watch::Receiver<bool>,
    ) -> Result<(), String> {
        let matches = crate::settings::command().get_matches();
        let config = matches
            .get_one::<String>("config")
            .ok_or("Service configuration path missing")?;
        let config = Path::new(config);
        let executable = std::env::current_exe().map_err(|_| "Cannot locate service executable")?;
        validate_install_paths(&executable, config, None)?;
        let source = crate::settings::Settings::read_config(
            config
                .to_str()
                .ok_or("Service configuration path must be valid UTF-8")?,
        )?;
        if let Some(password_file) = service_password_file(config, &source, Some(&matches))? {
            validate_install_paths(&executable, config, Some(&password_file))?;
        }
        let mut settings = crate::settings::Settings::from_matches(&matches)?;
        settings.no_log = false;
        let directory = config
            .parent()
            .ok_or("Service configuration needs an absolute parent directory")?;
        // Services start in System32; relative user log paths must never create
        // files there. The checked configuration parent supplies a private root.
        settings.log.file_directory = directory.join("logs").to_string_lossy().into_owned();
        settings.log.enable_file = true;
        settings.log.enable_console = false;
        settings.log.level_filter = log::LevelFilter::Info;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|error| format!("Cannot initialize service runtime: {error}"))?;
        handle
            .set_service_status(status(ServiceState::Running, false))
            .map_err(|error| format!("Cannot report service status: {error}"))?;
        // Running means the supervisor is alive, not that SCUT accepted login.
        runtime.block_on(crate::client::run(settings, receiver))
    }

    #[cfg(not(feature = "log4rs"))]
    fn run_client(_: ServiceStatusHandle, _: watch::Receiver<bool>) -> Result<(), String> {
        Err("Windows service requires the default log4rs feature".into())
    }

    pub(super) fn manage(action: &str, config: &Path) -> Result<String, String> {
        if action == "install" {
            return install(config);
        }
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
                .map_err(|error| format!("Cannot connect to Windows service manager: {error}"))?;
        let access = match action {
            "start" => ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            "stop" => ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
            "uninstall" => ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
            _ => ServiceAccess::QUERY_STATUS,
        };
        let service = manager
            .open_service(SERVICE_NAME, access)
            .map_err(|error| format!("Cannot open {SERVICE_NAME} service: {error}"))?;
        match action {
            "start" => {
                service
                    .start::<&str>(&[])
                    .map_err(|error| format!("Cannot start service: {error}"))?;
                Ok("Service start requested; use --service-status and the private status/log files to check authentication".into())
            }
            "stop" => {
                if service
                    .query_status()
                    .map_err(|error| error.to_string())?
                    .current_state
                    != ServiceState::Stopped
                {
                    service
                        .stop()
                        .map_err(|error| format!("Cannot stop service: {error}"))?;
                }
                Ok("Service stop requested; the client will send a bounded EAPOL-Logoff".into())
            }
            "uninstall" => {
                if service
                    .query_status()
                    .map_err(|error| error.to_string())?
                    .current_state
                    != ServiceState::Stopped
                {
                    return Err("Stop the service and wait for Stopped before uninstalling".into());
                }
                service
                    .delete()
                    .map_err(|error| format!("Cannot uninstall service: {error}"))?;
                Ok(
                    "Service uninstalled; executable, private configuration and logs were retained"
                        .into(),
                )
            }
            _ => {
                let status = service.query_status().map_err(|error| error.to_string())?;
                Ok(format!(
                    "{SERVICE_NAME}: {:?}; SCM state does not establish campus authentication",
                    status.current_state
                ))
            }
        }
    }

    fn install(config: &Path) -> Result<String, String> {
        if !cfg!(feature = "log4rs") {
            return Err("Windows service requires a build with the default log4rs feature".into());
        }
        let config = std::fs::canonicalize(config)
            .map_err(|_| "Cannot resolve service configuration file")?;
        let executable = std::env::current_exe().map_err(|_| "Cannot locate service executable")?;
        validate_install_paths(&executable, &config, None)?;
        let source = crate::settings::Settings::read_config(
            config
                .to_str()
                .ok_or("Service configuration path must be valid UTF-8")?,
        )?;
        if let Some(password_file) = service_password_file(&config, &source, None)? {
            validate_install_paths(&executable, &config, Some(&password_file))?;
        }
        let arguments = launch_arguments(&config)?;
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .map_err(|error| {
            format!("Cannot connect to Windows service manager (Administrator required): {error}")
        })?;
        let info = ServiceInfo {
            name: SERVICE_NAME.into(),
            display_name: "SCUT DrCOM authentication".into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: executable,
            launch_arguments: arguments,
            dependencies: Vec::new(),
            // Raw packet access may require elevation; this is an explicit
            // administrator-installed LocalSystem service, not the GUI account.
            account_name: None,
            account_password: None,
        };
        // Refuse an existing service instead of overwriting an unrelated program.
        let service = manager.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::DELETE)
            .map_err(|error| format!("Cannot install service; an existing registration will not be overwritten: {error}"))?;
        let configure = || -> windows_service::Result<()> {
            service.set_description(
                "SCUT Ethernet EAP/UDP client; see private status file for authentication state",
            )?;
            service.update_failure_actions(ServiceFailureActions {
                reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
                reboot_msg: None,
                command: None,
                actions: Some(vec![
                    ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay: Duration::from_secs(30)
                    };
                    3
                ]),
            })?;
            service.set_failure_actions_on_non_crash_failures(true)
        };
        if let Err(error) = configure() {
            let _ = service.delete();
            return Err(format!(
                "Cannot configure service recovery; registration rolled back: {error}"
            ));
        }
        Ok("Automatic LocalSystem service installed without starting authentication; use --service-start explicitly".into())
    }

    fn validate_install_paths(
        executable: &Path,
        config: &Path,
        password_file: Option<&Path>,
    ) -> Result<(), String> {
        for path in [Some(executable), Some(config), password_file]
            .into_iter()
            .flatten()
        {
            if !path.is_absolute()
                || !matches!(path.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
            {
                return Err("Service files must use absolute local disk paths".into());
            }
            let metadata =
                std::fs::symlink_metadata(path).map_err(|_| "Cannot inspect service files")?;
            if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
                return Err("Service files must be regular files, not reparse points".into());
            }
        }
        // Resolve the system utility using the Windows API, not PATH or a
        // user-controlled SystemRoot. Only fixed script text reaches PowerShell;
        // paths are separate non-secret environment values and used literally.
        let mut system = vec![0u16; 32768];
        let length = unsafe {
            windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
                system.as_mut_ptr(),
                system.len() as u32,
            )
        };
        if length == 0 || length as usize >= system.len() {
            return Err("Cannot locate the trusted Windows system directory".into());
        }
        let system = PathBuf::from(String::from_utf16_lossy(&system[..length as usize]));
        let powershell = system.join("WindowsPowerShell/v1.0/powershell.exe");
        let checked = Command::new(powershell)
            .args(["-NoProfile", "-NonInteractive", "-Command", ACL_AUDIT])
            .env("DRCOM_SERVICE_EXE_PATH", executable)
            .env("DRCOM_SERVICE_CONFIG_PATH", config)
            .env(
                "DRCOM_SERVICE_PASSWORD_PATH",
                password_file.unwrap_or_else(|| Path::new("")),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| "Cannot validate service file permissions")?;
        if !checked.success() {
            return Err("Unsafe service file permissions: executable/config must be Administrator- or SYSTEM-owned, config/password_file readable only by those accounts, and paths protected against replacement; see docs/windows-service.md".into());
        }
        Ok(())
    }

    // Included in the executable: no mutable script file is trusted at runtime.
    // The same policy has native PowerShell descriptor/traversal regression tests.
    const ACL_AUDIT: &str = include_str!("../scripts/audit-service-acl.ps1");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn service_launch_uses_fixed_protocol_and_separate_path_arguments() {
        let config = std::env::temp_dir()
            .join("private configs")
            .join("config.yml");
        let arguments = launch_arguments(&config).unwrap();
        assert_eq!(arguments.len(), 5);
        assert_eq!(arguments[0], "--service-run");
        assert_eq!(arguments[1], "--config");
        assert_eq!(PathBuf::from(&arguments[2]), config);
        assert_eq!(arguments[3], "--status-file");
        assert_eq!(
            PathBuf::from(&arguments[4]),
            config.parent().unwrap().join("status.json")
        );
        assert!(
            !arguments
                .iter()
                .any(|arg| arg == "--password" || arg == "--password-stdin")
        );
    }

    #[test]
    fn relative_service_config_is_never_registered() {
        for path in ["config.yml", "../config.yml", ""] {
            assert!(launch_arguments(Path::new(path)).is_err());
        }
    }

    fn config(source: &str) -> config::Config {
        config::Config::builder()
            .add_source(config::File::from_str(source, config::FileFormat::Yaml))
            .build()
            .unwrap()
    }

    fn command(arguments: &[&str]) -> clap::ArgMatches {
        crate::settings::command()
            .try_get_matches_from(["drcom4scut"].into_iter().chain(arguments.iter().copied()))
            .unwrap()
    }

    #[test]
    fn service_password_file_is_relative_to_its_protected_config() {
        let directory = std::env::temp_dir().join("private-service");
        let config_path = directory.join("config.yml");
        let source = config("password: null\npassword_file: private/password.key");
        assert_eq!(
            service_password_file(&config_path, &source, None).unwrap(),
            Some(directory.join("private/password.key"))
        );
    }

    #[test]
    fn service_cli_file_override_audits_the_actual_selected_source() {
        let config_path = std::env::temp_dir().join("service-config/config.yml");
        let source = config("password_file: ignored.key");
        let matches = command(&["--password-file", "actual.key"]);
        assert_eq!(
            service_password_file(&config_path, &source, Some(&matches)).unwrap(),
            Some(std::env::current_dir().unwrap().join("actual.key"))
        );
        let absolute = std::env::temp_dir().join("absolute-password.key");
        let matches = command(&["--password-file", absolute.to_str().unwrap()]);
        assert_eq!(
            service_password_file(&config_path, &source, Some(&matches)).unwrap(),
            Some(absolute)
        );
    }

    #[test]
    fn service_rejects_interactive_and_plaintext_argv_credentials() {
        let config_path = std::env::temp_dir().join("service-config/config.yml");
        let source = config("password_file: private.key");
        for arguments in [
            vec!["--password-stdin"],
            vec!["--password", "private-value"],
        ] {
            let matches = command(&arguments);
            let error = service_password_file(&config_path, &source, Some(&matches)).unwrap_err();
            assert!(!error.contains("private-value"));
        }
    }

    #[test]
    fn service_rejects_conflicting_or_invalid_configured_secret_sources() {
        let config_path = std::env::temp_dir().join("service-config/config.yml");
        for yaml in [
            "password: private-value\npassword_file: other.key",
            "password_file: 1234",
            "password_file: ''",
            "password: [private-value]",
        ] {
            let error = service_password_file(&config_path, &config(yaml), None).unwrap_err();
            assert!(!error.contains("private-value"));
        }
        assert!(
            service_password_file(&config_path, &config("password: private-value"), None)
                .unwrap()
                .is_none()
        );
        assert!(
            service_password_file(&config_path, &config("password: null"), None)
                .unwrap()
                .is_none()
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_service_commands_fail_without_touching_system_state() {
        assert!(dispatch().unwrap_err().contains("only on Windows"));
        for action in ["install", "start", "stop", "status", "uninstall"] {
            assert!(
                manage(action, Path::new("unused"))
                    .unwrap_err()
                    .contains("only on Windows")
            );
        }
        assert!(
            manage("restart-unknown", Path::new("unused"))
                .unwrap_err()
                .contains("Unknown")
        );
    }
}
