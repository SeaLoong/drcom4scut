//! Console host: inspection actions do not load credentials or open a session.
mod inspect;

use drcom4scut::{
    client, device,
    settings::{self, Settings},
};
use tokio::sync::watch;

fn main() -> std::process::ExitCode {
    match dispatch() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("drcom4scut: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn dispatch() -> Result<(), String> {
    let matches = settings::command().get_matches();
    validate_action(&matches)?;
    let config = matches.get_one::<String>("config").expect("default config");
    if matches.get_flag("update") || matches.get_flag("check-update") {
        let options = Settings::update_from_matches(&matches)?.options();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|_| "Cannot start update runtime")?;
        return runtime.block_on(async {
            if matches.get_flag("update") {
                match drcom4scut::update::apply_latest(&options)
                    .await
                    .map_err(|error| error.to_string())?
                {
                    drcom4scut::update::UpdateOutcome::UpToDate => {
                        println!("drcom4scut is up to date ({}).", env!("CARGO_PKG_VERSION"));
                    }
                    drcom4scut::update::UpdateOutcome::Updated {
                        version,
                        restart_required,
                    } => {
                        if restart_required {
                            println!("Installed drcom4scut {version}. Restart drcom4scut to use it.");
                        } else {
                            println!("Installed drcom4scut {version}. Start drcom4scut again to use it.");
                        }
                    }
                }
            } else {
                match drcom4scut::update::check_latest(&options)
                    .await
                    .map_err(|error| error.to_string())?
                {
                    Some(release) => println!(
                        "New drcom4scut version {} is available. Run drcom4scut --update to install.",
                        release.version
                    ),
                    None => println!("drcom4scut is up to date ({}).", env!("CARGO_PKG_VERSION")),
                }
            }
            Ok(())
        });
    }
    if matches.get_flag("service-run") {
        return drcom4scut::service::dispatch();
    }
    for (flag, action) in [
        ("service-install", "install"),
        ("service-start", "start"),
        ("service-stop", "stop"),
        ("service-status", "status"),
        ("service-uninstall", "uninstall"),
    ] {
        if matches.get_flag(flag) {
            if action == "install"
                && (matches.get_flag("password-stdin")
                    || matches.get_one::<String>("password").is_some()
                    || matches.get_one::<String>("password-file").is_some())
            {
                return Err("Service installation uses credentials from protected --config; CLI password options are not registered".into());
            }
            println!(
                "{}",
                drcom4scut::service::manage(action, std::path::Path::new(config))?
            );
            return Ok(());
        }
    }
    if matches.get_flag("list-interfaces") {
        let interfaces = device::get_all_interfaces();
        let name_width = interfaces
            .iter()
            .map(|interface| interface.name.chars().count())
            .max()
            .unwrap_or(0)
            .max("NAME".len());
        println!("{:<name_width$}  {:<17}  {:<5}  IPv4", "NAME", "MAC", "UP");
        for interface in interfaces {
            let ips = interface
                .ips
                .iter()
                .filter(|ip| ip.is_ipv4())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            println!(
                "{:<name_width$}  {:<17}  {:<5}  {}",
                interface.name,
                interface.mac.map(|mac| mac.to_string()).unwrap_or_default(),
                interface.is_up(),
                ips
            );
        }
        return Ok(());
    }
    if matches.get_flag("init-config") || matches.subcommand_name() == Some("init") {
        Settings::read_config(config)?;
        println!(
            "Configuration template available at {config}. Store passwords in a private password_file."
        );
        return Ok(());
    }
    if matches.get_flag("doctor") || matches.subcommand_name() == Some("doctor") {
        return doctor(&matches);
    }
    if matches.subcommand_name() == Some("status") {
        let path = matches
            .get_one::<String>("status-file")
            .ok_or("status requires --status-file PATH")?;
        let status = inspect::status(std::path::Path::new(path))?;
        println!(
            "{}",
            serde_json::to_string_pretty(&status).map_err(|_| "Invalid status file")?
        );
        return Ok(());
    }
    if matches.subcommand_name() == Some("logs") {
        let cfg = Settings::read_config(config)?;
        let directory = cfg
            .get_string("log.file_directory")
            .unwrap_or_else(|_| "./logs".into());
        let path = std::path::Path::new(&directory).join("latest.log");
        for line in inspect::logs(&path)? {
            println!("{line}");
        }
        return Ok(());
    }
    let settings = Settings::from_matches(&matches)?;
    if settings.check_config {
        println!("Configuration is valid.");
        return Ok(());
    }
    if settings.logoff && settings.mode == settings::Mode::Eap {
        let device = std::sync::Arc::new(
            device::get_device_on(settings.interface.as_deref(), settings.mac, settings.ip)
                .map_err(|error| format!("Cannot open capture: {error}"))?,
        );
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|_| "Cannot start runtime")?;
        return runtime.block_on(async {
            let (auth, _) = watch::channel(drcom4scut::util::ChannelData::stopped());
            let process = drcom4scut::eap::Process::new(&settings, device, auth);
            tokio::time::timeout(std::time::Duration::from_secs(1), process.logoff())
                .await
                .map_err(|_| "Logoff timed out".to_owned())?
                .map_err(|error| format!("Logoff failed: {error}"))
        });
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| "Cannot start asynchronous runtime")?;
    runtime.block_on(async move {
        let (stop, receiver) = watch::channel(false);
        let control_name = settings.control_pipe.clone();
        let control_socket = settings.control_socket.clone();
        let client = client::run(settings, receiver);
        tokio::pin!(client);
        tokio::select! {
            result = &mut client => result,
            signal = async {
                tokio::select! {
                    result = shutdown_signal() => result,
                    result = drcom4scut::control::wait(control_name.as_deref()) => result,
                    result = drcom4scut::control::wait_socket(control_socket.as_deref()) => result,
                }
            } => {
                stop.send_replace(true);
                let result = tokio::time::timeout(std::time::Duration::from_secs(3), &mut client).await
                    .map_err(|_| "Client shutdown timed out".to_owned())?;
                signal?;
                result
            }
        }
    })
}

/// Resolve aliases before acting so a diagnostic command cannot accidentally
/// manage a service, log out, or open capture through a second action flag.
fn validate_action(matches: &clap::ArgMatches) -> Result<(), String> {
    let subcommand = matches.subcommand_name();
    let actions = [
        matches.get_flag("list-interfaces"),
        matches.get_flag("doctor") || subcommand == Some("doctor"),
        matches.get_flag("init-config") || subcommand == Some("init"),
        matches.get_flag("check-config"),
        matches.get_flag("update"),
        matches.get_flag("check-update"),
        subcommand == Some("status"),
        subcommand == Some("logs"),
        // Checking a logout configuration is intentionally credential-free and
        // performs only validation, just as checking a login configuration does.
        matches.get_flag("logoff") && !matches.get_flag("check-config"),
        matches.get_flag("service-run"),
        matches.get_flag("service-install"),
        matches.get_flag("service-start"),
        matches.get_flag("service-stop"),
        matches.get_flag("service-status"),
        matches.get_flag("service-uninstall"),
    ];
    if actions.into_iter().filter(|enabled| *enabled).count() > 1 {
        return Err("Choose one client action per command; run inspection, update and service operations separately".into());
    }
    Ok(())
}

async fn shutdown_signal() -> Result<(), String> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate =
            signal(SignalKind::terminate()).map_err(|_| "Cannot listen for SIGTERM")?;
        tokio::select! { result = tokio::signal::ctrl_c() => result.map_err(|_| "Cannot listen for Ctrl-C".to_owned()), _ = terminate.recv() => Ok(()) }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|_| "Cannot listen for Ctrl-C".to_owned())
    }
}

fn doctor(matches: &clap::ArgMatches) -> Result<(), String> {
    println!(
        "drcom4scut {} diagnostics (no authentication)",
        env!("CARGO_PKG_VERSION")
    );
    let interfaces = device::get_all_interfaces();
    for interface in &interfaces {
        println!(
            "interface={} up={} mac={} ipv4={}",
            interface.name,
            interface.is_up(),
            interface.mac.map(|mac| mac.to_string()).unwrap_or_default(),
            interface
                .ips
                .iter()
                .filter(|ip| ip.is_ipv4())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    let selected = matches.get_one::<String>("interface");
    let mac = matches
        .get_one::<String>("mac")
        .map(|value| value.parse())
        .transpose()
        .map_err(|_| "Invalid MAC address")?;
    let ip = matches
        .get_one::<String>("ip")
        .map(|value| value.parse())
        .transpose()
        .map_err(|_| "Invalid IP address")?;
    match device::get_device_on(selected.map(String::as_str), mac, ip) {
        Ok(device) => println!(
            "capture=ok selected={} source={}",
            device.interface.name, device.ip_net
        ),
        Err(error) => {
            println!("capture=unavailable: {error}");
            println!(
                "Install Npcap on Windows; on Unix grant capture permissions (CAP_NET_RAW). Ensure the selected Ethernet adapter has IPv4."
            );
            return Err("Capture prerequisite check failed".into());
        }
    }
    println!(
        "Campus EAP/UDP authorization has not been attempted. Use --check-config for private configuration validation."
    );
    Ok(())
}
