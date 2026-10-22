//! Console host: inspection actions do not load credentials or open a session.
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
    let config = matches.get_one::<String>("config").expect("default config");
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
        println!("NAME\tMAC\tUP\tIPv4");
        for interface in device::get_all_interfaces() {
            let ips = interface
                .ips
                .iter()
                .filter(|ip| ip.is_ipv4())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            println!(
                "{}\t{}\t{}\t{}",
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
        let data = std::fs::read(path).map_err(
            |_| "Cannot read status file; configure --status-file when starting the client",
        )?;
        let status: serde_json::Value =
            serde_json::from_slice(&data).map_err(|_| "Invalid status file")?;
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
        let data = std::fs::read_to_string(path).map_err(|_| "Cannot read local log file")?;
        let lines: Vec<_> = data.lines().rev().take(200).collect();
        for line in lines.into_iter().rev() {
            println!("{line}");
        }
        return Ok(());
    }
    let settings = Settings::from_matches(&matches)?;
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
    if settings.check_config {
        println!("Configuration is valid.");
        return Ok(());
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| "Cannot start asynchronous runtime")?;
    runtime.block_on(async move {
        let (stop, receiver) = watch::channel(false);
        let control_name = settings.control_pipe.clone();
        let client = client::run(settings, receiver);
        tokio::pin!(client);
        tokio::select! {
            result = &mut client => result,
            signal = async {
                tokio::select! { result = shutdown_signal() => result, result = drcom4scut::control::wait(control_name.as_deref()) => result }
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
