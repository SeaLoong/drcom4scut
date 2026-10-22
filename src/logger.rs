use crate::settings::Settings;

pub fn init(settings: &Settings) -> Result<(), String> {
    #[cfg(not(feature = "log4rs"))]
    simple_logger::init(settings.debug)?;
    #[cfg(feature = "log4rs")]
    init_log4rs(settings)?;
    Ok(())
}

#[cfg(not(feature = "log4rs"))]
mod simple_logger {
    use log::{LevelFilter, Metadata, Record};

    static LOGGER: SimpleLogger = SimpleLogger;

    pub fn init(debug: bool) -> Result<(), String> {
        log::set_logger(&LOGGER)
            .map(|()| {
                log::set_max_level(if debug {
                    LevelFilter::Debug
                } else {
                    LevelFilter::Info
                })
            })
            .map_err(|_| "Failed to initialize logger".to_owned())
    }

    struct SimpleLogger;

    impl log::Log for SimpleLogger {
        #[inline]
        fn enabled(&self, _: &Metadata) -> bool {
            true
        }
        fn log(&self, record: &Record) {
            let dt = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            let thread_name = std::thread::current()
                .clone()
                .name()
                .unwrap_or("unnamed")
                .to_string();
            println!(
                "[{}][{}][{}] {}",
                dt,
                record.level(),
                thread_name,
                record.args()
            );
        }
        fn flush(&self) {}
    }
}

#[cfg(feature = "log4rs")]
fn init_log4rs(settings: &Settings) -> Result<(), String> {
    if log::LevelFilter::Off == settings.log.level_filter {
        return Ok(());
    }
    use log4rs::{
        append::{
            console::ConsoleAppender,
            rolling_file::{
                RollingFileAppender,
                policy::compound::{
                    CompoundPolicy, roll::fixed_window::FixedWindowRoller,
                    trigger::size::SizeTrigger,
                },
            },
        },
        config::{Appender, Config, Root},
        encode::pattern::PatternEncoder,
    };
    let stdout = if settings.debug || settings.log.enable_console {
        Some(
            ConsoleAppender::builder()
                .encoder(Box::new(PatternEncoder::new(
                    "{h([{d(%Y-%m-%d %H:%M:%S)}][{l}][{T}] {m}{n})}",
                )))
                .build(),
        )
    } else {
        None
    };
    let logfile = if settings.log.enable_file {
        let directory = &settings.log.file_directory;
        Some(
            RollingFileAppender::builder()
                .encoder(Box::new(PatternEncoder::new(
                    "[{d(%Y-%m-%d %H:%M:%S)}][{l}][{T}][{M}:{L}] {m}{n}",
                )))
                .build(
                    directory.clone() + "/latest.log",
                    Box::new(CompoundPolicy::new(
                        Box::new(SizeTrigger::new(1 << 20)),
                        Box::new(
                            FixedWindowRoller::builder()
                                .base(1)
                                .build(&(directory.clone() + "/log-{}.gz"), 10)
                                .map_err(|_| "Cannot configure log rotation".to_owned())?,
                        ),
                    )),
                )
                .map_err(|_| "Cannot open log file".to_owned())?,
        )
    } else {
        None
    };

    if stdout.is_none() && logfile.is_none() {
        return Ok(());
    }

    let mut config = Config::builder();
    let mut root = Root::builder();
    if let Some(stdout) = stdout {
        config = config.appender(Appender::builder().build("stdout", Box::new(stdout)));
        root = root.appender("stdout");
    }
    if let Some(logfile) = logfile {
        config = config.appender(Appender::builder().build("logfile", Box::new(logfile)));
        root = root.appender("logfile");
    }

    let config = config
        .build(root.build(settings.log.level_filter))
        .map_err(|_| "Cannot build log configuration".to_owned())?;

    log4rs::init_config(config).map_err(|_| "Cannot initialize log configuration".to_owned())?;
    Ok(())
}
