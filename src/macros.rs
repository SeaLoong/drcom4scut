#[cfg(not(feature = "enablelog"))]
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => ({
        eprint!("[{}][{}] ",chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),"TRACE");
        eprintln!($($arg)*);
    });
}
#[cfg(not(feature = "enablelog"))]
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => ({
        eprint!("[{}][{}] ",chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),"DEBUG");
        eprintln!($($arg)*);
    });
}
#[cfg(not(feature = "enablelog"))]
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => ({
        eprint!("[{}][{}] ",chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),"INFO");
        eprintln!($($arg)*);
    });
}
#[cfg(not(feature = "enablelog"))]
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => ({
        eprint!("[{}][{}] ",chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),"WARN");
        eprintln!($($arg)*);
    });
}
#[cfg(not(feature = "enablelog"))]
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => ({
        eprint!("[{}][{}] ",chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),"ERROR");
        eprintln!($($arg)*);
    });
}
