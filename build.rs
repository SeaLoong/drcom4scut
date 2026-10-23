fn main() {
    println!(
        "cargo:rustc-env=DRCOM_BUILD_TARGET={}",
        std::env::var("TARGET").expect("Cargo build target")
    );
    println!("cargo:rerun-if-changed=build.rs");
    // Inspection commands and packet-free tests must run before Npcap is
    // installed. Real capture still loads the official runtime when first used.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        for argument in [
            "/DELAYLOAD:Packet.dll",
            "/DELAYLOAD:wpcap.dll",
            "delayimp.lib",
        ] {
            println!("cargo:rustc-link-arg={argument}");
        }
    }
}
