//! Formal-release updates. Only the validated executable is ever installed.
//!
//! GitHub metadata and assets travel through the configured HTTPS mirror. Hashes
//! detect corrupt/inconsistent downloads; they are not publisher signatures.
use std::{
    collections::HashSet,
    fmt, fs,
    io::{self, Cursor, Read, Write},
    path::Path,
    time::Duration,
};

use reqwest::{Client, Url};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[cfg(windows)]
mod windows;

pub const DEFAULT_PROXY: &str = "https://gh-proxy.com/";
const REPOSITORY: &str = "SeaLoong/drcom4scut";
const MAX_METADATA: usize = 1024 * 1024;
const MAX_DOWNLOAD: usize = 128 * 1024 * 1024;
const MAX_UNPACKED: usize = 256 * 1024 * 1024;
const MAX_BINARY: usize = 96 * 1024 * 1024;
const MAX_MEMBERS: usize = 4096;

#[derive(Clone, Debug)]
pub struct UpdateOptions {
    pub proxy: String,
}

impl Default for UpdateOptions {
    fn default() -> Self {
        Self {
            proxy: DEFAULT_PROXY.into(),
        }
    }
}

#[derive(Debug)]
pub struct UpdateError(String);

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for UpdateError {}
impl From<io::Error> for UpdateError {
    fn from(error: io::Error) -> Self {
        Self(format!("update file operation failed: {error}"))
    }
}

fn invalid(message: &str) -> UpdateError {
    UpdateError(message.into())
}

#[derive(Clone, Debug)]
pub struct AvailableUpdate {
    pub version: String,
    pub tag: String,
    asset: Asset,
    sums: Asset,
    source: String,
    target: Target,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    UpToDate,
    Updated {
        version: String,
        restart_required: bool,
    },
}

/// Reject credentials and URL decorations before the proxy can enter diagnostics.
pub fn validate_proxy(value: &str) -> Result<(), UpdateError> {
    let url = Url::parse(value).map_err(|_| invalid("update proxy must be an HTTPS base URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "update proxy must be an HTTPS base URL without credentials, query or fragment",
        ));
    }
    Ok(())
}

struct Transport {
    client: Client,
    proxy: String,
}

impl Transport {
    fn new(options: &UpdateOptions) -> Result<Self, UpdateError> {
        validate_proxy(&options.proxy)?;
        let mut roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // Keep bundled public roots for minimal router images, and honor native
        // trust (including SSL_CERT_FILE/SSL_CERT_DIR) for institutional proxies.
        // Bad/unavailable individual OS roots do not disable TLS verification.
        for certificate in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(certificate);
        }
        let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid("cannot configure update TLS"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let client = Client::builder()
            .use_preconfigured_tls(tls)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(120))
            .user_agent(concat!("drcom4scut/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| invalid("cannot create HTTPS update client"))?;
        Ok(Self {
            client,
            proxy: format!("{}/", options.proxy.trim_end_matches('/')),
        })
    }

    async fn get(&self, canonical: &str, limit: usize) -> Result<Vec<u8>, UpdateError> {
        // Redirects are deliberately disabled: a mirror must fetch GitHub's CDN
        // itself, rather than sending any updater request outside this base URL.
        let mut response = self
            .client
            .get(format!("{}{canonical}", self.proxy))
            .send()
            .await
            .map_err(|_| invalid("update HTTPS request failed"))?;
        if !response.status().is_success() {
            return Err(invalid("update proxy returned an unsuccessful HTTP status"));
        }
        if response
            .content_length()
            .is_some_and(|size| size > limit as u64)
        {
            return Err(invalid("update response exceeds size limit"));
        }
        let mut data = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| invalid("update download failed"))?
        {
            if chunk.len() > limit.saturating_sub(data.len()) {
                return Err(invalid("update response exceeds size limit"));
            }
            data.extend_from_slice(&chunk);
        }
        Ok(data)
    }
}

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    html_url: String,
    draft: bool,
    prerelease: bool,
    target_commitish: String,
    assets: Vec<Asset>,
}

#[derive(Clone, Debug, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    size: u64,
    digest: Option<String>,
}

#[derive(Clone, Copy, Debug)]
struct Target {
    name: &'static str,
    machine: u32,
    bits: u8,
    format: &'static str,
    openwrt: bool,
    arm_arch: Option<u8>,
}

fn target_named(name: &str) -> Result<Target, UpdateError> {
    let (machine, bits, format, openwrt, arm_arch) = match name {
        "x86_64-unknown-linux-gnu" => (62, 64, "elf", false, None),
        "aarch64-unknown-linux-gnu" => (183, 64, "elf", false, None),
        "x86_64-unknown-linux-musl" => (62, 64, "elf", true, None),
        "aarch64-unknown-linux-musl" => (183, 64, "elf", true, None),
        "armv5te-unknown-linux-musleabi" => (40, 32, "elf", true, Some(4)),
        "armv7-unknown-linux-musleabi" => (40, 32, "elf", true, Some(10)),
        "riscv64gc-unknown-linux-musl" => (243, 64, "elf", true, None),
        "x86_64-apple-darwin" => (0x1000007, 64, "macho", false, None),
        "aarch64-apple-darwin" => (0x100000c, 64, "macho", false, None),
        "x86_64-pc-windows-msvc" => (0x8664, 64, "pe", false, None),
        "aarch64-pc-windows-msvc" => (0xaa64, 64, "pe", false, None),
        _ => {
            return Err(invalid(
                "this build target has no supported release update asset",
            ));
        }
    };
    let name = match name {
        "x86_64-unknown-linux-gnu" => "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu" => "aarch64-unknown-linux-gnu",
        "x86_64-unknown-linux-musl" => "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl" => "aarch64-unknown-linux-musl",
        "armv5te-unknown-linux-musleabi" => "armv5te-unknown-linux-musleabi",
        "armv7-unknown-linux-musleabi" => "armv7-unknown-linux-musleabi",
        "riscv64gc-unknown-linux-musl" => "riscv64gc-unknown-linux-musl",
        "x86_64-apple-darwin" => "x86_64-apple-darwin",
        "aarch64-apple-darwin" => "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc" => "x86_64-pc-windows-msvc",
        _ => "aarch64-pc-windows-msvc",
    };
    Ok(Target {
        name,
        machine,
        bits,
        format,
        openwrt,
        arm_arch,
    })
}

fn stable_version(tag: &str) -> Result<Version, UpdateError> {
    let version = tag
        .strip_prefix('v')
        .and_then(|s| Version::parse(s).ok())
        .ok_or_else(|| invalid("latest release has no canonical stable version tag"))?;
    if !version.pre.is_empty() || !version.build.is_empty() || tag != format!("v{version}") {
        return Err(invalid("latest release is not a formal stable version"));
    }
    Ok(version)
}

fn sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn select_release(
    bytes: &[u8],
    current: &str,
    target: Target,
) -> Result<Option<AvailableUpdate>, UpdateError> {
    let release: Release =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid latest-release metadata"))?;
    if release.draft || release.prerelease {
        return Err(invalid("latest release is a draft or prerelease"));
    }
    let version = stable_version(&release.tag_name)?;
    if release.html_url
        != format!(
            "https://github.com/{REPOSITORY}/releases/tag/{}",
            release.tag_name
        )
    {
        return Err(invalid(
            "latest release does not belong to the canonical repository",
        ));
    }
    let current = Version::parse(current).map_err(|_| invalid("invalid current version"))?;
    if version <= current {
        return Ok(None);
    }
    if !sha(&release.target_commitish) {
        return Err(invalid(
            "release must identify its full validated source commit",
        ));
    }
    if release.assets.len() > 256 {
        return Err(invalid("too many release assets"));
    }
    let extension = if target.format == "pe" {
        "zip"
    } else {
        "tar.gz"
    };
    let name = format!("drcom4scut-{version}-{}.{extension}", target.name);
    let find = |name: &str| -> Result<Asset, UpdateError> {
        let matches: Vec<_> = release.assets.iter().filter(|a| a.name == name).collect();
        if matches.len() != 1 {
            return Err(invalid("release asset is missing or duplicated"));
        }
        let asset = matches[0];
        if asset.browser_download_url
            != format!(
                "https://github.com/{REPOSITORY}/releases/download/{}/{name}",
                release.tag_name
            )
            || asset.size == 0
            || asset.size > MAX_DOWNLOAD as u64
        {
            return Err(invalid("release asset has an invalid URL or size"));
        }
        let digest = asset
            .digest
            .as_deref()
            .and_then(|s| s.strip_prefix("sha256:"));
        if !digest.is_some_and(valid_digest) {
            return Err(invalid("release asset lacks a SHA-256 digest"));
        }
        Ok(asset.clone())
    };
    Ok(Some(AvailableUpdate {
        version: version.to_string(),
        tag: release.tag_name.clone(),
        asset: find(&name)?,
        sums: find("SHA256SUMS")?,
        source: release.target_commitish.clone(),
        target,
    }))
}

/// Check only: this function never downloads an archive or changes files.
pub async fn check_latest(options: &UpdateOptions) -> Result<Option<AvailableUpdate>, UpdateError> {
    let target = target_named(env!("DRCOM_BUILD_TARGET"))?;
    check_with(&Transport::new(options)?, env!("CARGO_PKG_VERSION"), target).await
}

async fn check_with(
    transport: &Transport,
    current: &str,
    target: Target,
) -> Result<Option<AvailableUpdate>, UpdateError> {
    let bytes = transport
        .get(
            &format!("https://api.github.com/repos/{REPOSITORY}/releases/latest"),
            MAX_METADATA,
        )
        .await?;
    select_release(&bytes, current, target)
}

/// Check and immediately install a newer formal release into the running binary's path.
pub async fn apply_latest(options: &UpdateOptions) -> Result<UpdateOutcome, UpdateError> {
    let transport = Transport::new(options)?;
    let target = target_named(env!("DRCOM_BUILD_TARGET"))?;
    let Some(release) = check_with(&transport, env!("CARGO_PKG_VERSION"), target).await? else {
        return Ok(UpdateOutcome::UpToDate);
    };
    let binary = download_binary(&transport, &release).await?;
    let executable = std::env::current_exe()?.canonicalize()?;
    tokio::task::spawn_blocking(move || install_binary(&executable, &binary))
        .await
        .map_err(|_| invalid("update installer task failed"))??;
    Ok(UpdateOutcome::Updated {
        version: release.version,
        restart_required: true,
    })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn verify_digest(asset: &Asset, bytes: &[u8]) -> Result<(), UpdateError> {
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
    if bytes.len() as u64 != asset.size || asset.digest.as_deref() != Some(&digest) {
        return Err(invalid(
            "downloaded asset size or SHA-256 digest does not match the release",
        ));
    }
    Ok(())
}

fn verify_sums(sums: &[u8], asset: &Asset) -> Result<(), UpdateError> {
    let sums = std::str::from_utf8(sums).map_err(|_| invalid("SHA256SUMS is not UTF-8"))?;
    let mut found = false;
    let mut names = HashSet::new();
    for line in sums.lines() {
        let (digest, name) = line
            .split_once("  ")
            .ok_or_else(|| invalid("malformed SHA256SUMS row"))?;
        if !valid_digest(digest)
            || name.is_empty()
            || name.contains(['/', '\\', ':'])
            || !names.insert(name)
        {
            return Err(invalid("invalid or duplicate SHA256SUMS row"));
        }
        if name == asset.name {
            if asset.digest.as_deref() != Some(&format!("sha256:{digest}")) {
                return Err(invalid("release digest disagrees with SHA256SUMS"));
            }
            found = true;
        }
    }
    if !found {
        return Err(invalid("SHA256SUMS does not contain the selected archive"));
    }
    Ok(())
}

async fn download_binary(
    transport: &Transport,
    release: &AvailableUpdate,
) -> Result<Vec<u8>, UpdateError> {
    let sums = transport
        .get(&release.sums.browser_download_url, MAX_METADATA)
        .await?;
    verify_digest(&release.sums, &sums)?;
    verify_sums(&sums, &release.asset)?;
    let archive = transport
        .get(&release.asset.browser_download_url, MAX_DOWNLOAD)
        .await?;
    verify_digest(&release.asset, &archive)?;
    // Decompression and executable inspection can be expensive on routers.
    let release = release.clone();
    tokio::task::spawn_blocking(move || unpack_binary(&archive, &release))
        .await
        .map_err(|_| invalid("update archive task failed"))?
}

#[derive(Deserialize)]
struct BuildInfo {
    version: String,
    target: String,
    source_commit: String,
    source_dirty: bool,
    openwrt: bool,
}

fn read_bounded(reader: impl Read, limit: usize) -> Result<Vec<u8>, UpdateError> {
    let mut output = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut output)?;
    if output.len() > limit {
        return Err(invalid("archive member exceeds size limit"));
    }
    Ok(output)
}

fn safe_member(name: &str, root: &str, directory: bool) -> Result<String, UpdateError> {
    if name.len() > 1024 || name.contains(['\\', ':', '\0']) || name.starts_with('/') {
        return Err(invalid("archive contains an unsafe path"));
    }
    let name = if directory {
        name.strip_suffix('/').unwrap_or(name)
    } else {
        name
    };
    if name
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
        || !(name == root || name.strip_prefix(root).is_some_and(|s| s.starts_with('/')))
    {
        return Err(invalid(
            "archive path escapes the expected package directory",
        ));
    }
    Ok(name.into())
}

fn unpack_binary(bytes: &[u8], release: &AvailableUpdate) -> Result<Vec<u8>, UpdateError> {
    let root = format!("drcom4scut-{}-{}", release.version, release.target.name);
    let binary_path = format!(
        "{root}/drcom4scut{}",
        if release.target.format == "pe" {
            ".exe"
        } else {
            ""
        }
    );
    let info_path = format!("{root}/BUILD-INFO.json");
    let mut binary = None;
    let mut info = None;
    let mut seen = HashSet::new();
    let mut total = 0_u64;
    let mut capture = |name: &str,
                       directory: bool,
                       size: u64,
                       reader: &mut dyn Read|
     -> Result<(), UpdateError> {
        let name = safe_member(name, &root, directory)?;
        if seen.len() >= MAX_MEMBERS || !seen.insert(name.clone()) {
            return Err(invalid("archive has too many or duplicate members"));
        }
        total = total
            .checked_add(size)
            .ok_or_else(|| invalid("archive size overflow"))?;
        if total > MAX_UNPACKED as u64 {
            return Err(invalid("archive exceeds expanded size limit"));
        }
        if directory {
            if size != 0 {
                return Err(invalid("archive directory contains data"));
            }
            return Ok(());
        }
        if name == binary_path {
            binary = Some(read_bounded(reader, MAX_BINARY)?);
        } else if name == info_path {
            info = Some(read_bounded(reader, 64 * 1024)?);
        } else {
            io::copy(&mut reader.take(size + 1), &mut io::sink())?;
        }
        Ok(())
    };
    if release.target.format == "pe" {
        let mut zip = zip::ZipArchive::new(Cursor::new(bytes))
            .map_err(|_| invalid("invalid release ZIP archive"))?;
        if zip.len() > MAX_MEMBERS {
            return Err(invalid("archive has too many members"));
        }
        for index in 0..zip.len() {
            let mut entry = zip
                .by_index(index)
                .map_err(|_| invalid("invalid ZIP member"))?;
            let directory = entry.is_dir();
            if let Some(mode) = entry.unix_mode() {
                let kind = mode & 0o170000;
                if kind != 0 && kind != if directory { 0o040000 } else { 0o100000 } {
                    return Err(invalid("archive contains a link or special file"));
                }
            }
            let name = entry
                .name()
                .map_err(|_| invalid("invalid ZIP member name"))?
                .into_owned();
            let size = entry.size();
            capture(&name, directory, size, &mut entry)?;
        }
    } else {
        // Stream decompression on memory-constrained routers; the limit also
        // counts tar headers/PAX metadata, including entries tar hides for us.
        let mut expanded = flate2::read::GzDecoder::new(bytes).take(MAX_UNPACKED as u64 + 1);
        {
            let mut archive = tar::Archive::new(&mut expanded);
            for entry in archive.entries()? {
                let mut entry = entry?;
                let kind = entry.header().entry_type();
                if !kind.is_file() && !kind.is_dir() {
                    return Err(invalid("archive contains a link or special file"));
                }
                let name = entry.path_bytes();
                let name = std::str::from_utf8(&name)
                    .map_err(|_| invalid("archive path is not UTF-8"))?
                    .to_string();
                let size = entry.size();
                capture(&name, kind.is_dir(), size, &mut entry)?;
            }
        }
        // Drain through the gzip footer so a truncated stream/CRC error cannot
        // be hidden after tar's end marker.
        io::copy(&mut expanded, &mut io::sink())?;
        if expanded.limit() == 0 {
            return Err(invalid("archive exceeds expanded size limit"));
        }
    }
    let info: BuildInfo =
        serde_json::from_slice(&info.ok_or_else(|| invalid("archive lacks BUILD-INFO.json"))?)
            .map_err(|_| invalid("invalid BUILD-INFO.json"))?;
    if info.version != release.version
        || info.target != release.target.name
        || info.source_commit != release.source
        || info.source_dirty
        || info.openwrt != release.target.openwrt
    {
        return Err(invalid(
            "archive build information does not match the formal release",
        ));
    }
    let binary = binary.ok_or_else(|| invalid("archive lacks the core executable"))?;
    verify_abi(&binary, release.target)?;
    Ok(binary)
}

fn number(data: &[u8], offset: usize, size: usize) -> Result<u64, UpdateError> {
    let value = data
        .get(
            offset
                ..offset
                    .checked_add(size)
                    .ok_or_else(|| invalid("executable offset overflow"))?,
        )
        .ok_or_else(|| invalid("truncated executable header"))?;
    Ok(value
        .iter()
        .enumerate()
        .fold(0, |n, (i, byte)| n | (u64::from(*byte) << (8 * i))))
}

fn verify_abi(data: &[u8], target: Target) -> Result<(), UpdateError> {
    let bad = || invalid("executable ABI does not match the selected release target");
    match target.format {
        "elf" => {
            let header = if target.bits == 64 { 64 } else { 52 };
            if data.len() < header
                || &data[..4] != b"\x7fELF"
                || data[5] != 1
                || data[4] != if target.bits == 64 { 2 } else { 1 }
                || number(data, 18, 2)? != u64::from(target.machine)
                || ![2, 3].contains(&number(data, 16, 2)?)
            {
                return Err(bad());
            }
            let (offset, size, count) = if target.bits == 64 {
                (
                    number(data, 32, 8)?,
                    number(data, 54, 2)?,
                    number(data, 56, 2)?,
                )
            } else {
                (
                    number(data, 28, 4)?,
                    number(data, 42, 2)?,
                    number(data, 44, 2)?,
                )
            };
            if size < if target.bits == 64 { 56 } else { 32 }
                || count == 0
                || offset
                    .checked_add(size * count)
                    .is_none_or(|end| end > data.len() as u64)
            {
                return Err(bad());
            }
            if target.openwrt {
                for index in 0..count {
                    if number(data, (offset + size * index) as usize, 4)? == 3 {
                        return Err(invalid(
                            "OpenWrt update is not a static executable (PT_INTERP present)",
                        ));
                    }
                }
            }
            if let Some(arch) = target.arm_arch {
                if number(data, 36, 4)? & 0x400 != 0 {
                    return Err(invalid("ARM update has a hard-float ABI"));
                }
                verify_arm_attributes(data, arch)?;
            }
        }
        "macho" => {
            if data.len() < 32
                || &data[..4] != b"\xcf\xfa\xed\xfe"
                || number(data, 4, 4)? != u64::from(target.machine)
                || number(data, 12, 4)? != 2
            {
                return Err(bad());
            }
            let count = number(data, 16, 4)?;
            let end = 32 + number(data, 20, 4)?;
            if end > data.len() as u64 || count > (end - 32) / 8 {
                return Err(bad());
            }
            let mut offset = 32;
            for _ in 0..count {
                let size = number(data, offset as usize + 4, 4)?;
                if size < 8 || size % 8 != 0 || offset + size > end {
                    return Err(bad());
                }
                offset += size;
            }
            if offset != end {
                return Err(bad());
            }
        }
        "pe" => {
            if data.len() < 64 || &data[..2] != b"MZ" {
                return Err(bad());
            }
            let offset = number(data, 60, 4)? as usize;
            if data.get(offset..offset + 4) != Some(b"PE\0\0")
                || number(data, offset + 4, 2)? != u64::from(target.machine)
                || number(data, offset + 22, 2)? & 0x0002 == 0
                || number(data, offset + 24, 2)? != 0x20b
            {
                return Err(bad());
            }
        }
        _ => return Err(bad()),
    }
    Ok(())
}

fn uleb(bytes: &[u8], position: &mut usize) -> Result<u64, UpdateError> {
    let mut result = 0;
    for shift in (0..=63).step_by(7) {
        let byte = *bytes
            .get(*position)
            .ok_or_else(|| invalid("truncated ARM attributes"))?;
        *position += 1;
        if shift == 63 && byte > 1 {
            return Err(invalid("ARM attribute integer overflow"));
        }
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
    }
    Err(invalid("ARM attribute integer overflow"))
}

fn skip_string(bytes: &[u8], position: &mut usize) -> Result<(), UpdateError> {
    *position += bytes
        .get(*position..)
        .and_then(|s| s.iter().position(|b| *b == 0))
        .ok_or_else(|| invalid("unterminated ARM attribute string"))?
        + 1;
    Ok(())
}

fn verify_arm_attributes(data: &[u8], expected: u8) -> Result<(), UpdateError> {
    let offset = number(data, 32, 4)?;
    let size = number(data, 46, 2)?;
    let count = number(data, 48, 2)?;
    if size < 40
        || count == 0
        || offset
            .checked_add(size * count)
            .is_none_or(|end| end > data.len() as u64)
    {
        return Err(invalid("missing ARM architecture attributes"));
    }
    let mut found = false;
    for index in 0..count {
        let section = (offset + size * index) as usize;
        if number(data, section + 4, 4)? != 0x70000003 {
            continue;
        }
        let start = number(data, section + 16, 4)? as usize;
        let length = number(data, section + 20, 4)? as usize;
        let bytes = data
            .get(
                start
                    ..start
                        .checked_add(length)
                        .ok_or_else(|| invalid("ARM attribute overflow"))?,
            )
            .ok_or_else(|| invalid("truncated ARM attributes"))?;
        if bytes.first() != Some(&b'A') {
            return Err(invalid("invalid ARM attributes"));
        }
        let mut vendor = 1;
        while vendor < bytes.len() {
            let length = number(bytes, vendor, 4)? as usize;
            let end = vendor
                .checked_add(length)
                .filter(|end| *end <= bytes.len() && length >= 5)
                .ok_or_else(|| invalid("invalid ARM vendor attributes"))?;
            let mut position = vendor + 4;
            let aeabi = bytes.get(position..position + 6) == Some(b"aeabi\0");
            skip_string(&bytes[..end], &mut position)?;
            if aeabi {
                while position < end {
                    let subsection = position;
                    let tag = uleb(&bytes[..end], &mut position)?;
                    let length = number(bytes, position, 4)? as usize;
                    position += 4;
                    let subend = subsection
                        .checked_add(length)
                        .filter(|n| *n <= end && *n >= position)
                        .ok_or_else(|| invalid("invalid ARM file attributes"))?;
                    if tag == 1 {
                        while position < subend {
                            let tag = uleb(&bytes[..subend], &mut position)?;
                            match tag {
                                6 => {
                                    let arch = uleb(&bytes[..subend], &mut position)?;
                                    if arch != u64::from(expected) {
                                        return Err(invalid(
                                            "ARM CPU baseline does not match the release target",
                                        ));
                                    }
                                    found = true;
                                }
                                4 | 5 | 65 | 67 => skip_string(&bytes[..subend], &mut position)?,
                                32 => {
                                    uleb(&bytes[..subend], &mut position)?;
                                    skip_string(&bytes[..subend], &mut position)?;
                                }
                                _ if tag >= 32 && tag % 2 == 1 => {
                                    skip_string(&bytes[..subend], &mut position)?
                                }
                                _ => {
                                    uleb(&bytes[..subend], &mut position)?;
                                }
                            }
                        }
                    }
                    position = subend;
                }
            }
            vendor = end;
        }
    }
    if !found {
        return Err(invalid("missing ARM CPU baseline attribute"));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn install_binary(executable: &Path, binary: &[u8]) -> Result<(), UpdateError> {
    install_with(executable, binary, || Ok(()))
}

fn install_with(
    executable: &Path,
    binary: &[u8],
    after_replace: impl FnOnce() -> io::Result<()>,
) -> Result<(), UpdateError> {
    let original = fs::symlink_metadata(executable)?;
    if !original.is_file() || original.file_type().is_symlink() {
        return Err(invalid("update destination must be a regular executable"));
    }
    let parent = executable
        .parent()
        .ok_or_else(|| invalid("update destination has no parent directory"))?;
    let staging = tempfile::Builder::new().prefix(".drcom4scut-update-").tempdir_in(parent)
        .map_err(|_| invalid("cannot create update staging directory beside the executable; check directory permissions or retry as administrator"))?;
    let replacement = staging.path().join("replacement");
    let backup = staging.path().join("previous");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&replacement)?;
    file.write_all(binary)?;
    preserve_permissions(executable, &original, &file)?;
    #[cfg(windows)]
    windows::preserve_security(executable, &replacement)?;
    file.sync_all()?;
    drop(file);
    // A hard link retains the original image and its metadata without first
    // removing the active pathname on Unix. Windows must rename a loaded image.
    #[cfg(unix)]
    fs::hard_link(executable, &backup)?;
    #[cfg(windows)]
    fs::rename(executable, &backup)?;
    let commit = fs::rename(&replacement, executable)
        .and_then(|()| after_replace())
        .and_then(|()| sync_directory(parent));
    if let Err(error) = commit {
        #[cfg(windows)]
        if executable.exists() {
            let _ = fs::remove_file(executable);
        }
        if let Err(rollback) = fs::rename(&backup, executable) {
            let recovery = staging.keep();
            return Err(UpdateError(format!(
                "update failed: {error}; rollback failed: {rollback}; original executable retained at {}",
                recovery.join("previous").display()
            )));
        }
        sync_directory(parent)?;
        return Err(UpdateError(format!(
            "update failed and original executable was restored: {error}"
        )));
    }
    // Windows keeps the old process image locked. Retain its uniquely named
    // backup instead of launching any downloaded or shell-based cleanup helper.
    if fs::remove_file(&backup).is_err() {
        let _ = staging.keep();
    }
    Ok(())
}

fn preserve_permissions(
    executable: &Path,
    metadata: &fs::Metadata,
    replacement: &fs::File,
) -> Result<(), UpdateError> {
    #[cfg(unix)]
    {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        let staged = replacement.metadata()?;
        if staged.uid() != metadata.uid() || staged.gid() != metadata.gid() {
            // SAFETY: the descriptor is live and uid/gid came from filesystem metadata.
            if unsafe { libc::fchown(replacement.as_raw_fd(), metadata.uid(), metadata.gid()) } != 0
            {
                return Err(invalid(
                    "cannot preserve executable ownership; retry the update as root",
                ));
            }
        }
    }
    replacement.set_permissions(metadata.permissions())?;
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let old = fs::File::open(executable)?;
        let name = c"security.capability";
        let mut capability = [0_u8; 64];
        // SAFETY: live descriptor, NUL-terminated name and bounded output buffer.
        let size = unsafe {
            libc::fgetxattr(
                old.as_raw_fd(),
                name.as_ptr(),
                capability.as_mut_ptr().cast(),
                capability.len(),
            )
        };
        if size >= 0 {
            // Restore the exact existing capability, never add a new privilege.
            // SAFETY: the bounded xattr bytes and replacement descriptor are live.
            if unsafe {
                libc::fsetxattr(
                    replacement.as_raw_fd(),
                    name.as_ptr(),
                    capability.as_ptr().cast(),
                    size as usize,
                    0,
                )
            } != 0
            {
                return Err(invalid(
                    "cannot preserve executable file capabilities (including cap_net_raw); retry the update as root",
                ));
            }
        } else {
            let error = io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(libc::ENODATA | libc::ENOTSUP)) {
                return Err(error.into());
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = executable;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        net::TcpListener,
        sync::{Arc, Mutex},
    };

    fn target() -> Target {
        target_named("x86_64-unknown-linux-gnu").unwrap()
    }

    fn elf(target: Target) -> Vec<u8> {
        let mut bytes = vec![0; 512];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = if target.bits == 64 { 2 } else { 1 };
        bytes[5] = 1;
        bytes[16] = 2;
        bytes[18..20].copy_from_slice(&(target.machine as u16).to_le_bytes());
        if target.bits == 64 {
            bytes[32] = 64;
            bytes[54] = 56;
            bytes[56] = 1;
        } else {
            bytes[28] = 52;
            bytes[42] = 32;
            bytes[44] = 1;
        }
        bytes
    }

    fn release(target: Target) -> AvailableUpdate {
        let version = "99.1.0".to_string();
        let name = format!(
            "drcom4scut-{version}-{}.{}",
            target.name,
            if target.format == "pe" {
                "zip"
            } else {
                "tar.gz"
            }
        );
        let asset = |name: String| Asset {
            browser_download_url: format!(
                "https://github.com/{REPOSITORY}/releases/download/v{version}/{name}"
            ),
            name,
            size: 1,
            digest: None,
        };
        AvailableUpdate {
            tag: format!("v{version}"),
            asset: asset(name),
            sums: asset("SHA256SUMS".into()),
            version,
            source: "a".repeat(40),
            target,
        }
    }

    fn info(release: &AvailableUpdate) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"version":release.version,"target":release.target.name,"source_commit":release.source,"source_dirty":false,"openwrt":release.target.openwrt})).unwrap()
    }

    fn tar_package(
        release: &AvailableUpdate,
        binary: &[u8],
        extra: Option<(&str, tar::EntryType)>,
    ) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut archive = tar::Builder::new(encoder);
        let root = format!("drcom4scut-{}-{}", release.version, release.target.name);
        for (name, bytes) in [
            (format!("{root}/drcom4scut"), binary.to_vec()),
            (format!("{root}/BUILD-INFO.json"), info(release)),
            (
                format!("{root}/config.example.yml"),
                b"do not overwrite account".to_vec(),
            ),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            archive.append_data(&mut header, name, &bytes[..]).unwrap();
        }
        if let Some((name, kind)) = extra {
            let mut header = tar::Header::new_gnu();
            // Write the raw path deliberately: tar's builder normally rejects traversal.
            header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
            header.set_entry_type(kind);
            header.set_mode(0o644);
            header.set_size(0);
            if kind.is_symlink() || kind.is_hard_link() {
                header.set_link_name("/etc/passwd").unwrap();
            }
            header.set_cksum();
            archive.append(&header, io::empty()).unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap()
    }

    fn attach_digest(asset: &mut Asset, bytes: &[u8]) {
        asset.size = bytes.len() as u64;
        asset.digest = Some(format!("sha256:{}", hex::encode(Sha256::digest(bytes))));
    }

    fn metadata(release: &AvailableUpdate) -> Vec<u8> {
        let asset = |asset: &Asset| serde_json::json!({"name":asset.name,"size":asset.size,"digest":asset.digest,"browser_download_url":asset.browser_download_url});
        serde_json::to_vec(&serde_json::json!({"tag_name":release.tag,"html_url":format!("https://github.com/{REPOSITORY}/releases/tag/{}",release.tag),"draft":false,"prerelease":false,"target_commitish":release.source,"assets":[asset(&release.asset),asset(&release.sums)]})).unwrap()
    }

    fn transport(
        responses: HashMap<String, Vec<u8>>,
        requests: Arc<Mutex<Vec<String>>>,
    ) -> (Transport, std::thread::JoinHandle<()>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..responses.len() {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut buffer = [0; 16384];
                let size = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..size]);
                let path = request.split_whitespace().nth(1).unwrap().to_string();
                requests.lock().unwrap().push(path.clone());
                let bytes = responses.get(&path).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                )
                .unwrap();
                stream.write_all(bytes).unwrap();
            }
        });
        (
            Transport {
                client: Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(5))
                    .build()
                    .unwrap(),
                proxy: format!("http://{address}/mirror/"),
            },
            server,
        )
    }

    #[test]
    fn stable_and_proxy_policy() {
        for tag in [
            "v1.2.3-rc.1",
            "v1.2.3+build",
            "1.2.3",
            "v01.2.3",
            "v1.2",
            "v1.2.3/evil",
        ] {
            assert!(stable_version(tag).is_err(), "{tag}");
        }
        assert_eq!(stable_version("v1.2.3").unwrap(), Version::new(1, 2, 3));
        for proxy in [
            "",
            "http://gh-proxy.com/",
            "https://name:secret@host/",
            "https://host/?key=secret",
            "https://host/#x",
            "file:///tmp",
        ] {
            assert!(validate_proxy(proxy).is_err(), "{proxy}");
        }
        assert!(validate_proxy(DEFAULT_PROXY).is_ok());
        assert!(validate_proxy("https://mirror.example:8443/prefix/").is_ok());
        // Default transport has HTTPS independently of optional portal features.
        assert!(Transport::new(&UpdateOptions::default()).is_ok());
    }

    #[test]
    fn metadata_rejects_prerelease_wrong_repo_assets_and_source() {
        let mut release = release(target());
        attach_digest(&mut release.asset, b"archive");
        attach_digest(&mut release.sums, b"sums");
        let good = metadata(&release);
        assert!(select_release(&good, "99.1.0", target()).unwrap().is_none());
        assert!(
            select_release(&good, "100.0.0", target())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            select_release(&good, "99.0.0", target())
                .unwrap()
                .unwrap()
                .version,
            "99.1.0"
        );
        for (key, value) in [
            ("draft", serde_json::json!(true)),
            ("prerelease", serde_json::json!(true)),
            ("tag_name", serde_json::json!("v99.1.0-rc.1")),
            (
                "html_url",
                serde_json::json!("https://github.com/attacker/drcom4scut/releases/tag/v99.1.0"),
            ),
            ("target_commitish", serde_json::json!("master")),
        ] {
            let mut bad: serde_json::Value = serde_json::from_slice(&good).unwrap();
            bad[key] = value;
            assert!(
                select_release(&serde_json::to_vec(&bad).unwrap(), "0.0.0", target()).is_err(),
                "{key}"
            );
        }
        for mutation in 0..4 {
            let mut bad: serde_json::Value = serde_json::from_slice(&good).unwrap();
            match mutation {
                0 => {
                    bad["assets"][0]["browser_download_url"] =
                        serde_json::json!("https://attacker.example/core")
                }
                1 => bad["assets"][0]["digest"] = serde_json::Value::Null,
                2 => {
                    let duplicate = bad["assets"][0].clone();
                    bad["assets"].as_array_mut().unwrap().push(duplicate);
                }
                _ => bad["assets"][0]["name"] = serde_json::json!("drcom4scut-wrong-cpu.tar.gz"),
            }
            assert!(select_release(&serde_json::to_vec(&bad).unwrap(), "0.0.0", target()).is_err());
        }
    }

    #[test]
    fn checksum_failures_and_missing_duplicate_rows_are_rejected() {
        let mut asset = release(target()).asset;
        attach_digest(&mut asset, b"correct");
        assert!(verify_digest(&asset, b"corrupt").is_err());
        let row = format!(
            "{}  {}\n",
            asset
                .digest
                .as_ref()
                .unwrap()
                .strip_prefix("sha256:")
                .unwrap(),
            asset.name
        );
        assert!(verify_sums(row.as_bytes(), &asset).is_ok());
        assert!(verify_sums(format!("{row}{row}").as_bytes(), &asset).is_err());
        assert!(verify_sums(b"", &asset).is_err());
        assert!(
            verify_sums(
                format!("{}  {}\n", "0".repeat(64), asset.name).as_bytes(),
                &asset
            )
            .is_err()
        );
    }

    #[test]
    fn malicious_tar_members_and_wrong_build_info_are_rejected() {
        let release = release(target());
        let binary = elf(target());
        let root = format!("drcom4scut-{}-{}", release.version, release.target.name);
        assert_eq!(
            unpack_binary(&tar_package(&release, &binary, None), &release).unwrap(),
            binary
        );
        for (name, kind) in [
            (format!("{root}/../../account.yml"), tar::EntryType::Regular),
            (format!("/{root}/absolute"), tar::EntryType::Regular),
            (format!("{root}/C:evil"), tar::EntryType::Regular),
            (format!("{root}/sym"), tar::EntryType::Symlink),
            (format!("{root}/hard"), tar::EntryType::Link),
            (format!("{root}/device"), tar::EntryType::Char),
            (format!("{root}/fifo"), tar::EntryType::Fifo),
            (format!("{root}/drcom4scut"), tar::EntryType::Regular),
        ] {
            assert!(
                unpack_binary(
                    &tar_package(&release, &binary, Some((&name, kind))),
                    &release
                )
                .is_err(),
                "{name}"
            );
        }
        let archive = tar_package(&release, &binary, None);
        let mut wrong_source = release.clone();
        wrong_source.source = "b".repeat(40);
        assert!(unpack_binary(&archive, &wrong_source).is_err());
        assert!(
            unpack_binary(&tar_package(&release, b"#!/bin/sh\nexit 0", None), &release).is_err()
        );
        assert!(read_bounded(&b"0123456789"[..], 9).is_err());
    }

    #[test]
    fn zip_links_traversal_and_duplicate_members_are_rejected() {
        use zip::write::SimpleFileOptions;
        let release = release(target_named("x86_64-pc-windows-msvc").unwrap());
        let root = format!("drcom4scut-{}-{}", release.version, release.target.name);
        for mode in 0..3 {
            let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
            match mode {
                0 => {
                    zip.start_file(
                        format!("{root}/../account.yml"),
                        SimpleFileOptions::default(),
                    )
                    .unwrap();
                }
                1 => {
                    zip.add_symlink(
                        format!("{root}/link"),
                        "/etc/passwd",
                        SimpleFileOptions::default(),
                    )
                    .unwrap();
                }
                _ => {
                    for executable in ["drcom4scut.exe", "ercom4scut.exe"] {
                        zip.start_file(
                            format!("{root}/{executable}"),
                            SimpleFileOptions::default(),
                        )
                        .unwrap();
                    }
                }
            }
            let mut bytes = zip.finish().unwrap().into_inner();
            if mode == 2 {
                for index in 0..bytes.len().saturating_sub(13) {
                    if &bytes[index..index + 13] == b"ercom4scut.exe" {
                        bytes[index] = b'd';
                    }
                }
            }
            assert!(unpack_binary(&bytes, &release).is_err());
        }
    }

    #[test]
    fn static_architecture_checks_reject_interpreter_and_wrong_cpu() {
        let target = target_named("x86_64-unknown-linux-musl").unwrap();
        let mut binary = elf(target);
        assert!(verify_abi(&binary, target).is_ok());
        binary[64] = 3;
        assert!(verify_abi(&binary, target).is_err());
        binary[64] = 1;
        binary[18] = 183;
        assert!(verify_abi(&binary, target).is_err());
        assert!(verify_abi(&[0; 64], target).is_err());
    }

    #[test]
    fn atomic_install_preserves_accounts_and_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("core");
        let account = dir.path().join("config.yml");
        fs::write(&executable, b"original").unwrap();
        fs::write(&account, b"private account").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o751)).unwrap();
        }
        let before = fs::metadata(&executable).unwrap().permissions();
        assert!(
            install_with(&executable, b"replacement", || Err(io::Error::other(
                "injected commit failure"
            )))
            .is_err()
        );
        assert_eq!(fs::read(&executable).unwrap(), b"original");
        assert_eq!(fs::read(&account).unwrap(), b"private account");
        install_binary(&executable, b"replacement").unwrap();
        assert_eq!(fs::read(&executable).unwrap(), b"replacement");
        assert_eq!(fs::metadata(&executable).unwrap().permissions(), before);
        assert_eq!(fs::read(&account).unwrap(), b"private account");
    }

    #[test]
    fn running_image_waiter() {
        // Only the copied test harness reads this test-only rendezvous path.
        let Some(directory) = std::env::var_os("DRCOM_UPDATE_TEST_WAITER_PRIVATE") else {
            return;
        };
        let directory = Path::new(&directory);
        fs::write(directory.join("ready"), b"ready").unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while !directory.join("exit").exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "parent installer timed out"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn actual_running_image_replacement_and_rollback() {
        let runner_key = format!(
            "CARGO_TARGET_{}_RUNNER",
            env!("DRCOM_BUILD_TARGET")
                .replace('-', "_")
                .to_ascii_uppercase()
        );
        // QEMU user-mode can run the test harness, but cannot exec a foreign
        // child without host binfmt registration. Native matrix jobs cover this.
        if std::env::var(runner_key).is_ok_and(|runner| !runner.is_empty()) {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join(if cfg!(windows) {
            "running.exe"
        } else {
            "running"
        });
        fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        let original_digest = Sha256::digest(fs::read(&executable).unwrap());
        let mut child = std::process::Command::new(&executable)
            .args(["--exact", "update::tests::running_image_waiter"])
            .env("DRCOM_UPDATE_TEST_WAITER_PRIVATE", directory.path())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !directory.path().join("ready").exists() {
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                panic!("copied native test executable did not start");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let rollback = install_with(&executable, b"uncommitted", || {
            Err(io::Error::other("injected commit failure"))
        });
        let restored = Sha256::digest(fs::read(&executable).unwrap()) == original_digest;
        let install = install_binary(&executable, b"installed replacement");
        fs::write(directory.path().join("exit"), b"exit").unwrap();
        assert!(child.wait().unwrap().success());
        assert!(rollback.is_err());
        assert!(restored);
        install.unwrap();
        assert_eq!(fs::read(executable).unwrap(), b"installed replacement");
    }

    #[tokio::test]
    async fn loopback_release_download_and_install_all_requests_use_proxy_prefix() {
        let mut release = release(target());
        let binary = elf(target());
        let archive = tar_package(&release, &binary, None);
        attach_digest(&mut release.asset, &archive);
        let sums = format!(
            "{}  {}\n",
            release
                .asset
                .digest
                .as_ref()
                .unwrap()
                .strip_prefix("sha256:")
                .unwrap(),
            release.asset.name
        )
        .into_bytes();
        attach_digest(&mut release.sums, &sums);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let metadata_path =
            format!("/mirror/https://api.github.com/repos/{REPOSITORY}/releases/latest");
        let responses = HashMap::from([
            (metadata_path, metadata(&release)),
            (
                format!("/mirror/{}", release.asset.browser_download_url),
                archive,
            ),
            (
                format!("/mirror/{}", release.sums.browser_download_url),
                sums,
            ),
        ]);
        let (transport, server) = transport(responses, requests.clone());
        let selected = check_with(&transport, "0.0.0", target())
            .await
            .unwrap()
            .unwrap();
        let downloaded = download_binary(&transport, &selected).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("core");
        fs::write(&executable, b"original").unwrap();
        install_binary(&executable, &downloaded).unwrap();
        assert_eq!(fs::read(executable).unwrap(), binary);
        server.join().unwrap();
        let paths = requests.lock().unwrap();
        assert_eq!(paths.len(), 3);
        assert!(
            paths
                .iter()
                .all(|path| path.starts_with("/mirror/https://"))
        );
    }

    #[tokio::test]
    async fn loopback_corrupt_archive_never_changes_installed_binary() {
        let mut release = release(target());
        let archive = tar_package(&release, &elf(target()), None);
        attach_digest(&mut release.asset, &archive);
        let sums = format!(
            "{}  {}\n",
            release
                .asset
                .digest
                .as_ref()
                .unwrap()
                .strip_prefix("sha256:")
                .unwrap(),
            release.asset.name
        )
        .into_bytes();
        attach_digest(&mut release.sums, &sums);
        let mut corrupt = archive;
        corrupt[20] ^= 0x80;
        let responses = HashMap::from([
            (
                format!("/mirror/{}", release.asset.browser_download_url),
                corrupt,
            ),
            (
                format!("/mirror/{}", release.sums.browser_download_url),
                sums,
            ),
        ]);
        let (transport, server) = transport(responses, Arc::default());
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("core");
        fs::write(&executable, b"original").unwrap();
        assert!(download_binary(&transport, &release).await.is_err());
        assert_eq!(fs::read(executable).unwrap(), b"original");
        server.join().unwrap();
    }

    /// CI supplies the actual packaged native executable, rather than a synthetic ABI fixture.
    #[test]
    fn native_packaged_archive_install() {
        let Some(path) = std::env::var_os("DRCOM_UPDATE_TEST_ARCHIVE") else {
            return;
        };
        let source =
            std::env::var("DRCOM_UPDATE_TEST_SOURCE").expect("native update test source commit");
        let mut release = release(target_named(env!("DRCOM_BUILD_TARGET")).unwrap());
        release.version = env!("CARGO_PKG_VERSION").into();
        release.source = source;
        let binary = unpack_binary(&fs::read(path).unwrap(), &release).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join(if cfg!(windows) {
            "drcom4scut.exe"
        } else {
            "drcom4scut"
        });
        fs::write(&executable, b"old image").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        }
        install_binary(&executable, &binary).unwrap();
        let output = std::process::Command::new(executable)
            .arg("--version")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            concat!("drcom4scut ", env!("CARGO_PKG_VERSION"))
        );
    }
}
