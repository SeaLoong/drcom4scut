"""Build a MIPS musl std with the pinned stable compiler, without rebuilding rustc.

Rust's supported bootstrap local-rebuild/stage0 path compiles the cross standard
library. Bootstrap uses its normal internal feature gates; application Cargo
commands need neither nightly nor RUSTC_BOOTSTRAP. Downloads retain TLS checking
and are checked against independently pinned source archive hashes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile
import urllib.request

RUST_VERSION = "1.99.1"
HOST = "x86_64-unknown-linux-gnu"
TARGETS = {
    "mips-unknown-linux-musl": "mips",
    "mipsel-unknown-linux-musl": "mipsel",
    "mips64-unknown-linux-muslabi64": "mips64",
    "mips64el-unknown-linux-muslabi64": "mips64el",
    "mips64-openwrt-linux-musl": "mips64-openwrt",
}
# Rust: https://static.rust-lang.org/dist/rustc-1.99.1-src.tar.xz.sha256
# musl: OpenWrt openwrt-24.10/toolchain/musl/common.mk, PKG_VERSION=1.2.5.
SOURCES = {
    "rust": (f"https://static.rust-lang.org/dist/rustc-{RUST_VERSION}-src.tar.xz",
             "6451598a99e77f07571960f6b21d577399d3a30f33e80cbd2e3a4aae6535d265"),
    "musl": ("https://musl.libc.org/releases/musl-1.2.5.tar.gz",
             "a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4"),
}


def run(arguments, *, cwd=None, env=None, capture=False):
    return subprocess.run([str(argument) for argument in arguments], cwd=cwd,
                          env=env, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def checked_target(target):
    if target not in TARGETS:
        raise ValueError("Only reviewed MIPS32r2 O32 and MIPS64r2 N64 musl targets are supported")
    return TARGETS[target]


def compiler_flags(target):
    arch = checked_target(target)
    if target == "mips64-openwrt-linux-musl":
        return ["-mips64r2", "-msoft-float", "-mabi=64"]
    if arch.startswith("mips64"):
        return ["-mips64r2", "-mhard-float", "-mabi=64"]
    return ["-mips32r2", "-msoft-float", "-mabi=32"]


def verify_archive(path, expected):
    with Path(path).open("rb") as source:
        actual = hashlib.file_digest(source, "sha256").hexdigest()
    if actual != expected:
        raise ValueError(f"Source SHA-256 mismatch: {Path(path).name}")


def download_source(kind, cache):
    url, expected = SOURCES[kind]
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / url.rsplit("/", 1)[-1]
    if not archive.exists():
        temporary = archive.with_suffix(archive.suffix + ".partial")
        try:
            with urllib.request.urlopen(url, timeout=120) as response, temporary.open("wb") as output:
                shutil.copyfileobj(response, output, length=1024 * 1024)
            verify_archive(temporary, expected)
            temporary.replace(archive)
        finally:
            temporary.unlink(missing_ok=True)
    verify_archive(archive, expected)
    return archive, expected


def unpack(archive, destination, directory, expected):
    """Extract only a verified source; refuse unmarked pre-existing source trees."""
    verify_archive(archive, expected)
    root = destination / directory
    marker = root / ".drcom-source-sha256"
    if root.exists():
        if not marker.is_file() or marker.read_text().strip() != expected:
            raise ValueError(f"Refusing to reuse an unverified source directory: {root}")
        return root
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as source:
        if any(member.name.split("/", 1)[0] != directory for member in source.getmembers()):
            raise ValueError("Unexpected source archive root")
        source.extractall(destination, filter="data")
    marker.write_text(expected + "\n")
    return root


def compiler_sysroot():
    # Re-running setup after GITHUB_ENV has activated the custom toolchain must
    # still select the original official compiler. Prefer the versioned install;
    # local environments may already have the exact release installed as stable.
    names = {line.split()[0] for line in run(["rustup", "toolchain", "list"], capture=True).splitlines() if line.strip()}
    selected = RUST_VERSION if f"{RUST_VERSION}-{HOST}" in names else "stable"
    command = ["rustup", "run", selected, "rustc"]
    info = run([*command, "--version", "--verbose"], capture=True)
    fields = dict(line.split(": ", 1) for line in info.splitlines() if ": " in line)
    if fields.get("release") != RUST_VERSION or fields.get("host") != HOST:
        raise ValueError(f"Use the official stable Rust {RUST_VERSION} {HOST} compiler")
    return Path(run([*command, "--print", "sysroot"], capture=True).strip()).resolve()


def tool_path(value):
    found = shutil.which(value)
    if found is None:
        raise ValueError(f"Required tool was not found: {value}")
    return Path(found).absolute()


def write_wrapper(path, command):
    path.write_text("#!/bin/sh\nexec " + " ".join(shlex.quote(str(part)) for part in command) + ' "$@"\n')
    path.chmod(0o755)


def bootstrap_config(work, stable, target, sysroot, cc, cxx, ar, ranlib, jobs):
    checked_target(target)
    q = lambda value: json.dumps(str(value))
    return f'''change-id = 160100
[build]
build = "{HOST}"
host = ["{HOST}"]
target = ["{target}"]
rustc = {q(stable / 'bin/rustc')}
cargo = {q(stable / 'bin/cargo')}
build-dir = {q(work / 'build')}
local-rebuild = true
submodules = false
docs = false
extended = false
optimized-compiler-builtins = false
jobs = {jobs}
[rust]
channel = "stable"
download-rustc = false
[target.{target}]
cc = {q(cc)}
cxx = {q(cxx)}
ar = {q(ar)}
ranlib = {q(ranlib)}
linker = {q(cc)}
musl-root = {q(sysroot)}
crt-static = true
llvm-libunwind = "in-tree"
'''


def isolated_compiler(stable, isolated):
    """Link immutable host files individually, leaving target directories writable."""
    if isolated.resolve() == stable.resolve():
        raise ValueError("The cross sysroot must be separate from the installed host toolchain")
    if not isolated.exists():
        (isolated / "lib/rustlib").mkdir(parents=True)
        # Keep compiler executables inside the isolated layout rather than
        # redirecting their paths to the host toolchain.
        shutil.copytree(stable / "bin", isolated / "bin", symlinks=True)
        for path in (stable / "lib").iterdir():
            if path.name != "rustlib":
                destination = isolated / "lib" / path.name
                if path.name.startswith("librustc_driver"):
                    # The driver also derives the sysroot from its real dylib
                    # path. Copy it; LLVM and host std can remain shared.
                    shutil.copy2(path, destination)
                else:
                    destination.symlink_to(path, target_is_directory=path.is_dir())
        (isolated / "lib/rustlib" / HOST).symlink_to(stable / "lib/rustlib" / HOST, target_is_directory=True)
    # Never allow a prefix that redirects installation into the host's rustlib.
    if (isolated / "lib/rustlib").resolve() == (stable / "lib/rustlib").resolve():
        raise ValueError("The isolated target library directory must not point into the host sysroot")
    for path in (stable / "lib").glob("librustc_driver*"):
        destination = isolated / "lib" / path.name
        if destination.is_symlink():
            destination.unlink()
            shutil.copy2(path, destination)


def github_environment(path, values):
    if any("\n" in value or "\r" in value for value in values.values()):
        raise ValueError("Environment export values must each occupy one line")
    # Export only after installation/validation succeeds. One complete append
    # preserves previous workflow settings without reading their possible secrets.
    with path.open("a") as output:
        output.write("".join(f"{key}={value}\n" for key, value in values.items()))


def bootstrap_environment(environment):
    # Bootstrap owns its host/target flags and artifact directories. Application
    # overrides must not leak into it, especially a previous target's float ABI.
    result = dict(environment)
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR"):
        result.pop(key, None)
    for key in list(result):
        if any(key == flag or key.startswith(flag + "_") or key.endswith("_" + flag)
               for flag in ("CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS")):
            result.pop(key)
    return result


def setup(args):
    arch = checked_target(args.target)
    stable = compiler_sysroot()
    work, prefix = args.work_dir.resolve(), args.prefix.resolve()
    cache = (args.download_dir or work / "downloads").resolve()
    work.mkdir(parents=True, exist_ok=True)
    prefix.mkdir(parents=True, exist_ok=True)
    clang, clangxx, ar, ranlib = (tool_path(value) for value in
                                (args.clang, args.clangxx, args.ar, args.ranlib))
    rust_archive, rust_hash = download_source("rust", cache)
    musl_archive, musl_hash = download_source("musl", cache)
    print("Verified pinned Rust and musl source archives; preparing bootstrap sources.", flush=True)
    rust = unpack(rust_archive, work, f"rustc-{RUST_VERSION}-src", rust_hash)
    musl = unpack(musl_archive, work, "musl-1.2.5", musl_hash)
    binaries = prefix / "bin"
    binaries.mkdir(exist_ok=True)
    linker = stable / "lib/rustlib" / HOST / "bin/rust-lld"
    write_wrapper(binaries / "ld.lld", [linker, "-flavor", "gnu"])
    sysroot = prefix / f"{arch}-musl"
    # LLVM uses musl rather than Rust's muslabi64 suffix; the explicit N64
    # compiler flag selects the matching C ABI for the 64-bit targets.
    clang_target = args.target.replace("muslabi64", "musl")
    common = ["-no-canonical-prefixes", f"--target={clang_target}", f"--sysroot={sysroot}",
              *compiler_flags(args.target), f"-fuse-ld={binaries / 'ld.lld'}"]
    cc, cxx = binaries / f"{arch}-linux-musl-gcc", binaries / f"{arch}-linux-musl-g++"
    write_wrapper(cc, [clang, *common])
    write_wrapper(cxx, [clangxx, *common])
    native = work / f"musl-build-{arch}"
    native.mkdir(exist_ok=True)
    env = bootstrap_environment(os.environ) | {"CC": str(cc), "AR": str(ar), "RANLIB": str(ranlib)}
    run([musl / "configure", f"--target={clang_target}", f"--prefix={sysroot}",
         "--disable-shared", "--disable-gcc-wrapper"], cwd=native, env=env)
    run(["make", f"-j{args.jobs}"], cwd=native, env=env)
    run(["make", "install"], cwd=native, env=env)
    config = work / f"bootstrap-{arch}.toml"
    config.write_text(bootstrap_config(work, stable, args.target, sysroot, cc, cxx, ar, ranlib, args.jobs))
    run(["python3", rust / "x.py", "--config", config, "dist", "--stage", "0",
         "--target", args.target, "rust-std"], cwd=rust, env=bootstrap_environment(os.environ))
    isolated = prefix / f"rust-{RUST_VERSION}"
    isolated_compiler(stable, isolated)
    component = work / "build/tmp/tarball/rust-std" / args.target / f"rust-std-{RUST_VERSION}-{args.target}"
    run(["bash", component / "install.sh", f"--prefix={isolated}", "--disable-ldconfig"])
    toolchain = f"drcom-{arch}-{RUST_VERSION}"
    run(["rustup", "toolchain", "link", toolchain, isolated])
    upper = args.target.upper().replace("-", "_")
    lower = args.target.replace("-", "_")
    values = {"RUSTUP_TOOLCHAIN": toolchain, f"CC_{lower}": str(cc), f"CXX_{lower}": str(cxx),
              f"AR_{lower}": str(ar), f"CARGO_TARGET_{upper}_LINKER": str(linker)}
    # Confirm the self-contained std exists before publishing environment state.
    lib = isolated / "lib/rustlib" / args.target / "lib"
    if not list(lib.glob("libstd-*.rlib")) or not (lib / "self-contained/libc.a").is_file():
        raise ValueError("Bootstrap did not install the complete cross standard library")
    selected_lib = Path(run(["rustup", "run", toolchain, "rustc", "--print", "target-libdir",
                             "--target", args.target], capture=True).strip())
    if selected_lib.resolve() != lib.resolve():
        raise ValueError("The compiler did not select the isolated cross standard library")
    if args.github_env:
        github_environment(args.github_env, values)
    (work / f"environment-{arch}.json").write_text(json.dumps(values, indent=2) + "\n")
    print(f"Prepared stable Rust {RUST_VERSION} standard library for {args.target}; application builds retain stable Cargo and TLS.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    if sys.version_info < (3, 12):
        parser.error("Python 3.12 or newer is required for verified source extraction")
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--download-dir", type=Path)
    parser.add_argument("--github-env", type=Path)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--clangxx", default="clang++")
    parser.add_argument("--ar", default="llvm-ar")
    parser.add_argument("--ranlib", default="llvm-ranlib")
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1 or args.jobs > 32:
        parser.error("--jobs must be between 1 and 32")
    setup(args)
