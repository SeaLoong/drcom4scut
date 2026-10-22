# LuCI administration package

This independently authored package uses the public [LuCI JavaScript APIs](https://openwrt.github.io/luci/jsapi/) and [rpcd executable plugin protocol](https://openwrt.org/docs/techref/rpcd). It does not copy source from other clients or AGPL LuCI applications. The source is covered by this repository's LGPL-3.0-or-later license.

The package provides connection status, start/stop/reconnect, safe categories for recent events, UCI service settings, and a JSON diagnostics download. It never reads password files or puts a password input in the browser. Accounts and passwords remain in the root-owned private core configuration/password files maintained through SSH.

Install the architecture-matched core and procd integration first. The LuCI package is architecture-independent; its rpcd helper supervises the fixed `/etc/init.d/drcom4scut` service and reads only `/var/run/drcom4scut/status.json`. It does not execute a path or command supplied by the browser.

## SDK package build

Within a matching OpenWrt SDK with the LuCI feed installed, copy this directory into `package/luci-app-drcom4scut` and build:

```sh
make package/luci-app-drcom4scut/compile V=s
```

The package depends on `luci-base`, `rpcd`, `jshn`, and `logd`. Install the resulting architecture-independent package (`.ipk` or `.apk`, as produced by that SDK) using the package manager for that OpenWrt release. See the parent OpenWrt installation guide for the optional source-asset installer when an SDK is unavailable. Reload rpcd/uhttpd, sign back into LuCI, then open **Services → SCUT DrCOM**. Preserve the existing authentication and HTTPS settings for LuCI; this application does not create anonymous access.

## Data and permission boundaries

The `luci-app-drcom4scut` ACL permits only its own UCI namespace and six fixed `drcom4scut` methods. There are no `file`, generic `exec`, wildcard ubus, or credential-read grants. A LuCI account granted write access can control this service and its dedicated configuration paths. Those paths are confined to direct files in the root-private `/etc/drcom4scut` directory by the procd service.

Status is limited to known phase/version/interface/time fields and booleans. Diagnostics additionally omit process identifiers and interface/IP/MAC/account information. Recent logs contain only allowlisted event categories and levels: arbitrary client/server message text is not sent to the browser. This avoids guessing which unstructured server text might contain credentials. Full messages remain available to an administrator through the router's system log.

## Validation

```sh
python3 -m unittest discover -s packaging/openwrt/luci-app-drcom4scut/tests -v
```

Tests execute the RPC allowlist rejection paths, shell sanitizers, and the authored JavaScript view against LuCI API fixtures. They check credential exclusion, path confinement, unknown fields, and diagnostic export. Shell/JSON/JavaScript syntax is validated. These tests are not a native OpenWrt/rpcd browser run; package installation, routing, and campus authentication still need validation on the target router.
