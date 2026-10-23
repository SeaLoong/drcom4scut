#!/bin/sh
# Run from an extracted, architecture-matched release package on OpenWrt.
set -eu
umask 077
package_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
. "$package_dir/openwrt/install-common.sh"
[ -f /etc/openwrt_release ] || { echo 'This installer requires OpenWrt.' >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo 'Run as root.' >&2; exit 1; }
[ -x "$package_dir/drcom4scut" ] || { echo 'Release executable is missing.' >&2; exit 1; }
# Execute before changing the system: wrong-CPU/ABI packages fail here.
"$package_dir/drcom4scut" --version
require_root_owned_existing /etc/drcom4scut directory
mkdir -p /etc/drcom4scut
chmod 700 /etc/drcom4scut
require_root_owned_existing /etc/drcom4scut/config.yml file
require_root_owned_existing /etc/drcom4scut/password file
require_root_owned_existing /etc/config/drcom4scut file
# Do not overwrite accounts, credentials, or an existing service configuration.
[ -e /etc/drcom4scut/config.yml ] || cp "$package_dir/openwrt/files/config.yml" /etc/drcom4scut/config.yml
chmod 600 /etc/drcom4scut/config.yml
[ -e /etc/config/drcom4scut ] || cp "$package_dir/openwrt/files/drcom4scut.uci" /etc/config/drcom4scut
chmod 600 /etc/config/drcom4scut
if [ ! -e /etc/drcom4scut/password ]; then
	: > /etc/drcom4scut/password
fi
chmod 600 /etc/drcom4scut/password
temporary_binary="/usr/bin/.drcom4scut.$$"
temporary_service="/etc/init.d/.drcom4scut.$$"
trap 'rm -f "$temporary_binary" "$temporary_service"' 0
trap 'exit 1' HUP INT TERM
cp "$package_dir/drcom4scut" "$temporary_binary"
chmod 755 "$temporary_binary"
mv -f "$temporary_binary" /usr/bin/drcom4scut
cp "$package_dir/openwrt/files/drcom4scut.init" "$temporary_service"
chmod 755 "$temporary_service"
mv -f "$temporary_service" /etc/init.d/drcom4scut
echo 'Installed without starting the service; existing enabled settings are preserved. See docs/openwrt.md.'
