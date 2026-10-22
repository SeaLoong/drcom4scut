#!/bin/sh
# Optional UI integration for an already-installed LuCI/rpcd environment.
set -eu
umask 022
package_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
source_dir="$package_dir/luci-app-drcom4scut"
[ -f /etc/openwrt_release ] || { echo 'This installer requires OpenWrt.' >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo 'Run as root.' >&2; exit 1; }
[ -d /www/luci-static/resources/view ] && [ -x /sbin/rpcd ] && [ -r /usr/share/libubox/jshn.sh ] || {
	echo 'Install luci-base, rpcd, jshn and logd first.' >&2; exit 1;
}
[ -x /etc/init.d/drcom4scut ] && [ -f /etc/config/drcom4scut ] || {
	echo 'Install the core OpenWrt service first (openwrt/install.sh).' >&2; exit 1;
}
# Each resource has a fixed source/destination; no request-controlled file copy.
install_asset() {
	local source="$1" destination="$2" mode="$3" temporary
	[ -f "$source" ] && [ ! -L "$source" ] || { echo 'A required LuCI resource is missing.' >&2; exit 1; }
	mkdir -p "$(dirname -- "$destination")"
	temporary="$destination.drcom4scut-new.$$"
	cp "$source" "$temporary"
	chmod "$mode" "$temporary"
	mv -f "$temporary" "$destination"
}
install_asset "$source_dir/htdocs/luci-static/resources/view/drcom4scut.js" /www/luci-static/resources/view/drcom4scut.js 644
install_asset "$source_dir/root/usr/share/luci/menu.d/luci-app-drcom4scut.json" /usr/share/luci/menu.d/luci-app-drcom4scut.json 644
install_asset "$source_dir/root/usr/share/rpcd/acl.d/luci-app-drcom4scut.json" /usr/share/rpcd/acl.d/luci-app-drcom4scut.json 644
install_asset "$source_dir/root/usr/libexec/rpcd/drcom4scut" /usr/libexec/rpcd/drcom4scut 755
install_asset "$source_dir/root/usr/libexec/drcom4scut-luci-sanitize.sh" /usr/libexec/drcom4scut-luci-sanitize.sh 644
# LuCI keeps its compiled menu/modules under /tmp. Remove only its named caches.
rm -f /tmp/luci-indexcache
rm -rf /tmp/luci-modulecache
/etc/init.d/rpcd restart
[ ! -x /etc/init.d/uhttpd ] || /etc/init.d/uhttpd reload
echo 'LuCI resources installed. Sign in again and open Services / SCUT DrCOM.'
echo 'Authentication is not automatically enabled; passwords remain in the private root-owned file.'
