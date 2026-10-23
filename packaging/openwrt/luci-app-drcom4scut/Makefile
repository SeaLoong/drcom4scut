include $(TOPDIR)/rules.mk

PKG_VERSION:=0.5.1
PKG_RELEASE:=1
PKG_LICENSE:=LGPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE

LUCI_TITLE:=SCUT DrCOM client administration
LUCI_DEPENDS:=+luci-base +rpcd +jshn +logd
LUCI_PKGARCH:=all

include $(TOPDIR)/feeds/luci/luci.mk

# This package is independently authored against LuCI/rpcd public APIs.
# It does not bundle or build the architecture-specific authentication binary.
