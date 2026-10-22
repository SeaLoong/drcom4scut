#!/bin/sh
# Attribute-only destination checks. Never follow a pre-existing symbolic link.
require_root_owned_existing() {
	local path="$1" kind="$2"
	[ ! -L "$path" ] || { echo 'Refusing a symbolic-link installation destination.' >&2; return 1; }
	[ -e "$path" ] || return 0
	case "$kind" in
		directory) [ -d "$path" ] || return 1 ;;
		file) [ -f "$path" ] || return 1 ;;
		*) return 1 ;;
	esac
	[ "$(stat -c '%u' "$path" 2>/dev/null)" = 0 ] || {
		echo 'Existing private configuration must be audited and owned by root.' >&2
		return 1
	}
}
