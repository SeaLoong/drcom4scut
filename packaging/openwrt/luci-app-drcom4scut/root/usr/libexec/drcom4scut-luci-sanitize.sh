#!/bin/sh
# Only allow known metadata and event categories into the browser. Raw server
# text may contain credentials even when it has no recognizable "password" key.

drcom_phase() {
	case "$1" in
		online|offline|waiting-interface|eap-authentication|udp-authentication) printf '%s' "$1" ;;
		*) printf 'unavailable' ;;
	esac
}

drcom_version() {
	if [ "${#1}" -le 48 ] && printf '%s' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
		printf '%s' "$1"
	else
		printf 'unknown'
	fi
}

drcom_interface() {
	case "$1" in
		''|*[!0-9A-Za-z_.:@-]*) printf '' ;;
		*) [ "${#1}" -le 32 ] && printf '%s' "$1" || printf '' ;;
	esac
}

drcom_updated() {
	case "$1" in
		''|*[!0-9TtZz:,.+-]*) printf '' ;;
		*) [ "${#1}" -le 40 ] && printf '%s' "$1" || printf '' ;;
	esac
}

drcom_event() {
	case "$1" in
		*'802.1X Authorization success!'*) printf 'eap-authenticated' ;;
		*'UDP heartbeat completed.'*) printf 'udp-heartbeat' ;;
		*'EAP response timed out'*|*'EAP heartbeat timed out'*) printf 'eap-timeout' ;;
		*'UDP response timeout'*) printf 'udp-timeout' ;;
		*'Cannot resolve '*|*'DNS lookup using '*' failed:'*) printf 'dns-error' ;;
		*'Shutdown requested.'*) printf 'shutdown' ;;
		*'EAP transport error:'*|*'UDP send failed:'*|*'UDP receive failed:'*) printf 'transport-error' ;;
		*'EAP server notification:'*|*'Server information:'*) printf 'server-notice-redacted' ;;
		*) printf 'message-redacted' ;;
	esac
}

drcom_level() {
	case "$1" in
		*'[ERROR]'*|*' err '*|*'.err '*) printf 'error' ;;
		*'[WARN]'*|*' warn '*|*'.warn '*) printf 'warning' ;;
		*) printf 'info' ;;
	esac
}
