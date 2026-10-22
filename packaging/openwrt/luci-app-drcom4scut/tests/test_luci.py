"""Rootless package, RPC scope and privacy fixtures; no router runtime claimed."""
import json
import os
import tempfile
from pathlib import Path
import shutil
import subprocess
import unittest

PACKAGE = Path(__file__).resolve().parents[1]
PLUGIN = PACKAGE / 'root/usr/libexec/rpcd/drcom4scut'
SANITIZE = PACKAGE / 'root/usr/libexec/drcom4scut-luci-sanitize.sh'
VIEW = PACKAGE / 'htdocs/luci-static/resources/view/drcom4scut.js'


def backend_action(method, enabled, service_result=0):
    """Execute production dispatch with only fixed OpenWrt dependencies replaced."""
    with tempfile.TemporaryDirectory(prefix='luci-rpc-') as directory:
        directory = Path(directory)
        service_log, uci_log = directory / 'service.log', directory / 'uci.log'
        shim = directory / 'jshn.sh'
        shim.write_text(r'''json_init() { result_success=0; result_error=''; }
json_add_boolean() { [ "$1" != success ] || result_success="$2"; }
json_add_string() { [ "$1" != error ] || result_error="$2"; }
json_dump() {
    if [ "$result_success" = 1 ]; then printf '{"success":true}\n';
    else printf '{"success":false,"error":"%s"}\n' "$result_error"; fi
}
''')
        service = directory / 'service'
        service.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> "$SERVICE_LOG"\nexit "$SERVICE_RESULT"\n')
        uci = directory / 'uci'
        uci.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> "$UCI_LOG"\nprintf "%s\\n" "$SAVED_ENABLED"\n')
        service.chmod(0o755)
        uci.chmod(0o755)
        source = PLUGIN.read_text()
        source = source.replace('. /usr/share/libubox/jshn.sh', '. "$FIXTURE_JSHN"')
        source = source.replace('. /usr/libexec/drcom4scut-luci-sanitize.sh', '. "$FIXTURE_SANITIZE"')
        source = source.replace('readonly SERVICE=/etc/init.d/drcom4scut', 'readonly SERVICE="$FIXTURE_SERVICE"')
        source = source.replace('/sbin/uci -q get drcom4scut.main.enabled', '"$FIXTURE_UCI" -q get drcom4scut.main.enabled')
        plugin = directory / 'rpc-plugin'
        plugin.write_text(source)
        environment = dict(os.environ, FIXTURE_JSHN=str(shim), FIXTURE_SANITIZE=str(SANITIZE),
                           FIXTURE_SERVICE=str(service), FIXTURE_UCI=str(uci), SERVICE_LOG=str(service_log),
                           UCI_LOG=str(uci_log), SAVED_ENABLED=enabled, SERVICE_RESULT=str(service_result))
        result = subprocess.run(['sh', str(plugin), 'call', method], input='{}', text=True,
                                capture_output=True, env=environment, check=True)
        return json.loads(result.stdout), (service_log.read_text().splitlines() if service_log.exists() else []), (uci_log.read_text().splitlines() if uci_log.exists() else [])


class LuciTests(unittest.TestCase):
    def classify(self, function, text):
        # Input is stdin and is never interpolated into a shell command.
        command = '. "$1"; IFS= read -r line; "$2" "$line"'
        return subprocess.check_output(['sh', '-c', command, 'fixture', str(SANITIZE), function], input=text + '\n', text=True)

    def test_acl_exposes_only_its_uci_and_fixed_rpc_methods(self):
        data = json.loads((PACKAGE / 'root/usr/share/rpcd/acl.d/luci-app-drcom4scut.json').read_text())
        self.assertEqual(set(data), {'luci-app-drcom4scut'})
        acl = data['luci-app-drcom4scut']
        self.assertEqual(acl['read'], {'ubus': {'drcom4scut': ['status', 'logs', 'diagnostics']}, 'uci': ['drcom4scut']})
        self.assertEqual(acl['write'], {'ubus': {'drcom4scut': ['start', 'stop', 'restart']}, 'uci': ['drcom4scut']})
        self.assertNotIn('file', json.dumps(acl))
        self.assertNotIn('exec', json.dumps(acl))

    def test_plugin_lists_no_arguments_and_rejects_arbitrary_commands(self):
        methods = json.loads(subprocess.check_output([str(PLUGIN), 'list'], text=True))
        self.assertEqual(set(methods), {'status', 'logs', 'diagnostics', 'start', 'stop', 'restart'})
        self.assertTrue(all(value == {} for value in methods.values()))
        for method in ['exec', 'read', 'cat /etc/shadow', 'start;reboot', '../../password', '']:
            result = subprocess.run([str(PLUGIN), 'call', method], input='{}', text=True, capture_output=True)
            self.assertEqual(result.returncode, 3)
            self.assertEqual(result.stdout, '')

    def test_disabled_start_and_restart_are_rejected_without_init_execution(self):
        for method in ['start', 'restart']:
            for enabled in ['0', '']:
                with self.subTest(method=method, enabled=enabled):
                    result, service_calls, uci_calls = backend_action(method, enabled)
                    self.assertEqual(result, {'success': False, 'error': 'disabled'})
                    self.assertEqual(service_calls, [])
                    self.assertEqual(uci_calls, ['-q', 'get', 'drcom4scut.main.enabled'])

    def test_enabled_start_and_restart_use_only_the_fixed_action(self):
        for method in ['start', 'restart']:
            with self.subTest(method=method):
                result, service_calls, uci_calls = backend_action(method, '1')
                self.assertEqual(result, {'success': True})
                self.assertEqual(service_calls, [method])
                self.assertEqual(uci_calls, ['-q', 'get', 'drcom4scut.main.enabled'])
        result, _, _ = backend_action('start', '1', service_result=1)
        self.assertEqual(result, {'success': False, 'error': 'operation-failed'})

    def test_stop_remains_available_when_persistent_enable_is_off(self):
        result, service_calls, uci_calls = backend_action('stop', '0')
        self.assertEqual(result, {'success': True})
        self.assertEqual(service_calls, ['stop'])
        self.assertEqual(uci_calls, [])

    def test_logs_never_return_raw_server_or_client_content(self):
        secret = 'fixture-private-password-without-any-label'
        for line, expected in [
            ('EAP server notification: ' + secret, 'server-notice-redacted'),
            ('Server information: ' + secret, 'server-notice-redacted'),
            (secret, 'message-redacted'),
            ('[ERROR] UDP send failed: ' + secret, 'transport-error'),
            ('[INFO] 802.1X Authorization success! ' + secret, 'eap-authenticated'),
            ('[INFO] UDP heartbeat completed. ' + secret, 'udp-heartbeat')
        ]:
            with self.subTest(line=line):
                output = self.classify('drcom_event', line)
                self.assertEqual(output, expected)
                self.assertNotIn(secret, output)

    def test_metadata_is_limited_to_safe_fields_and_lengths(self):
        self.assertEqual(self.classify('drcom_phase', 'online'), 'online')
        self.assertEqual(self.classify('drcom_phase', '<script>secret</script>'), 'unavailable')
        self.assertEqual(self.classify('drcom_interface', 'eth0.2'), 'eth0.2')
        self.assertEqual(self.classify('drcom_interface', 'eth0;secret'), '')
        self.assertEqual(self.classify('drcom_version', '0.4.0'), '0.4.0')
        self.assertEqual(self.classify('drcom_version', 'private-account-name'), 'unknown')
        self.assertEqual(self.classify('drcom_version', 'A' * 49), 'unknown')
        self.assertEqual(self.classify('drcom_updated', 'secret-account-name'), '')

    def test_shell_and_javascript_parse(self):
        for script in [PLUGIN, SANITIZE]:
            subprocess.run(['sh', '-n', str(script)], check=True)
        self.assertIsNotNone(shutil.which('node'), 'Node is required for LuCI syntax fixtures')
        subprocess.run(['node', '--check', str(VIEW)], check=True)

    def test_authored_view_uses_private_paths_and_redacts_export(self):
        subprocess.run(['node', str(PACKAGE / 'tests/view_fixture.cjs'), str(VIEW)], check=True)

    def test_backend_has_no_secret_file_reader_or_dynamic_command(self):
        source = PLUGIN.read_text()
        self.assertNotIn('/etc/drcom4scut/password', source)
        self.assertNotIn('eval ', source)
        self.assertIn('readonly STATUS_FILE=/var/run/drcom4scut/status.json', source)
        self.assertIn('head -c 8192 "$STATUS_FILE"', source)
        self.assertIn('if [ "$diagnostic" = 0 ]; then json_add_string interface', source)
        self.assertNotIn('json_add_string password', source)
        self.assertNotIn('json_add_string username', source)


if __name__ == '__main__':
    unittest.main()
