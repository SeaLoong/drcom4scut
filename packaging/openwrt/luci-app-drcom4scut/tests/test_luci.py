"""Rootless package, RPC scope and privacy fixtures; no router runtime claimed."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest

PACKAGE = Path(__file__).resolve().parents[1]
PLUGIN = PACKAGE / 'root/usr/libexec/rpcd/drcom4scut'
SANITIZE = PACKAGE / 'root/usr/libexec/drcom4scut-luci-sanitize.sh'
VIEW = PACKAGE / 'htdocs/luci-static/resources/view/drcom4scut.js'


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
