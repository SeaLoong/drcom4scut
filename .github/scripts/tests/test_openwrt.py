"""Exercise procd arguments/security gates without root or an OpenWrt host."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SERVICE = ROOT / "packaging/openwrt/files/drcom4scut.init"
HARNESS = r'''
config_load() { :; }
config_get_bool() { eval "$1=\"$ENABLED\""; }
config_get() {
    case "$3" in
        config) eval "$1=\"$CLIENT_CONFIG\"" ;;
        password_file) eval "$1=\"$PASSWORD_FILE\"" ;;
        interface) eval "$1=\"eth0.2\"" ;;
        network) eval "$1=\"wan\"" ;;
    esac
}
stat() { printf '%s\n' "$FILE_MODE"; }
logger() { printf 'LOG:%s\n' "$*"; }
procd_open_instance() { printf 'OPEN\n'; }
procd_set_param() { printf 'PARAM'; printf '<%s>' "$@"; printf '\n'; }
procd_close_instance() { printf 'CLOSE\n'; }
procd_add_reload_trigger() { printf 'RELOAD:%s\n' "$*"; }
procd_add_interface_trigger() { printf 'TRIGGER'; printf '<%s>' "$@"; printf '\n'; }
. "$SERVICE_FILE"
validate_private_config() { :; }
prepare_status_directory() { printf 'STATUSDIR\n'; }
start_service
'''


class OpenWrtServiceTests(unittest.TestCase):
    def run_service(self, mode="0:600", enabled="1", symlink=False):
        with tempfile.TemporaryDirectory(prefix="drcom-service-") as directory:
            directory = Path(directory)
            config = directory / "account config.yml"
            config.write_text("username: student\n")
            password = directory / "private password"
            password.write_text("never-expose-this-password\n")
            if symlink:
                link = directory / "link"
                link.symlink_to(password)
                password = link
            env = dict(os.environ, SERVICE_FILE=str(SERVICE), CLIENT_CONFIG=str(config),
                       PASSWORD_FILE=str(password), FILE_MODE=mode, ENABLED=enabled)
            result = subprocess.run(["sh", "-c", HARNESS], env=env, text=True, capture_output=True)
            return result, str(config), str(password)

    def test_private_file_is_passed_by_path_and_interface_is_explicit(self):
        result, config, password = self.run_service()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"<--config><{config}><--password-file><{password}><--interface><eth0.2>", result.stdout)
        self.assertNotIn("never-expose-this-password", result.stdout + result.stderr)
        self.assertIn("PARAM<respawn><3600><5><5>", result.stdout)

    def test_public_or_foreign_owned_credentials_never_start_process(self):
        for mode in ["0:644", "1000:600", "0:666", ""]:
            with self.subTest(mode=mode):
                result, _, _ = self.run_service(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("OPEN", result.stdout)
                self.assertNotIn("never-expose-this-password", result.stdout)

    def test_symlink_credentials_are_rejected(self):
        result, _, _ = self.run_service(symlink=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("OPEN", result.stdout)

    def test_disabled_service_does_not_start(self):
        result, _, _ = self.run_service(enabled="0")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_layer2_device_is_available_before_dhcp(self):
        script = r'''
. "$SERVICE_FILE"
network_get_physdev() { interface=eth0.2; return 0; }
network_get_device() { echo 'L3_NOT_READY' >&2; return 1; }
network=wan
resolve_network_device
printf '%s' "$interface"
'''
        env = dict(os.environ, SERVICE_FILE=str(SERVICE))
        result = subprocess.run(["sh", "-c", script], env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "eth0.2")
        self.assertNotIn("L3_NOT_READY", result.stderr)

    def test_uci_paths_cannot_escape_the_private_config_directory(self):
        env = dict(os.environ, SERVICE_FILE=str(SERVICE))
        for path, accepted in [
            ("/etc/drcom4scut/config.yml", True),
            ("/etc/drcom4scut/password-2", True),
            ("/etc/shadow", False),
            ("/tmp/root-hook.yml", False),
            ("/etc/drcom4scut/../shadow", False),
            ("/etc/drcom4scut/../../etc/shadow", False),
            ("/etc/drcom4scut/.", False),
            ("/etc/drcom4scut/subdir/file", False),
            ("/etc/drcom4scut/", False),
        ]:
            with self.subTest(path=path):
                result = subprocess.run(["sh", "-c", '. "$SERVICE_FILE"; private_config_path "$1"', "test", path], env=env)
                self.assertEqual(result.returncode == 0, accepted)

    def test_installer_refuses_symlinks_foreign_owners_and_wrong_types(self):
        helper = ROOT / "packaging/openwrt/install-common.sh"
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            ordinary = directory / "private"
            ordinary.write_text("not read by the validator")
            if os.geteuid() == 0:
                os.chown(ordinary, 1001, 1001)
            symlink = directory / "link"
            symlink.symlink_to(ordinary)
            for path, kind in [(ordinary, "file"), (symlink, "file"), (directory, "file")]:
                with self.subTest(path=path, kind=kind):
                    result = subprocess.run(["sh", "-c", '. "$1"; require_root_owned_existing "$2" "$3"', "test", str(helper), str(path), kind], capture_output=True)
                    self.assertNotEqual(result.returncode, 0)
            missing = directory / "new-file"
            subprocess.run(["sh", "-c", '. "$1"; require_root_owned_existing "$2" file', "test", str(helper), str(missing)], check=True)

    def test_shell_files_parse(self):
        for script in [SERVICE, ROOT / "packaging/openwrt/install.sh", ROOT / "packaging/openwrt/install-luci.sh", ROOT / "packaging/openwrt/install-common.sh"]:
            subprocess.run(["sh", "-n", str(script)], check=True)


if __name__ == "__main__":
    unittest.main()
