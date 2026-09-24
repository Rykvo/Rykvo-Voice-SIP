import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installer', REPO / 'deploy/manage.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class InstallerTests(unittest.TestCase):
    def test_network_validation(self):
        result = m.validate_network('8.8.8.8', '10.0.0.5', 'ens3')
        self.assertEqual(result['SIP_PUBLIC_IF'], 'ens3')
        self.assertEqual(result['SIP_BIND_IP'], '10.0.0.5')
        for public, bind, interface in [('127.0.0.1', '10.0.0.5', 'ens3'),
                                       ('8.8.8.8', '127.0.0.1', 'ens3'),
                                       ('8.8.8.8', '10.0.0.5', 'eth0; reboot')]:
            with self.assertRaises(ValueError):
                m.validate_network(public, bind, interface)

    def test_atomic_private_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private.json'
            m.write(path, {'value': 'fixture'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(path.with_name(path.name + '.tmp').exists())
            m.write(path, {'value': 'updated'})
            self.assertIn('updated', path.read_text())

    def test_remove_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'project'
            root.mkdir()
            outside = Path(directory) / 'other'
            outside.mkdir()
            owned = root / 'app-next'
            owned.mkdir()
            with patch.object(m, 'ROOT', root):
                with self.assertRaises(ValueError):
                    m.bounded_remove(outside)
                m.bounded_remove(owned)
            self.assertTrue(outside.exists())
            self.assertFalse(owned.exists())

    def test_uninstall_requires_owned_marker(self):
        with patch.object(m, 'read_marker', side_effect=ValueError('unmanaged')), patch.object(m, 'run') as run:
            with self.assertRaises(ValueError):
                m.uninstall()
            run.assert_not_called()

    def test_purge_cancel_changes_nothing(self):
        with patch.object(m, 'read_marker', return_value={}), patch('builtins.input', return_value='no'), patch.object(m, 'run') as run:
            m.uninstall(purge=True)
            run.assert_not_called()

    def test_removes_only_owned_firewall_jumps(self):
        calls = []
        def fake_run(args, **kwargs):
            calls.append(args)
            if args[-1] == '-S':
                return subprocess.CompletedProcess(args, 0, '-P INPUT DROP\n-A INPUT -j SIPT_INPUT\n-A INPUT -j OTHER\n', '')
            return subprocess.CompletedProcess(args, 0, '', '')
        with patch.object(m, 'run', side_effect=fake_run):
            m.remove_rules()
        self.assertFalse(any('-D' in args and 'OTHER' in args for args in calls))
        self.assertFalse(any(args[-1] == '-F' for args in calls))
        self.assertTrue(any('-D' in args and 'SIPT_INPUT' in args for args in calls))

    def test_service_files_are_scoped_and_loopback_api_is_preserved(self):
        written = {}
        with patch.object(m, 'write', side_effect=lambda path, data, *args: written.update({str(path): data})):
            m.write_services()
        self.assertEqual(len(written), 4)
        self.assertIn('ReadWritePaths=/opt/sip-tunnel', written['/etc/systemd/system/sip-simple-panel.service'])
        compose = (REPO / 'deploy/compose.yaml').read_text()
        self.assertIn('HOST: "127.0.0.1"', compose)
        self.assertNotIn('latest', compose)
        self.assertNotIn('INIT_PASSWORD', compose)

    def test_source_update_keeps_runtime_data_and_one_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'backups').mkdir()
            (root / 'app').mkdir()
            (root / 'app/previous.py').write_text('previous')
            state = root / 'clients.json'
            state.write_text('{"clients":[{"name":"preserved"}]}')
            with patch.object(m, 'ROOT', root), patch.object(m, 'run'), patch.object(m, 'SOURCE_REPLACED', False):
                m.install_source()
                self.assertTrue(m.SOURCE_REPLACED)
            self.assertEqual((root / 'backups/app-rollback/previous.py').read_text(), 'previous')
            self.assertTrue((root / 'app/server.py').is_file())
            self.assertIn('preserved', state.read_text())

    def test_existing_administrator_never_prompts_or_resets(self):
        panel = Mock()
        panel.ADMIN.exists.return_value = True
        with patch('builtins.input') as prompt, patch.object(m, 'write') as write:
            m.administrator(panel)
        prompt.assert_not_called()
        write.assert_not_called()

    def test_bootstrap_removes_init_secret_and_preserves_split_route(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            panel = Mock(PUBLIC_IP='203.0.113.10')
            panel.authenticate_service.return_value.call.return_value = {}
            with patch.object(m, 'ROOT', root), patch.object(m, 'compose') as compose, patch.object(m, 'run', return_value=Mock(returncode=1)):
                m.initialize_wireguard(panel)
            credentials = json.loads((root / 'admin-credentials.json').read_text())
            self.assertGreaterEqual(len(credentials['password']), 32)
            self.assertFalse((root / 'bootstrap.env').exists())
            self.assertFalse((root / 'bootstrap.yaml').exists())
            compose.assert_any_call('up', '-d', '--force-recreate')
            calls = panel.authenticate_service.return_value.call.call_args_list
            config = next(call.args[1] for call in calls if call.args[0] == 'admin/userconfig' and len(call.args) == 2)
            self.assertEqual(config['defaultAllowedIps'], ['10.77.0.1/32'])
            self.assertEqual(config['defaultDns'], [])


if __name__ == '__main__':
    unittest.main()
