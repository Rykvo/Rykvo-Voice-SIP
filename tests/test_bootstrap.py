import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import tarfile
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'deploy.sh'


class BootstrapTests(unittest.TestCase):
    def test_help_and_invalid_command(self):
        help_result = subprocess.run(['bash', str(SCRIPT), '--help'], capture_output=True, text=True)
        self.assertEqual(help_result.returncode, 0)
        self.assertIn('rykvo-sip', help_result.stdout)
        result = subprocess.run(['bash', str(SCRIPT), 'unknown'], capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    @unittest.skipUnless(os.geteuid() == 0, 'Run with sudo to test the root-only bootstrap.')
    def test_pipe_keeps_interactive_prompts_and_cleans_download(self):
        self.run_fixture(0)

    @unittest.skipUnless(os.geteuid() == 0, 'Run with sudo to test the root-only bootstrap.')
    def test_failed_install_also_cleans_download(self):
        self.run_fixture(17)

    @unittest.skipUnless(os.geteuid() == 0, 'Run with sudo to test the root-only bootstrap.')
    def test_missing_terminal_stops_before_download(self):
        result = subprocess.run(['bash', str(SCRIPT), 'install'], capture_output=True, start_new_session=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'ssh -t', result.stdout)

    def run_fixture(self, exit_code):
        # Only the download and installer are fixtures; pipe, TTY and cleanup are real.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'fixture'
            (source / 'deploy').mkdir(parents=True)
            (source / 'deploy/manage.py').write_text('# fixture\n')
            (source / 'install.sh').write_text(
                'set -eu\nread -r -p "ACCOUNT> " account\n'
                'read -r -s -p "PASSWORD> " password\n'
                '[[ "$account" == fixture-admin && "$password" == fixture-password ]]\n'
                f'printf "\\nTTY_OK\\n"\nexit {exit_code}\n')
            archive = root / 'fixture.tar.gz'
            with tarfile.open(archive, 'w:gz') as bundle:
                bundle.add(source, arcname='Rykvo-Voice-SIP-main')
            binary = root / 'bin'
            binary.mkdir()
            curl = binary / 'curl'
            curl.write_text('#!/usr/bin/env bash\nset -eu\nprintf "%s" "${@: -1}" > "$DOWNLOAD_RECORD"\ncp "$SOURCE_FIXTURE" "${@: -1}"\n')
            curl.chmod(0o755)
            record = root / 'download-path'
            environment = dict(os.environ, SOURCE_FIXTURE=str(archive), DOWNLOAD_RECORD=str(record),
                               PATH=str(binary) + os.pathsep + os.environ['PATH'])
            pid, terminal = pty.fork()
            if pid == 0:
                os.execve('/bin/bash', ['bash', '-o', 'pipefail', '-c',
                          'cat "$1" | bash -s -- install', 'test', str(SCRIPT)], environment)
            output = b''
            sent_account = sent_password = False
            status = None
            try:
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    if select.select([terminal], [], [], .1)[0]:
                        try:
                            output += os.read(terminal, 65536)
                        except OSError:
                            break
                    if b'ACCOUNT> ' in output and not sent_account:
                        os.write(terminal, b'fixture-admin\n')
                        sent_account = True
                    if b'PASSWORD> ' in output and not sent_password:
                        os.write(terminal, b'fixture-password\n')
                        sent_password = True
                    child, child_status = os.waitpid(pid, os.WNOHANG)
                    if child:
                        status = child_status
                        break
                if status is None:
                    child, child_status = os.waitpid(pid, os.WNOHANG)
                    if child:
                        status = child_status
                    else:
                        os.kill(pid, signal.SIGKILL)
                        os.waitpid(pid, 0)
                        self.fail('Bootstrap did not finish: ' + output.decode(errors='replace'))
                self.assertEqual(os.waitstatus_to_exitcode(status), exit_code, output)
                self.assertIn(b'TTY_OK', output)
                self.assertNotIn(b'fixture-password', output)
                self.assertFalse(Path(record.read_text()).parent.exists())
            finally:
                os.close(terminal)


if __name__ == '__main__':
    unittest.main()
