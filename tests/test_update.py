"""Exercise the Windows update transaction with isolated files and no live download."""
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import update_files
import updater


URL = 'https://github.com/JunHyuk1203/autoshutdown/releases/download/v1.2.3/auto_shutdown.exe'


class TestUpdate(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.target = self.directory / 'auto_shutdown.exe'
        self.target.write_bytes(b'old')

    def test_download_streams_and_rejects_partial_or_invalid_payloads(self):
        class Response(io.BytesIO):
            def read(self, size=-1):
                if not 0 < size <= 256 * 1024:
                    raise AssertionError('Download read must be bounded')
                return super().read(size)

        pe = bytearray(1_048_576)
        pe[:2] = b'MZ'
        pe[60:64] = (64).to_bytes(4, 'little')
        pe[64:68] = b'PE\0\0'
        for data, length, valid in ((pe, len(pe), True), (pe, len(pe) + 1, False),
                                    (b'x' * len(pe), len(pe), False)):
            with self.subTest(length=length, valid=valid):
                response = Response(data)
                response.headers = {'Content-Length': str(length)}
                with patch.object(update_files.urllib.request, 'urlopen', return_value=response):
                    if valid:
                        with update_files.downloaded_update(URL, self.target) as staged:
                            self.assertEqual(staged.stat().st_size, length)
                    else:
                        with self.assertRaises(ValueError):
                            with update_files.downloaded_update(URL, self.target):
                                self.fail('Invalid download was accepted')
                self.assertEqual(self.target.read_bytes(), b'old')
                self.assertEqual(list(self.directory.glob('*.download')), [])

    @unittest.skipUnless(os.name == 'nt', 'Windows file locking')
    def test_updates_cannot_hold_the_same_target_lock(self):
        with update_files.update_lock(self.target):
            with self.assertRaises(RuntimeError):
                with update_files.update_lock(self.target):
                    self.fail('Acquired a lock already held for the same target')
        with update_files.update_lock(self.target):
            pass

    def test_locked_target_is_retried_then_installed(self):
        staged = self.directory / 'new.download'
        staged.write_bytes(b'new')
        with (patch.object(update_files.os, 'replace', side_effect=[PermissionError(), PermissionError(), None]) as replace,
              patch.object(update_files.time, 'sleep')):
            update_files.replace_when_unlocked(staged, self.target)
            self.assertEqual(replace.call_count, 3)
        with patch.object(update_files, 'launch_detached') as launch:
            update_files.install_update(staged, self.target, ['--headless'])
            self.assertEqual(self.target.read_bytes(), b'new')
            launch.assert_called_once_with(self.target, ['--headless'])

    def test_failed_launch_restores_previous_executable(self):
        staged = self.directory / 'new.download'
        staged.write_bytes(b'new')
        with patch.object(update_files, 'launch_detached', side_effect=OSError('launch failed')):
            with self.assertRaisesRegex(OSError, 'launch failed'):
                update_files.install_update(staged, self.target)
        self.assertEqual(self.target.read_bytes(), b'old')
        self.assertEqual(list(self.directory.glob('*.backup')), [])

    def test_permanent_replace_failure_leaves_previous_file_in_place(self):
        staged = self.directory / 'new.download'
        staged.write_bytes(b'new')
        with (patch.object(update_files, 'replace_when_unlocked', side_effect=PermissionError()),
              patch.object(update_files, 'launch_detached') as launch):
            with self.assertRaises(PermissionError):
                update_files.install_update(staged, self.target)
        launch.assert_not_called()
        self.assertEqual(self.target.read_bytes(), b'old')

    @unittest.skipUnless(os.name == 'nt', 'Windows process handles')
    def test_updater_requires_download_and_client_acknowledgement(self):
        import _winapi
        from contextlib import nullcontext

        handoff = self.directory / 'handoff'
        handoff.mkdir()
        with (patch.object(_winapi, 'OpenProcess', return_value=42),
              patch.object(_winapi, 'CloseHandle'),
              patch.object(_winapi, 'WaitForSingleObject', return_value=_winapi.WAIT_OBJECT_0) as wait,
              patch.object(updater, 'install_update') as install,
              patch.object(updater, 'downloaded_update', side_effect=OSError('interrupted')) as download):
            with self.assertRaises(OSError):
                updater.run_update(123, URL, self.target, handoff, ['--headless'], Mock())
            wait.assert_not_called()
            self.assertFalse((handoff / 'ready').exists())
            download.side_effect = None
            staged = self.directory / 'new.download'
            download.return_value = nullcontext(staged)
            self.assertEqual(updater.run_update(123, URL, self.target, handoff, ['--headless'], Mock()), 1)
            install.assert_not_called()

            def acknowledge(handle, timeout):
                (handoff / 'ready').rename(handoff / 'apply')
                return _winapi.WAIT_OBJECT_0

            wait.side_effect = acknowledge
            self.assertEqual(updater.run_update(123, URL, self.target, handoff, ['--headless'], Mock()), 0)
            install.assert_called_once_with(staged, self.target, ['--headless'])


if __name__ == '__main__':
    unittest.main()
