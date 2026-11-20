"""Download and install Windows client updates without removing a working executable first."""
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.request

from security import validate_download_url


@contextmanager
def update_lock(target):
    import msvcrt

    target.parent.mkdir(parents=True, exist_ok=True)
    with target.with_suffix('.update.lock').open('a+b') as lock:
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise RuntimeError('이미 다른 업데이트가 진행 중입니다.') from exc
        yield


@contextmanager
def downloaded_update(url, target, progress=None):
    url = validate_download_url(url)
    request = urllib.request.Request(url, headers={
        'User-Agent': 'SmartPower-Updater/1.0', 'Cache-Control': 'no-cache',
    })
    fd, name = tempfile.mkstemp(prefix=target.stem + '-', suffix='.download', dir=target.parent)
    staged = Path(name)
    try:
        with os.fdopen(fd, 'w+b') as output:
            with urllib.request.urlopen(request, timeout=60, context=ssl.create_default_context()) as response:
                expected = int(response.headers.get('Content-Length', '0'))
                downloaded = 0
                while chunk := response.read(256 * 1024):
                    output.write(chunk)
                    downloaded += len(chunk)
                    if progress:
                        progress(downloaded, expected)

            if downloaded < 1_000_000 or (expected and downloaded != expected):
                raise ValueError(f'다운로드가 완료되지 않았습니다 ({downloaded}/{expected} bytes).')
            output.seek(0)
            header = output.read(64)
            pe_offset = int.from_bytes(header[60:64], 'little')
            if header[:2] != b'MZ' or not 64 <= pe_offset <= downloaded - 4:
                raise ValueError('Windows 실행 파일 형식이 올바르지 않습니다.')
            output.seek(pe_offset)
            if output.read(4) != b'PE\0\0':
                raise ValueError('Windows 실행 파일 형식이 올바르지 않습니다.')
            os.fsync(output.fileno())
        yield staged
    finally:
        remove_update_file(staged)


def remove_update_file(path):
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def launch_detached(executable, args=()):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('_PYI_', 'TCL_', 'TK_')) and key != '_MEIPASS2'}
    env['PYINSTALLER_RESET_ENVIRONMENT'] = '1'
    return subprocess.Popen(
        [str(executable), *args], env=env,
        creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
    )


def replace_when_unlocked(source, target, timeout=45):
    deadline = time.monotonic() + timeout
    while True:
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.5)


class UpdateRollbackError(RuntimeError):
    """The previous version is still available at the backup path."""


def install_update(staged, target, args=()):
    backup = staged.with_suffix('.backup')
    preserve_backup = False
    try:
        if target.exists():
            try:
                os.link(target, backup)
            except OSError:
                shutil.copyfile(target, backup)
        replace_when_unlocked(staged, target)
        try:
            launch_detached(target, args)
        except OSError:
            if backup.exists():
                try:
                    replace_when_unlocked(backup, target)
                except OSError as exc:
                    preserve_backup = True
                    raise UpdateRollbackError(f'이전 실행 파일 복구 경로: {backup}') from exc
            raise
    finally:
        if not preserve_backup:
            remove_update_file(backup)
