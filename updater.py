"""Bundled updater. Stage the download before asking the live client to exit."""
from pathlib import Path
import sys
import time

from update_files import (UpdateRollbackError, downloaded_update, install_update,
                          launch_detached, remove_update_file, update_lock)


def run_update(pid, url, target, handoff, args, log):
    import _winapi

    ready = handoff / 'ready'
    apply = handoff / 'apply'
    # Keep the handle from before the download so a reused PID cannot be mistaken for the client.
    parent = _winapi.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
    try:
        with update_lock(target), downloaded_update(url, target) as staged:
            ready.touch(exist_ok=False)
            if _winapi.WaitForSingleObject(parent, 120_000) != _winapi.WAIT_OBJECT_0:
                raise TimeoutError('클라이언트가 업데이트를 위해 종료되지 않았습니다.')
            if not apply.exists():
                log('클라이언트가 업데이트 적용을 요청하지 않고 종료했습니다.')
                return 1

            try:
                install_update(staged, target, args)
            except UpdateRollbackError:
                raise
            except OSError as exc:
                log(f'업데이트 적용 실패, 이전 버전 재실행: {exc}')
                launch_detached(target, [*args, '--skip-auto-update'])
                return 1
        log('업데이트 적용 및 실행 요청 완료')
        return 0
    finally:
        _winapi.CloseHandle(parent)
        remove_update_file(ready)
        remove_update_file(apply)


def main():
    if len(sys.argv) < 6 or sys.argv[1] != '--handoff':
        return 1
    pid, url, executable, handoff, *args = sys.argv[2:]
    target = Path(executable)

    def log(message):
        try:
            with target.with_name('updater.log').open('a', encoding='utf-8') as output:
                output.write(f'[{time.strftime("%Y-%m-%d %H:%M:%S")}] {message}\n')
        except OSError:
            pass

    try:
        return run_update(int(pid), url, target, Path(handoff), args, log)
    except Exception as exc:
        log(f'업데이트 실패: {exc}')
        return 1


if __name__ == '__main__':
    sys.exit(main())
