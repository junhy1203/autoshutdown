r"""
manual_updater.py - 수동 업데이트 프로그램 (더블클릭 실행)

동작 순서:
  1. Firebase 에서 최신 download_url 조회
  2. 새 파일 다운로드 및 검증
  3. 설치 경로에서 실행 중인 클라이언트 종료
  4. %LOCALAPPDATA%\AutoShutdown\auto_shutdown.exe 교체
  5. 새 프로세스 실행
  6. 자기 자신 종료
"""

import os
import time
import json
from pathlib import Path
import threading
import urllib.request
import ssl
from update_files import (UpdateRollbackError, downloaded_update, install_update,
                          launch_detached, update_lock)
import tkinter as tk
from tkinter import ttk, messagebox

INSTALL_DIR  = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "AutoShutdown")
EXE_NAME     = "auto_shutdown.exe"
FIREBASE_URL = "https://atss-a1f9e-default-rtdb.firebaseio.com/update_info.json"

try:
    _ssl_ctx = ssl.create_default_context()
except Exception:
    _ssl_ctx = None


def _stop_installed_client(target):
    import psutil

    for process in psutil.process_iter(['exe']):
        executable = process.info['exe']
        if executable and Path(executable) == target:
            try:
                process.terminate()
            except psutil.NoSuchProcess:
                pass


class ManualUpdaterApp:
    def __init__(self):
        self.root = tk.Tk()
        self._closing = threading.Event()
        self.root.title("스마트 전원 관리자 - 수동 업데이트")
        self.root.geometry("420x200")
        self.root.resizable(False, False)
        self.root.configure(bg="#1e1e2e")

        tk.Label(
            self.root, text="⬆  수동 업데이트",
            font=("Malgun Gothic", 14, "bold"),
            bg="#1e1e2e", fg="#cba6f7"
        ).pack(pady=(20, 4))

        self.status_var = tk.StringVar(value="업데이트 준비 중...")
        tk.Label(
            self.root, textvariable=self.status_var,
            font=("Malgun Gothic", 9), bg="#1e1e2e", fg="#89b4fa"
        ).pack(pady=(8, 4))

        self.progress = ttk.Progressbar(
            self.root, orient="horizontal", length=360, mode="determinate"
        )
        self.progress.pack()

        self.btn = tk.Button(
            self.root, text="지금 업데이트",
            font=("Malgun Gothic", 11, "bold"),
            bg="#cba6f7", fg="#1e1e2e",
            activebackground="#b4befe",
            relief="flat", padx=20, pady=6,
            command=self._on_update
        )
        self.btn.pack(pady=16)
        self.root.protocol('WM_DELETE_WINDOW', self._on_close)

    def _on_close(self):
        self._closing.set()
        self.root.destroy()

    def _set(self, msg: str, pct: int = None):
        def _do():
            self.status_var.set(msg)
            if pct is not None:
                self.progress["value"] = pct
        self.root.after(0, _do)

    def _on_update(self):
        self.btn.config(state="disabled")
        threading.Thread(target=self._run_update).start()

    def _run_update(self):
        target = Path(INSTALL_DIR) / EXE_NAME
        next_progress = 0

        def progress(downloaded, total):
            nonlocal next_progress
            if self._closing.is_set():
                raise InterruptedError()
            now = time.monotonic()
            if now >= next_progress:
                pct = 10 + min(70, downloaded * 70 // total) if total else 10
                self._set(f'다운로드 중... {downloaded // (1024 * 1024)} MB', pct)
                next_progress = now + 0.25

        try:
            # 1. 최신 URL 조회
            self._set("서버에서 최신 버전 확인 중...", 5)
            req = urllib.request.Request(FIREBASE_URL, headers={"User-Agent": "ManualUpdater/1.0"})
            with urllib.request.urlopen(req, timeout=10, context=_ssl_ctx) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            dl_url = data.get("download_url")
            if not dl_url:
                raise RuntimeError("다운로드 URL을 가져오지 못했습니다.")

            self._set("새 버전 다운로드 중...", 10)
            with update_lock(target), downloaded_update(dl_url, target, progress) as staged:
                had_client = target.is_file()
                self._set('기존 프로그램 종료 및 파일 교체 중...', 88)
                if self._closing.is_set():
                    return
                _stop_installed_client(target)
                try:
                    install_update(staged, target)
                except UpdateRollbackError:
                    raise
                except OSError:
                    if had_client:
                        launch_detached(target, ['--skip-auto-update'])
                    raise
            if not self._closing.is_set():
                self._set('업데이트 완료! 프로그램 재시작 중...', 100)
                self.root.after(500, self._on_close)

        except Exception as e:
            if not self._closing.is_set():
                self._set(f"오류: {e}", 0)
                self.root.after(0, messagebox.showerror, '업데이트 오류', str(e))
                self.root.after(0, lambda: self.btn.config(state="normal"))

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = ManualUpdaterApp()
    app.run()
