import os
import sys
import threading
import base64
import winreg
import getpass
from security import (protect_password, unprotect_password, store_logon_secret,
                      public_config, remote_config, fresh_command, private_updater_copy, validate_ws_url,
                      validate_download_url, open_remote_url, kill_remote_process)

def _get_encryption_key():
    import uuid
    mac = str(uuid.getnode())
    return [ord(c) for c in mac]

def encrypt_password(password):
    return protect_password(password)

def decrypt_password(encrypted_b64):
    try:
        return unprotect_password(encrypted_b64)
    except Exception:
        return ""

def set_auto_logon(username, password):
    try:
        store_logon_secret(password)
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "AutoAdminLogon", 0, winreg.REG_SZ, "1")
        winreg.SetValueEx(key, "DefaultUserName", 0, winreg.REG_SZ, username)
        try:
            winreg.DeleteValue(key, "DefaultPassword")
        except FileNotFoundError:
            pass
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"set_auto_logon error: {e}")
        return False

def disable_auto_logon():
    try:
        store_logon_secret(None)
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "AutoAdminLogon", 0, winreg.REG_SZ, "0")
        try:
            winreg.DeleteValue(key, "DefaultPassword")
        except FileNotFoundError:
            pass
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"disable_auto_logon error: {e}")
        return False


def migrate_saved_credentials():
    """Upgrade old saves without disabling Windows automatic logon."""
    for filename in ('config.json', 'schedule_config.json'):
        path = os.path.join(application_path, filename)
        if not os.path.isfile(path):
            continue
        with open(path, encoding='utf-8') as source:
            config = json.load(source)
        value = config.get('encrypted_password', '')
        if value and not value.startswith('dpapi:'):
            config['encrypted_password'] = protect_password(unprotect_password(value))
            import tempfile
            fd, temporary = tempfile.mkstemp(dir=application_path, suffix='.json')
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as target:
                    json.dump(config, target, ensure_ascii=False, indent=4)
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.remove(temporary)
    # Migrating a machine-wide Winlogon secret requires elevation.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
                            0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            value, _ = winreg.QueryValueEx(key, 'DefaultPassword')
            store_logon_secret(value)
            winreg.DeleteValue(key, 'DefaultPassword')
    except FileNotFoundError:
        pass

import time
import json
import socket
socket.setdefaulttimeout(15.0)  # 스쿨넷 방화벽망 등에서 urllib 무한 락 방지용 소켓 전역 타임아웃 강제 설정
import urllib.request
import urllib.error
import urllib.parse
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import re
from datetime import datetime, timedelta
import ssl

import urllib.request
import urllib.error
import urllib.parse
import json
import time

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _http_sessions = threading.local()
    def _get_http_session():
        if not hasattr(_http_sessions, 'session'):
            _http_sessions.session = requests.Session()
            _http_sessions.session.verify = True
        return _http_sessions.session
    _original_urlopen = urllib.request.urlopen
    
    class MockResponse:
        def __init__(self, content, status):
            self.content = content
            self.status = status
            self.code = status
        def read(self):
            return self.content
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    def _fast_urlopen(url_or_req, *args, **kwargs):
        req = url_or_req
        if isinstance(req, urllib.request.Request):
            url = req.full_url
            method = getattr(req, 'method', None) or ('POST' if req.data else 'GET')
            headers = dict(req.headers)
            headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            headers['Pragma'] = 'no-cache'
            headers['Expires'] = '0'
            data = req.data
            timeout = kwargs.get('timeout', 10)
            
            _global_session = _get_http_session()
            # Only intercept Firebase realtime database requests
            if urllib.parse.urlsplit(url).hostname == 'atss-a1f9e-default-rtdb.firebaseio.com':
                parsed = urllib.parse.urlsplit(url)
                if parsed.scheme != 'https':
                    raise ValueError('Firebase requires HTTPS')
                if not parsed.path.startswith('/update_info'):
                    # Registration-free PC endpoints must never receive legacy admin secrets.
                    query = urllib.parse.parse_qs(parsed.query)
                    query.pop('auth', None)
                    url = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query, doseq=True)))
                try:
                    if method == 'GET':
                        res = _global_session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
                    elif method == 'PATCH':
                        res = _global_session.patch(url, data=data, headers=headers, timeout=timeout, allow_redirects=True)
                    elif method == 'PUT':
                        res = _global_session.put(url, data=data, headers=headers, timeout=timeout, allow_redirects=True)
                    elif method == 'POST':
                        res = _global_session.post(url, data=data, headers=headers, timeout=timeout, allow_redirects=True)
                    elif method == 'DELETE':
                        res = _global_session.delete(url, headers=headers, timeout=timeout, allow_redirects=True)
                    else:
                        return _original_urlopen(url_or_req, *args, **kwargs)
                    
                    if res.status_code >= 400:
                        from io import BytesIO
                        raise urllib.error.HTTPError(url, res.status_code, res.reason, res.headers, BytesIO(res.content))
                        
                    return MockResponse(res.content, res.status_code)
                except urllib.error.HTTPError:
                    raise
                except requests.RequestException as e:
                    # Do not repeat the same failing request with another full timeout.
                    raise urllib.error.URLError(str(e)) from e
        return _original_urlopen(url_or_req, *args, **kwargs)

    urllib.request.urlopen = _fast_urlopen
except ImportError:
    pass

try:
    from pycaw.pycaw import AudioUtilities
    PYCAW_AVAILABLE = True
except ImportError:
    PYCAW_AVAILABLE = False

try:
    _global_ssl_context = ssl.create_default_context()
except AttributeError:
    _global_ssl_context = None

# 전역 앱 인스턴스 (http_poller_thread 등에서 참조)
app_instance = None

# PyInstaller 환경 변수 오염(init.tcl) 방지 패치
# 업데이트 후 부모 프로세스의 환경변수가 상속되면 삭제된 임시 폴더를 참조하므로
# 항상 현재 _MEIPASS 기준으로 강제 재설정
if getattr(sys, 'frozen', False):
    # console=False 일 때 sys.stdout/err가 None이 되어 발생하는 AttributeError 방지 및 로그 저장
    class NullWriter:
        def __init__(self):
            self.encoding = 'utf-8'
            self.errors = 'strict'
        def write(self, text):
            try:
                # AppData 폴더 또는 실행 파일 위치에 stdout_stderr.log 기록
                with open(os.path.join(os.path.dirname(sys.executable), 'stdout_stderr.log'), 'a', encoding='utf-8') as f:
                    f.write(text)
            except:
                pass
        def flush(self): pass
        def isatty(self): return False
        def fileno(self): return -1
    sys.stdout = NullWriter()
    sys.stderr = NullWriter()

    # _MEIPASS2가 남아있으면 PyInstaller 부트로더가 혼동할 수 있으므로 제거
    os.environ.pop('_MEIPASS2', None)
    # 항상 현재 _MEIPASS 기준으로 TCL/TK 경로를 강제 설정 (기존 값 무시)
    _meipass = sys._MEIPASS.replace('\\', '/')
    os.environ['TCL_LIBRARY'] = _meipass + '/_tcl_data'
    os.environ['TK_LIBRARY'] = _meipass + '/_tk_data'


import tkinter as tk
from tkinter import messagebox
import tkinter.font as tkfont
import customtkinter as ctk
import pystray
from PIL import Image, ImageDraw
import ctypes
from ctypes import wintypes
import subprocess


def run_standalone_autologin_gui():
    import tkinter as tk
    from tkinter import messagebox
    import json
    import ctypes
    import getpass
    import os
    import sys

    config_file = 'config.json'
    if getattr(sys, 'frozen', False):
        config_file = os.path.join(os.path.dirname(sys.executable), 'config.json')
    
    current_cfg = {}
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                current_cfg = json.load(f)
        except:
            pass

    def save_cfg():
        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(current_cfg, f, ensure_ascii=False, indent=4)
        except:
            pass

    root = tk.Tk()
    root.title("부팅 시 자동 로그인 설정")
    root.geometry("370x205")
    root.resizable(False, False)
    root.configure(bg="#1a1a1a")
    root.attributes("-topmost", True)

    x = (root.winfo_screenwidth() - 370) // 2
    y = (root.winfo_screenheight() - 205) // 2
    root.geometry(f"370x205+{x}+{y}")

    auto_unlock_var = tk.BooleanVar(value=current_cfg.get('auto_unlock_enabled', False))

    def toggle_entry():
        password_entry.config(state="normal" if auto_unlock_var.get() else "disabled")

    r1 = tk.Frame(root, bg="#1a1a1a")
    r1.pack(fill="x", padx=15, pady=(15, 5))
    tk.Checkbutton(r1, text="  부팅 시 자동으로 잠금 해제 켜기",
                       variable=auto_unlock_var, command=toggle_entry,
                       bg="#1a1a1a", fg="white", selectcolor="#555",
                       activebackground="#1a1a1a", activeforeground="white",
                       font=("Segoe UI", 10)).pack(anchor="w")

    r2 = tk.Frame(root, bg="#1a1a1a")
    r2.pack(fill="x", padx=15, pady=4)
    tk.Label(r2, text="Windows 비밀번호:", font=("Segoe UI", 9),
                 bg="#1a1a1a", fg="#aaaaaa").pack(anchor="w")
    
    pwd_frame = tk.Frame(root, bg="#1a1a1a")
    pwd_frame.pack(fill="x", padx=15, pady=(0, 10))
    password_entry = tk.Entry(pwd_frame, show="*", font=("Segoe UI", 10),
                                  bg="#333333", fg="white", insertbackground="white",
                                  relief="flat", disabledbackground="#222222")
    password_entry.pack(fill="x", ipady=6, pady=(2, 0))

    saved_enc_pwd = current_cfg.get('encrypted_password', "")
    if saved_enc_pwd:
        try:
            password_entry.insert(0, decrypt_password(saved_enc_pwd))
        except:
            pass
    toggle_entry()

    def apply_settings():
        enabled = auto_unlock_var.get()
        pwd = password_entry.get()
        if not ctypes.windll.shell32.IsUserAnAdmin():
            messagebox.showwarning("권한 필요",
                "관리자 권한이 필요합니다.\n트레이 메뉴에서 '관리자 권한으로 열기'를 먼저 사용해주세요.")
            return
        
        username = getpass.getuser()
        if enabled:
            if not pwd:
                messagebox.showerror("오류", "비밀번호를 입력해주세요.")
                return
            if set_auto_logon(username, pwd):
                current_cfg['auto_unlock_enabled'] = True
                current_cfg['encrypted_password'] = encrypt_password(pwd)
                save_cfg()
                messagebox.showinfo("성공", "자동 로그인이 활성화되었습니다.\n(다음 부팅 시부터 적용됩니다)")
                root.destroy()
            else:
                messagebox.showerror("오류", "레지스트리 설정에 실패했습니다.")
        else:
            if disable_auto_logon():
                current_cfg['auto_unlock_enabled'] = False
                current_cfg['encrypted_password'] = ""
                save_cfg()
                messagebox.showinfo("성공", "자동 로그인이 비활성화되었습니다.")
                root.destroy()
            else:
                messagebox.showerror("오류", "레지스트리 설정에 실패했습니다.")

    r3 = tk.Frame(root, bg="#1a1a1a")
    r3.pack(fill="x", padx=15, pady=(8, 15))
    tk.Button(r3, text="적용", command=apply_settings,
                  bg="#3a7bd5", fg="white", relief="flat", cursor="hand2",
                  font=("Segoe UI", 10), padx=16, pady=5).pack(side="left")
    tk.Button(r3, text="닫기", command=root.destroy,
                  bg="#555555", fg="white", relief="flat", cursor="hand2",
                  font=("Segoe UI", 10), padx=16, pady=5).pack(side="left", padx=(8, 0))

    root.mainloop()

CURRENT_VERSION = "1.1.207"

try:
    from pycaw.pycaw import AudioUtilities
    HAS_PYCAW = True
except ImportError:
    HAS_PYCAW = False

if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(application_path, "schedule_config.json")

DAYS = ["월", "화", "수", "목", "금", "토", "일"]
TIMETABLE = {
    "1교시 (08:40)": "08:40",
    "2교시 (09:40)": "09:40",
    "3교시 (10:40)": "10:40",
    "4교시 (11:40)": "11:40",
    "점심시간 (12:40)": "12:40",
    "5교시 (13:30)": "13:30",
    "6교시 (14:30)": "14:30",
    "7교시 (15:30)": "15:30",
    "방과후/기타 (16:30)": "16:30",
}

class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [
        ('cbSize', wintypes.UINT),
        ('dwTime', wintypes.DWORD),
    ]

def get_idle_time():
    lii = LASTINPUTINFO()
    lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
    if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
        tick = ctypes.windll.kernel32.GetTickCount()
        millis = (tick - lii.dwTime) & 0xFFFFFFFF
        return millis / 1000.0
    return 0.0



def is_media_playing():
    if not HAS_PYCAW: return False
    try:
        import comtypes
        comtypes.CoInitialize()
        sessions = AudioUtilities.GetAllSessions()
        for session in sessions:
            if session.State == 1: return True
    except Exception: pass
    return False

_cached_local_ip = None
_cached_local_ip_at = 0

def get_local_ip():
    global _cached_local_ip, _cached_local_ip_at
    now = time.monotonic()
    if _cached_local_ip and now - _cached_local_ip_at < 30:
        return _cached_local_ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    _cached_local_ip, _cached_local_ip_at = ip, now
    return ip

_cached_pc_id = None

def get_pc_id():
    global _cached_pc_id
    if _cached_pc_id:
        return _cached_pc_id

    # 1. 설정 파일에서 기존 pc_id 확인 및 호스트명 일치 검증
    try:
        import socket, re, json, os
        hostname = socket.gethostname()
        cleaned_hostname = re.sub(r'[^a-zA-Z0-9\-]', '', hostname)
        if not cleaned_hostname or cleaned_hostname.strip('-') == '':
            cleaned_hostname = "PC"
            
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
                if "pc_id" in cfg:
                    saved_id = cfg["pc_id"]
                    if saved_id.startswith(cleaned_hostname + "_"):
                        _cached_pc_id = saved_id
                        return saved_id
    except Exception:
        pass

    # 2. 호스트명 기반으로 새로운 ID 생성
    try:
        import socket
        hostname = socket.gethostname()
    except Exception:
        hostname = "PC"
    
    import re
    cleaned_hostname = re.sub(r'[^a-zA-Z0-9\-]', '', hostname)
    if not cleaned_hostname or cleaned_hostname.strip('-') == '':
        cleaned_hostname = "PC"
    
    try:
        import uuid
        mac = uuid.getnode()
        mac_hex = f"{mac:012x}"[-6:]
    except Exception:
        mac_hex = "000000"
        
    new_pc_id = f"{cleaned_hostname}_{mac_hex}"
    
    # 3. 설정 파일에 저장하여 향후 영구 사용 (네트워크 변경으로 인한 분리 현상 방지)
    try:
        import json, os
        cfg = {}
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
        cfg["pc_id"] = new_pc_id
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=4)
    except Exception:
        pass
        
    _cached_pc_id = new_pc_id
    return new_pc_id

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

def force_close_window(hwnd):
    """창 소유 프로세스를 작업 관리자의 작업 끝내기처럼 강제 종료한다."""
    if isinstance(hwnd, bool) or not str(hwnd).isdecimal():
        return False
    hwnd = int(hwnd)
    if not 0 < hwnd < (1 << (ctypes.sizeof(wintypes.HWND) * 8)):
        return False
    pid = wintypes.DWORD()
    if not ctypes.windll.user32.GetWindowThreadProcessId(wintypes.HWND(hwnd), ctypes.byref(pid)) or not pid.value:
        return False
    kill_remote_process(pid.value)
    return True


def get_open_windows():
    """ALT+TAB 목록과 동일한 방식으로 사용자에게 보이는 창만 반환"""
    results = []
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    GW_OWNER = 4
    WS_EX_TOOLWINDOW = 0x00000080
    DWMWA_CLOAKED = 14

    def is_real_window(hwnd):
        """ALT+TAB에 나타나는 실제 사용자 창인지 확인"""
        if not ctypes.windll.user32.IsWindowVisible(hwnd):
            return False
        # 소유자(owner)가 있는 창은 자식/팝업 창 → 제외
        owner = ctypes.windll.user32.GetWindow(hwnd, GW_OWNER)
        if owner != 0:
            return False
        # 툴윈도우 스타일(트레이 팝업, 미니 유틸 등) → 제외
        ex_style = ctypes.windll.user32.GetWindowLongW(hwnd, -20)  # GWL_EXSTYLE
        if ex_style & WS_EX_TOOLWINDOW:
            return False
        # Windows 10+ 가상 데스크탑의 숨겨진 창(Cloaked) → 제외
        try:
            cloaked = ctypes.c_int(0)
            ctypes.windll.dwmapi.DwmGetWindowAttribute(
                hwnd, DWMWA_CLOAKED, ctypes.byref(cloaked), ctypes.sizeof(cloaked)
            )
            if cloaked.value != 0:
                return False
        except Exception:
            pass
        return True

    def enum_handler(hwnd, _):
        try:
            if not is_real_window(hwnd):
                return True
            buf = ctypes.create_unicode_buffer(256)
            ctypes.windll.user32.GetWindowTextW(hwnd, buf, 256)
            title = buf.value.strip()
            if not title:
                return True
            pid = ctypes.c_ulong()
            ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            exe = "unknown.exe"
            try:
                h = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
                if h:
                    exe_buf = ctypes.create_unicode_buffer(260)
                    size = ctypes.c_ulong(260)
                    ctypes.windll.kernel32.QueryFullProcessImageNameW(h, 0, exe_buf, ctypes.byref(size))
                    ctypes.windll.kernel32.CloseHandle(h)
                    exe = os.path.basename(exe_buf.value) if exe_buf.value else "unknown.exe"
            except Exception:
                pass
            results.append({"title": title[:120], "exe": exe, "pid": pid.value, "hwnd": hwnd})
        except Exception:
            pass
        return True

    try:
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
        ctypes.windll.user32.EnumWindows(WNDENUMPROC(enum_handler), 0)
    except Exception:
        pass
    return results[:40]

def sanitize_rtdb_keys(data):
    if isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_key = k
            if isinstance(k, str):
                for char in [".", "$", "#", "[", "]", "/"]:
                    new_key = new_key.replace(char, "_")
            new_data[new_key] = sanitize_rtdb_keys(v)
        return new_data
    elif isinstance(data, list):
        return [sanitize_rtdb_keys(x) for x in data]
    return data

def _sync_windows_time():
    """백그라운드에서 조용히 Windows 시간 동기화를 수행합니다."""
    def _do_sync():
        import subprocess
        try:
            res = subprocess.run(['w32tm', '/resync', '/force'], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=5)
            if res.returncode != 0:
                subprocess.run(['sc', 'config', 'w32time', 'start=', 'demand'], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=5)
                subprocess.run(['net', 'stop', 'w32time'], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=5)
                subprocess.run(['net', 'start', 'w32time'], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=5)
                subprocess.run(['w32tm', '/resync', '/force'], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=5)
        except Exception:
            pass
    threading.Thread(target=_do_sync, daemon=True).start()

def _take_and_upload_screenshot(central_url, pc_id, db_secret, ssl_context, sct=None, monitor=None, session=None):
    import base64, io, time
    try:
        w, h = 0, 0
        try:
            if sct is None:
                import mss as _mss
                sct = _mss.mss()
            if monitor is None:
                monitor = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
            w, h = monitor['width'], monitor['height']
            shot = sct.grab(monitor)
            from PIL import Image
            img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
        except Exception as mss_err:
            try:
                from PIL import ImageGrab
                img = ImageGrab.grab(all_screens=True)
                if img is None: raise Exception("ImageGrab returned None")
                w, h = img.size
            except Exception as grab_err:
                from PIL import Image, ImageDraw
                w, h = 800, 600
                img = Image.new("RGB", (w, h), color=(40, 40, 40))
                draw = ImageDraw.Draw(img)
                draw.text((40, 280), f"Screen Capture Failed\nmss:{mss_err}", fill=(255, 100, 100))

        # 극한 최소화: 640px, quality=15 → 프레임당 ~8~15KB
        max_w = 640
        if img.width > max_w:
            ratio = max_w / img.width
            from PIL import Image
            img = img.resize((max_w, int(img.height * ratio)), Image.NEAREST)  # NEAREST: 가장 빠름

        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=15, optimize=False, progressive=False)
        img_b64 = base64.b64encode(buf.getvalue()).decode('ascii')

        payload_str = f'{{"data":"{img_b64}","ts":{time.time():.3f},"w":{w},"h":{h}}}'
        payload_bytes = payload_str.encode('utf-8')

        ss_url = f"{central_url.rstrip('/')}/screenshots/{pc_id}.json"
        if db_secret:
            ss_url += f"?auth={db_secret}"

        if session is not None:
            # requests.Session: keep-alive TCP 재사용 (TLS 핸드셰이크 생략)
            session.put(ss_url.split('?')[0], data=payload_bytes,
                        headers={'Content-Type': 'application/json'}, timeout=3)
        else:
            req = urllib.request.Request(ss_url, data=payload_bytes, method="PUT",
                                         headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=3, context=ssl_context) as _:
                pass
    except Exception:
        pass

_stream_active = False
_stream_thread = None

def _start_screen_streaming(central_url, pc_id, db_secret, ssl_context):
    global _stream_active, _stream_thread
    _stream_active = True

    def _stream_loop():
        global _stream_active
        import mss as _mss
        import queue as _queue
        from PIL import Image
        import base64, io

        # requests.Session으로 HTTP keep-alive 연결 재사용 (TLS 핸드셰이크 생략)
        try:
            import requests as _requests
            import urllib3
            urllib3.disable_warnings()
            session = _requests.Session()
            session.verify = True
            adapter = _requests.adapters.HTTPAdapter(
                pool_connections=1, pool_maxsize=1, max_retries=0
            )
            session.mount('https://', adapter)
            session.mount('http://', adapter)
        except ImportError:
            session = None

        # mss 인스턴스 한 번만 생성
        try:
            sct = _mss.mss()
            monitor = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
        except:
            sct = None
            monitor = None

        ss_url = f"{central_url.rstrip('/')}/screenshots/{pc_id}.json"
        if db_secret:
            ss_url += f"?auth={db_secret}"

        # 업로드 큐: 캡처/인코딩과 업로드를 별도 스레드로 분리 (파이프라인)
        upload_q = _queue.Queue(maxsize=2)

        def _upload_worker():
            while True:
                try:
                    item = upload_q.get(timeout=1)
                    if item is None:
                        break
                    payload_bytes = item
                    try:
                        if session is not None:
                            session.put(ss_url.split('?')[0], data=payload_bytes,
                                        headers={'Content-Type': 'application/json'}, timeout=3)
                        else:
                            req = urllib.request.Request(ss_url, data=payload_bytes, method="PUT",
                                                         headers={'Content-Type': 'application/json'})
                            with urllib.request.urlopen(req, timeout=3, context=ssl_context) as _:
                                pass
                    except Exception:
                        pass
                    finally:
                        upload_q.task_done()
                except _queue.Empty:
                    if not _stream_active:
                        break

        upload_thread = threading.Thread(target=_upload_worker, daemon=True)
        upload_thread.start()

        start_t = time.time()
        while _stream_active and (time.time() - start_t < 1800):
            t0 = time.time()
            try:
                if sct:
                    shot = sct.grab(monitor)
                    img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
                    w, h = monitor['width'], monitor['height']
                else:
                    from PIL import ImageGrab
                    img = ImageGrab.grab()
                    w, h = img.size

                # 리사이즈: 640px, NEAREST (최속)
                if img.width > 640:
                    img = img.resize((640, int(img.height * 640 / img.width)), Image.NEAREST)

                # JPEG: quality=15 -> 프레임당 ~8~15KB
                buf = io.BytesIO()
                img.save(buf, format="JPEG", quality=15, optimize=False, progressive=False)
                img_b64 = base64.b64encode(buf.getvalue()).decode('ascii')
                payload_str = f'{{"data":"{img_b64}","ts":{time.time():.3f},"w":{w},"h":{h}}}'
                payload_bytes = payload_str.encode('utf-8')

                # 큐 가득 차면 오래된 프레임 버리고 최신 프레임으로 교체
                if upload_q.full():
                    try:
                        upload_q.get_nowait()
                        upload_q.task_done()
                    except _queue.Empty:
                        pass
                try:
                    upload_q.put_nowait(payload_bytes)
                except _queue.Full:
                    pass
            except Exception:
                pass

            elapsed = time.time() - t0
            # 목표 ~15FPS (66ms 간격)
            wait = max(0, 0.066 - elapsed)
            if wait > 0:
                time.sleep(wait)

        _stream_active = False
        upload_q.put(None)  # 업로드 스레드 종료

    if _stream_thread is None or not _stream_thread.is_alive():
        _stream_thread = threading.Thread(target=_stream_loop, daemon=True)
        _stream_thread.start()

def _stop_screen_streaming():
    global _stream_active
    _stream_active = False


_config_cache_lock = threading.Lock()
_config_cache_stamp = None
_config_cache_data = {}

def read_runtime_config():
    """Return a snapshot; a partial/failed write must not erase the last valid config."""
    global _config_cache_stamp, _config_cache_data
    import copy
    with _config_cache_lock:
        try:
            stat = os.stat(CONFIG_FILE)
            stamp = (stat.st_mtime_ns, stat.st_size)
            if stamp != _config_cache_stamp:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as source:
                    data = json.load(source)
                if not isinstance(data, dict):
                    raise ValueError('Configuration must be an object')
                _config_cache_data, _config_cache_stamp = data, stamp
        except FileNotFoundError:
            _config_cache_data, _config_cache_stamp = {}, None
        except (OSError, ValueError):
            pass
        return copy.deepcopy(_config_cache_data)

class AutoShutdownAppV2:
    def __init__(self, root):
        self.root = root
        _sync_windows_time()
        
        self._just_updated = "--just-updated" in sys.argv
        
        # 이전 업데이트에서 남겨진 임시 파일들 삭제 시도
        def _cleanup_old_files():
            try:
                current_exe = sys.executable if getattr(sys, 'frozen', False) else None
                if current_exe:
                    old_exe = current_exe + ".old"
                    if os.path.exists(old_exe):
                        try:
                            os.remove(old_exe)
                        except PermissionError:
                            # 프로세스가 아직 덜 닫혀 잠겨있을 수 있으므로 1초 뒤 재시도
                            self.root.after(1000, _cleanup_old_files)
                            return
                    launcher_vbs = os.path.join(os.path.dirname(current_exe), "_update_launcher.vbs")
                    if os.path.exists(launcher_vbs):
                        os.remove(launcher_vbs)
                    launcher_bat = os.path.join(os.path.dirname(current_exe), "_update_launcher.bat")
                    if os.path.exists(launcher_bat):
                        os.remove(launcher_bat)
            except: pass
            
        _cleanup_old_files()
        
        available_fonts = tkfont.families(root=self.root)
        self.font_family = "Malgun Gothic"
        for f in ["Pretendard Variable", "Pretendard", "Noto Sans KR", "NanumSquareNeo", "NanumSquare", "NanumGothic", "나눔스퀘어", "나눔고딕", "Malgun Gothic"]:
            if f in available_fonts:
                self.font_family = f
                break
                
        self.root.title(f"스마트 전원 관리자 (v{CURRENT_VERSION})")
        self.root.geometry("340x460")
        self.root.resizable(False, False)
        self.root.protocol('WM_DELETE_WINDOW', self.hide_window)
        
        self.skipped_events = set()
        self.config = self.load_config()
        self.vars = {day: {} for day in DAYS}
        self.subject_labels = {day: {} for day in DAYS}
        
        self.school_info = self.config.get("school_info", {})
        self.timetable_cache = self.config.get("timetable_cache", {})
        self.meal_cache = self.config.get("meal_cache", {})
        
        self.show_popup_var = ctk.BooleanVar(value=self.config.get("show_popup_alert", True))
        self.autostart_var = ctk.BooleanVar(value=self.config.get("autostart", False))
        self.last_applied_autostart = self.config.get("autostart", False)
        self.minutes_var = ctk.StringVar(value=str(self.config.get("minutes_before", 2)))
        self.skip_today_var = ctk.BooleanVar(value=(self.config.get("skip_date") == datetime.now().strftime("%Y-%m-%d")))
        
        for day in DAYS:
            for class_name in TIMETABLE.keys():
                class_config = self.config.get(day, {}).get(class_name, {})
                if isinstance(class_config, bool):
                    is_enabled = class_config
                    action_val = "시스템 종료"
                else:
                    is_enabled = class_config.get("enabled", False)
                    action_val = class_config.get("action", "시스템 종료")
                    
                self.vars[day][class_name] = {
                    "enabled": ctk.BooleanVar(value=is_enabled),
                    "action": ctk.StringVar(value=action_val)
                }
                self.vars[day][class_name]["enabled"].trace_add('write', self.save_config_callback)
                self.vars[day][class_name]["action"].trace_add('write', self.save_config_callback)
                
        self.show_popup_var.trace_add('write', self.save_config_callback)
        self.autostart_var.trace_add('write', self.save_config_callback)
        self.minutes_var.trace_add('write', self.save_config_callback)
        
        self.main_tabview = ctk.CTkTabview(self.root)
        self.main_tabview.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.dash_frame = self.main_tabview.add("메인 화면")
        self.alert_frame = self.main_tabview.add("시스템 알림")
        
        self.alert_textbox = ctk.CTkTextbox(self.alert_frame, font=ctk.CTkFont(family=self.font_family, size=11), state="disabled")
        self.alert_textbox.pack(fill="both", expand=True, padx=10, pady=10)
        
        title_lbl = ctk.CTkLabel(self.dash_frame, text=f"스마트 전원 관리자 (v{CURRENT_VERSION})", font=ctk.CTkFont(family=self.font_family, size=16, weight="bold"))
        title_lbl.pack(pady=(0, 5))
        
        url_lbl = ctk.CTkLabel(self.dash_frame, text="🌐 Firebase 원격 제어 작동 중", font=ctk.CTkFont(family=self.font_family, size=11, weight="bold"), text_color="#2ECC71")
        url_lbl.pack(pady=(0, 10))
        
        status_card = ctk.CTkFrame(self.dash_frame, fg_color=("gray95", "gray15"), corner_radius=15)
        status_card.pack(fill="x", pady=5, ipady=15)
        
        self.countdown_var = ctk.StringVar(value="상태를 점검 중입니다...")
        self.countdown_label = ctk.CTkLabel(status_card, textvariable=self.countdown_var, font=ctk.CTkFont(family=self.font_family, size=14, weight="bold"), text_color="#1F6AA5")
        self.countdown_label.pack(pady=(15, 5))
        
        self.status_detail_var = ctk.StringVar(value="대기 중...")
        ctk.CTkLabel(status_card, textvariable=self.status_detail_var, font=ctk.CTkFont(family=self.font_family, size=11), text_color="gray").pack()
        
        self.timetable_label = ctk.CTkLabel(status_card, text="", font=ctk.CTkFont(family=self.font_family, size=10), text_color="#27AE60", wraplength=280)
        self.timetable_label.pack(pady=(5, 0))
        
        self.meal_label = ctk.CTkLabel(status_card, text="", font=ctk.CTkFont(family=self.font_family, size=10), text_color="#E67E22", wraplength=300, justify="left")
        self.meal_label.pack(pady=(2, 5))
        
        action_frame = ctk.CTkFrame(self.dash_frame, fg_color="transparent")
        action_frame.pack(fill="x", pady=15)
        
        skip_today_chk = ctk.CTkSwitch(action_frame, text="오늘 하루 작동 끄기", variable=self.skip_today_var, font=ctk.CTkFont(family=self.font_family, size=12, weight="bold"), command=self.toggle_skip_today_dashboard)
        skip_today_chk.pack(anchor="w", pady=5, padx=10)
        
        skip_next_btn = ctk.CTkButton(action_frame, text="이번 스케줄 건너뛰기 ⏭️", command=self.skip_next_schedule, font=ctk.CTkFont(family=self.font_family, size=12, weight="bold"), fg_color="#E67E22", hover_color="#D35400", height=32)
        skip_next_btn.pack(fill="x", pady=5, padx=10)
        
        bottom_frame = ctk.CTkFrame(self.dash_frame, fg_color="transparent")
        bottom_frame.pack(side="bottom", fill="x", pady=(10, 0))
        
        settings_btn = ctk.CTkButton(bottom_frame, text="⚙️ 상세 설정", command=self.open_settings_window, font=ctk.CTkFont(family=self.font_family, size=13), width=130, height=35)
        settings_btn.pack(side="left")
        
        hide_btn = ctk.CTkButton(bottom_frame, text="창 숨기기", command=self.hide_window, font=ctk.CTkFont(family=self.font_family, size=13), width=130, height=35, fg_color=("gray75", "gray30"), text_color=("black", "white"), hover_color=("gray65", "gray20"))
        hide_btn.pack(side="right")
        
        self.is_running = True
        self.icon = None
        self.last_triggered_time = None
        self.pending_shutdown = False
        self.pending_shutdown_target = None
        self.pending_action = "시스템 종료"
        self.last_media_time = 0
        self._is_reloading = False
        self.api_key_error_shown = False
        self.snooze_target = None
        self.snooze_action = "시스템 종료"
        self.last_all_cmd_ts = 0
        self.triggered_custom_schedules = set()
        self.custom_schedules = {}
        
        global app_instance
        app_instance = self
        
        # on 폴더 자동 생성 (초기세팅 모드용)
        try:
            os.makedirs(os.path.join(application_path, 'on'), exist_ok=True)
        except Exception:
            pass
        
        threading.Thread(target=self.monitor_time, daemon=True).start()
        threading.Thread(target=self.check_for_updates, daemon=True).start()
        threading.Thread(target=self.http_poller_thread, daemon=True).start()
        threading.Thread(target=self.custom_server_ws_thread, daemon=True).start()
            
        today = datetime.today()
        monday_str = (today - timedelta(days=today.weekday())).strftime("%Y%m%d")
        if self.school_info and monday_str not in self.timetable_cache:
            threading.Thread(target=self.update_timetable_background, daemon=True).start()
        else:
            self.root.after(0, self.update_timetable_ui)
        
    def add_system_alert(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.alert_textbox.configure(state="normal")
            self.alert_textbox.insert("0.0", f"[{timestamp}] {message}\n\n")
            self.alert_textbox.configure(state="disabled")
        except:
            pass



    def reload_config_from_web(self, data):
        """Firebase에서 원격 설정 변경 시 tkinter 변수 업데이트"""
        try:
            self._is_reloading = True
            
            # 먼저 CONFIG_FILE에 저장된 최신 전체 설정을 로드하여 school_code 유실 방지
            self.config = self.load_config()
            
            if 'school_info' in data:
                old_info = getattr(self, 'school_info', {})
                self.school_info = self.config.get('school_info', {})
                
                name = self.school_info.get("name", "")
                office = self.school_info.get("office_code", "")
                
                # school_code가 유실되었거나 학교명/교육청코드가 변경된 경우 자동으로 NEIS API를 통해 복구/갱신
                if name and office and (not self.school_info.get("school_code") or 
                                       old_info.get("name") != name or 
                                       old_info.get("office_code") != office):
                    def auto_resolve_school_code():
                        try:
                            url = f"https://open.neis.go.kr/hub/schoolInfo?Type=json&pIndex=1&pSize=5&ATPT_OFCDC_SC_CODE={office}&SCHUL_NM={urllib.parse.quote(name)}"
                            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                            with urllib.request.urlopen(req, timeout=5, context=_global_ssl_context) as res:
                                res_data = json.loads(res.read().decode('utf-8'))
                                if "schoolInfo" in res_data:
                                    row = res_data["schoolInfo"][1]["row"][0]
                                    self.school_info["school_code"] = row["SD_SCHUL_CODE"]
                                    self.school_info["school_kind"] = row["SCHUL_KND_SC_NM"]
                                    self.config["school_info"] = self.school_info
                                    self.save_config()
                        except Exception as ex:
                            try:
                                with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                    ef.write(f"[{datetime.now()}] auto_resolve_school_code error: {ex}\n")
                            except: pass
                        
                        # 복구/갱신 완료 후 시간표 및 급식 정보 다시 가져오기
                        self.timetable_cache = {}
                        self.meal_cache = {}
                        self.root.after(0, lambda: self.timetable_label.configure(text="시간표 정보를 불러오는 중...") if hasattr(self, 'timetable_label') and self.timetable_label.winfo_exists() else None)
                        self.root.after(0, lambda: self.meal_label.configure(text="급식 정보를 불러오는 중...") if hasattr(self, 'meal_label') and self.meal_label.winfo_exists() else None)
                        threading.Thread(target=self.update_timetable_background, daemon=True).start()
                        
                    threading.Thread(target=auto_resolve_school_code, daemon=True).start()
                else:
                    # 정보가 같거나 단순 학년/반/API키 변경 시 일반 시간표 업데이트 수행
                    if (old_info.get('grade') != self.school_info.get('grade') or
                        old_info.get('class_nm') != self.school_info.get('class_nm') or
                        old_info.get('api_key') != self.school_info.get('api_key')):
                        
                        self.timetable_cache = {}
                        self.meal_cache = {}
                        if hasattr(self, 'timetable_label') and self.timetable_label.winfo_exists():
                            self.timetable_label.configure(text="시간표 정보를 불러오는 중...")
                        if hasattr(self, 'meal_label') and self.meal_label.winfo_exists():
                            self.meal_label.configure(text="급식 정보를 불러오는 중...")
                            
                        threading.Thread(target=self.update_timetable_background, daemon=True).start()
                
                # GUI 학교명 라벨 갱신
                if hasattr(self, 'lbl_school') and self.lbl_school.winfo_exists():
                    school_name = self.school_info.get("name", "학교 미설정")
                    grade = self.school_info.get("grade", "")
                    class_nm = self.school_info.get("class_nm", "")
                    self.lbl_school.configure(text=f"{school_name} {grade}학년 {class_nm}반" if grade else school_name)

            if 'minutes_before' in data:
                self.minutes_var.set(str(data['minutes_before']))
            if 'show_popup_alert' in data:
                self.show_popup_var.set(bool(data['show_popup_alert']))
            if 'autostart' in data:
                self.autostart_var.set(bool(data['autostart']))
            if 'skip_date' in data:
                today = datetime.now().strftime("%Y-%m-%d")
                self.skip_today_var.set(data['skip_date'] == today)
            for day in DAYS:
                if day in data:
                    for class_name, val in data[day].items():
                        if day in self.vars and class_name in self.vars[day]:
                            if isinstance(val, dict):
                                self.vars[day][class_name]["enabled"].set(val.get("enabled", False))
                                self.vars[day][class_name]["action"].set(val.get("action", "시스템 종료"))
            self._is_reloading = False
            self.save_config()
            self.update_status_info()

        except Exception as e:
            self._is_reloading = False
            try:
                with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                    ef.write(f"[{datetime.now()}] reload_config_from_web FAILED: {e}\n")
            except: pass




    def custom_server_ws_thread(self):
        import time, json, socket, urllib.request, threading
        try:
            import websockets.sync.client
        except ImportError:
            return
            
        central_url = "https://atss-a1f9e-default-rtdb.firebaseio.com/"
        while self.is_running:
            try:
                # 1. Firebase에서 자체 서버 URL 가져오기
                config_url = f"{central_url}update_info/custom_server_url.json"
                req = urllib.request.Request(config_url, method='GET')
                
                ssl_context = None
                try:
                    import ssl
                    ssl_context = ssl.create_default_context()
                except: pass
                
                with urllib.request.urlopen(req, timeout=5, context=ssl_context) as res:
                    ws_url = json.loads(res.read().decode('utf-8'))
                
                if not ws_url or not isinstance(ws_url, str):
                    time.sleep(10)
                    continue
                    
                pc_id = get_pc_id()
                
                # 2. WebSocket 연결
                connect_kwargs = {}
                if ws_url.startswith("wss://"):
                    connect_kwargs["ssl"] = ssl_context
                    
                with websockets.sync.client.connect(validate_ws_url(ws_url), max_size=1048576, **connect_kwargs) as ws:
                    # PC ID로 연결하며 PC별 등록·토큰은 사용하지 않음
                    auth_msg = {"type": "auth", "role": "client", "pc_id": pc_id}
                    ws.send(json.dumps(auth_msg))
                    
                    try:
                        # auth_result 응답 대기
                        auth_resp = json.loads(ws.recv(timeout=10))
                        if auth_resp.get("status") != "success":
                            time.sleep(5)
                            continue
                    except Exception as e:
                        time.sleep(5)
                        continue
                        
                    last_status_time = 0

                    
                    def recv_loop():
                        while self.is_running:
                            try:
                                msg_raw = ws.recv()
                                msg = json.loads(msg_raw)
                                if msg.get("type") == "command":
                                    action = msg.get("action")
                                    payload = msg.get("payload", {})
                                    message = payload.get("message", "")
                                    
                                    # 명령어 실행 (기존 로직과 동일하게 분기 처리)
                                    if action == 'shutdown':
                                        import subprocess
                                        subprocess.run(['shutdown', '/s', '/t', '0'], creationflags=subprocess.CREATE_NO_WINDOW)
                                    elif action == 'sleep':
                                        import subprocess
                                        subprocess.run(['rundll32.exe', 'powrprof.dll,SetSuspendState', '0,1,0'], creationflags=subprocess.CREATE_NO_WINDOW)
                                    elif action == 'restart':
                                        import subprocess
                                        subprocess.run(['shutdown', '/r', '/t', '0'], creationflags=subprocess.CREATE_NO_WINDOW)
                                    elif action == 'update':
                                        threading.Thread(target=self.check_for_updates, kwargs={'silent': True, 'force': True}, daemon=True).start()
                                    elif action == 'setup_mode':
                                        threading.Thread(target=self.run_setup_mode, daemon=True).start()
                                    elif action == 'alert':
                                        from tkinter import messagebox
                                        threading.Thread(target=lambda: messagebox.showwarning("관리자 알림", message), daemon=True).start()
                                    elif action == 'volume_control':
                                        try:
                                            from pycaw.pycaw import AudioUtilities
                                            import comtypes
                                            comtypes.CoInitialize()
                                            _devs = AudioUtilities.GetSpeakers()
                                            _vol_intf = _devs.EndpointVolume
                                            level = float(payload.get('level', 0.5))
                                            _vol_intf.SetMasterVolumeLevelScalar(level, None)
                                        except: pass
                                    elif action == 'open_url':
                                        url = payload.get("url", "")
                                        browser = payload.get("browser", "default")
                                        if url:
                                            import subprocess
                                            open_remote_url(url, browser)
                                    elif action == 'open_file':
                                        file_path = payload.get("file_path", "")
                                        app_path = payload.get("app_path", "")
                                        if file_path:
                                            import subprocess, os
                                            if app_path and os.path.exists(app_path):
                                                subprocess.Popen([app_path, file_path])
                                            else:
                                                os.startfile(file_path)
                                    elif action == 'screenshot':
                                        import threading
                                        threading.Thread(target=_take_and_upload_screenshot, args=(central_url, pc_id, "", ssl_context), daemon=True).start()
                                    elif action == 'stream_start':
                                        _start_screen_streaming(central_url, pc_id, "", ssl_context)
                                    elif action == 'stream_stop':
                                        _stop_screen_streaming()
                                    elif action == 'bring_to_front' and isinstance(message, dict):
                                        target_hwnd = message.get('hwnd')
                                        if target_hwnd:
                                            try: target_hwnd = int(target_hwnd)
                                            except ValueError: target_hwnd = None
                                        if target_hwnd:
                                            try:
                                                ctypes.windll.user32.ShowWindow(target_hwnd, 9)
                                                ctypes.windll.user32.SetForegroundWindow(target_hwnd)
                                            except Exception: pass
                                    elif action == 'close_window' and isinstance(message, dict):
                                        force_close_window(message.get('hwnd'))
                                    elif action == 'minimize_window' and isinstance(message, dict):
                                        target_hwnd = message.get('hwnd')
                                        if target_hwnd:
                                            try: target_hwnd = int(target_hwnd)
                                            except ValueError: target_hwnd = None
                                        if target_hwnd:
                                            try: ctypes.windll.user32.ShowWindow(target_hwnd, 6)
                                            except Exception: pass
                                    elif action == 'maximize_window' and isinstance(message, dict):
                                        target_hwnd = message.get('hwnd')
                                        if target_hwnd:
                                            try: target_hwnd = int(target_hwnd)
                                            except ValueError: target_hwnd = None
                                        if target_hwnd:
                                            try: ctypes.windll.user32.ShowWindow(target_hwnd, 3)
                                            except Exception: pass
                                    elif action == 'restore_window' and isinstance(message, dict):
                                        target_hwnd = message.get('hwnd')
                                        if target_hwnd:
                                            try: target_hwnd = int(target_hwnd)
                                            except ValueError: target_hwnd = None
                                        if target_hwnd:
                                            try: ctypes.windll.user32.ShowWindow(target_hwnd, 9)
                                            except Exception: pass

                                    elif action == 'list_dir' and isinstance(message, dict):
                                        target_path = message.get('path', '') or ''
                                        target_path = target_path.replace('/', '\\\\')
                                        import os
                                        application_path = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
                                        def upload_dir_data(t_path):
                                            try:
                                                import urllib.request, json
                                                items = []
                                                import win32api
                                                if t_path == 'DRIVES':
                                                    drives = win32api.GetLogicalDriveStrings()
                                                    drives = drives.split('\\000')[:-1]
                                                    for d in drives:
                                                        items.append({'name': d, 'type': 'drive'})
                                                    result = {'path': 'DRIVES', 'error': None, 'items': items}
                                                else:
                                                    if not os.path.exists(t_path):
                                                        result = {'path': t_path, 'error': '경로를 찾을 수 없습니다.', 'items': []}
                                                    else:
                                                        try:
                                                            for entry in os.scandir(t_path):
                                                                items.append({'name': entry.name, 'type': 'directory' if entry.is_dir() else 'file'})
                                                            result = {'path': t_path, 'error': None, 'items': items}
                                                        except Exception as e:
                                                            result = {'path': t_path, 'error': str(e), 'items': []}
                                                if result is not None:
                                                    try:
                                                        data_bytes = json.dumps(result, ensure_ascii=False).encode('utf-8')
                                                        req = urllib.request.Request(f'https://atss-a1f9e-default-rtdb.firebaseio.com/explorer/{pc_id}.json', data=data_bytes, method='PUT')
                                                        req.add_header('Content-Type', 'application/json')
                                                        urllib.request.urlopen(req, timeout=5)
                                                    except: pass
                                            except: pass
                                        threading.Thread(target=upload_dir_data, args=(target_path,), daemon=True).start()
                                    elif action == 'get_processes':
                                        def upload_process_data():
                                            import psutil, urllib.request, json
                                            try:
                                                proc_list = []
                                                for p in psutil.process_iter(['pid', 'name', 'memory_info']):
                                                    try:
                                                        proc_list.append({'pid': p.info['pid'], 'name': p.info['name'], 'memory': p.info['memory_info'].rss})
                                                    except: pass
                                                data_bytes = json.dumps(proc_list, ensure_ascii=False).encode('utf-8')
                                                req = urllib.request.Request(f'https://atss-a1f9e-default-rtdb.firebaseio.com/processes/{pc_id}.json', data=data_bytes, method='PUT')
                                                req.add_header('Content-Type', 'application/json')
                                                urllib.request.urlopen(req, timeout=5)
                                            except: pass
                                        threading.Thread(target=upload_process_data, daemon=True).start()
                                    elif action == 'remote_input' and isinstance(message, dict):
                                        input_type = message.get('input_type')
                                        input_data = message.get('data', {})
                                        if input_type and PYAUTOGUI_AVAILABLE:
                                            try:
                                                import pyautogui
                                                if input_type == 'mouse_move':
                                                    dx = input_data.get('dx', 0)
                                                    dy = input_data.get('dy', 0)
                                                    if dx != 0 or dy != 0: pyautogui.move(dx, dy, _pause=False)
                                                elif input_type == 'mouse_click':
                                                    btn = input_data.get('button', 'left')
                                                    if btn == 'left': pyautogui.click(_pause=False)
                                                    elif btn == 'right': pyautogui.click(button='right', _pause=False)
                                                    elif btn == 'double': pyautogui.doubleClick(_pause=False)
                                                elif input_type == 'mouse_down':
                                                    pyautogui.mouseDown(_pause=False)
                                                elif input_type == 'mouse_up':
                                                    pyautogui.mouseUp(_pause=False)
                                                elif input_type == 'mouse_scroll':
                                                    dy = input_data.get('dy', 0)
                                                    if dy != 0: pyautogui.scroll(-dy * 5, _pause=False)
                                                elif input_type == 'key_down':
                                                    k = input_data.get('key')
                                                    if k: pyautogui.keyDown(k, _pause=False)
                                                elif input_type == 'key_up':
                                                    k = input_data.get('key')
                                                    if k: pyautogui.keyUp(k, _pause=False)
                                            except: pass
                                    elif action == 'show_desktop':
                                        try:
                                            ctypes.windll.user32.keybd_event(0x5B, 0, 0, 0)
                                            ctypes.windll.user32.keybd_event(0x44, 0, 0, 0)
                                            ctypes.windll.user32.keybd_event(0x44, 0, 2, 0)
                                            ctypes.windll.user32.keybd_event(0x5B, 0, 2, 0)
                                        except Exception: pass
                                    
                            except Exception as e:
                                break
                    
                    recv_thread = threading.Thread(target=recv_loop, daemon=True)
                    recv_thread.start()
                    if PYCAW_AVAILABLE:
                        try:
                            import comtypes
                            comtypes.CoInitialize()
                        except: pass
                    while self.is_running and recv_thread.is_alive():
                        now = time.time()
                        if now - last_status_time > 3.0:
                            last_status_time = now
                            
                            # 상태 정보 수집
                            current_vol = 50
                            if PYCAW_AVAILABLE:
                                try:
                                    _devs = AudioUtilities.GetSpeakers()
                                    _vol_intf = _devs.EndpointVolume
                                    current_vol = int(_vol_intf.GetMasterVolumeLevelScalar() * 100)
                                except: pass
                                
                            next_time, next_action = self.get_next_event()
                            if next_time and next_time != "skip":
                                from datetime import datetime
                                date_diff = (next_time.date() - datetime.now().date()).days
                                if date_diff == 0: day_prefix = "오늘 "
                                elif date_diff == 1: day_prefix = "내일 "
                                else: day_prefix = f"{DAYS[next_time.weekday()]}요일 "
                                next_str = f"{day_prefix}{next_time.strftime('%H:%M')} [{next_action}]"
                            else:
                                next_str = "오늘 안 함" if next_time == "skip" else "없음"
                                
                            try:
                                current_user = os.getlogin()
                            except Exception:
                                current_user = os.environ.get('USERNAME') or 'SYSTEM'
                                
                            payload = {
                                'volume': current_vol,
                                'ip': get_local_ip(),
                                'mac': '',
                                'hostname': socket.gethostname(),
                                'user': current_user,
                                'version': CURRENT_VERSION,
                                'status': 'online',
                                'next_event': next_str,
                                'last_seen': time.strftime('%H:%M:%S'),
                                'last_seen_ts': time.time(),
                                'windows': get_open_windows()
                            }
                            ws.send(json.dumps({"type": "status", "payload": payload}))
                            
                        time.sleep(1.0)
            except Exception as e:
                time.sleep(5)

    def http_poller_thread(self):
        processed_push_ids = set()
        while self.is_running:
            central_url = "https://atss-a1f9e-default-rtdb.firebaseio.com/"
            try:
                pc_id = get_pc_id()
                    
                next_time, next_action = self.get_next_event()
                if next_time and next_time != "skip":
                    date_diff = (next_time.date() - datetime.now().date()).days
                    if date_diff == 0: day_prefix = "오늘 "
                    elif date_diff == 1: day_prefix = "내일 "
                    else: day_prefix = f"{DAYS[next_time.weekday()]}요일 "
                    next_str = f"{day_prefix}{next_time.strftime('%H:%M')} [{next_action}]"
                else:
                    next_str = "오늘 안 함" if next_time == "skip" else "없음"
                
                current_cfg = sanitize_rtdb_keys(read_runtime_config())
                db_secret = current_cfg.get('db_secret', '')  # Firebase DB secret for auth
                
                ip = get_local_ip()
                ssl_context = ssl.create_default_context()
                
                try:
                    current_user = os.getlogin()
                except Exception:
                    current_user = os.environ.get('USERNAME') or 'SYSTEM'
                
                # 1. 내 PC 상태 보고 (PATCH)
                now_ts = time.time()
                if not hasattr(self, 'last_status_update'): self.last_status_update = 0
                if now_ts - self.last_status_update >= 5.0:
                    self.last_status_update = now_ts
                
                    current_vol = 50
                    if PYCAW_AVAILABLE:
                        try:
                            import comtypes
                            comtypes.CoInitialize()
                            _devs = AudioUtilities.GetSpeakers()
                            _vol_intf = _devs.EndpointVolume
                            current_vol = int(_vol_intf.GetMasterVolumeLevelScalar() * 100)
                        except:
                            pass
                    status_payload = json.dumps({
                        'volume': current_vol,
                        'ip': ip,
                        'mac': '',
                        'hostname': socket.gethostname(),
                        'user': current_user,
                        'version': CURRENT_VERSION,
                        'status': 'online',
                        'next_event': next_str,
                        'last_seen': datetime.now().strftime('%H:%M:%S'),
                        'last_seen_ts': {'.sv': 'timestamp'},
                        'config': public_config(current_cfg),
                        'windows': get_open_windows()
                    }).encode('utf-8')
                
                    patch_url = f"{central_url.rstrip('/')}/pcs/{pc_id}.json"
                    patch_req = urllib.request.Request(
                        patch_url, 
                        data=status_payload, 
                        method='PATCH', 
                        headers={
                            'Content-Type': 'application/json',
                            'Content-Length': str(len(status_payload))
                        }
                    )
                    try:
                        with urllib.request.urlopen(patch_req, timeout=10, context=ssl_context) as res:
                            pass
                    except urllib.error.HTTPError as he:
                        try:
                            err_body = he.read().decode('utf-8', errors='replace')
                            with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                ef.write(f"[{datetime.now()}] PUT error: {he.code} {he.reason} | URL: {patch_url} | Body: {err_body}\n")
                        except: pass
                    except Exception as e:
                        try:
                            with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                ef.write(f"[{datetime.now()}] PUT error: {e}\n")
                        except: pass
                
                # 2. 다른 PC 목록 가져오기 (비활성화 - Firebase 직접 연동)
                
                # 3. 대기 중인 명령 확인 (GET)
                cmd = None
                cmd_type = None
                
                # 개별 명령 조회
                cmd_url = f"{central_url.rstrip('/')}/commands/{pc_id}.json"
                cmd_req = urllib.request.Request(cmd_url, method='GET')
                try:
                    with urllib.request.urlopen(cmd_req, timeout=6, context=ssl_context) as res:
                        cmd = json.loads(res.read().decode('utf-8'))
                        if cmd:
                            cmd_type = 'individual'
                except Exception as e:
                    try:
                        with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                            ef.write(f"[{datetime.now()}] GET cmd error: {e}\n")
                    except: pass
                        
                # 개별 명령이 없으면 전체 명령 조회
                if not cmd:
                    all_cmd_url = f"{central_url.rstrip('/')}/commands/__ALL__.json"
                    all_cmd_req = urllib.request.Request(all_cmd_url, method='GET')
                    try:
                        with urllib.request.urlopen(all_cmd_req, timeout=6, context=ssl_context) as res:
                            cmd = json.loads(res.read().decode('utf-8'))
                            if cmd:
                                cmd_type = 'all'
                                cmd_ts = cmd.get('timestamp', 0)
                                # 이미 처리한 전체 명령이거나 5분 이상 지난 오래된 명령이면 무시
                                if cmd_ts == getattr(self, 'last_all_cmd_ts', 0) or time.time() - cmd_ts > 300.0:
                                    cmd = None
                                else:
                                    # 유효한 전체 명령이므로 중복 실행을 막기 위해 타임스탬프 기록
                                    self.last_all_cmd_ts = cmd_ts
                    except Exception as e:
                        try:
                            with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                ef.write(f"[{datetime.now()}] GET all cmd error: {e}\n")
                        except: pass
                                
                # 명령 실행
                if cmd and isinstance(cmd, dict):
                    commands_to_process = []
                    if "action" in cmd:
                        commands_to_process.append((None, cmd))
                    else:
                        for push_id, payload in cmd.items():
                            if isinstance(payload, dict) and "action" in payload:
                                commands_to_process.append((push_id, payload))

                    for push_id, payload in commands_to_process:
                        action = payload.get("action")
                        message = payload.get("message", "")
                        
                        # 10초 이상 지난 오래된 명령 무시 및 삭제
                        cmd_ts = payload.get("timestamp", 0)
                        
                        dedup_key = push_id if push_id else f"{action}_{cmd_ts}"
                        if dedup_key in processed_push_ids:
                            continue
                            
                        processed_push_ids.add(dedup_key)
                        if len(processed_push_ids) > 1000:
                            processed_push_ids.clear()
                            
                        if not fresh_command(cmd_ts):
                            cmd_success = True
                            continue
                            
                        # [핵심] 명령 중복 실행 방지를 위해 '실행 전 먼저 삭제'
                        if cmd_type == 'individual':
                            if push_id:
                                del_url = f"{central_url.rstrip('/')}/commands/{pc_id}/{push_id}.json"
                            else:
                                del_url = f"{central_url.rstrip('/')}/commands/{pc_id}.json"
                                
                            db_secret = current_cfg.get('db_secret', '')
                            if db_secret: del_url += f"?auth={db_secret}"
                            del_req = urllib.request.Request(del_url, method='DELETE', headers={'User-Agent': 'Mozilla/5.0'})
                            try:
                                with urllib.request.urlopen(del_req, timeout=5, context=ssl_context) as res:
                                    pass
                            except Exception as de:
                                pass
                            
                            # 삭제 후 상태 업데이트 시간 강제 초기화
                            self.last_status_update = 0
                    
                        # 진단 로그: 명령 수신 기록
                        try:
                            with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                ef.write(f"[{datetime.now()}] CMD RECEIVED: action={action}, type={cmd_type}, msg_type={type(message).__name__}, msg_keys={list(message.keys()) if isinstance(message, dict) else 'N/A'}\n")
                        except: pass
                    
                        # 명령 실행 액션 (성공 후에 삭제)
                        cmd_success = False
                        if action == 'shutdown':
                            subprocess.run(['shutdown', '/s', '/t', '0'], creationflags=subprocess.CREATE_NO_WINDOW)
                            cmd_success = True
                        elif action == 'sleep':
                            subprocess.run(['rundll32.exe', 'powrprof.dll,SetSuspendState', '0,1,0'], creationflags=subprocess.CREATE_NO_WINDOW)
                            cmd_success = True
                        elif action == 'restart':
                            subprocess.run(['shutdown', '/r', '/t', '0'], creationflags=subprocess.CREATE_NO_WINDOW)
                            cmd_success = True
                        elif action == 'update':
                            threading.Thread(target=self.check_for_updates, kwargs={'silent': True, 'force': True}, daemon=True).start()
                            cmd_success = True
                        elif action == 'setup_mode':
                            threading.Thread(target=self.run_setup_mode, daemon=True).start()
                            cmd_success = True
                        elif action == 'kill_process' and isinstance(message, dict):
                            target_pid = message.get('pid')
                            target_exe = message.get('exe', '')
                            target_hwnd = message.get('hwnd')
                            if target_pid:
                                if target_exe == 'explorer.exe' and target_hwnd:
                                    try:
                                        ctypes.windll.user32.PostMessageW(target_hwnd, 0x0010, 0, 0) # WM_CLOSE
                                    except Exception: pass
                                else:
                                    kill_remote_process(target_pid)
                                cmd_success = True
                        elif action == 'bring_to_front' and isinstance(message, dict):
                            target_hwnd = message.get('hwnd')
                            if target_hwnd:
                                try:
                                    target_hwnd = int(target_hwnd)
                                except ValueError:
                                    target_hwnd = None
                            if target_hwnd:
                                try:
                                    # ALT key hack to bypass SetForegroundWindow restrictions
                                    ctypes.windll.user32.keybd_event(0x12, 0, 0, 0) # ALT down
                                    ctypes.windll.user32.keybd_event(0x12, 0, 2, 0) # ALT up
                                    
                                    if ctypes.windll.user32.IsIconic(target_hwnd):
                                        ctypes.windll.user32.ShowWindow(target_hwnd, 9) # SW_RESTORE
                                    else:
                                        ctypes.windll.user32.ShowWindow(target_hwnd, 5) # SW_SHOW
                                        
                                    ctypes.windll.user32.SetForegroundWindow(target_hwnd)
                                except Exception: pass
                                cmd_success = True
                        elif action == 'minimize_window' and isinstance(message, dict):
                            target_hwnd = message.get('hwnd')
                            if target_hwnd:
                                try:
                                    target_hwnd = int(target_hwnd)
                                except ValueError:
                                    target_hwnd = None
                            if target_hwnd:
                                try:
                                    ctypes.windll.user32.ShowWindow(target_hwnd, 6) # SW_MINIMIZE
                                except Exception: pass
                                cmd_success = True
                        elif action == 'maximize_window' and isinstance(message, dict):
                            target_hwnd = message.get('hwnd')
                            if target_hwnd:
                                try:
                                    target_hwnd = int(target_hwnd)
                                except ValueError:
                                    target_hwnd = None
                            if target_hwnd:
                                try:
                                    ctypes.windll.user32.ShowWindow(target_hwnd, 3) # SW_MAXIMIZE
                                    ctypes.windll.user32.SetForegroundWindow(target_hwnd)
                                except Exception: pass
                                cmd_success = True
                        elif action == 'restore_window' and isinstance(message, dict):
                            target_hwnd = message.get('hwnd')
                            if target_hwnd:
                                try:
                                    target_hwnd = int(target_hwnd)
                                except ValueError:
                                    target_hwnd = None
                            if target_hwnd:
                                try:
                                    ctypes.windll.user32.ShowWindow(target_hwnd, 9) # SW_RESTORE
                                    ctypes.windll.user32.SetForegroundWindow(target_hwnd)
                                except Exception: pass
                                cmd_success = True
                        elif action == 'close_window' and isinstance(message, dict):
                            cmd_success = force_close_window(message.get('hwnd'))
                        elif action == 'show_desktop':
                            try:
                                ctypes.windll.user32.keybd_event(0x5B, 0, 0, 0) # LWIN down
                                ctypes.windll.user32.keybd_event(0x44, 0, 0, 0) # D down
                                ctypes.windll.user32.keybd_event(0x44, 0, 2, 0) # D up
                                ctypes.windll.user32.keybd_event(0x5B, 0, 2, 0) # LWIN up
                            except Exception: pass
                            cmd_success = True

                        elif action == 'set_config' and isinstance(message, dict):
                            try:
                                current = {}
                                if os.path.exists(CONFIG_FILE):
                                    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                                        current = json.load(f)
                                    
                                # 복구된 설정을 GUI 릴로드에도 적용하기 위해 message_clean 딕셔너리 생성
                                message_clean = {}
                                for k, v in remote_config(message).items():
                                    # 요일 스케줄 데이터 처리 (Firebase 우회용 언더바를 원래 슬래시로 De-sanitize 복구)
                                    if k in DAYS and isinstance(v, dict):
                                        if k not in current:
                                            current[k] = {}
                                        message_clean[k] = {}
                                        for period, p_data in v.items():
                                            orig_period = period.replace("_", "/") # '방과후_기타' -> '방과후/기타'
                                            current[k][orig_period] = p_data
                                            message_clean[k][orig_period] = p_data
                                    else:
                                        message_clean[k] = v
                                        if isinstance(v, dict) and k in current and isinstance(current[k], dict):
                                            current[k].update(v)
                                        else:
                                            current[k] = v
                                        
                                with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                                    json.dump(current, f, ensure_ascii=False, indent=4)
                                
                                if app_instance:
                                    app_instance.root.after(0, lambda d=message_clean: app_instance.reload_config_from_web(d))
                            
                                cmd_success = True
                            
                                # ★ 핵심 수정: set_config 성공 직후 Firebase /pcs/{pc_id}/config를 즉시 갱신
                                # 기존 로직은 다음 폴링 루프(2초 후)에서야 config를 올려 대시보드에 이전 값이 보이는 문제가 있었음
                                try:
                                    updated_cfg = public_config(sanitize_rtdb_keys(current))
                                    cfg_patch_payload = json.dumps({'config': updated_cfg}).encode('utf-8')
                                    cfg_patch_url = f"{central_url.rstrip('/')}/pcs/{pc_id}.json"
                                    cfg_patch_req = urllib.request.Request(
                                        cfg_patch_url,
                                        data=cfg_patch_payload,
                                        method='PATCH',
                                        headers={'Content-Type': 'application/json'}
                                    )
                                    with urllib.request.urlopen(cfg_patch_req, timeout=5, context=ssl_context) as _:
                                        pass
                                except Exception as patch_ex:
                                    try:
                                        with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                            ef.write(f"[{datetime.now()}] set_config immediate PATCH failed: {patch_ex}\n")
                                    except: pass
                            
                                # 진단 로그: 설정 적용 성공
                                try:
                                    with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                        ef.write(f"[{datetime.now()}] set_config SUCCESS: wrote {len(message)} keys to config, scheduled GUI reload\n")
                                except: pass
                            
                                # 시스템 알림: 원격 설정 수신 알림
                                if app_instance:
                                    app_instance.root.after(0, lambda: app_instance.add_system_alert("✅ 원격 설정 변경이 수신되어 적용되었습니다."))
                            except Exception as ex:
                                try:
                                    with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                        ef.write(f"[{datetime.now()}] set_config FAILED: {ex}\n")
                                except: pass
                        elif action == 'open_file' and isinstance(message, dict):
                            file_path = message.get('file_path', '').strip()
                            app_path  = message.get('app_path', '').strip()
                            if file_path:
                                try:
                                    is_url = file_path.lower().startswith(('http://', 'https://', 'ftp://'))
                                    if app_path:
                                        # Use specific app (browser or any program)
                                        subprocess.Popen(
                                            [app_path, file_path],
                                            creationflags=subprocess.CREATE_NO_WINDOW
                                        )
                                    elif is_url:
                                        # URL without specific app -> use Windows 'start' command (most reliable)
                                        open_remote_url(file_path)
                                    else:
                                        # Local file -> os.startfile
                                        os.startfile(file_path)
                                    cmd_success = True
                                    if app_instance:
                                        icon = '🌐' if is_url else '📂'
                                        app_instance.root.after(0, lambda fp=file_path: app_instance.add_system_alert(f"{icon} 원격 열기 실행: {fp}"))
                                except Exception as open_ex:
                                    try:
                                        with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                            ef.write(f"[{datetime.now()}] open_file FAILED: file={file_path!r} app={app_path!r} err={open_ex}\n")
                                    except: pass
                        elif action == 'list_dir' and isinstance(message, dict):
                            target_path = message.get('path', '') or ''
                            # Normalize: forward-slash -> backslash
                            target_path = target_path.replace('/', '\\')
                            # Ensure trailing backslash for root drives (e.g., "C:" -> "C:\")
                            if len(target_path) == 2 and target_path[1] == ':':
                                target_path = target_path + '\\'
                            result = None
                            try:
                                if target_path == "DRIVES" or not target_path:
                                    drives = [chr(x) + ":\\" for x in range(65, 91) if os.path.exists(chr(x) + ":")]
                                    items = [{"name": d, "type": "folder", "size": 0} for d in drives]
                                    result = {"path": "DRIVES", "items": items}
                                else:
                                    items = []
                                    with os.scandir(target_path) as it:
                                        for entry in it:
                                            try:
                                                items.append({
                                                    "name": entry.name,
                                                    "type": "folder" if entry.is_dir() else "file",
                                                    "size": entry.stat().st_size if entry.is_file() else 0
                                                })
                                            except Exception: pass
                                    items.sort(key=lambda x: (x["type"] == "file", x["name"].lower()))
                                    result = {"path": target_path, "items": items}
                            except Exception as e:
                                result = {"path": target_path, "error": str(e), "items": []}
                                try:
                                    with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                        ef.write(f"[{datetime.now()}] list_dir scandir FAILED path={target_path!r}: {e}\n")
                                except: pass
                            if result is not None:
                                try:
                                    exp_url = f"{central_url.rstrip('/')}/explorer/{pc_id}.json"
                                    if db_secret: exp_url += f"?auth={db_secret}"
                                    exp_payload = json.dumps(result, ensure_ascii=False).encode('utf-8')
                                    exp_req = urllib.request.Request(exp_url, data=exp_payload, method="PUT", headers={'Content-Type': 'application/json'})
                                    with urllib.request.urlopen(exp_req, timeout=10, context=ssl_context) as _: pass
                                    cmd_success = True
                                except Exception as e:
                                    try:
                                        with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                            ef.write(f"[{datetime.now()}] list_dir FAILED upload path={target_path!r}: {e}\n")
                                    except: pass
                        elif action == 'volume_control' and isinstance(message, dict):
                            if PYCAW_AVAILABLE:
                                try:
                                    level = float(message.get('level', 0.5))
                                    import comtypes
                                    comtypes.CoInitialize()
                                    devices = AudioUtilities.GetSpeakers()
                                    volume = devices.EndpointVolume
                                    volume.SetMasterVolumeLevelScalar(level, None)
                                    volume.SetMute(0, None)
                                    cmd_success = True
                                    if app_instance:
                                        app_instance.root.after(0, lambda: app_instance.add_system_alert(f'원격 음량 제어: {int(level*100)}%'))
                                except Exception as e:
                                    try:
                                        with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                            ef.write(f'[{datetime.now()}] volume_control FAILED: {e}\n')
                                    except: pass
                        elif action == 'unlock_screen':
                            # 원격 잠금 해제 시도 (화면 깨우기)
                            try:
                                ctypes.windll.user32.mouse_event(0x0001, 0, 0, 0, 0)
                                ctypes.windll.user32.keybd_event(0x0D, 0, 0, 0) # Enter down
                                ctypes.windll.user32.keybd_event(0x0D, 0, 2, 0) # Enter up
                                
                                if app_instance:
                                    app_instance.root.after(0, lambda: app_instance.add_system_alert("🔓 화면 깨우기 및 잠금해제 시도"))
                            except Exception as ex:
                                try:
                                    with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                        ef.write(f"[{datetime.now()}] unlock_screen FAILED: {ex}\n")
                                except: pass
                            # cmd_success를 True로 안해줘도 개별명령은 무조건 지워지도록 패치되어 있으나, 성공 로깅을 위해
                            cmd_success = True
                            
                        elif action == 'screenshot':
                            threading.Thread(
                                target=_take_and_upload_screenshot,
                                args=(central_url, pc_id, db_secret, ssl_context),
                                daemon=True
                            ).start()
                            cmd_success = True
                            if app_instance:
                                app_instance.root.after(0, lambda: app_instance.add_system_alert("📸 원격 화면 캡처 요청됨"))
                                

                        elif action == 'stream_start':
                            _start_screen_streaming(central_url, pc_id, db_secret, ssl_context)
                            cmd_success = True
                            if app_instance:
                                app_instance.root.after(0, lambda: app_instance.add_system_alert("⚡ 실시간 화면 스트리밍 시작됨"))
                        elif action == 'stream_stop':
                            _stop_screen_streaming()
                            cmd_success = True

                        elif action == 'close_active_window':
                            try:
                                hwnd = ctypes.windll.user32.GetForegroundWindow()
                                if hwnd:
                                    length = 256
                                    class_name = ctypes.create_unicode_buffer(length)
                                    ctypes.windll.user32.GetClassNameW(hwnd, class_name, length)
                                    if class_name.value not in ["Progman", "WorkerW", "Shell_TrayWnd"]:
                                        ctypes.windll.user32.PostMessageW(hwnd, 0x0010, 0, 0)
                                cmd_success = True
                                if app_instance:
                                    app_instance.root.after(0, lambda: app_instance.add_system_alert("❌ 원격 활성 창 종료 실행"))
                            except Exception as close_ex:
                                try:
                                    with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                        ef.write(f"[{datetime.now()}] close_active_window FAILED: err={close_ex}\n")
                                except: pass
                                cmd_success = True
                        elif action == 'message' and message:
                            try:
                                with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                    ef.write(f"[{datetime.now()}] MESSAGE: {message}\n")
                            except: pass
                            if app_instance:
                                app_instance.root.after(0, lambda m=message: messagebox.showinfo("관리자 메시지", m))
                            cmd_success = True
                    
            except Exception as ge:
                try:
                    with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                        ef.write(f"[{datetime.now()}] General thread error: {ge}\n")
                except: pass
            # 스트리밍 활성 중 remote_input 요청 정군 대기 최소화: 50ms
            time.sleep(0.05 if _stream_active else 0.5)

    def get_timetable_endpoint(self, school_kind):
        if "초등" in school_kind: return "elsTimetable"
        if "중학" in school_kind: return "misTimetable"
        if "고등" in school_kind: return "hisTimetable"
        if "특수" in school_kind: return "spsTimetable"
        return "hisTimetable"

    def fetch_this_week_timetable(self, office_code, school_code, school_kind, grade, class_nm):
        endpoint = self.get_timetable_endpoint(school_kind)
        today = datetime.today()
        monday = today - timedelta(days=today.weekday())
        
        api_key = self.school_info.get("api_key", "").strip()
        cache = {}
        
        if api_key:
            start_date = monday.strftime("%Y%m%d")
            end_date = (monday + timedelta(days=4)).strftime("%Y%m%d")
            url = f"https://open.neis.go.kr/hub/{endpoint}?KEY={api_key}&Type=json&pSize=100&ATPT_OFCDC_SC_CODE={office_code}&SD_SCHUL_CODE={school_code}&GRADE={grade}&CLASS_NM={class_nm}&TI_FROM_YMD={start_date}&TI_TO_YMD={end_date}"
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=5, context=_global_ssl_context) as res:
                    data = json.loads(res.read().decode('utf-8'))
                if endpoint in data:
                    for row in data[endpoint][1]["row"]:
                        ymd = row["ALL_TI_YMD"]
                        perio = row["PERIO"]
                        subj = row["ITRT_CNTNT"]
                        if ymd not in cache: cache[ymd] = {}
                        cache[ymd][perio] = subj
                elif "RESULT" in data and "CODE" in data["RESULT"]:
                    code = data["RESULT"]["CODE"]
                    msg = data["RESULT"]["MESSAGE"]
                    if code == "ERROR-290":
                        if getattr(self, 'api_key_error_shown', False) is False:
                            self.api_key_error_shown = True
                    api_key = "" # Fallback to no-key logic
            except Exception as e:
                print("시간표(KEY) 불러오기 실패:", e)
                api_key = "" # Fallback
                
        if not api_key:
            for i in range(5):
                date_str = (monday + timedelta(days=i)).strftime("%Y%m%d")
                url = f"https://open.neis.go.kr/hub/{endpoint}?Type=json&pSize=5&ATPT_OFCDC_SC_CODE={office_code}&SD_SCHUL_CODE={school_code}&GRADE={grade}&CLASS_NM={class_nm}&TI_FROM_YMD={date_str}&TI_TO_YMD={date_str}"
                try:
                    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=3, context=_global_ssl_context) as res:
                        data = json.loads(res.read().decode('utf-8'))
                    if endpoint in data:
                        for row in data[endpoint][1]["row"]:
                            ymd = row["ALL_TI_YMD"]
                            perio = row["PERIO"]
                            subj = row["ITRT_CNTNT"]
                            if ymd not in cache: cache[ymd] = {}
                            cache[ymd][perio] = subj
                except Exception as e:
                    print(f"시간표({date_str}) 불러오기 실패:", e)

        return cache if cache else None

    def clean_meal_text(self, text):
        text = text.replace("<br/>", ", ").replace("<br>", ", ")
        text = re.sub(r'\([^)]*\)', '', text)
        text = re.sub(r',\s*,', ',', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text.strip(", ")

    def fetch_this_week_meals(self, office_code, school_code):
        today = datetime.today()
        monday = today - timedelta(days=today.weekday())
        api_key = self.school_info.get("api_key", "").strip()
        cache = {}
        
        if api_key:
            start_date = monday.strftime("%Y%m%d")
            end_date = (monday + timedelta(days=4)).strftime("%Y%m%d")
            url = f"https://open.neis.go.kr/hub/mealServiceDietInfo?KEY={api_key}&Type=json&pSize=100&ATPT_OFCDC_SC_CODE={office_code}&SD_SCHUL_CODE={school_code}&MLSV_FROM_YMD={start_date}&MLSV_TO_YMD={end_date}"
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=5, context=_global_ssl_context) as res:
                    data = json.loads(res.read().decode('utf-8'))
                if "mealServiceDietInfo" in data:
                    for row in data["mealServiceDietInfo"][1]["row"]:
                        ymd = row["MLSV_YMD"]
                        mmeal_nm = row["MMEAL_SC_NM"]
                        dish = self.clean_meal_text(row["DDISH_NM"])
                        if ymd not in cache: cache[ymd] = {}
                        cache[ymd][mmeal_nm] = dish
                elif "RESULT" in data and "CODE" in data["RESULT"]:
                    api_key = "" # Fallback
            except Exception as e:
                print("급식(KEY) 불러오기 실패:", e)
                api_key = "" # Fallback
                
        if not api_key:
            for i in range(5):
                date_str = (monday + timedelta(days=i)).strftime("%Y%m%d")
                url = f"https://open.neis.go.kr/hub/mealServiceDietInfo?Type=json&pSize=5&ATPT_OFCDC_SC_CODE={office_code}&SD_SCHUL_CODE={school_code}&MLSV_FROM_YMD={date_str}&MLSV_TO_YMD={date_str}"
                try:
                    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=3, context=_global_ssl_context) as res:
                        data = json.loads(res.read().decode('utf-8'))
                    if "mealServiceDietInfo" in data:
                        for row in data["mealServiceDietInfo"][1]["row"]:
                            ymd = row["MLSV_YMD"]
                            mmeal_nm = row["MMEAL_SC_NM"]
                            dish = self.clean_meal_text(row["DDISH_NM"])
                            if ymd not in cache: cache[ymd] = {}
                            cache[ymd][mmeal_nm] = dish
                except Exception as e:
                    print(f"급식({date_str}) 불러오기 실패:", e)
        return cache if cache else None

    def update_timetable_background(self):
        office_code = self.school_info.get("office_code")
        school_code = self.school_info.get("school_code")
        grade = self.school_info.get("grade")
        class_nm = self.school_info.get("class_nm")
        
        if not office_code or not school_code or not grade or not class_nm:
            self.root.after(0, self.update_timetable_ui)
            return

        cache = self.fetch_this_week_timetable(
            office_code,
            school_code,
            self.school_info.get("school_kind"),
            grade,
            class_nm
        )
        meal_cache = self.fetch_this_week_meals(
            self.school_info.get("office_code"),
            self.school_info.get("school_code")
        )
        if cache:
            self.timetable_cache = cache
        if meal_cache:
            self.meal_cache = meal_cache
            
        if cache or meal_cache:
            self.save_config()
            self.root.after(0, self.update_timetable_ui)

    def update_timetable_ui(self):
        today_str = datetime.today().strftime("%Y%m%d")
        if today_str in self.timetable_cache:
            subjects = []
            for p in sorted(self.timetable_cache[today_str].keys(), key=int):
                subjects.append(f"{p}교시:{self.timetable_cache[today_str][p]}")
            text = "오늘 시간표: " + ", ".join(subjects)
            if hasattr(self, 'timetable_label'):
                self.timetable_label.configure(text=text)
        else:
            if hasattr(self, 'timetable_label'):
                self.timetable_label.configure(text="오늘의 시간표 정보가 없습니다.")
                
        if today_str in getattr(self, 'meal_cache', {}):
            meals = self.meal_cache[today_str]
            meal_texts = []
            if "조식" in meals: meal_texts.append(f"[조식] {meals['조식']}")
            if "중식" in meals: meal_texts.append(f"[중식] {meals['중식']}")
            if "석식" in meals: meal_texts.append(f"[석식] {meals['석식']}")
            
            if meal_texts:
                text = "\n".join(meal_texts)
            else:
                text = "오늘의 급식 정보가 없습니다."
                
            if hasattr(self, 'meal_label'):
                self.meal_label.configure(text=text)
        else:
            if hasattr(self, 'meal_label'):
                self.meal_label.configure(text="오늘의 급식 정보가 없습니다.")
                
        if hasattr(self, 'subject_labels'):
            today = datetime.today()
            monday = today - timedelta(days=today.weekday())
            for i, day in enumerate(DAYS[:5]):
                ymd = (monday + timedelta(days=i)).strftime("%Y%m%d")
                for class_name, _ in TIMETABLE.items():
                    subj = ""
                    if ymd in self.timetable_cache:
                        if "1교시" in class_name: subj = self.timetable_cache[ymd].get("1", "")
                        elif "2교시" in class_name: subj = self.timetable_cache[ymd].get("2", "")
                        elif "3교시" in class_name: subj = self.timetable_cache[ymd].get("3", "")
                        elif "4교시" in class_name: subj = self.timetable_cache[ymd].get("4", "")
                        elif "5교시" in class_name: subj = self.timetable_cache[ymd].get("5", "")
                        elif "6교시" in class_name: subj = self.timetable_cache[ymd].get("6", "")
                        elif "7교시" in class_name: subj = self.timetable_cache[ymd].get("7", "")
                        elif "8교시" in class_name: subj = self.timetable_cache[ymd].get("8", "")
                    
                    if day in self.subject_labels and class_name in self.subject_labels[day]:
                        lbl = self.subject_labels[day][class_name]
                        if lbl.winfo_exists():
                            lbl.configure(text=f"({subj})" if subj else "")

    def check_for_updates(self, silent=False, force=False):
        try:
            url = "https://atss-a1f9e-default-rtdb.firebaseio.com/update_info.json"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            try:
                ssl_context = ssl.create_default_context()
            except AttributeError:
                ssl_context = None
            with urllib.request.urlopen(req, timeout=8, context=ssl_context) as response:
                data = json.loads(response.read().decode('utf-8'))
                remote_version = data.get("version", CURRENT_VERSION)
                download_url = data.get("download_url")
            if (force or self._is_newer_version(remote_version, CURRENT_VERSION)) and download_url:
                self.perform_auto_update(download_url, is_manual=force, silent=silent)
        except Exception as e:
            if not silent:
                print("업데이트 확인 실패:", e)

    def _is_newer_version(self, remote, current):
        try:
            r_parts = [int(x) for x in remote.split('.')]
            c_parts = [int(x) for x in current.split('.')]
            max_len = max(len(r_parts), len(c_parts))
            r_parts.extend([0] * (max_len - len(r_parts)))
            c_parts.extend([0] * (max_len - len(c_parts)))
            return r_parts > c_parts
        except Exception:
            return False

    def _show_update_error(self, msg):
        try:
            with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                ef.write(f"[{datetime.now()}] UPDATE ERROR: {msg}\n")
        except Exception:
            pass

    def perform_auto_update(self, download_url, is_manual=False, silent=False):
        threading.Thread(
            target=self._launch_updater_process,
            args=(download_url,),
            daemon=True
        ).start()

    def _launch_updater_process(self, download_url):
        """독립 updater.exe 프로세스를 실행하고, 메인 프로그램을 종료한다.

        순서:
          1. updater.exe 위치 파악 (PyInstaller 번들 내 _MEIPASS, 또는 exe 옆)
          2. 실행 가능한 임시 경로로 복사 (MEIPASS는 종료 시 삭제됨)
          3. updater.exe <pid> <download_url> <target_exe_path> 실행 (분리 프로세스)
          4. 현재 프로세스(메인) 종료
        """
        _ulog_path = os.path.join(application_path, 'update_debug.log')
        def _ulog(msg):
            try:
                with open(_ulog_path, 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now()}] {msg}\n")
            except Exception:
                pass

        try:
            if not getattr(sys, 'frozen', False):
                _ulog("[updater] Not frozen exe — skipping update.")
                return

            # 1. updater.exe 원본 위치
            meipass_updater = os.path.join(sys._MEIPASS, 'updater.exe')
            exe_dir_updater = os.path.join(os.path.dirname(sys.executable), 'updater.exe')
            if os.path.exists(meipass_updater):
                src_updater = meipass_updater
            elif os.path.exists(exe_dir_updater):
                src_updater = exe_dir_updater
            else:
                _ulog("[updater] updater.exe not found in MEIPASS or exe dir!")
                return

            # 2. 임시 경로로 복사 (MEIPASS는 프로세스 종료 시 삭제됨)
            import shutil
            tmp_updater = private_updater_copy(src_updater)
            _ulog(f"[updater] Copied updater to: {tmp_updater}")

            # 3. 대상 경로: %LOCALAPPDATA%\AutoShutdown\auto_shutdown.exe
            local_app = os.environ.get('LOCALAPPDATA', application_path)
            target_dir = os.path.join(local_app, 'AutoShutdown')
            target_exe = os.path.join(target_dir, 'auto_shutdown.exe')

            pid = str(os.getpid())
            cmd = [tmp_updater, pid, download_url, target_exe]
            _ulog(f"[updater] Launching: {cmd}")

            subprocess.Popen(
                cmd,
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
            )
            _ulog("[updater] Updater process launched. Quitting main app.")

            # 4. 메인 프로세스 종료
            self.root.after(0, self.quit_app)

        except Exception as e:
            _ulog(f"[updater] _launch_updater_process FAILED: {e}")
            self._show_update_error(f"업데이트 준비 중 오류: {e}")

    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                config = read_runtime_config()

                # 마이그레이션: 이전 버전의 "1교시" 키를 "1교시 (08:40)" 등으로 변환
                for day in DAYS:
                    if day in config and isinstance(config[day], dict):
                        new_day_config = {}
                        for old_key, val in config[day].items():
                            matched = False
                            for new_key in TIMETABLE.keys():
                                if old_key.split(' ')[0] == new_key.split(' ')[0]:
                                    new_day_config[new_key] = val
                                    matched = True
                                    break
                            if not matched:
                                new_day_config[old_key] = val
                        config[day] = new_day_config

                return config
        except Exception: pass
        return {}

    def update_autostart_shortcut(self, enable):
        appdata = os.getenv('APPDATA')
        if not appdata: return
        startup_dir = os.path.join(appdata, r'Microsoft\Windows\Start Menu\Programs\Startup')
        vbs_path = os.path.join(startup_dir, "AutoShutdownBG.vbs")
        if enable:
            if getattr(sys, 'frozen', False):
                exe_path = os.path.join(application_path, "auto_shutdown.exe")
                # 부팅 시 Explorer 쉘이 준비될 시간을 주기 위해 5초 대기 후 실행
                script = f'WScript.Sleep 5000\nSet WshShell = CreateObject("WScript.Shell")\nWshShell.Run chr(34) & "{exe_path}" & Chr(34), 0\nSet WshShell = Nothing'
            else:
                bg_script = os.path.join(application_path, "auto_shutdown.py")
                pythonw = sys.executable.replace("python.exe", "pythonw.exe")
                script = f'WScript.Sleep 5000\nSet WshShell = CreateObject("WScript.Shell")\nWshShell.Run chr(34) & "{pythonw}" & Chr(34) & " " & chr(34) & "{bg_script}" & chr(34), 0\nSet WshShell = Nothing'
            with open(vbs_path, 'w', encoding='utf-8') as f:
                f.write(script)
            
            # 부팅 시(로그인 전) 백그라운드 실행을 위한 작업 스케줄러 자동 등록
            if getattr(sys, 'frozen', False):
                exe_path = os.path.join(application_path, "auto_shutdown.exe")
                try:
                    # 이미 등록되어 있는지 확인
                    chk = subprocess.run(['powershell', '-Command', 'Get-ScheduledTask -TaskName "AutoShutdown_Headless"'],
                                         capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    if chk.returncode != 0:
                        # 미등록 시 관리자 권한으로 등록 시도
                        ps_cmds = (
                            f"$action = New-ScheduledTaskAction -Execute '{exe_path}' -Argument '--headless'; "
                            f"$trigger = New-ScheduledTaskTrigger -AtStartup; "
                            f"$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\\\SYSTEM' -LogonType ServiceAccount; "
                            f"Register-ScheduledTask -TaskName 'AutoShutdown_Headless' -Action $action -Trigger $trigger -Principal $principal -Force"
                        )
                        run_cmd = f"Start-Process powershell -ArgumentList '-Command \"{ps_cmds}\"' -Verb RunAs -WindowStyle Hidden -Wait"
                        subprocess.run(['powershell', '-Command', run_cmd],
                                       creationflags=subprocess.CREATE_NO_WINDOW)
                except Exception:
                    pass
        else:
            if os.path.exists(vbs_path): os.remove(vbs_path)
            # 작업 스케줄러 등록 해제
            try:
                subprocess.run(['powershell', '-Command', "Start-Process powershell -ArgumentList '-Command \"Unregister-ScheduledTask -TaskName ''AutoShutdown_Headless'' -Confirm:$false\"' -Verb RunAs -WindowStyle Hidden -Wait"],
                               capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception:
                pass

    def save_config_callback(self, *args):
        if getattr(self, '_is_reloading', False): return
        self.save_config()

    def save_config(self):
        try:
            try: mins = int(self.minutes_var.get())
            except: mins = 2
                
            new_config = {
                "minutes_before": mins,
                "autostart": self.autostart_var.get(),
                "show_popup_alert": self.show_popup_var.get(),
                "skip_date": datetime.now().strftime("%Y-%m-%d") if self.skip_today_var.get() else "",
                "school_info": getattr(self, 'school_info', {}),
                "timetable_cache": getattr(self, 'timetable_cache', {}),
                "meal_cache": getattr(self, 'meal_cache', {})
            }
                
            for day in DAYS:
                new_config[day] = {}
                for class_name in TIMETABLE.keys():
                    new_config[day][class_name] = {
                        "enabled": self.vars[day][class_name]["enabled"].get(),
                        "action": self.vars[day][class_name]["action"].get()
                    }
            
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(new_config, f, ensure_ascii=False, indent=4)
                
            autostart_val = new_config.get("autostart", False)
            if getattr(self, 'last_applied_autostart', None) != autostart_val:
                self.last_applied_autostart = autostart_val
                threading.Thread(target=self.update_autostart_shortcut, args=(autostart_val,), daemon=True).start()
                
            self.update_status_info()
        except Exception: pass


    def toggle_skip_today_dashboard(self):
        self.save_config()
        self.update_status_info()

    def get_skip_state(self, item): return self.skip_today_var.get()
    def toggle_skip_state(self, icon, item):
        self.skip_today_var.set(not self.skip_today_var.get())
        self.save_config()
        self.update_status_info()

    def skip_next_schedule(self):
        next_time, next_action = self.get_next_event()
        if next_time and next_time != "skip":
            self.skipped_events.add(next_time.strftime("%Y-%m-%d %H:%M"))
            msg = f"예정된 {next_time.strftime('%H:%M')} 일정을"
                
            self.update_status_info()
            if self.icon: self.icon.notify(f"{msg} 건너뛰었습니다.", "알림")
            else: _log(f"안내: {msg} 1회 건너뜁니다.")

    def open_settings_window(self):
        if getattr(self, 'settings_win', None) and self.settings_win.winfo_exists():
            self.settings_win.focus()
            return
            
        self.settings_win = ctk.CTkToplevel(self.root)
        self.settings_win.protocol("WM_DELETE_WINDOW", self.settings_win.withdraw)
        self.settings_win.title("상세 설정")
        self.settings_win.geometry("380x370")
        self.settings_win.resizable(False, False)
        self.settings_win.attributes('-topmost', True)
        self.settings_win.after(100, lambda: self.settings_win.attributes('-topmost', False))
        
        scroll = ctk.CTkScrollableFrame(self.settings_win, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=5, pady=5)
        
        popup_card = ctk.CTkFrame(scroll, fg_color=("gray95", "gray15"), corner_radius=15)
        popup_card.pack(fill="x", pady=5, ipady=5)
        ctk.CTkLabel(popup_card, text="🔔 알림 설정", font=ctk.CTkFont(family=self.font_family, size=13, weight="bold")).pack(pady=(10, 5))
        
        popup_chk = ctk.CTkSwitch(popup_card, text="화면 중앙 팝업 알림 표시", variable=self.show_popup_var, font=ctk.CTkFont(family=self.font_family, size=11), switch_width=32, switch_height=16)
        popup_chk.pack(pady=5)
        ctk.CTkLabel(popup_card, text="※ 끄더라도 스케줄은 1분의 유예시간이\n백그라운드에서 동일하게 작동합니다.", font=ctk.CTkFont(family=self.font_family, size=10), text_color="gray").pack(pady=(0, 5))
        
        neis_card = ctk.CTkFrame(scroll, fg_color=("#E8F5E9", "#1E3A2F"), corner_radius=15, border_width=1, border_color="#2ECC71")
        neis_card.pack(fill="x", pady=5, ipady=5)
        ctk.CTkLabel(neis_card, text="🏫 나이스(NEIS) 학교 및 시간표 연동", font=ctk.CTkFont(family=self.font_family, size=12, weight="bold")).pack(pady=(8, 2))
        
        neis_info_frame = ctk.CTkFrame(neis_card, fg_color="transparent")
        neis_info_frame.pack(fill="x", padx=10, pady=5)
        
        school_name = self.school_info.get("name", "학교 미설정")
        grade = self.school_info.get("grade", "")
        class_nm = self.school_info.get("class_nm", "")
        
        self.lbl_school = ctk.CTkLabel(neis_info_frame, text=f"{school_name} {grade}학년 {class_nm}반" if grade else school_name, font=ctk.CTkFont(family=self.font_family, size=11))
        self.lbl_school.pack(side="left", padx=5)
        
        btn_search_school = ctk.CTkButton(neis_info_frame, text="학교 검색", command=self.open_school_search, width=70, height=24, font=ctk.CTkFont(family=self.font_family, size=11))
        btn_search_school.pack(side="right", padx=5)
        
        api_key_frame = ctk.CTkFrame(neis_card, fg_color="transparent")
        api_key_frame.pack(fill="x", padx=10, pady=(0, 5))
        
        ctk.CTkLabel(api_key_frame, text="API KEY:", font=ctk.CTkFont(family=self.font_family, size=11)).pack(side="left", padx=5)
        self.api_key_entry = ctk.CTkEntry(api_key_frame, placeholder_text="선택사항 (6~7교시 조회용)", font=ctk.CTkFont(family=self.font_family, size=10), height=24)
        self.api_key_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.api_key_entry.insert(0, self.school_info.get("api_key", ""))
        
        def save_api_key():
            self.school_info["api_key"] = self.api_key_entry.get().strip()
            self.api_key_error_shown = False
            self.save_config()
            self.timetable_cache = {}
            if hasattr(self, 'timetable_label'):
                self.timetable_label.configure(text="시간표 다시 불러오는 중...")
            threading.Thread(target=self.update_timetable_background, daemon=True).start()
            _log("API 키가 저장되고 데이터를 다시 불러옵니다.\n※ 인증키를 방금 발급받았다면 1~2시간 뒤에 활성화될 수 있습니다.")
            
        ctk.CTkButton(api_key_frame, text="키 적용", command=save_api_key, width=50, height=24, font=ctk.CTkFont(family=self.font_family, size=11)).pack(side="right", padx=5)
        

        
        schedule_card = ctk.CTkFrame(scroll, fg_color=("gray95", "gray15"), corner_radius=15)
        schedule_card.pack(fill="x", pady=5, ipady=5)
        ctk.CTkLabel(schedule_card, text="📅 주간 스케줄 예약", font=ctk.CTkFont(family=self.font_family, size=12, weight="bold")).pack(pady=(8, 2))
        
        min_frame = ctk.CTkFrame(schedule_card, fg_color="transparent")
        min_frame.pack(pady=2)
        ctk.CTkLabel(min_frame, text="체크한 시간의", font=ctk.CTkFont(family=self.font_family, size=11)).pack(side="left", padx=5)
        
        minutes_options = [str(i) for i in range(11)] + ["15", "20", "30", "45", "60", "90", "120"]
        if self.minutes_var.get() not in minutes_options:
            minutes_options.append(self.minutes_var.get())
            minutes_options.sort(key=int)
            
        min_opt = ctk.CTkOptionMenu(min_frame, variable=self.minutes_var, values=minutes_options, width=60, height=24, font=ctk.CTkFont(family=self.font_family, size=11))
        min_opt.pack(side="left", padx=5)
        ctk.CTkLabel(min_frame, text="분 전에 제어 실행", font=ctk.CTkFont(family=self.font_family, size=11)).pack(side="left", padx=5)
        
        self.tabview = ctk.CTkTabview(schedule_card, width=300, height=180)
        self.tabview.pack(pady=2, padx=10, fill="both", expand=True)
        
        for day in DAYS:
            self.tabview.add(day)
            tab_frame = self.tabview.tab(day)
            for class_name, _ in TIMETABLE.items():
                row_frame = ctk.CTkFrame(tab_frame, fg_color="transparent")
                row_frame.pack(anchor="w", fill="x", pady=4, padx=5)
                var_en = self.vars[day][class_name]["enabled"]
                var_act = self.vars[day][class_name]["action"]
                chk = ctk.CTkSwitch(row_frame, text=class_name, variable=var_en, font=ctk.CTkFont(family=self.font_family, size=11), switch_width=32, switch_height=16)
                chk.pack(side="left")
                
                subj_lbl = ctk.CTkLabel(row_frame, text="", font=ctk.CTkFont(family=self.font_family, size=10), text_color="#3498DB")
                subj_lbl.pack(side="left", padx=5)
                self.subject_labels[day][class_name] = subj_lbl
                
                cb = ctk.CTkOptionMenu(row_frame, variable=var_act, values=["시스템 종료", "절전 모드"], width=70, height=24, font=ctk.CTkFont(family=self.font_family, size=11))
                cb.pack(side="right")
                
        self.update_timetable_ui()
        
        auto_chk = ctk.CTkSwitch(scroll, text="윈도우 시작 시 백그라운드로 자동 실행", variable=self.autostart_var, font=ctk.CTkFont(family=self.font_family, size=11), switch_width=32, switch_height=16)
        auto_chk.pack(pady=(10, 5))

        update_card = ctk.CTkFrame(scroll, fg_color=("gray95", "gray15"), corner_radius=15)
        update_card.pack(fill="x", pady=5, ipady=5)
        ctk.CTkLabel(update_card, text=f"ℹ️ 현재 버전: v{CURRENT_VERSION}", font=ctk.CTkFont(family=self.font_family, size=12, weight="bold")).pack(pady=(8, 2))
        ctk.CTkLabel(update_card, text=f"🔑 PC 고유 ID: {get_pc_id()}", font=ctk.CTkFont(family=self.font_family, size=11), text_color="gray").pack(pady=(2, 2))
        self.update_btn = ctk.CTkButton(update_card, text="🔄 수동 업데이트 확인", command=self.manual_update_check, width=150, height=28, font=ctk.CTkFont(family=self.font_family, size=11))
        self.update_btn.pack(pady=(5, 8))

    def open_school_search(self):
        search_win = ctk.CTkToplevel(self.settings_win)
        search_win.title("학교 검색")
        search_win.geometry("300x350")
        search_win.attributes('-topmost', True)
        search_win.grab_set()
        
        entry = ctk.CTkEntry(search_win, placeholder_text="학교명 입력 (예: 서울과학고)")
        entry.pack(pady=10, padx=10, fill="x")
        
        result_frame = ctk.CTkScrollableFrame(search_win)
        result_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        def select_school(row):
            search_win.destroy()
            self.ask_grade_class(row)
            
        def do_search():
            q = entry.get().strip()
            if not q: return
            url = f"https://open.neis.go.kr/hub/schoolInfo?Type=json&pIndex=1&pSize=20&SCHUL_NM={urllib.parse.quote(q)}"
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=5, context=_global_ssl_context) as res:
                    data = json.loads(res.read().decode('utf-8'))
                
                for widget in result_frame.winfo_children():
                    widget.destroy()
                    
                if "schoolInfo" in data:
                    rows = data["schoolInfo"][1]["row"]
                    for r in rows:
                        name = r["SCHUL_NM"]
                        addr = r["ORG_RDNMA"]
                        btn = ctk.CTkButton(result_frame, text=f"{name}\n({addr})", anchor="w", command=lambda row=r: select_school(row))
                        btn.pack(fill="x", pady=2)
                else:
                    ctk.CTkLabel(result_frame, text="검색 결과가 없습니다.").pack()
            except Exception as e:
                print(e)
                
        btn_search = ctk.CTkButton(search_win, text="검색", command=do_search)
        btn_search.pack(pady=5)

    def ask_grade_class(self, row):
        gc_win = ctk.CTkToplevel(self.settings_win)
        gc_win.title("학년/반 입력")
        gc_win.geometry("250x200")
        gc_win.attributes('-topmost', True)
        gc_win.grab_set()
        
        ctk.CTkLabel(gc_win, text=row["SCHUL_NM"], font=ctk.CTkFont(family=self.font_family, weight="bold")).pack(pady=10)
        
        frame = ctk.CTkFrame(gc_win, fg_color="transparent")
        frame.pack(pady=10)
        
        ctk.CTkLabel(frame, text="학년:").grid(row=0, column=0, padx=5, pady=5)
        grade_entry = ctk.CTkEntry(frame, width=50)
        grade_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ctk.CTkLabel(frame, text="반:").grid(row=1, column=0, padx=5, pady=5)
        class_entry = ctk.CTkEntry(frame, width=50)
        class_entry.grid(row=1, column=1, padx=5, pady=5)
        
        def save_and_fetch():
            g = grade_entry.get().strip()
            c = class_entry.get().strip()
            if not g or not c:
                _log("오류: 학년과 반을 모두 입력해주세요.")
                return
            
            self.school_info = {
                "name": row["SCHUL_NM"],
                "office_code": row["ATPT_OFCDC_SC_CODE"],
                "school_code": row["SD_SCHUL_CODE"],
                "school_kind": row["SCHUL_KND_SC_NM"],
                "grade": g,
                "class_nm": c
            }
            self.save_config()
            if hasattr(self, 'lbl_school'):
                self.lbl_school.configure(text=f"{row['SCHUL_NM']} {g}학년 {c}반")
            gc_win.destroy()
            
            self.timetable_cache = {}
            if hasattr(self, 'timetable_label'):
                self.timetable_label.configure(text="시간표 정보를 불러오는 중...")
            threading.Thread(target=self.update_timetable_background, daemon=True).start()
            
        btn = ctk.CTkButton(gc_win, text="저장 및 연동", command=save_and_fetch)
        btn.pack(pady=10)

    def manual_update_check(self):
        # 저사양 PC에서 수동 확인 버튼을 누를 시 창이 굳는 현상 방지를 위해 UI를 비활성화하고 비동기로 체크
        if hasattr(self, 'update_btn') and self.update_btn and self.update_btn.winfo_exists():
            self.update_btn.configure(state="disabled", text="⏳ 업데이트 확인 중...")
        threading.Thread(target=self._async_manual_update_check, daemon=True).start()

    def _async_manual_update_check(self):
        try:
            # Firebase RTDB를 통해 업데이트 정보 조회
            url = "https://atss-a1f9e-default-rtdb.firebaseio.com/update_info.json"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            try:
                ssl_context = ssl.create_default_context()
            except AttributeError:
                ssl_context = None
            with urllib.request.urlopen(req, timeout=8, context=ssl_context) as response:
                data = json.loads(response.read().decode('utf-8'))
                remote_version = data.get("version", CURRENT_VERSION)
                download_url = data.get("download_url")
            
            # 성공 시 결과를 메인 스레드로 전달
            self.root.after(0, lambda: self._handle_update_check_result(remote_version, download_url, None))
        except Exception as e:
            # 실패 시 에러를 메인 스레드로 전달
            self.root.after(0, lambda: self._handle_update_check_result(None, None, str(e)))

    def _handle_update_check_result(self, remote_version, download_url, error_msg):
        self._restore_update_btn()
        
        if error_msg:
            _log(f"업데이트 오류: {error_msg}")
            return
            
        if self._is_newer_version(remote_version, CURRENT_VERSION) and download_url:
            _log(f"새로운 버전(v{remote_version}) 업데이트를 조용히 시작합니다.")
            if hasattr(self, 'update_btn') and self.update_btn and self.update_btn.winfo_exists():
                self.update_btn.configure(state="disabled", text="📥 다운로드 준비 중...")
            self.perform_auto_update(download_url, is_manual=True)
        elif download_url:
            _log(f"현재 최신 버전(v{CURRENT_VERSION})을 사용 중입니다. 강제 재설치를 조용히 시작합니다.")
            if hasattr(self, 'update_btn') and self.update_btn and self.update_btn.winfo_exists():
                self.update_btn.configure(state="disabled", text="📥 다운로드 준비 중...")
            self.perform_auto_update(download_url, is_manual=True)
        else:
            _log("업데이트 오류: 버전 정보를 불러오지 못했습니다.")

    def _update_download_progress(self, percent):
        try:
            if hasattr(self, 'update_btn') and self.update_btn and self.update_btn.winfo_exists():
                self.update_btn.configure(text=f"📥 {percent}% 다운로드 중...")
        except Exception:
            pass
        # 트레이 메뉴 텍스트도 동기화
        self._tray_update_label = f"📥 {percent}% 다운로드 중..."
        try:
            if self.icon:
                self.icon.update_menu()
        except Exception:
            pass

    def _restore_update_btn(self):
        try:
            if hasattr(self, 'update_btn') and self.update_btn and self.update_btn.winfo_exists():
                self.update_btn.configure(state="normal", text="🔄 수동 업데이트 확인")
        except Exception:
            pass
        self._tray_update_label = "🔄 업데이트 확인"
        try:
            if self.icon:
                self.icon.update_menu()
        except Exception:
            pass

    def _get_tray_update_label(self, item=None):
        return getattr(self, '_tray_update_label', '🔄 업데이트 확인')

    def tray_update_check(self, icon=None, item=None):
        """트레이에서 호출 - 묻지 않고 바로 다운로드 시작"""
        if getattr(self, '_update_in_progress', False):
            return
        self._update_in_progress = True
        self._tray_update_label = "⏳ 버전 확인 중..."
        try:
            if self.icon: self.icon.update_menu()
        except Exception:
            pass
        threading.Thread(target=self._tray_async_update_check, daemon=True).start()

    def _tray_async_update_check(self):
        try:
            url = "https://atss-a1f9e-default-rtdb.firebaseio.com/update_info.json"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            try:
                ssl_context = ssl.create_default_context()
            except AttributeError:
                ssl_context = None
            with urllib.request.urlopen(req, timeout=8, context=ssl_context) as response:
                data = json.loads(response.read().decode('utf-8'))
                remote_version = data.get("version", CURRENT_VERSION)
                download_url = data.get("download_url")

            if download_url and (self._is_newer_version(remote_version, CURRENT_VERSION) or True):
                # 새 버전이든 같은 버전이든 바로 다운로드 (트레이는 무조건 실행)
                self._tray_update_label = f"📥 v{remote_version} 다운로드 준비 중..."
                try:
                    if self.icon: self.icon.update_menu()
                except Exception:
                    pass
                self.perform_auto_update(download_url, is_manual=True, silent=True)
            else:
                self._tray_update_label = "🔄 업데이트 확인"
                self._update_in_progress = False
                try:
                    if self.icon: self.icon.update_menu()
                except Exception:
                    pass
        except Exception as e:
            self._tray_update_label = "🔄 업데이트 확인"
            self._update_in_progress = False
            try:
                if self.icon: self.icon.update_menu()
            except Exception:
                pass
            with open(os.path.join(application_path, 'update_debug.log'), 'a', encoding='utf-8') as f:
                f.write(f"[{datetime.now()}] [tray_check] error: {e}\n")

    def get_tray_server_status(self, item=None):
        return "✅ Firebase 원격 제어 연동 완료"

    def cancel_shutdown(self, icon=None, item=None):
        self.pending_shutdown = False
        if self.icon: self.icon.notify("예약된 시스템 종료/절전이 취소되었습니다.", "종료 취소")

    def restart_as_admin(self, icon=None, item=None):
        def _do_restart():
            import subprocess
            exe = sys.executable
            args = sys.argv[1:] if getattr(sys, 'frozen', False) else sys.argv
            try:
                ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, " ".join(args), None, 1)
                if ret > 32:  # success
                    self.root.after(500, lambda: (
                        self.icon.stop() if self.icon else None,
                        self.root.quit()
                    ))
            except Exception as e:
                pass
        threading.Thread(target=_do_restart, daemon=True).start()

    def open_autologin_settings(self, icon=None, item=None):
        import subprocess
        import sys
        if getattr(sys, 'frozen', False):
            subprocess.Popen([sys.executable, "--autologin-gui"])
        else:
            subprocess.Popen([sys.executable, sys.argv[0], "--autologin-gui"])

    def get_menu(self):
        menu_items = [
            pystray.MenuItem(f"버전: v{CURRENT_VERSION}", lambda icon, item: None),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("✅ Firebase 원격 제어 연동 중", lambda icon, item: None),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('관리자 권한으로 열기', self.restart_as_admin, visible=lambda item: not ctypes.windll.shell32.IsUserAnAdmin()),
            pystray.MenuItem('부팅 시 자동로그인 설정', self.open_autologin_settings),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('오늘 하루 끄지 않기', self.toggle_skip_state, checked=self.get_skip_state),
            pystray.MenuItem('열기 (대시보드)', self.show_window),
            pystray.MenuItem(self._get_tray_update_label, self.tray_update_check)
        ]
        menu_items.append(pystray.MenuItem('❌ 대기열에 있는 제어 강제 취소', self.cancel_shutdown, visible=lambda item: getattr(self, 'pending_shutdown', False)))
        menu_items.append(pystray.Menu.SEPARATOR)
        menu_items.append(pystray.MenuItem('종료', self.quit_app))
        return tuple(menu_items)

    def _show_update_success_popup(self):
        """업데이트 성공 시에도 팝업이나 경고창을 전혀 띄우지 않음"""
        pass

    def _is_shell_ready(self):
        """Explorer 쉘(시스템 트레이)이 준비되었는지 확인"""
        hwnd = ctypes.windll.user32.FindWindowW("Shell_TrayWnd", None)
        return hwnd != 0

    def _create_tray_icon_with_retry(self, attempt=0):
        """트레이 아이콘 생성 — 쉘 미준비 시 재시도 (부팅 직후 대비)"""
        MAX_RETRIES = 30  # 최대 30회, 약 60초

        if not self._is_shell_ready():
            if attempt < MAX_RETRIES:
                self.root.after(2000, lambda: self._create_tray_icon_with_retry(attempt + 1))
                return
            # 최대 재시도 초과 — 그래도 한 번 시도

        try:
            image = self.create_image(64, 64)
            menu = pystray.Menu(self.get_menu)
            self.icon = pystray.Icon("autoshutdown_v2", image, "스마트 전원 관리자 동작중", menu)
            self.icon.notify = lambda *args, **kwargs: None
            self.icon.run_detached()
            
            # 업데이트 후 재시작이었다면 성공 팝업 띄우기
            if getattr(self, '_just_updated', False):
                self._just_updated = False
                self.root.after(2000, self._show_update_success_popup)
        except Exception as e:
            print(f"트레이 아이콘 생성 실패 (시도 {attempt + 1}): {e}")
            self.icon = None
            if attempt < MAX_RETRIES:
                self.root.after(3000, lambda: self._create_tray_icon_with_retry(attempt + 1))

    def hide_window(self):
        self.root.withdraw()
        if getattr(self, 'settings_win', None) and self.settings_win.winfo_exists():
            self.settings_win.destroy()
        if not self.icon:
            self._create_tray_icon_with_retry()

    def _prompt_password(self):
        if getattr(self, '_is_prompting', False): return
        self._is_prompting = True

        pwd_win = ctk.CTkToplevel(self.root)
        pwd_win.title("보안 잠금")
        pwd_win.geometry("200x300")
        pwd_win.resizable(False, False)
        pwd_win.attributes('-topmost', True)
        pwd_win.grab_set()
        
        def on_close():
            self._is_prompting = False
            pwd_win.destroy()
        pwd_win.protocol("WM_DELETE_WINDOW", on_close)
        pwd_win.bind("<Key>", lambda e: "break" if e.keysym not in ('Alt_L', 'Alt_R', 'F4') else None)
        
        ctk.CTkLabel(pwd_win, text="비밀번호 입력", font=ctk.CTkFont(family=self.font_family, size=11)).pack(pady=(15, 5))
        display_var = ctk.StringVar(value="")
        lbl = ctk.CTkLabel(pwd_win, textvariable=display_var, font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"), width=90, height=35, corner_radius=8, fg_color=("gray85", "gray20"))
        lbl.pack(pady=5)
        
        def check_pwd():
            if not pwd_win.winfo_exists(): return
            if display_var.get() == "1235":
                self._is_prompting = False
                pwd_win.destroy()
                if self.icon:
                    self.icon.stop()
                    self.icon = None
                self.root.deiconify()
            else:
                _log("오류: 비밀번호가 틀렸습니다.")
                display_var.set("")
                
        def btn_click(num):
            current = display_var.get()
            if len(current) < 4:
                new_val = current + str(num)
                display_var.set(new_val)
                if len(new_val) == 4: pwd_win.after(100, check_pwd)
                
        pad_frame = ctk.CTkFrame(pwd_win, fg_color="transparent")
        pad_frame.pack(pady=5)
        buttons = ['1','2','3','4','5','6','7','8','9','C','0','']
        row = 0; col = 0
        for btn in buttons:
            if btn == 'C':
                cmd = lambda: display_var.set("")
                color = "#E74C3C"
                hover = "#C0392B"
            elif btn == '':
                col += 1
                if col > 2: col = 0; row += 1
                continue
            else:
                cmd = lambda n=btn: btn_click(n)
                color = ["#3B8ED0", "#1F6AA5"]
                hover = ["#36719F", "#144870"]
            btn_widget = ctk.CTkButton(pad_frame, text=btn, font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"), width=40, height=40, corner_radius=20, command=cmd)
            if btn == 'C': btn_widget.configure(fg_color=color, hover_color=hover)
            btn_widget.grid(row=row, column=col, padx=4, pady=4)
            col += 1
            if col > 2: col = 0; row += 1

    def show_window(self, icon=None, item=None):
        self.root.after(0, self._prompt_password)

    def send_offline_status(self):
        try:
            pc_id = get_pc_id()
            central_url = "https://atss-a1f9e-default-rtdb.firebaseio.com/"
            ssl_context = ssl.create_default_context()
            
            offline_payload = json.dumps({
                'status': 'offline',
                'last_seen': datetime.now().strftime('%H:%M:%S'),
                'last_seen_ts': {'.sv': 'timestamp'}
            }).encode('utf-8')
            
            patch_url = f"{central_url.rstrip('/')}/pcs/{pc_id}.json"
            req = urllib.request.Request(
                patch_url,
                data=offline_payload,
                method='PATCH',
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(req, timeout=3, context=ssl_context) as res:
                pass
        except Exception:
            pass

    def quit_app(self, icon=None, item=None):
        self.is_running = False
        try:
            if self.icon:
                self.icon.stop()
        except:
            pass
            
        # 메인 스레드에서 안전하게 종료하기 위해 root.after 사용
        def force_exit():
            self.send_offline_status()
            try:
                self.root.destroy()
            except:
                pass
            # 데몬 스레드들이 남아있을 수 있으므로 프로세스 강제 종료로 확실히 마무리
            os._exit(0)
            
        self.root.after(100, force_exit)

    def run_setup_mode(self):
        """필수 프로세스를 제외한 모든 프로세스를 강제 종료,
        파일탐색기(explorer.exe)는 프로세스를 죽이지 않고 열린 창만 부드럽게 닫음.
        이후 on 폴더의 프로그램을 실행."""
        if getattr(self, '_setup_in_progress', False):
            self.root.after(0, lambda: self.add_system_alert("⏳ 이미 초기세팅이 진행 중입니다."))
            return
        self._setup_in_progress = True

        def _task():
            try:
                self.root.after(0, lambda: self.add_system_alert("🚀 초기세팅 모드 시작 중..."))
                
                KEEP = {
                    'system', 'idle', 'smss.exe', 'csrss.exe', 'wininit.exe',
                    'winlogon.exe', 'services.exe', 'lsass.exe', 'svchost.exe',
                    'dwm.exe', 'registry', 'memcompression',
                    'auto_shutdown.exe', 'taskmgr.exe', 'conhost.exe',
                    'fontdrvhost.exe', 'spoolsv.exe', 'runtimebroker.exe',
                    'sihost.exe', 'taskhostw.exe', 'ctfmon.exe', 'dllhost.exe',
                    'audiodg.exe', 'python.exe', 'pythonw.exe', 'searchhost.exe',
                    'startmenuexperiencehost.exe', 'shellexperiencehost.exe',
                    'textinputhost.exe', 'securityhealthservice.exe', 'explorer.exe'
                }
                my_pid = os.getpid()

                # ── 1단계: 파일탐색기(explorer.exe) 창만 부드럽게 닫기 ──
                try:
                    # PowerShell의 Shell.Application COM 객체를 이용해 안전하게 폴더 창만 닫기
                    ps_cmd = "$shell = New-Object -ComObject Shell.Application; $shell.Windows() | ForEach-Object { $_.Quit() }"
                    subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=10)
                    self.root.after(0, lambda: self.add_system_alert("📂 파일탐색기 창 닫기 완료 (프로세스 유지)"))
                except Exception as e:
                    self.root.after(0, lambda m=str(e): self.add_system_alert(f"⚠️ 파일탐색기 창 닫기 오류: {m}"))

                # ── 2단계: 불필요 프로세스 강제 종료 (일괄 종료로 속도 개선) ──
                try:
                    result = subprocess.run(
                        ['tasklist', '/fo', 'csv', '/nh'],
                        capture_output=True, text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        timeout=10
                    )
                    pids_to_kill = []
                    for line in result.stdout.strip().split('\n'):
                        try:
                            line = line.strip()
                            if not line: continue
                            parts = line.strip('"').split('","')
                            if len(parts) < 2: continue
                            name = parts[0].strip('"').lower()
                            pid = int(parts[1].strip('"'))
                            if pid == my_pid: continue
                            if name in KEEP: continue
                            pids_to_kill.append(str(pid))
                        except: pass
                        
                    if pids_to_kill:
                        # 30개씩 분할하여 taskkill 실행 (명령어 길이 제한 대비 및 비동기 처리 방지)
                        chunk_size = 30
                        for i in range(0, len(pids_to_kill), chunk_size):
                            chunk = pids_to_kill[i:i+chunk_size]
                            args = ['taskkill', '/f']
                            for p in chunk:
                                args.extend(['/pid', p])
                            subprocess.run(args, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=10)
                except Exception as e:
                    self.root.after(0, lambda m=str(e): self.add_system_alert(f"⚠️ 프로세스 종료 오류: {m}"))
                
                time.sleep(1.0) # 창이 닫히고 정리될 시간을 충분히 줌

                # ── 3단계: on 폴더의 프로그램 실행 ──
                on_folder = os.path.join(application_path, 'on')
                os.makedirs(on_folder, exist_ok=True)
                
                desktop_on_folder = os.path.join(os.path.expanduser("~"), "Desktop", "on")
                search_folders = [on_folder]
                if os.path.exists(desktop_on_folder) and desktop_on_folder != on_folder:
                    search_folders.append(desktop_on_folder)
                
                launched = 0
                RUNNABLE_EXTS = ('.exe', '.lnk', '.bat', '.cmd', '.vbs')
                EXT_PRIORITY = {'.exe': 0, '.lnk': 1, '.bat': 2, '.cmd': 3, '.vbs': 4}
                
                try:
                    running_procs = set()
                    try:
                        tl = subprocess.run(
                            ['tasklist', '/fo', 'csv', '/nh'],
                            capture_output=True, text=True,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                            timeout=10
                        )
                        for line in tl.stdout.strip().split('\n'):
                            line = line.strip()
                            if not line: continue
                            parts = line.strip('"').split('","')
                            if parts:
                                running_procs.add(parts[0].strip('"').lower())
                    except Exception:
                        pass
                    
                    stem_map = {}
                    for folder_to_search in search_folders:
                        if not os.path.exists(folder_to_search): continue
                        for f in os.listdir(folder_to_search):
                            ext = os.path.splitext(f)[1].lower()
                            stem = os.path.splitext(f)[0].lower()
                            if ext not in EXT_PRIORITY:
                                continue
                            pri = EXT_PRIORITY[ext]
                            if stem not in stem_map or pri < stem_map[stem][0]:
                                stem_map[stem] = (pri, f, folder_to_search)
                    
                    for stem, (pri, f, folder_to_search) in stem_map.items():
                        ext = os.path.splitext(f)[1].lower()
                        if ext == '.exe' and f.lower() in running_procs:
                            self.root.after(0, lambda m=f: self.add_system_alert(f"⏭️ 이미 실행 중 (건너뜀): {m}"))
                            continue
                        try:
                            full_path = os.path.join(folder_to_search, f)
                            
                            # 로그 기록
                            with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                ef.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] run_setup_mode: Attempting to launch: {full_path}\n")

                            # 포커스 강제 가져오기 트릭 (Alt 키 시뮬레이션)
                            try:
                                ctypes.windll.user32.keybd_event(0x12, 0, 0, 0) # Alt 누름
                                ctypes.windll.user32.keybd_event(0x12, 0, 2, 0) # Alt 뗌
                            except: pass

                            try:
                                # os.startfile이 ShellExecuteW를 안전하게 래핑하며 COM 초기화 문제 등을 파이썬 내부에서 처리함
                                os.startfile(full_path)
                            except Exception as ex1:
                                with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                    ef.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] os.startfile failed: {ex1}. Trying Popen...\n")
                                # 실패 시 fallback (공백 경로를 안전하게 처리하기 위해 리스트 형태로 전달하고, lnk 실행을 위해 shell=True 유지하되 인용부호 추가)
                                os.startfile(full_path)
                                
                            launched += 1
                            time.sleep(0.5) # 여러 프로그램 실행 시 포커스 경합 방지
                            
                            with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                ef.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] run_setup_mode: Successfully launched {f}\n")
                        except Exception as e:
                            with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                                ef.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] run_setup_mode: FAILED to launch {f} - {e}\n")
                            self.root.after(0, lambda m=f"{f}: {e}": self.add_system_alert(f"⚠️ 실행 실패 - {m}"))
                except Exception as e:
                    with open(os.path.join(application_path, 'error.log'), 'a', encoding='utf-8') as ef:
                        ef.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] run_setup_mode: on folder iteration error - {e}\n")
                    self.root.after(0, lambda m=str(e): self.add_system_alert(f"⚠️ on 폴더 오류: {m}"))
                
                self.root.after(0, lambda: self.add_system_alert(f"✅ 초기세팅 완료: 창 정리 후 {launched}개 프로그램 실행됨"))
            finally:
                self._setup_in_progress = False

        threading.Thread(target=_task, daemon=True).start()

    def create_image(self, width, height):
        # 완전히 투명한 이미지 반환
        return Image.new('RGBA', (width, height), (0, 0, 0, 0))

    def get_next_event(self):
        config = self.load_config()
        skip_date = config.get("skip_date", "")
        today_str = datetime.now().strftime("%Y-%m-%d")
        if skip_date == today_str:
            return "skip", None
            
        try: minutes_off = int(config.get("minutes_before", 2))
        except: minutes_off = 0
            
        now = datetime.now()
        next_time = None
        next_action = "시스템 종료"
        
        for i in range(8):
            check_date = now + timedelta(days=i)
            day_str = DAYS[check_date.weekday()]
            
            day_schedule = config.get(day_str, {})
            for class_name, schedule_time in TIMETABLE.items():
                class_config = day_schedule.get(class_name, {})
                is_enabled = False
                action_val = "시스템 종료"
                if isinstance(class_config, bool):
                    is_enabled = class_config
                elif isinstance(class_config, dict):
                    is_enabled = class_config.get("enabled", False)
                    action_val = class_config.get("action", "시스템 종료")
                    
                if is_enabled:
                    target_dt = datetime.strptime(schedule_time, "%H:%M")
                    target_datetime = datetime(check_date.year, check_date.month, check_date.day, target_dt.hour, target_dt.minute) - timedelta(minutes=minutes_off)
                    
                    if target_datetime.replace(second=0, microsecond=0) >= now.replace(second=0, microsecond=0):
                        if target_datetime.strftime("%Y-%m-%d %H:%M") in self.skipped_events:
                            continue
                        if next_time is None or target_datetime < next_time:
                            next_time = target_datetime
                            next_action = action_val
        return next_time, next_action

    def update_status_info(self):
        next_time, next_action = self.get_next_event()
        now = datetime.now()
        
        if getattr(self, 'pending_shutdown', False):
            target = getattr(self, 'pending_shutdown_target', now)
            diff = target - now
            secs = int(diff.total_seconds())
            if secs < 0: secs = 0
            status_text = f"곧 {getattr(self, 'pending_action', '시스템 종료')}됩니다! ({secs}초 남음)"
            tooltip_text = f"스마트 예약 작동중\n{status_text}"
            detail_text = "예약된 제어가 곧 실행됩니다."

        elif next_time == "skip":
            status_text = "오늘 하루 알림 끄기 켜짐"
            tooltip_text = "스마트 전원 관리자\n(오늘 하루 끄기 활성화됨)"
            detail_text = "오늘은 스케줄이 작동하지 않습니다."
        elif next_time:
            diff = next_time - now
            if diff.total_seconds() < 0: diff = timedelta(seconds=0)
            hours, remainder = divmod(diff.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            days = diff.days
            
            if days > 0: time_left_str = f"{days}일 {hours:02d}:{minutes:02d}:{seconds:02d} 남음"
            else: time_left_str = f"{hours:02d}:{minutes:02d}:{seconds:02d} 남음"
                
            date_diff = (next_time.date() - now.date()).days
            if date_diff == 0: day_prefix = "오늘 "
            elif date_diff == 1: day_prefix = "내일 "
            else: day_prefix = f"{DAYS[next_time.weekday()]}요일 "

            status_text = f"다음: {day_prefix}{next_time.strftime('%H:%M')} [{next_action}]"
            detail_text = time_left_str
            if date_diff == 0: tooltip_text = f"스마트 전원 관리자\n다음: 오늘 {next_time.strftime('%H:%M')} [{next_action}]\n{time_left_str}"
            elif date_diff == 1: tooltip_text = f"스마트 전원 관리자\n다음: 내일 {next_time.strftime('%H:%M')} [{next_action}]\n{time_left_str}"
            else: tooltip_text = f"스마트 전원 관리자\n다음: {DAYS[next_time.weekday()]}요일 {next_time.strftime('%H:%M')} [{next_action}]\n{time_left_str}"
        else:
            status_text = "예약된 일정이 없습니다."
            detail_text = "설정창에서 스케줄을 추가해주세요."
            tooltip_text = "스마트 전원 관리자\n예약된 일정이 없습니다."
            
        if hasattr(self, 'countdown_var'):
            try: 
                self.root.after(0, lambda: self.countdown_var.set(status_text))
                self.root.after(0, lambda: self.status_detail_var.set(detail_text))
            except Exception: pass
            
        if self.icon:
            full_title = tooltip_text + f"\n{self.get_tray_server_status()}"
            if len(full_title) >= 128:
                full_title = full_title[:124] + "..."
            self.icon.title = full_title
            try: self.icon.update_menu()
            except: pass

    def show_toast_popup(self, title, message, duration, action):
        """팝업/경고창을 전혀 띄우지 않도록 비활성화"""
        pass

    def monitor_time(self):
        last_tooltip_update = 0
        if HAS_PYCAW:
            try:
                import comtypes
                comtypes.CoInitialize()
            except Exception: pass
        
        while self.is_running:
            now = datetime.now()
            now_min = now.replace(second=0, microsecond=0)
            
            if time.time() - last_tooltip_update > 1:
                self.update_status_info()
                last_tooltip_update = time.time()
            
            if getattr(self, 'pending_shutdown', False):
                if getattr(self, 'pending_shutdown_target', None) and now >= self.pending_shutdown_target:
                    self.pending_shutdown = False
                    action = getattr(self, 'pending_action', "시스템 종료")
                    if action == "시스템 종료": subprocess.run(['shutdown', '/s', '/t', '0'], creationflags=subprocess.CREATE_NO_WINDOW)
                    elif action == "절전 모드": subprocess.run(['rundll32.exe', 'powrprof.dll,SetSuspendState', '0,1,0'], creationflags=subprocess.CREATE_NO_WINDOW)
                time.sleep(1)
                continue
                
            if getattr(self, 'snooze_target', None) and now >= self.snooze_target:
                self.snooze_target = None
                action = getattr(self, 'snooze_action', "시스템 종료")
                self.pending_shutdown = True
                self.pending_shutdown_target = now + timedelta(minutes=1)
                self.pending_action = action
                if self.show_popup_var.get():
                    self.root.after(0, lambda a=action: self.show_toast_popup("연기된 스마트 알림", "연기했던 일정에 따라 잠시 후 제어가 시작됩니다.", 60, a))
            
            config = self.load_config()
            skip_date = config.get("skip_date", "")
            today_str = now.strftime("%Y-%m-%d")
            if skip_date == today_str:
                time.sleep(5)
                continue
                
            next_time, next_action = self.get_next_event()
            if next_time and next_time != "skip":
                target_min = next_time.replace(second=0, microsecond=0)
                if now_min == target_min and getattr(self, 'last_triggered_time', None) != target_min:
                    self.last_triggered_time = target_min
                    self.current_triggered_event_time = next_time.strftime("%Y-%m-%d %H:%M")
                    if next_action == "시스템 종료":
                        subprocess.run(['shutdown', '/s', '/t', '0'], creationflags=subprocess.CREATE_NO_WINDOW)
                    elif next_action == "절전 모드":
                        subprocess.run(['rundll32.exe', 'powrprof.dll,SetSuspendState', '0,1,0'], creationflags=subprocess.CREATE_NO_WINDOW)
                    elif next_action in ["재부팅", "시스템 재시작"]:
                        subprocess.run(['shutdown', '/r', '/t', '0'], creationflags=subprocess.CREATE_NO_WINDOW)
            
            time.sleep(1)

class HeadlessShutdownApp:
    def __init__(self):
        _sync_windows_time()
        self.is_running = True
        self.skipped_events = set()
        self.last_triggered_time = None
        self.last_all_cmd_ts = 0
        self.config = self.load_config()
        self.triggered_custom_schedules = set()
        self.custom_schedules = {}
        
        # 백그라운드 스레드들 시작
        threading.Thread(target=self.socket_listener, daemon=True).start()
        threading.Thread(target=self.monitor_time, daemon=True).start()
        threading.Thread(target=self.http_poller_thread, daemon=True).start()
        threading.Thread(target=self.custom_server_ws_thread, daemon=True).start()
        threading.Thread(target=self.check_for_updates, daemon=True).start()
        
        # 메인 스레드 유지
        while self.is_running:
            time.sleep(1)
            
    def run_setup_mode(self):
        """헤드리스 모드용 초기세팅: 불필요 프로세스 강제 종료만 수행"""
        if getattr(self, '_setup_in_progress', False):
            _log("Setup mode already in progress")
            return
        self._setup_in_progress = True

        def _task():
            try:
                _log("Headless setup mode started...")
                KEEP = {
                    'system', 'idle', 'smss.exe', 'csrss.exe', 'wininit.exe',
                    'winlogon.exe', 'services.exe', 'lsass.exe', 'svchost.exe',
                    'dwm.exe', 'registry', 'memcompression',
                    'auto_shutdown.exe', 'taskmgr.exe', 'conhost.exe',
                    'fontdrvhost.exe', 'spoolsv.exe', 'runtimebroker.exe',
                    'sihost.exe', 'taskhostw.exe', 'ctfmon.exe', 'dllhost.exe',
                    'audiodg.exe', 'python.exe', 'pythonw.exe', 'searchhost.exe',
                    'startmenuexperiencehost.exe', 'shellexperiencehost.exe',
                    'textinputhost.exe', 'securityhealthservice.exe', 'explorer.exe'
                }
                my_pid = os.getpid()

                try:
                    result = subprocess.run(
                        ['tasklist', '/fo', 'csv', '/nh'],
                        capture_output=True, text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        timeout=10
                    )
                    pids_to_kill = []
                    for line in result.stdout.strip().split('\n'):
                        try:
                            line = line.strip()
                            if not line: continue
                            parts = line.strip('"').split('","')
                            if len(parts) < 2: continue
                            name = parts[0].strip('"').lower()
                            pid = int(parts[1].strip('"'))
                            if pid == my_pid: continue
                            if name in KEEP: continue
                            pids_to_kill.append(str(pid))
                        except: pass
                        
                    if pids_to_kill:
                        chunk_size = 30
                        for i in range(0, len(pids_to_kill), chunk_size):
                            chunk = pids_to_kill[i:i+chunk_size]
                            args = ['taskkill', '/f']
                            for p in chunk:
                                args.extend(['/pid', p])
                            subprocess.run(args, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=10)
                except Exception as e:
                    _log(f"Headless setup taskkill error: {e}")
                
                _log("Headless setup mode finished")
            finally:
                self._setup_in_progress = False

        threading.Thread(target=_task, daemon=True).start()

    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                return read_runtime_config()
        except Exception: pass
        return {}
        
    def save_config(self):
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, ensure_ascii=False, indent=4)
        except Exception: pass

    def get_next_event(self):
        self.config = self.load_config()
        
        skip_date = self.config.get("skip_date", "")
        today_str = datetime.now().strftime("%Y-%m-%d")
        if skip_date == today_str:
            return "skip", None
            
        try: minutes_off = int(self.config.get("minutes_before", 2))
        except: minutes_off = 0
            
        now = datetime.now()
        next_time = None
        next_action = "시스템 종료"
        
        for i in range(8):
            check_date = now + timedelta(days=i)
            day_str = DAYS[check_date.weekday()]
            
            day_schedule = self.config.get(day_str, {})
            for class_name, schedule_time in TIMETABLE.items():
                class_config = day_schedule.get(class_name, {})
                
                is_enabled = False
                action_val = "시스템 종료"
                if isinstance(class_config, bool):
                    is_enabled = class_config
                elif isinstance(class_config, dict):
                    is_enabled = class_config.get("enabled", False)
                    action_val = class_config.get("action", "시스템 종료")
                    
                if is_enabled:
                    target_dt = datetime.strptime(schedule_time, "%H:%M")
                    target_datetime = datetime(check_date.year, check_date.month, check_date.day, target_dt.hour, target_dt.minute) - timedelta(minutes=minutes_off)
                    
                    if target_datetime.replace(second=0, microsecond=0) >= now.replace(second=0, microsecond=0):
                        if target_datetime.strftime("%Y-%m-%d %H:%M") in self.skipped_events:
                            continue
                        if next_time is None or target_datetime < next_time:
                            next_time = target_datetime
                            next_action = action_val
        return next_time, next_action

    def monitor_time(self):
        while self.is_running:
            now = datetime.now()
            now_min = now.replace(second=0, microsecond=0)
            
            next_time, next_action = self.get_next_event()
            if next_time and next_time != "skip":
                target_min = next_time.replace(second=0, microsecond=0)
                if now_min == target_min and getattr(self, 'last_triggered_time', None) != target_min:
                    self.last_triggered_time = target_min
                    if next_action == "시스템 종료":
                        subprocess.run(['shutdown', '/s', '/t', '0'], creationflags=subprocess.CREATE_NO_WINDOW)
                    elif next_action == "절전 모드":
                        subprocess.run(['rundll32.exe', 'powrprof.dll,SetSuspendState', '0,1,0'], creationflags=subprocess.CREATE_NO_WINDOW)
                    elif next_action in ["재부팅", "시스템 재시작"]:
                        subprocess.run(['shutdown', '/r', '/t', '0'], creationflags=subprocess.CREATE_NO_WINDOW)
            time.sleep(1)

    def socket_listener(self):
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(('127.0.0.1', 19985))
            s.listen(1)
        except Exception:
            self.is_running = False
            return
            
        while self.is_running:
            try:
                s.settimeout(1.0)
                conn, addr = s.accept()
            except socket.timeout:
                continue
            except Exception:
                break
                
            try:
                data = conn.recv(1024).decode('utf-8')
                if data == "exit":
                    conn.sendall(b"ok")
                    conn.close()
                    self.is_running = False
                    break
                conn.close()
            except Exception:
                pass
        try:
            s.close()
        except:
            pass
        os._exit(0)


    def custom_server_ws_thread(self):
        import time, json, socket, urllib.request, threading
        try:
            import websockets.sync.client
        except ImportError:
            return
            
        central_url = "https://atss-a1f9e-default-rtdb.firebaseio.com/"
        while self.is_running:
            try:
                # 1. Firebase에서 자체 서버 URL 가져오기
                config_url = f"{central_url}update_info/custom_server_url.json"
                req = urllib.request.Request(config_url, method='GET')
                
                ssl_context = None
                try:
                    import ssl
                    ssl_context = ssl.create_default_context()
                except: pass
                
                with urllib.request.urlopen(req, timeout=5, context=ssl_context) as res:
                    ws_url = json.loads(res.read().decode('utf-8'))
                
                if not ws_url or not isinstance(ws_url, str):
                    time.sleep(10)
                    continue
                    
                pc_id = get_pc_id()
                
                # 2. WebSocket 연결
                connect_kwargs = {}
                if ws_url.startswith("wss://"):
                    connect_kwargs["ssl"] = ssl_context
                    
                with websockets.sync.client.connect(validate_ws_url(ws_url), max_size=1048576, **connect_kwargs) as ws:
                    # PC ID로 연결하며 PC별 등록·토큰은 사용하지 않음
                    auth_msg = {"type": "auth", "role": "client", "pc_id": pc_id}
                    ws.send(json.dumps(auth_msg))
                    
                    try:
                        # auth_result 응답 대기
                        auth_resp = json.loads(ws.recv(timeout=10))
                        if auth_resp.get("status") != "success":
                            time.sleep(5)
                            continue
                    except Exception as e:
                        time.sleep(5)
                        continue
                        
                    last_status_time = 0
                    
                    def recv_loop():
                        while self.is_running:
                            try:
                                msg_raw = ws.recv()
                                msg = json.loads(msg_raw)
                                if msg.get("type") == "command":
                                    action = msg.get("action")
                                    payload = msg.get("payload", {})
                                    message = payload.get("message", "")
                                    
                                    # 명령어 실행 (기존 로직과 동일하게 분기 처리)
                                    if action == 'shutdown':
                                        import subprocess
                                        subprocess.run(['shutdown', '/s', '/t', '0'], creationflags=subprocess.CREATE_NO_WINDOW)
                                    elif action == 'sleep':
                                        import subprocess
                                        subprocess.run(['rundll32.exe', 'powrprof.dll,SetSuspendState', '0,1,0'], creationflags=subprocess.CREATE_NO_WINDOW)
                                    elif action == 'restart':
                                        import subprocess
                                        subprocess.run(['shutdown', '/r', '/t', '0'], creationflags=subprocess.CREATE_NO_WINDOW)
                                    elif action == 'update':
                                        threading.Thread(target=self.check_for_updates, kwargs={'silent': True, 'force': True}, daemon=True).start()
                                    elif action == 'setup_mode':
                                        threading.Thread(target=self.run_setup_mode, daemon=True).start()
                                    elif action == 'alert':
                                        from tkinter import messagebox
                                        threading.Thread(target=lambda: messagebox.showwarning("관리자 알림", message), daemon=True).start()
                                    elif action == 'volume_control':
                                        try:
                                            from pycaw.pycaw import AudioUtilities
                                            import comtypes
                                            comtypes.CoInitialize()
                                            _devs = AudioUtilities.GetSpeakers()
                                            _vol_intf = _devs.EndpointVolume
                                            level = float(payload.get('level', 0.5))
                                            _vol_intf.SetMasterVolumeLevelScalar(level, None)
                                        except: pass
                                    elif action == 'open_url':
                                        url = payload.get("url", "")
                                        browser = payload.get("browser", "default")
                                        if url:
                                            import subprocess
                                            open_remote_url(url, browser)
                                    elif action == 'open_file':
                                        file_path = payload.get("file_path", "")
                                        app_path = payload.get("app_path", "")
                                        if file_path:
                                            import subprocess, os
                                            if app_path and os.path.exists(app_path):
                                                subprocess.Popen([app_path, file_path])
                                            else:
                                                os.startfile(file_path)
                                    elif action == 'screenshot':
                                        import threading
                                        threading.Thread(target=_take_and_upload_screenshot, args=(central_url, pc_id, "", ssl_context), daemon=True).start()
                                    elif action == 'stream_start':
                                        _start_screen_streaming(central_url, pc_id, "", ssl_context)
                                    elif action == 'stream_stop':
                                        _stop_screen_streaming()
                                    elif action == 'bring_to_front' and isinstance(message, dict):
                                        target_hwnd = message.get('hwnd')
                                        if target_hwnd:
                                            try: target_hwnd = int(target_hwnd)
                                            except ValueError: target_hwnd = None
                                        if target_hwnd:
                                            try:
                                                ctypes.windll.user32.ShowWindow(target_hwnd, 9)
                                                ctypes.windll.user32.SetForegroundWindow(target_hwnd)
                                            except Exception: pass
                                    elif action == 'close_window' and isinstance(message, dict):
                                        force_close_window(message.get('hwnd'))
                                    elif action == 'minimize_window' and isinstance(message, dict):
                                        target_hwnd = message.get('hwnd')
                                        if target_hwnd:
                                            try: target_hwnd = int(target_hwnd)
                                            except ValueError: target_hwnd = None
                                        if target_hwnd:
                                            try: ctypes.windll.user32.ShowWindow(target_hwnd, 6)
                                            except Exception: pass
                                    elif action == 'maximize_window' and isinstance(message, dict):
                                        target_hwnd = message.get('hwnd')
                                        if target_hwnd:
                                            try: target_hwnd = int(target_hwnd)
                                            except ValueError: target_hwnd = None
                                        if target_hwnd:
                                            try: ctypes.windll.user32.ShowWindow(target_hwnd, 3)
                                            except Exception: pass
                                    elif action == 'restore_window' and isinstance(message, dict):
                                        target_hwnd = message.get('hwnd')
                                        if target_hwnd:
                                            try: target_hwnd = int(target_hwnd)
                                            except ValueError: target_hwnd = None
                                        if target_hwnd:
                                            try: ctypes.windll.user32.ShowWindow(target_hwnd, 9)
                                            except Exception: pass

                                    elif action == 'list_dir' and isinstance(message, dict):
                                        target_path = message.get('path', '') or ''
                                        target_path = target_path.replace('/', '\\\\')
                                        import os
                                        application_path = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
                                        def upload_dir_data(t_path):
                                            try:
                                                import urllib.request, json
                                                items = []
                                                import win32api
                                                if t_path == 'DRIVES':
                                                    drives = win32api.GetLogicalDriveStrings()
                                                    drives = drives.split('\\000')[:-1]
                                                    for d in drives:
                                                        items.append({'name': d, 'type': 'drive'})
                                                    result = {'path': 'DRIVES', 'error': None, 'items': items}
                                                else:
                                                    if not os.path.exists(t_path):
                                                        result = {'path': t_path, 'error': '경로를 찾을 수 없습니다.', 'items': []}
                                                    else:
                                                        try:
                                                            for entry in os.scandir(t_path):
                                                                items.append({'name': entry.name, 'type': 'directory' if entry.is_dir() else 'file'})
                                                            result = {'path': t_path, 'error': None, 'items': items}
                                                        except Exception as e:
                                                            result = {'path': t_path, 'error': str(e), 'items': []}
                                                if result is not None:
                                                    try:
                                                        data_bytes = json.dumps(result, ensure_ascii=False).encode('utf-8')
                                                        req = urllib.request.Request(f'https://atss-a1f9e-default-rtdb.firebaseio.com/explorer/{pc_id}.json', data=data_bytes, method='PUT')
                                                        req.add_header('Content-Type', 'application/json')
                                                        urllib.request.urlopen(req, timeout=5)
                                                    except: pass
                                            except: pass
                                        threading.Thread(target=upload_dir_data, args=(target_path,), daemon=True).start()
                                    elif action == 'get_processes':
                                        def upload_process_data():
                                            import psutil, urllib.request, json
                                            try:
                                                proc_list = []
                                                for p in psutil.process_iter(['pid', 'name', 'memory_info']):
                                                    try:
                                                        proc_list.append({'pid': p.info['pid'], 'name': p.info['name'], 'memory': p.info['memory_info'].rss})
                                                    except: pass
                                                data_bytes = json.dumps(proc_list, ensure_ascii=False).encode('utf-8')
                                                req = urllib.request.Request(f'https://atss-a1f9e-default-rtdb.firebaseio.com/processes/{pc_id}.json', data=data_bytes, method='PUT')
                                                req.add_header('Content-Type', 'application/json')
                                                urllib.request.urlopen(req, timeout=5)
                                            except: pass
                                        threading.Thread(target=upload_process_data, daemon=True).start()
                                    elif action == 'remote_input' and isinstance(message, dict):
                                        input_type = message.get('input_type')
                                        input_data = message.get('data', {})
                                        if input_type and PYAUTOGUI_AVAILABLE:
                                            try:
                                                import pyautogui
                                                if input_type == 'mouse_move':
                                                    dx = input_data.get('dx', 0)
                                                    dy = input_data.get('dy', 0)
                                                    if dx != 0 or dy != 0: pyautogui.move(dx, dy, _pause=False)
                                                elif input_type == 'mouse_click':
                                                    btn = input_data.get('button', 'left')
                                                    if btn == 'left': pyautogui.click(_pause=False)
                                                    elif btn == 'right': pyautogui.click(button='right', _pause=False)
                                                    elif btn == 'double': pyautogui.doubleClick(_pause=False)
                                                elif input_type == 'mouse_down':
                                                    pyautogui.mouseDown(_pause=False)
                                                elif input_type == 'mouse_up':
                                                    pyautogui.mouseUp(_pause=False)
                                                elif input_type == 'mouse_scroll':
                                                    dy = input_data.get('dy', 0)
                                                    if dy != 0: pyautogui.scroll(-dy * 5, _pause=False)
                                                elif input_type == 'key_down':
                                                    k = input_data.get('key')
                                                    if k: pyautogui.keyDown(k, _pause=False)
                                                elif input_type == 'key_up':
                                                    k = input_data.get('key')
                                                    if k: pyautogui.keyUp(k, _pause=False)
                                            except: pass
                                    elif action == 'show_desktop':
                                        try:
                                            ctypes.windll.user32.keybd_event(0x5B, 0, 0, 0)
                                            ctypes.windll.user32.keybd_event(0x44, 0, 0, 0)
                                            ctypes.windll.user32.keybd_event(0x44, 0, 2, 0)
                                            ctypes.windll.user32.keybd_event(0x5B, 0, 2, 0)
                                        except Exception: pass
                                    
                            except Exception as e:
                                break
                    
                    recv_thread = threading.Thread(target=recv_loop, daemon=True)
                    recv_thread.start()
                    if PYCAW_AVAILABLE:
                        try:
                            import comtypes
                            comtypes.CoInitialize()
                        except: pass
                    while self.is_running and recv_thread.is_alive():
                        now = time.time()
                        if now - last_status_time > 3.0:
                            last_status_time = now
                            
                            # 상태 정보 수집
                            current_vol = 50
                            if PYCAW_AVAILABLE:
                                try:
                                    _devs = AudioUtilities.GetSpeakers()
                                    _vol_intf = _devs.EndpointVolume
                                    current_vol = int(_vol_intf.GetMasterVolumeLevelScalar() * 100)
                                except: pass
                                
                            next_time, next_action = self.get_next_event()
                            if next_time and next_time != "skip":
                                from datetime import datetime
                                date_diff = (next_time.date() - datetime.now().date()).days
                                if date_diff == 0: day_prefix = "오늘 "
                                elif date_diff == 1: day_prefix = "내일 "
                                else: day_prefix = f"{DAYS[next_time.weekday()]}요일 "
                                next_str = f"{day_prefix}{next_time.strftime('%H:%M')} [{next_action}]"
                            else:
                                next_str = "오늘 안 함" if next_time == "skip" else "없음"
                                
                            try:
                                current_user = os.getlogin()
                            except Exception:
                                current_user = os.environ.get('USERNAME') or 'SYSTEM'
                                
                            payload = {
                                'volume': current_vol,
                                'ip': get_local_ip(),
                                'mac': '',
                                'hostname': socket.gethostname(),
                                'user': current_user,
                                'version': CURRENT_VERSION,
                                'status': 'online',
                                'next_event': next_str,
                                'last_seen': time.strftime('%H:%M:%S'),
                                'last_seen_ts': time.time(),
                                'windows': get_open_windows()
                            }
                            ws.send(json.dumps({"type": "status", "payload": payload}))
                            
                        time.sleep(1.0)
            except Exception as e:
                time.sleep(5)

    def http_poller_thread(self):
        _log_path = os.path.join(application_path, 'headless_debug.log')
        def _log(msg):
            try:
                with open(_log_path, 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now()}] {msg}\n")
            except: pass

        _log("headless http_poller_thread started")
        _headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
        processed_push_ids = set()

        while self.is_running:
            central_url = "https://atss-a1f9e-default-rtdb.firebaseio.com/"
            try:
                pc_id = get_pc_id()
                    
                next_time, next_action = self.get_next_event()
                if next_time and next_time != "skip":
                    date_diff = (next_time.date() - datetime.now().date()).days
                    if date_diff == 0: day_prefix = "오늘 "
                    elif date_diff == 1: day_prefix = "내일 "
                    else: day_prefix = f"{DAYS[next_time.weekday()]}요일 "
                    next_str = f"{day_prefix}{next_time.strftime('%H:%M')} [{next_action}]"
                else:
                    next_str = "오늘 안 함" if next_time == "skip" else "없음"
                
                current_cfg = sanitize_rtdb_keys(read_runtime_config())
                
                ip = get_local_ip()
                ssl_context = ssl.create_default_context()
                
                try:
                    current_user = os.getlogin()
                except Exception:
                    current_user = os.environ.get('USERNAME') or 'SYSTEM'
                
                # 1. 상태 보고 (PUT) 매 5초마다만 실행하여 반응속도 최적화
                now_ts = time.time()
                if not hasattr(self, 'last_status_update'): self.last_status_update = 0
                
                if now_ts - self.last_status_update >= 5.0:
                    self.last_status_update = now_ts
                    current_vol = 50
                    if PYCAW_AVAILABLE:
                        try:
                            import comtypes
                            comtypes.CoInitialize()
                            _devs = AudioUtilities.GetSpeakers()
                            _vol_intf = _devs.EndpointVolume
                            current_vol = int(_vol_intf.GetMasterVolumeLevelScalar() * 100)
                        except:
                            pass
                    status_payload = json.dumps({
                        'volume': current_vol,
                        'ip': ip,
                        'mac': '',
                        'hostname': socket.gethostname(),
                        'user': current_user,
                        'version': CURRENT_VERSION + "-Headless",
                        'status': 'online',
                        'next_event': next_str,
                        'last_seen': datetime.now().strftime('%H:%M:%S'),
                        'last_seen_ts': {'.sv': 'timestamp'},
                        'config': public_config(current_cfg)
                    }).encode('utf-8')
                
                    patch_url = f"{central_url.rstrip('/')}/pcs/{pc_id}.json"
                    patch_req = urllib.request.Request(
                        patch_url, 
                        data=status_payload, 
                        method='PATCH', 
                        headers={
                            'Content-Type': 'application/json',
                            'Content-Length': str(len(status_payload)),
                            'User-Agent': 'Mozilla/5.0'
                        }
                    )
                    try:
                        with urllib.request.urlopen(patch_req, timeout=10, context=ssl_context) as res:
                            pass
                    except Exception as e:
                        _log(f"PUT status error: {e}")
                
                # 2. 명령 수신 확인 (GET)
                cmd = None
                cmd_type = None
                
                cmd_url = f"{central_url.rstrip('/')}/commands/{pc_id}.json"
                cmd_req = urllib.request.Request(cmd_url, method='GET', headers={'User-Agent': 'Mozilla/5.0'})
                try:
                    with urllib.request.urlopen(cmd_req, timeout=5, context=ssl_context) as res:
                        cmd = json.loads(res.read().decode('utf-8'))
                        if cmd:
                            cmd_type = 'individual'
                            _log("CMD found (individual)")
                except Exception as e:
                    _log(f"GET cmd error: {e}")
                        
                if not cmd:
                    all_cmd_url = f"{central_url.rstrip('/')}/commands/__ALL__.json"
                    all_cmd_req = urllib.request.Request(all_cmd_url, method='GET', headers={'User-Agent': 'Mozilla/5.0'})
                    try:
                        with urllib.request.urlopen(all_cmd_req, timeout=5, context=ssl_context) as res:
                            cmd = json.loads(res.read().decode('utf-8'))
                            if cmd:
                                cmd_type = 'all'
                                cmd_ts = cmd.get('timestamp', 0)
                                if cmd_ts == getattr(self, 'last_all_cmd_ts', 0) or time.time() - cmd_ts > 300.0:
                                    cmd = None
                                else:
                                    _log("CMD found (all)")
                                    # 유효한 전체 명령이므로 중복 실행을 막기 위해 타임스탬프 기록
                                    self.last_all_cmd_ts = cmd_ts
                    except Exception as e:
                        _log(f"GET all cmd error: {e}")
                                
                # 3. 명령 실행
                if cmd and isinstance(cmd, dict):
                    commands_to_process = []
                    if "action" in cmd:
                        commands_to_process.append((None, cmd))
                    else:
                        for push_id, payload in cmd.items():
                            if isinstance(payload, dict) and "action" in payload:
                                commands_to_process.append((push_id, payload))

                    for push_id, payload in commands_to_process:
                        action = payload.get("action")
                        message = payload.get("message", "")
                        
                        cmd_ts = payload.get("timestamp", 0)
                        
                        dedup_key = push_id if push_id else f"{action}_{cmd_ts}"
                        if dedup_key in processed_push_ids:
                            continue
                            
                        processed_push_ids.add(dedup_key)
                        if len(processed_push_ids) > 1000:
                            processed_push_ids.clear()
                        
                        # 10초 이상 지난 오래된 명령 무시 및 삭제
                        if not fresh_command(cmd_ts, max_age=10):
                            cmd_success = True
                            _log(f"Ignored stale cmd: action={action} (older than 10s)")
                            continue
                            
                        # [핵심] 명령 중복 실행 방지를 위해 '실행 전 먼저 삭제'
                        if cmd_type == 'individual':
                            if push_id:
                                del_url = f"{central_url.rstrip('/')}/commands/{pc_id}/{push_id}.json"
                            else:
                                del_url = f"{central_url.rstrip('/')}/commands/{pc_id}.json"
                                
                            db_secret = current_cfg.get('db_secret', '')
                            if db_secret: del_url += f"?auth={db_secret}"
                            del_req = urllib.request.Request(del_url, method='DELETE', headers={'User-Agent': 'Mozilla/5.0'})
                            try:
                                with urllib.request.urlopen(del_req, timeout=5, context=ssl_context) as res:
                                    pass
                                _log("CMD deleted from Firebase before execution")
                            except Exception as de:
                                _log(f"CMD delete error: {de}")
                            
                            # 삭제 후 상태 업데이트 시간 초기화
                            self.last_status_update = 0

                        _log(f"Executing cmd: action={action}")
                    
                        cmd_success = False
                        try:
                            if action == 'shutdown':
                                _log("Executing: shutdown /s /t 0")
                                subprocess.run(['shutdown', '/s', '/t', '0'], creationflags=subprocess.CREATE_NO_WINDOW)
                                cmd_success = True
                            elif action == 'sleep':
                                _log("Executing: sleep (SetSuspendState)")
                                subprocess.run(['rundll32.exe', 'powrprof.dll,SetSuspendState', '0,1,0'], creationflags=subprocess.CREATE_NO_WINDOW)
                                cmd_success = True
                            elif action == 'restart':
                                _log("Executing: shutdown /r /t 0")
                                subprocess.run(['shutdown', '/r', '/t', '0'], creationflags=subprocess.CREATE_NO_WINDOW)
                                cmd_success = True
                            elif action == 'update':
                                _log("Executing: update check")
                                threading.Thread(target=self.check_for_updates, kwargs={'force': True}, daemon=True).start()
                                cmd_success = True
                            elif action == 'setup_mode':
                                _log("Executing: headless setup_mode (taskkill only)")
                                threading.Thread(target=self.run_setup_mode, daemon=True).start()
                                cmd_success = True

                            elif action == 'list_dir' and isinstance(message, dict):
                                target_path = message.get('path', '') or ''
                                # Normalize: forward-slash -> backslash
                                target_path = target_path.replace('/', '\\')
                                # Ensure trailing backslash for root drives (e.g., "C:" -> "C:\")
                                if len(target_path) == 2 and target_path[1] == ':':
                                    target_path = target_path + '\\'
                                result = None
                                try:
                                    if target_path == "DRIVES" or not target_path:
                                        drives = [chr(x) + ":\\" for x in range(65, 91) if os.path.exists(chr(x) + ":")]
                                        items = [{"name": d, "type": "folder", "size": 0} for d in drives]
                                        result = {"path": "DRIVES", "items": items}
                                    else:
                                        items = []
                                        with os.scandir(target_path) as it:
                                            for entry in it:
                                                try:
                                                    items.append({
                                                        "name": entry.name,
                                                        "type": "folder" if entry.is_dir() else "file",
                                                        "size": entry.stat().st_size if entry.is_file() else 0
                                                    })
                                                except Exception: pass
                                        items.sort(key=lambda x: (x["type"] == "file", x["name"].lower()))
                                        result = {"path": target_path, "items": items}
                                except Exception as e:
                                    result = {"path": target_path, "error": str(e), "items": []}
                                if result is not None:
                                    try:
                                        db_secret = current_cfg.get('db_secret', '')
                                        exp_url = f"{central_url.rstrip('/')}/explorer/{pc_id}.json"
                                        if db_secret: exp_url += f"?auth={db_secret}"
                                        exp_payload = json.dumps(result, ensure_ascii=False).encode('utf-8')
                                        exp_req = urllib.request.Request(exp_url, data=exp_payload, method="PUT", headers={'Content-Type': 'application/json'})
                                        with urllib.request.urlopen(exp_req, timeout=10, context=ssl_context) as _: pass
                                        cmd_success = True
                                    except Exception as e:
                                        pass
                            elif action == 'volume_control' and isinstance(message, dict):
                                _log("Executing: volume control")
                                if PYCAW_AVAILABLE:
                                    try:
                                        level = float(message.get('level', 0.5))
                                        import comtypes
                                        comtypes.CoInitialize()
                                        devices = AudioUtilities.GetSpeakers()
                                        volume = devices.EndpointVolume
                                        volume.SetMasterVolumeLevelScalar(level, None)
                                        volume.SetMute(0, None)
                                        cmd_success = True
                                    except Exception as e:
                                        _log(f"volume_control error: {e}")
                            elif action == 'unlock_screen':
                                try:
                                    ctypes.windll.user32.mouse_event(0x0001, 0, 0, 0, 0)
                                    ctypes.windll.user32.keybd_event(0x0D, 0, 0, 0)
                                    ctypes.windll.user32.keybd_event(0x0D, 0, 2, 0)
                                except: pass
                                cmd_success = True
                            elif action == 'screenshot':
                                _log("Executing: screenshot")
                                threading.Thread(
                                    target=_take_and_upload_screenshot,
                                    args=(central_url, pc_id, db_secret, ssl_context),
                                    daemon=True
                                ).start()
                                cmd_success = True

                            elif action == 'stream_start':
                                _log("Executing: stream_start")
                                _start_screen_streaming(central_url, pc_id, db_secret, ssl_context)
                                cmd_success = True
                            elif action == 'stream_stop':
                                _log("Executing: stream_stop")
                                _stop_screen_streaming()
                                cmd_success = True

                            elif action == 'close_active_window':
                                _log("Executing: close active window")
                                try:
                                    hwnd = ctypes.windll.user32.GetForegroundWindow()
                                    if hwnd:
                                        length = 256
                                        class_name = ctypes.create_unicode_buffer(length)
                                        ctypes.windll.user32.GetClassNameW(hwnd, class_name, length)
                                        if class_name.value not in ["Progman", "WorkerW", "Shell_TrayWnd"]:
                                            ctypes.windll.user32.PostMessageW(hwnd, 0x0010, 0, 0)
                                except Exception as close_ex:
                                    _log(f"close_active_window error: {close_ex}")
                                cmd_success = True
                            elif action == 'kill_process' and isinstance(message, dict):
                                target_pid = message.get('pid')
                                target_exe = message.get('exe', '')
                                target_hwnd = message.get('hwnd')
                                if target_pid:
                                    if target_exe == 'explorer.exe' and target_hwnd:
                                        try:
                                            target_hwnd_int = int(target_hwnd)
                                            ctypes.windll.user32.PostMessageW(target_hwnd_int, 0x0010, 0, 0)
                                        except Exception: pass
                                    else:
                                        kill_remote_process(target_pid)
                                    cmd_success = True
                            elif action == 'bring_to_front' and isinstance(message, dict):
                                target_hwnd = message.get('hwnd')
                                if target_hwnd:
                                    try:
                                        target_hwnd_int = int(target_hwnd)
                                        ctypes.windll.user32.keybd_event(0x12, 0, 0, 0)
                                        ctypes.windll.user32.keybd_event(0x12, 0, 2, 0)
                                        if ctypes.windll.user32.IsIconic(target_hwnd_int):
                                            ctypes.windll.user32.ShowWindow(target_hwnd_int, 9)
                                        else:
                                            ctypes.windll.user32.ShowWindow(target_hwnd_int, 5)
                                        ctypes.windll.user32.SetForegroundWindow(target_hwnd_int)
                                    except Exception: pass
                                    cmd_success = True
                            elif action == 'minimize_window' and isinstance(message, dict):
                                target_hwnd = message.get('hwnd')
                                if target_hwnd:
                                    try:
                                        target_hwnd_int = int(target_hwnd)
                                        ctypes.windll.user32.ShowWindow(target_hwnd_int, 6)
                                    except Exception: pass
                                    cmd_success = True
                            elif action == 'maximize_window' and isinstance(message, dict):
                                target_hwnd = message.get('hwnd')
                                if target_hwnd:
                                    try:
                                        target_hwnd_int = int(target_hwnd)
                                        ctypes.windll.user32.ShowWindow(target_hwnd_int, 3)
                                        ctypes.windll.user32.SetForegroundWindow(target_hwnd_int)
                                    except Exception: pass
                                    cmd_success = True
                            elif action == 'restore_window' and isinstance(message, dict):
                                target_hwnd = message.get('hwnd')
                                if target_hwnd:
                                    try:
                                        target_hwnd_int = int(target_hwnd)
                                        ctypes.windll.user32.ShowWindow(target_hwnd_int, 9)
                                        ctypes.windll.user32.SetForegroundWindow(target_hwnd_int)
                                    except Exception: pass
                                    cmd_success = True
                            elif action == 'close_window' and isinstance(message, dict):
                                cmd_success = force_close_window(message.get('hwnd'))
                            elif action == 'open_file' and isinstance(message, dict):
                                file_path = message.get('file_path', '').strip()
                                app_path  = message.get('app_path', '').strip()
                                if file_path:
                                    try:
                                        is_url = file_path.lower().startswith(('http://', 'https://', 'ftp://'))
                                        if app_path:
                                            subprocess.Popen([app_path, file_path], creationflags=subprocess.CREATE_NO_WINDOW)
                                        elif is_url:
                                            open_remote_url(file_path)
                                        else:
                                            os.startfile(file_path)
                                        cmd_success = True
                                    except Exception: pass
                            elif action == 'message':
                                _log(f"message received in headless - showing ctypes messagebox: {message}")
                                try:
                                    import ctypes
                                    threading.Thread(target=lambda m=message: ctypes.windll.user32.MessageBoxW(0, m, "관리자 메시지", 0x40000), daemon=True).start()
                                except Exception as e:
                                    _log(f"headless message error: {e}")
                                cmd_success = True
                            elif action == 'set_config' and isinstance(message, dict):
                                _log(f"Executing: set_config with {len(message)} keys")
                                current = self.load_config()
                                for k, v in remote_config(message).items():
                                    if k in DAYS and isinstance(v, dict):
                                        if k not in current:
                                            current[k] = {}
                                        for period, p_data in v.items():
                                            orig_period = period.replace("_", "/")
                                            current[k][orig_period] = p_data
                                    else:
                                        if isinstance(v, dict) and k in current and isinstance(current[k], dict):
                                            current[k].update(v)
                                        else:
                                            current[k] = v
                                self.config = current
                                self.save_config()
                                cmd_success = True
                            
                                try:
                                    updated_cfg = public_config(sanitize_rtdb_keys(current))
                                    cfg_patch_payload = json.dumps({'config': updated_cfg}).encode('utf-8')
                                    cfg_patch_url = f"{central_url.rstrip('/')}/pcs/{pc_id}.json"
                                    cfg_patch_req = urllib.request.Request(
                                        cfg_patch_url,
                                        data=cfg_patch_payload,
                                        method='PATCH',
                                        headers=_headers
                                    )
                                    with urllib.request.urlopen(cfg_patch_req, timeout=5, context=ssl_context) as _:
                                        pass
                                    _log("set_config Firebase PATCH success")
                                except Exception as pe:
                                    _log(f"set_config Firebase PATCH error: {pe}")
                            else:
                                # 알 수 없는 명령도 소비하여 큐에 쌓이지 않도록 함
                                _log(f"Unknown action '{action}' - acknowledging to clear queue")
                                cmd_success = True
                        except Exception as exec_err:
                            _log(f"CMD execution error: {exec_err}")
                    
            except Exception as ge:
                _log(f"General poller error: {ge}")
            # 스트리밍 활성 중 remote_input 요청 정군 대기 최소화: 50ms
            time.sleep(0.05 if _stream_active else 0.5)

    def check_for_updates(self, force=False):
        _log_path = os.path.join(application_path, 'headless_debug.log')
        def _log(msg):
            try:
                with open(_log_path, 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now()}] {msg}\n")
            except Exception:
                pass

        _log(f"[update] Starting check_for_updates... (force={force})")
        try:
            url = "https://atss-a1f9e-default-rtdb.firebaseio.com/update_info.json"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            try:
                ssl_context = ssl.create_default_context()
            except AttributeError:
                ssl_context = None
            with urllib.request.urlopen(req, timeout=8, context=ssl_context) as response:
                data = json.loads(response.read().decode('utf-8'))
                remote_version = data.get("version", CURRENT_VERSION)
                download_url = data.get("download_url")
            _log(f"[update] Current: {CURRENT_VERSION}, Remote: {remote_version}")
            if (force or self._is_newer_version(remote_version, CURRENT_VERSION)) and download_url:
                _log("[update] Update needed. Launching updater process...")
                self.perform_auto_update(download_url)
            else:
                _log("[update] No newer version or download URL missing.")
        except Exception as e:
            _log(f"[update] check_for_updates failed: {e}")

    def _is_newer_version(self, remote, current):
        try:
            r_parts = [int(x) for x in remote.split('.')]
            c_parts = [int(x) for x in current.split('.')]
            max_len = max(len(r_parts), len(c_parts))
            r_parts.extend([0] * (max_len - len(r_parts)))
            c_parts.extend([0] * (max_len - len(c_parts)))
            return r_parts > c_parts
        except Exception:
            return False

    def perform_auto_update(self, download_url):
        validate_download_url(download_url)
        """독립 updater.exe 프로세스를 실행하고 현재 프로세스를 종료한다."""
        _log_path = os.path.join(application_path, 'headless_debug.log')
        def _log(msg):
            try:
                with open(_log_path, 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now()}] {msg}\n")
            except Exception:
                pass

        try:
            if not getattr(sys, 'frozen', False):
                _log("[updater] Not frozen exe — skipping.")
                return

            # updater.exe 위치 (MEIPASS 번들 또는 exe 옆)
            meipass_updater = os.path.join(sys._MEIPASS, 'updater.exe')
            exe_dir_updater = os.path.join(os.path.dirname(sys.executable), 'updater.exe')
            if os.path.exists(meipass_updater):
                src_updater = meipass_updater
            elif os.path.exists(exe_dir_updater):
                src_updater = exe_dir_updater
            else:
                _log("[updater] updater.exe not found!")
                return

            import shutil
            tmp_updater = private_updater_copy(src_updater)
            _log(f"[updater] Copied to: {tmp_updater}")

            local_app = os.environ.get('LOCALAPPDATA', application_path)
            target_dir = os.path.join(local_app, 'AutoShutdown')
            target_exe = os.path.join(target_dir, 'auto_shutdown.exe')

            pid = str(os.getpid())
            cmd = [tmp_updater, pid, download_url, target_exe, '--headless']
            _log(f"[updater] Launching: {cmd}")
            subprocess.Popen(
                cmd,
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
            )
            _log("[updater] Updater launched. Exiting headless process.")
            os._exit(0)
        except Exception as e:
            _log(f"[updater] perform_auto_update FAILED: {e}")

if __name__ == "__main__":
    try:
        migrate_saved_credentials()
    except Exception:
        # A failed migration must not overwrite a previously working login configuration.
        print('자동로그인 자격 증명 보안 이전 실패: 관리자 권한으로 다시 실행하세요.')
    import sys
    if "--autologin-gui" in sys.argv:
        run_standalone_autologin_gui()
        sys.exit(0)

    import sys
    import os
    import traceback
    import socket
    
    # console=False 인 상태로 PyInstaller로 빌드된 경우, print()로 인한 크래시 방지 및 로그 저장
    if getattr(sys, 'frozen', False):
        class NullWriter:
            def __init__(self):
                self.encoding = 'utf-8'
                self.errors = 'strict'
            def write(self, text):
                try:
                    with open(os.path.join(os.path.dirname(sys.executable), 'stdout_stderr.log'), 'a', encoding='utf-8') as f:
                        f.write(text)
                except:
                    pass
            def flush(self): pass
            def isatty(self): return False
            def fileno(self): return -1
        sys.stdout = NullWriter()
        sys.stderr = NullWriter()
    
    # --headless 인자가 있으면 즉시 백그라운드 모드로 진입 (try/except 바깥)
    if "--headless" in sys.argv:
        # 전역 중복 방지 Mutex 체크
        ctypes.windll.kernel32.SetLastError(0)
        mutex_global = ctypes.windll.kernel32.CreateMutexW(None, False, "Global\\AutoShutdownAppV2_Mutex")
        err = ctypes.windll.kernel32.GetLastError()
        if err == 183:
            os._exit(0)  # sys.exit 대신 os._exit 사용하여 BaseException 우회
        HeadlessShutdownApp()
        os._exit(0)
        
    try:
        # 1. 세션 내 중복 실행 차단용 Local 뮤텍스부터 체크
        ctypes.windll.kernel32.SetLastError(0)
        mutex_local = ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\AutoShutdownAppV2_Mutex")
        if ctypes.windll.kernel32.GetLastError() == 183:
            sys.exit(0)

        # 2. 전역 중복 실행 차단용 Global 뮤텍스 체크
        ctypes.windll.kernel32.SetLastError(0)
        mutex_global = ctypes.windll.kernel32.CreateMutexW(None, False, "Global\\AutoShutdownAppV2_Mutex")
        err = ctypes.windll.kernel32.GetLastError()
        
        if err == 183 or err == 5:
            # 다른 인스턴스(예: --headless)가 이미 실행 중인 경우에만 소켓 연결 시도 (바통 터치)
            # 이로써 평상시 무의미한 소켓 연결 시도로 인한 딜레이를 100% 원천 차단!
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect(('127.0.0.1', 19985))
                s.sendall(b"exit")
                s.recv(1024)
                s.close()
                
                # 백그라운드 프로세스가 종료되고 Mutex를 해제할 때까지 최대 2초간 0.05초 간격으로 폴링
                # 고정 대기 시간(0.5초) 대신 실시간 감지로 반응 속도를 극대화!
                released = False
                for _ in range(40):
                    ctypes.windll.kernel32.SetLastError(0)
                    test_mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "Global\\AutoShutdownAppV2_Mutex")
                    test_err = ctypes.windll.kernel32.GetLastError()
                    if test_err != 183 and test_err != 5:
                        mutex_global = test_mutex
                        released = True
                        break
                    time.sleep(0.05)
                
                if not released:
                    sys.exit(0)
            except Exception:
                # 소켓 연결이 불가능한 경우 (실제 다른 GUI가 켜진 상태 등) 중복 실행 차단
                sys.exit(0)

        root = ctk.CTk()
        app = AutoShutdownAppV2(root)
        app_instance = app
        
        root.after(0, app.hide_window)
        root.mainloop()
    except SystemExit:
        pass  # 정상 종료 — 크래시 로그 남기지 않음
    except BaseException as e:
        try:
            with open(os.path.join(application_path, "crash_debug.log"), "w", encoding="utf-8") as f:
                f.write(f"CRASH OCCURRED: {type(e).__name__}: {e}\n")
                traceback.print_exc(file=f)
        except:
            pass
        sys.exit(1)
