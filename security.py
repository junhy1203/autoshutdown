"""Security boundaries shared by desktop clients and update programs."""
import base64
import ctypes
import os
import re
import subprocess
import time
import urllib.parse

FIREBASE_HOST = 'atss-a1f9e-default-rtdb.firebaseio.com'
PUBLIC_CONFIG_KEYS = frozenset({
    '월', '화', '수', '목', '금', '토', '일', 'school_info', 'minutes_before',
    'show_popup_alert', 'autostart', 'skip_date', 'skip_events', 'timetable',
})


def public_config(config):
    result = {key: value for key, value in config.items() if key in PUBLIC_CONFIG_KEYS}
    if isinstance(result.get('school_info'), dict):
        result['school_info'] = {k: v for k, v in result['school_info'].items() if k != 'api_key'}
    return result


def remote_config(config):
    # Only explicit remote settings may change; local credentials and device identity stay local.
    return {key: value for key, value in config.items() if key in PUBLIC_CONFIG_KEYS}


def fresh_command(timestamp, max_age=20, *, now=None):
    now = time.time() if now is None else now
    return (isinstance(timestamp, (float, int)) and not isinstance(timestamp, bool)
            and now - max_age <= timestamp <= now)


def private_updater_copy(source):
    import shutil
    import tempfile
    target = os.path.join(tempfile.mkdtemp(prefix='smartpower-updater-'), 'updater.exe')
    shutil.copy2(source, target)
    return target


def validate_download_url(url):
    """Only this project's HTTPS GitHub release assets may be executed."""
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.netloc != 'github.com'
            or parsed.username or parsed.password or parsed.fragment
            or not re.fullmatch(r'/JunHyuk1203/autoshutdown/releases/download/[^/]+/auto_shutdown\.exe', parsed.path)):
        raise ValueError('Untrusted update URL')
    return url


def validate_ws_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'wss' or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment):
        raise ValueError('A secure WebSocket URL is required')
    return url


def open_remote_url(url, browser='default'):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() not in ('https', 'http') or not parsed.hostname or any(ord(c) < 32 for c in url):
        raise ValueError('Only HTTP(S) URLs are allowed')
    names = {'chrome': 'chrome.exe', 'edge': 'msedge.exe', 'whale': 'whale.exe'}
    if browser in names:
        # ShellExecute resolves installed application names without cmd.exe.
        result = ctypes.windll.shell32.ShellExecuteW(None, 'open', names[browser],
                                                   subprocess.list2cmdline([url]), None, 1)
        if result <= 32:
            raise OSError('Browser launch failed')
    elif browser == 'default':
        os.startfile(url)
    else:
        raise ValueError('Unknown browser')


def kill_remote_process(pid):
    if isinstance(pid, bool) or not str(pid).isdecimal() or not 0 < int(pid) <= 0xffffffff:
        raise ValueError('Invalid process id')
    if int(pid) == os.getpid():
        raise ValueError('Cannot terminate the client itself')
    subprocess.run(['taskkill', '/F', '/PID', str(int(pid))],
                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), check=False)


class _Blob(ctypes.Structure):
    _fields_ = [('size', ctypes.c_ulong), ('data', ctypes.POINTER(ctypes.c_ubyte))]


def _dpapi(data, decrypt=False):
    if os.name != 'nt':
        raise OSError('Windows DPAPI is required')
    buf = ctypes.create_string_buffer(data)
    source = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))
    output = _Blob()
    api = ctypes.windll.crypt32.CryptUnprotectData if decrypt else ctypes.windll.crypt32.CryptProtectData
    if not api(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(output)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(output.data, output.size)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(output.data, ctypes.c_void_p))


def protect_password(password):
    return 'dpapi:' + base64.b64encode(_dpapi(password.encode('utf-8'))).decode('ascii') if password else ''


def unprotect_password(value):
    if not value:
        return ''
    if value.startswith('dpapi:'):
        return _dpapi(base64.b64decode(value[6:], validate=True), decrypt=True).decode('utf-8')
    # Legacy format is accepted only for migration to DPAPI.
    import uuid
    key = str(uuid.getnode()).encode('ascii')
    raw = base64.b64decode(value, validate=True)
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(raw)).decode('utf-8')


def store_logon_secret(password):
    """Winlogon reads DefaultPassword from LSA private data instead of plaintext registry."""
    from ctypes import wintypes
    class UnicodeString(ctypes.Structure):
        _fields_ = [('Length', wintypes.USHORT), ('MaximumLength', wintypes.USHORT), ('Buffer', wintypes.LPWSTR)]
    class ObjectAttributes(ctypes.Structure):
        _fields_ = [('Length', wintypes.ULONG), ('RootDirectory', wintypes.HANDLE),
                    ('ObjectName', ctypes.c_void_p), ('Attributes', wintypes.ULONG),
                    ('SecurityDescriptor', ctypes.c_void_p), ('SecurityQualityOfService', ctypes.c_void_p)]
    def string(value):
        return UnicodeString(len(value.encode('utf-16-le')), len(value.encode('utf-16-le')) + 2, value)
    advapi = ctypes.windll.advapi32
    attributes = ObjectAttributes()
    attributes.Length = ctypes.sizeof(attributes)
    handle = wintypes.HANDLE()
    status = advapi.LsaOpenPolicy(None, ctypes.byref(attributes), 0x20, ctypes.byref(handle))
    if status:
        raise ctypes.WinError(advapi.LsaNtStatusToWinError(status))
    try:
        name = string('DefaultPassword')
        secret = string(password) if password is not None else None
        status = advapi.LsaStorePrivateData(handle, ctypes.byref(name), ctypes.byref(secret) if secret else None)
        if status and not (password is None and advapi.LsaNtStatusToWinError(status) == 2):
            raise ctypes.WinError(advapi.LsaNtStatusToWinError(status))
    finally:
        advapi.LsaClose(handle)
