# -*- mode: python ; coding: utf-8 -*-
from os.path import join


a = Analysis(
    ['auto_shutdown.py'],
    pathex=[],
    binaries=[
        (r'C:\Windows\System32\ucrtbase.dll', '.'),
        (r'C:\Users\tntdr\AppData\Local\Programs\Python\Python313\vcruntime140.dll', '.'),
        (r'C:\Users\tntdr\AppData\Local\Programs\Python\Python313\vcruntime140_1.dll', '.'),
    ],
    datas=[
        (r'C:\Users\tntdr\AppData\Local\Programs\Python\Python313\tcl\tcl8.6', '_tcl_data'),
        (r'C:\Users\tntdr\AppData\Local\Programs\Python\Python313\tcl\tk8.6', '_tk_data'),
        (join(DISTPATH, 'updater.exe'), '.'),
    ],
    hiddenimports=['pycaw', 'customtkinter', 'mss', 'mss.tools', 'aiortc', 'av', 'pynput', 'pynput.keyboard', 'pynput.mouse', 'google_crc32c', 'cffi', '_cffi_backend', 'pylibsrtp', 'numpy', 'av.logging', 'av.video.frame', 'av.audio.frame'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='auto_shutdown',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='transparent.ico',
)
