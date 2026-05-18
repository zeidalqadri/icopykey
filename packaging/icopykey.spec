# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for icopykey macOS .app bundle.

Usage:
    pyinstaller packaging/icopykey.spec

Produces dist/icopykey.app — a standalone macOS application.
"""

import sys
from pathlib import Path

BLOCK_CIPHER_HID = __import__("importlib").util.find_spec("hid") is not None

a = Analysis(
    ["src/icopykey/gui/__main__.py"],
    pathex=[str(Path(".").resolve())],
    binaries=[],
    datas=[
        # Include the whole cli package for console subcommands
        ("src/icopykey/cli", "icopykey/cli"),
    ],
    hiddenimports=[
        "PyQt5",
        "PyQt5.QtCore",
        "PyQt5.QtWidgets",
        "PyQt5.QtGui",
        "numpy",
        "hid",
        "Crypto",
        "Crypto.Cipher",
        "Crypto.Protocol",
        "requests",
    ] if BLOCK_CIPHER_HID else [
        "PyQt5",
        "PyQt5.QtCore",
        "PyQt5.QtWidgets",
        "PyQt5.QtGui",
        "numpy",
        "Crypto",
        "Crypto.Cipher",
        "Crypto.Protocol",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "scipy",
        "PIL",
        "test",
    ],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="icopykey",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

app = BUNDLE(
    exe,
    a.binaries,
    a.datas,
    [],
    name="icopykey.app",
    icon="packaging/icopykey.icns",
    bundle_identifier="com.icopykey.app",
    info_plist={
        "CFBundleName": "icopykey",
        "CFBundleDisplayName": "icopykey",
        "CFBundleIdentifier": "com.icopykey.app",
        "CFBundleVersion": "0.2.0",
        "CFBundleShortVersionString": "0.2.0",
        "CFBundleExecutable": "icopykey",
        "CFBundlePackageType": "APPL",
        "CFBundleInfoDictionaryVersion": "6.0",
        "NSHighResolutionCapable": True,
        "NSHumanReadableCopyright": "MIT License",
        "LSMinimumSystemVersion": "10.15",
        "NSRequiresAquaSystemAppearance": False,
        "SMPrivilegedExecutables": [],
    },
)
