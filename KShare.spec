# -*- mode: python ; coding: utf-8 -*-
import os
from kivy_deps import sdl2, glew, gstreamer

# --- Configuration ---
block_cipher = None
app_name = 'KShare'
main_script = 'main.py'

# --- Analysis Section ---
a = Analysis(
    [main_script],
    pathex=[],
    binaries=[],
    datas=[
        # Bundle PNG images into the root of the EXE
        ('logo.png', '.'), 
        ('send.png', '.'), 
        ('receive.png', '.'),
        # Bundle settings if file exists (or it will be created on first run)
        ('kshare_settings.json', '.'),
    ],
    hiddenimports=[
        # Kivy core windowing and imaging
        'kivy.core.window.window_sdl2', 
        'kivy.core.image.img_pil',
        'kivy.uix.floatlayout',
        'kivy.modules.inspector',
        'PIL',
        'Pillow',
        
        # System & FileChooser Fixes
        'win32timezone',  # Fixes the 'ModuleNotFoundError' on Windows
        
        # Networking & App Logic
        'socket', 
        'threading',
        'os',
        'sys',
        'webbrowser',
        'qrcode',
        
        # Scanner Dependencies (Optional but prevents import crashes)
        'pyzbar', 
        'cv2',
        'numpy',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# --- Packaging Section ---
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    # Include Kivy's binary dependencies (Graphics/Sound/Input)
    a.binaries + getattr(sdl2, 'binaries', []) + getattr(glew, 'binaries', []) + getattr(gstreamer, 'binaries', []),
    a.zipfiles,
    # Include asset data
    a.datas + getattr(sdl2, 'datas', []) + getattr(glew, 'datas', []) + getattr(gstreamer, 'datas', []),
    
    name=app_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,           # Compresses the EXE (requires upx.exe, otherwise ignored)
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,      # Set to False to hide the CMD window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    onedir=False,       # Set to False to create a SINGLE .exe file
    # Optional: If you have an .ico file, uncomment the line below
    # icon='logo.ico', 
)