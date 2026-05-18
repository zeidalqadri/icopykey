# macOS Packaging

## Quick Start (on a Mac)

```bash
# 1. Install dependencies
pip install pyinstaller PyQt5 numpy hidapi pycryptodome requests rich

# 2. Build the .app bundle
pyinstaller --clean --noconfirm packaging/icopykey.spec

# 3. The app is at: dist/icopykey.app
open dist/icopykey.app
```

## Build Installer (.dmg)

```bash
bash packaging/build_mac.sh --dmg
```

## Build for Distribution

```bash
# Requires Apple Developer account for notarization
export APPLE_ID="your@email.com"
export APPLE_TEAM_ID="TEAMID"
export APPLE_APP_PASSWORD="@keychain:AC_PASSWORD"

bash packaging/build_mac.sh --notarize
```

## GitHub Actions

Push a `v*` tag to trigger automatic build:

```bash
git tag v0.2.0
git push origin v0.2.0
```

The workflow will build the .app + .dmg and attach them to the GitHub Release.

## Manual Install (no build needed)

The pip package works on macOS without any build step:

```bash
pip install icopyzed
# Optional extras:
pip install "icopyzed[gui]"  # for PyQt5 GUI
pip install "icopyzed[cli]"   # for numpy acceleration

# Run CLI:
icopyzed --help

# Run GUI:
python -m icopykey.gui
```

## Files

| File | Purpose |
|------|---------|
| `icopykey.spec` | PyInstaller spec for .app bundle |
| `build_mac.sh` | Build script (.app / .dmg / notarize) |
| `icopykey.icns` | App icon |
| `icon_1024.png` | Source icon (1024×1024) |
