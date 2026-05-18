#!/usr/bin/env bash
# Build standalone icopykey macOS .app bundle.
# Requires: Python 3.9+, PyInstaller, PyQt5, numpy, hidapi
#
# Usage:
#   bash packaging/build_mac.sh              # build .app only
#   bash packaging/build_mac.sh --dmg        # build .app + .dmg installer
#   bash packaging/build_mac.sh --notarize   # build + notarize for distribution

set -euo pipefail
cd "$(dirname "$0")/.."

APP_NAME="icopykey"
VERSION="0.2.0"
BUILD_DIR="dist"
SPEC_FILE="packaging/${APP_NAME}.spec"

echo "==> Installing build dependencies..."
pip install --quiet pyinstaller PyQt5 numpy hidapi

echo "==> Cleaning previous builds..."
rm -rf "${BUILD_DIR}" build *.spec

echo "==> Building ${APP_NAME} ${VERSION} with PyInstaller..."
pyinstaller --clean --noconfirm "${SPEC_FILE}"

echo "==> Verifying bundle..."
APP_BUNDLE="${BUILD_DIR}/${APP_NAME}.app"
if [ -d "${APP_BUNDLE}" ]; then
    echo "  ✅ Bundle created: ${APP_BUNDLE}"
    echo "  Size: $(du -sh "${APP_BUNDLE}" | cut -f1)"
    CONTENTS=$(find "${APP_BUNDLE}/Contents/MacOS" -type f)
    echo "  Executables: ${CONTENTS}"
else
    echo "  ❌ Bundle not found!"
    exit 1
fi

# ── Build .dmg installer ────────────────────────────────────────────
if [[ "${1:-}" == "--dmg" || "${1:-}" == "--notarize" ]]; then
    DMG_NAME="${APP_NAME}-${VERSION}-macos.dmg"
    echo "==> Creating DMG: ${DMG_NAME}..."

    if command -v create-dmg &>/dev/null; then
        create-dmg \
            --volname "${APP_NAME}" \
            --window-pos 200 120 \
            --window-size 800 400 \
            --icon-size 100 \
            --icon "${APP_NAME}.app" 200 190 \
            --hide-extension "${APP_NAME}.app" \
            --app-drop-link 600 185 \
            "${BUILD_DIR}/${DMG_NAME}" \
            "${APP_BUNDLE}"
    else
        # Fallback: use hdiutil
        ln -sf /Applications "${BUILD_DIR}/Applications"
        hdiutil create -volname "${APP_NAME}" -srcfolder "${BUILD_DIR}" \
            -ov -format UDZO "${BUILD_DIR}/${DMG_NAME}"
        rm -f "${BUILD_DIR}/Applications"
    fi
    echo "  ✅ DMG created: ${BUILD_DIR}/${DMG_NAME}"
fi

# ── Notarize (requires Apple Developer account) ─────────────────────
if [[ "${1:-}" == "--notarize" ]]; then
    echo "==> Notarizing..."
    xcrun notarytool submit "${BUILD_DIR}/${DMG_NAME:-${APP_NAME}.app}" \
        --apple-id "${APPLE_ID:-}" \
        --team-id "${APPLE_TEAM_ID:-}" \
        --password "${APPLE_APP_PASSWORD:-}" \
        --wait
    xcrun stapler staple "${APP_BUNDLE}"
    echo "  ✅ Notarization complete"
fi

echo ""
echo "🎉 Build complete!"
echo "   ${BUILD_DIR}/${APP_NAME}.app"
