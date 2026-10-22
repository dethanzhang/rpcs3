#!/bin/sh
# Download the official RPCS3 UI translations (Crowdin: RPCS3/rpcs3_translations)
# and install them into the Qt "translations" directory the emulator scans
# (QLibraryInfo::TranslationsPath).
#
# Usage:
#   scripts/fetch_translations.sh [TARGET_DIR] [QT_TRANSLATIONS_DIR]
#
# TARGET_DIR            where the .qm files are copied to.
#                       default: rpcs3.app/Contents/Resources/translations  (macOS bundle)
#                       Linux build dir: build/bin/translations
#                       Windows build dir: bin/qt6/translations
# QT_TRANSLATIONS_DIR   Qt's own translations (qtbase_*.qm), copied if given, e.g.
#                       /opt/homebrew/opt/qt/translations   (macOS)
#                       /usr/share/qt6/translations         (Linux)
#                       C:/Qt/6.x.x/msvc2019_64/translations (Windows)
set -eu

TARGET_DIR="${1:-rpcs3.app/Contents/Resources/translations}"
QT_TRANSLATIONS_DIR="${2:-}"

URL="https://github.com/RPCS3/rpcs3_translations/releases/latest/download/RPCS3-languages.zip"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$TARGET_DIR"

echo "Downloading $URL"
if ! curl -fsSL --retry 3 --retry-delay 5 -o "$TMP_DIR/languages.zip" "$URL"; then
    echo "Failed to download translations." >&2
    exit 1
fi

if ! unzip -oq "$TMP_DIR/languages.zip" -d "$TMP_DIR/extracted"; then
    echo "Failed to extract translations." >&2
    exit 1
fi

echo "Installing rpcs3_*.qm into $TARGET_DIR"
find "$TMP_DIR/extracted" -name 'rpcs3_*.qm' -exec cp -f {} "$TARGET_DIR"/ \;

if [ -n "$QT_TRANSLATIONS_DIR" ]; then
    if [ -d "$QT_TRANSLATIONS_DIR" ]; then
        echo "Copying Qt translations from $QT_TRANSLATIONS_DIR"
        cp -f "$QT_TRANSLATIONS_DIR"/qt_*.qm "$TARGET_DIR"/ 2>/dev/null || true
        cp -f "$QT_TRANSLATIONS_DIR"/qtbase_*.qm "$TARGET_DIR"/ 2>/dev/null || true
        cp -f "$QT_TRANSLATIONS_DIR"/qtmultimedia_*.qm "$TARGET_DIR"/ 2>/dev/null || true
        rm -f "$TARGET_DIR"/qt_help_*.qm || true
    else
        echo "Qt translations dir not found: $QT_TRANSLATIONS_DIR" >&2
    fi
fi

echo "Done. Available languages:"
ls "$TARGET_DIR" | sed -n 's/^rpcs3_\(.*\)\.qm$/  \1/p'
