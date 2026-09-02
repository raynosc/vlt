#!/usr/bin/env bash
# =============================================================================
# package-macos.sh — Construye y empaqueta vlt.app para macOS
# =============================================================================
set -e

DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$DIR"

APP_NAME="vlt"
BUNDLE_DIR="$DIR/build/$APP_NAME.app"
CONTENTS_DIR="$BUNDLE_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"

echo "==> 1. Compilando binario nativo vlt-gui..."
mkdir -p "$DIR/bin"
CGO_ENABLED=1 go build -ldflags="-s -w" -o "$DIR/bin/vlt-gui" ./cmd/vlt-gui
CGO_ENABLED=1 go build -ldflags="-s -w" -o "$DIR/bin/vlt" ./cmd/vlt

echo "==> 2. Creando estructura de macOS Bundle ($APP_NAME.app)..."
rm -rf "$BUNDLE_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

# Copiar ejecutable
cp "$DIR/bin/vlt-gui" "$MACOS_DIR/$APP_NAME"
chmod +x "$MACOS_DIR/$APP_NAME"

# Generar Info.plist
cat << 'EOF' > "$CONTENTS_DIR/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleDisplayName</key>
	<string>vlt</string>
	<key>CFBundleExecutable</key>
	<string>vlt</string>
	<key>CFBundleIconFile</key>
	<string>app-icon.icns</string>
	<key>CFBundleIdentifier</key>
	<string>com.passwd.vlt</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>vlt</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>1.2.0</string>
	<key>CFBundleVersion</key>
	<string>1.2.0</string>
	<key>LSMinimumSystemVersion</key>
	<string>11.0</string>
	<key>LSUIElement</key>
	<false/>
	<key>NSHighResolutionCapable</key>
	<true/>
	<key>NSSupportsAutomaticGraphicsSwitching</key>
	<true/>
</dict>
</plist>
EOF

echo "==> 3. Generando icono oficial .icns para macOS..."
ICONSET_DIR="/tmp/vlt.iconset"
rm -rf "$ICONSET_DIR"
mkdir -p "$ICONSET_DIR"

SRC_ICON="$DIR/internal/gui/assets/icon-128.png"

# Generar variantes de iconos a partir del PNG base
sips -z 16 16     "$SRC_ICON" --out "$ICONSET_DIR/icon_16x16.png" >/dev/null 2>&1
sips -z 32 32     "$SRC_ICON" --out "$ICONSET_DIR/icon_16x16@2x.png" >/dev/null 2>&1
sips -z 32 32     "$SRC_ICON" --out "$ICONSET_DIR/icon_32x32.png" >/dev/null 2>&1
sips -z 64 64     "$SRC_ICON" --out "$ICONSET_DIR/icon_32x32@2x.png" >/dev/null 2>&1
sips -z 128 128   "$SRC_ICON" --out "$ICONSET_DIR/icon_128x128.png" >/dev/null 2>&1
sips -z 256 256   "$SRC_ICON" --out "$ICONSET_DIR/icon_128x128@2x.png" >/dev/null 2>&1
sips -z 256 256   "$SRC_ICON" --out "$ICONSET_DIR/icon_256x256.png" >/dev/null 2>&1
sips -z 512 512   "$SRC_ICON" --out "$ICONSET_DIR/icon_256x256@2x.png" >/dev/null 2>&1
sips -z 512 512   "$SRC_ICON" --out "$ICONSET_DIR/icon_512x512.png" >/dev/null 2>&1
sips -z 1024 1024 "$SRC_ICON" --out "$ICONSET_DIR/icon_512x512@2x.png" >/dev/null 2>&1

iconutil -c icns "$ICONSET_DIR" -o "$RESOURCES_DIR/app-icon.icns"
rm -rf "$ICONSET_DIR"

echo "==> 4. Firmando paquete ad-hoc..."
codesign --force --deep --sign - "$BUNDLE_DIR"

echo "========================================================"
echo " [OK] macOS App creada exitosamente:"
echo "      $BUNDLE_DIR"
echo "========================================================"
