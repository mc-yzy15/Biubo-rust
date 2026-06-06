#!/bin/bash
set -e

APP_NAME="biubo-waf"
APP_VERSION="${1:-1.0.0}"
BINARY_PATH="${2:-target/release/${APP_NAME}}"
OUTPUT_DIR="${3:-dist}"

DMG_NAME="${APP_NAME}-${APP_VERSION}-x86_64-apple-darwin.dmg"
VOLUME_NAME="Biubo WAF"

echo "Creating DMG: ${DMG_NAME}"

mkdir -p "${OUTPUT_DIR}"

TEMP_DIR=$(mktemp -d)
APP_DIR="${TEMP_DIR}/${VOLUME_NAME}"
mkdir -p "${APP_DIR}"

cp "${BINARY_PATH}" "${APP_DIR}/${APP_NAME}"
chmod +x "${APP_DIR}/${APP_NAME}"

cat > "${APP_DIR}/README.txt" << EOF
Biubo WAF ${APP_VERSION}
========================

Installation:
1. Copy ${APP_NAME} to your desired location (e.g., /usr/local/bin)
2. Run: chmod +x /path/to/${APP_NAME}
3. Start: ./biubo-waf

Configuration:
- Create config.json in the same directory as the binary
- Default port: 80
- Dashboard: http://localhost/biubo-cgi

For more information, visit:
https://github.com/mc-yzy15/Biubo-rust
EOF

hdiutil create \
    -volname "${VOLUME_NAME}" \
    -srcfolder "${APP_DIR}" \
    -ov -format UDZO \
    "${OUTPUT_DIR}/${DMG_NAME}"

rm -rf "${TEMP_DIR}"

echo "DMG created: ${OUTPUT_DIR}/${DMG_NAME}"
