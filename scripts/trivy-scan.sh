#!/usr/bin/env bash
# trivy-scan.sh: vulnerability + secret scan against the Snort 3 Docker image.
# Installs Trivy if missing, builds the image if not present locally.
#
# Env vars (all optional):
#   TRIVY_IMAGE      image to scan (default: snort3:alpine-test)
#   DOCKERFILE_DIR   path containing the Dockerfile (default: repo root)
#   REPORT_DIR       where to write reports (default: ./trivy-reports)
#   TRIVY_SEVERITY   comma-separated severities (default: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL)
#   TRIVY_FORMAT     report format: table|json|sarif|cyclonedx (default: table)
#   TRIVY_EXIT_CODE  set to 1 to fail on CRITICAL/HIGH findings (default: 0)
set -euo pipefail

IMAGE="${TRIVY_IMAGE:-snort3:alpine-test}"
DOCKERFILE_DIR="${DOCKERFILE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
REPORT_DIR="${REPORT_DIR:-$(pwd)/trivy-reports}"
SEVERITY="${TRIVY_SEVERITY:-UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL}"
FORMAT="${TRIVY_FORMAT:-table}"
EXIT_CODE="${TRIVY_EXIT_CODE:-0}"


RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log()  { echo -e "${CYAN}[trivy-scan]${RESET} $*"; }
ok()   { echo -e "${GREEN}[trivy-scan]${RESET} $*"; }
warn() { echo -e "${YELLOW}[trivy-scan]${RESET} $*"; }
die()  { echo -e "${RED}[trivy-scan] ERROR${RESET} $*" >&2; exit 1; }

install_trivy() {
    log "Trivy not found — installing..."

    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$ARCH" in
        x86_64)  ARCH="64bit" ;;
        aarch64|arm64) ARCH="ARM64" ;;
        armv7l)  ARCH="ARM" ;;
        *) die "Unsupported architecture: $ARCH" ;;
    esac

    TRIVY_VERSION="$(curl -fsSL \
        https://api.github.com/repos/aquasecurity/trivy/releases/latest \
        | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')"

    [[ -z "$TRIVY_VERSION" ]] && die "Could not determine latest Trivy version."
    log "Installing Trivy v${TRIVY_VERSION} for ${OS}/${ARCH}..."

    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT

    if [[ "$OS" == "linux" ]]; then
        PKG="trivy_${TRIVY_VERSION}_Linux-${ARCH}.tar.gz"
        curl -fsSL \
            "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${PKG}" \
            -o "$TMP/$PKG"
        tar -xzf "$TMP/$PKG" -C "$TMP"
        if command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
            sudo install -m 755 "$TMP/trivy" /usr/local/bin/trivy
        else
            mkdir -p "$HOME/.local/bin"
            install -m 755 "$TMP/trivy" "$HOME/.local/bin/trivy"
            export PATH="$HOME/.local/bin:$PATH"
            warn "Trivy installed to ~/.local/bin — make sure that is in your PATH."
        fi

    elif [[ "$OS" == "darwin" ]]; then
        if command -v brew &>/dev/null; then
            brew install trivy
        else
            PKG="trivy_${TRIVY_VERSION}_macOS-${ARCH}.tar.gz"
            curl -fsSL \
                "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${PKG}" \
                -o "$TMP/$PKG"
            tar -xzf "$TMP/$PKG" -C "$TMP"
            mkdir -p "$HOME/.local/bin"
            install -m 755 "$TMP/trivy" "$HOME/.local/bin/trivy"
            export PATH="$HOME/.local/bin:$PATH"
            warn "Trivy installed to ~/.local/bin — make sure that is in your PATH."
        fi
    else
        die "Unsupported OS: $OS. Install Trivy manually: https://trivy.dev/latest/getting-started/installation/"
    fi

    ok "Trivy $(trivy --version | head -1) installed."
}

if ! command -v trivy &>/dev/null; then
    install_trivy
else
    ok "Trivy already installed: $(trivy --version | head -1)"
fi

# build image if not present locally
if ! docker image inspect "$IMAGE" &>/dev/null; then
    warn "Image '${IMAGE}' not found locally — building..."
    [[ -f "$DOCKERFILE_DIR/Dockerfile" ]] \
        || die "Dockerfile not found at: $DOCKERFILE_DIR/Dockerfile"

    docker build --platform linux/amd64 -t "$IMAGE" "$DOCKERFILE_DIR"
    ok "Image '${IMAGE}' built successfully."
else
    ok "Image '${IMAGE}' found locally — skipping build."
fi

mkdir -p "$REPORT_DIR"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

echo ""
log "Trivy Vulnerability Scan — ${IMAGE}"
echo ""

log "Scanning OS packages and libraries..."
trivy image \
    --severity "$SEVERITY" \
    --scanners vuln \
    --format table \
    "$IMAGE" \
    | tee "$REPORT_DIR/scan_${TIMESTAMP}_table.txt"

log "Writing JSON report..."
trivy image \
    --severity "$SEVERITY" \
    --scanners vuln \
    --format json \
    --output "$REPORT_DIR/scan_${TIMESTAMP}.json" \
    "$IMAGE"

log "Writing SARIF report..."
trivy image \
    --severity "$SEVERITY" \
    --scanners vuln \
    --format sarif \
    --output "$REPORT_DIR/scan_${TIMESTAMP}.sarif" \
    "$IMAGE"

log "Scanning for secrets..."
trivy image \
    --scanners secret \
    --format table \
    "$IMAGE" \
    | tee "$REPORT_DIR/scan_${TIMESTAMP}_secrets.txt"

echo ""
log "Scan Summary"
echo ""

CRITICAL=$(grep -c '"Severity": "CRITICAL"' "$REPORT_DIR/scan_${TIMESTAMP}.json" 2>/dev/null || echo 0)
HIGH=$(grep -c     '"Severity": "HIGH"'     "$REPORT_DIR/scan_${TIMESTAMP}.json" 2>/dev/null || echo 0)
MEDIUM=$(grep -c   '"Severity": "MEDIUM"'   "$REPORT_DIR/scan_${TIMESTAMP}.json" 2>/dev/null || echo 0)
LOW=$(grep -c      '"Severity": "LOW"'      "$REPORT_DIR/scan_${TIMESTAMP}.json" 2>/dev/null || echo 0)

echo -e "  Image:     ${BOLD}${IMAGE}${RESET}"
echo -e "  Timestamp: ${TIMESTAMP}"
echo -e "  Severity filter: ${SEVERITY}"
echo ""
echo -e "  ${RED}CRITICAL${RESET}: ${CRITICAL}"
echo -e "  ${RED}HIGH${RESET}:     ${HIGH}"
echo -e "  ${YELLOW}MEDIUM${RESET}:   ${MEDIUM}"
echo -e "  LOW:      ${LOW}"
echo ""
echo -e "  Reports saved to: ${BOLD}${REPORT_DIR}/${RESET}"
echo -e "    ├── scan_${TIMESTAMP}_table.txt   (human-readable)"
echo -e "    ├── scan_${TIMESTAMP}.json        (CI / SIEM)"
echo -e "    ├── scan_${TIMESTAMP}.sarif       (GitHub / VS Code)"
echo -e "    └── scan_${TIMESTAMP}_secrets.txt (secret scan)"
echo ""

if [[ "$EXIT_CODE" == "1" ]] && [[ "$CRITICAL" -gt 0 || "$HIGH" -gt 0 ]]; then
    die "Scan found CRITICAL or HIGH vulnerabilities. Failing build."
fi

ok "Scan complete."
