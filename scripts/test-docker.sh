#!/usr/bin/env bash
# test-docker.sh — build and test the Snort 3 Alpine image (T01–T40)
#
# Usage:
#   bash scripts/test-docker.sh                          # interactive
#   bash scripts/test-docker.sh --platform linux/amd64  # non-interactive
#
# Options:
#   --platform PLAT         target platform, e.g. linux/amd64
#   --image IMAGE           override the auto-derived image tag
#   --sections "A B C D E"  run only these sections (A=Metadata B=Binary C=Functional D=Live E=Trivy)
#   --skip-build            skip build; fail if image is missing
#   --skip-trivy            skip section E
#   --skip-live             skip section D (default)
#   --live                  include section D (live NIC test)
#   --iface IFACE           interface for T37 (default: eth0)
#   -h, --help              show this help
#
# Sections A B C E run by default. Section D requires --live. Trivy auto-installs if missing.
# Exit code: 0 = all passed, 1 = one or more failed
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'; GREY='\033[0;37m'
DIM='\033[2m'

# "docker-platform|tag|description|regex-engine"
PLATFORM_ENTRIES=(
    "linux/amd64|amd64|Intel / AMD 64-bit (x86_64)|Vectorscan enabled"
    "linux/arm64|arm64|Apple M*, AWS Graviton, RPi 64-bit|Vectorscan enabled"
    "linux/ppc64le|ppc64le|IBM POWER little-endian|Vectorscan enabled"
    "linux/arm/v7|armv7|Raspberry Pi 32-bit OS / embedded ARM|AC-BNFA fallback"
    "linux/386|386|Intel / AMD 32-bit|AC-BNFA fallback"
    "native||Current machine architecture (auto-detect)|auto"
)

OPT_PLATFORM=""          # set by --platform or picker
OPT_IMAGE_OVERRIDE=""    # set by --image
OPT_SECTIONS=""          # set by --sections
OPT_SKIP_BUILD=false
OPT_SKIP_TRIVY=false
OPT_SKIP_LIVE=false      # if true, overrides picker default for D
OPT_LIVE=false           # --live explicitly requested
OPT_IFACE="${SNORT_IFACE:-eth0}"
OPT_TIMEOUT=""           # per-test timeout in seconds; 0 = no limit; auto-set below

while [[ $# -gt 0 ]]; do
    case "$1" in
        --platform)   OPT_PLATFORM="$2";        shift 2 ;;
        --image)      OPT_IMAGE_OVERRIDE="$2";  shift 2 ;;
        --sections)   OPT_SECTIONS="$2";        shift 2 ;;
        --skip-build) OPT_SKIP_BUILD=true;      shift ;;
        --skip-trivy) OPT_SKIP_TRIVY=true;      shift ;;
        --skip-live)  OPT_SKIP_LIVE=true;       shift ;;
        --live)       OPT_LIVE=true;            shift ;;
        --iface)      OPT_IFACE="$2";           shift 2 ;;
        --timeout)    OPT_TIMEOUT="$2";         shift 2 ;;
        -h|--help)
            sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo -e "${RED}Unknown option: $1${RESET}" >&2; exit 1 ;;
    esac
done

divider() {
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}  $*${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}
log() { echo -e "${CYAN}[test-docker]${RESET} $*"; }

platform_to_tag() {
    # linux/arm/v7 → armv7,  linux/amd64 → amd64, etc.
    local plat="$1"
    for entry in "${PLATFORM_ENTRIES[@]}"; do
        local p t
        p="$(echo "$entry" | cut -d'|' -f1)"
        t="$(echo "$entry" | cut -d'|' -f2)"
        [[ "$p" == "$plat" ]] && { echo "$t"; return; }
    done
    echo "$plat" | sed 's|linux/||; s|/||g'
}

divider "Step 1 — Choose a platform"

if [[ -n "$OPT_PLATFORM" ]]; then
    PLATFORM="$OPT_PLATFORM"
    log "Platform supplied via flag: ${BOLD}$PLATFORM${RESET}"
else
    echo ""
    echo -e "  ${BOLD}Available build platforms:${RESET}"
    echo ""
    local_i=1
    for entry in "${PLATFORM_ENTRIES[@]}"; do
        p="$(echo "$entry" | cut -d'|' -f1)"
        d="$(echo "$entry" | cut -d'|' -f3)"
        n="$(echo "$entry" | cut -d'|' -f4)"
        printf "  ${BOLD}%d)${RESET}  %-20s  %-42s  ${DIM}%s${RESET}\n" \
               "$local_i" "$p" "$d" "$n"
        (( local_i++ )) || true
    done
    echo ""

    while true; do
        printf "  Select platform [1-%d]: " "${#PLATFORM_ENTRIES[@]}"
        read -r _choice
        if [[ "$_choice" =~ ^[0-9]+$ ]] && \
           (( _choice >= 1 && _choice <= ${#PLATFORM_ENTRIES[@]} )); then
            PLATFORM="$(echo "${PLATFORM_ENTRIES[$(( _choice - 1 ))]}" | cut -d'|' -f1)"
            break
        fi
        echo -e "  ${YELLOW}Please enter a number between 1 and ${#PLATFORM_ENTRIES[@]}${RESET}"
    done
    log "Selected: ${BOLD}$PLATFORM${RESET}"
fi

if [[ -n "$OPT_IMAGE_OVERRIDE" ]]; then
    IMAGE="$OPT_IMAGE_OVERRIDE"
    log "Image tag overridden: ${BOLD}$IMAGE${RESET}"
elif [[ "$PLATFORM" == "native" ]]; then
    PLATFORM=""
    IMAGE="snort3:alpine-native"
    log "Derived image tag: ${BOLD}$IMAGE${RESET}"
else
    IMAGE="snort3:alpine-$(platform_to_tag "$PLATFORM")"
    log "Derived image tag: ${BOLD}$IMAGE${RESET}"
fi

divider "Step 2 — Choose test sections"

_SECTION_FLAGS_PROVIDED=false
[[ -n "$OPT_SECTIONS" || "$OPT_SKIP_TRIVY" == true || \
   "$OPT_SKIP_LIVE" == true || "$OPT_LIVE" == true ]] && _SECTION_FLAGS_PROVIDED=true

RUN_A=true; RUN_B=true; RUN_C=true; RUN_D=false; RUN_E=true  # defaults

if $_SECTION_FLAGS_PROVIDED; then
    $OPT_SKIP_TRIVY && RUN_E=false
    $OPT_LIVE       && RUN_D=true
    $OPT_SKIP_LIVE  && RUN_D=false

    if [[ -n "$OPT_SECTIONS" ]]; then
        RUN_A=false; RUN_B=false; RUN_C=false; RUN_D=false; RUN_E=false
        _SEC="${OPT_SECTIONS^^}"
        [[ "$_SEC" == *A* ]] && RUN_A=true
        [[ "$_SEC" == *B* ]] && RUN_B=true
        [[ "$_SEC" == *C* ]] && RUN_C=true
        [[ "$_SEC" == *D* ]] && RUN_D=true
        [[ "$_SEC" == *E* ]] && RUN_E=true
    fi

    echo ""
    _active=""
    $RUN_A && _active+=" A"
    $RUN_B && _active+=" B"
    $RUN_C && _active+=" C"
    $RUN_D && _active+=" D"
    $RUN_E && _active+=" E"
    log "Sections from flags:${BOLD}${_active}${RESET}"
else
    echo ""
    echo -e "  ${BOLD}Available test sections:${RESET}"
    echo ""
    echo -e "  ${BOLD}A)${RESET}  Image Metadata        T01–T08   image inspect, size, entrypoint, labels"
    echo -e "  ${BOLD}B)${RESET}  Binary & Library      T09–T24   snort binary, ldd, DAQ modules, .so files"
    echo -e "  ${BOLD}C)${RESET}  Functional            T25–T36   config validation, pcap replay, alert rules"
    echo -e "  ${BOLD}D)${RESET}  Live Interface        T37       requires host network + physical NIC"
    echo -e "  ${BOLD}E)${RESET}  Trivy Security Scan   T38–T40   CVE + secret scan  ${DIM}(auto-installs trivy)${RESET}"
    echo ""
    echo -e "  ${DIM}Default (press Enter) = A B C E  — everything except live interface${RESET}"
    echo ""
    printf "  Enter sections to run (e.g. A B C E): "
    read -r _input

    if [[ -z "$_input" ]]; then
        log "Using defaults: ${BOLD}A B C E${RESET}"
    else
        RUN_A=false; RUN_B=false; RUN_C=false; RUN_D=false; RUN_E=false
        _input="${_input^^}"
        [[ "$_input" == *A* ]] && RUN_A=true
        [[ "$_input" == *B* ]] && RUN_B=true
        [[ "$_input" == *C* ]] && RUN_C=true
        [[ "$_input" == *D* ]] && RUN_D=true
        [[ "$_input" == *E* ]] && RUN_E=true

        _active=""
        $RUN_A && _active+=" A"
        $RUN_B && _active+=" B"
        $RUN_C && _active+=" C"
        $RUN_D && _active+=" D"
        $RUN_E && _active+=" E"
        log "Selected sections:${BOLD}${_active}${RESET}"
    fi
fi

# Warn if D selected without --live
if $RUN_D; then
    echo -e "  ${YELLOW}Note:${RESET} Section D (live interface) will use iface=${BOLD}${OPT_IFACE}${RESET}."
    echo -e "  ${YELLOW}Note:${RESET} Test will fail if the interface does not exist or lacks NET_ADMIN."
fi

# QEMU arches are slow; give them a longer timeout. Override via --timeout or SNORT_TEST_TIMEOUT.
if [[ -n "$OPT_TIMEOUT" ]]; then
    TEST_TIMEOUT="$OPT_TIMEOUT"
elif [[ -n "${SNORT_TEST_TIMEOUT:-}" ]]; then
    TEST_TIMEOUT="$SNORT_TEST_TIMEOUT"
elif [[ "$PLATFORM" == *arm/v7* || "$PLATFORM" == *386* ]]; then
    TEST_TIMEOUT=600   # 32-bit QEMU is very slow
elif [[ "$PLATFORM" == *ppc64le* || "$PLATFORM" == *s390x* || "$PLATFORM" == *riscv64* ]]; then
    TEST_TIMEOUT=300   # 64-bit QEMU
else
    TEST_TIMEOUT=60    # native
fi
log "Per-test timeout: ${BOLD}${TEST_TIMEOUT}s${RESET}"

divider "Step 3 — Build / verify image"

if docker image inspect "$IMAGE" &>/dev/null; then
    log "Image ${BOLD}$IMAGE${RESET} already present locally — skipping build."
elif $OPT_SKIP_BUILD; then
    echo -e "${RED}ERROR${RESET}: Image '$IMAGE' not found and --skip-build was set." >&2
    exit 1
else
    _PFLAG=""
    [[ -n "$PLATFORM" ]] && _PFLAG="--platform $PLATFORM"

    log "Image not found — building ${BOLD}$IMAGE${RESET}${PLATFORM:+ for $PLATFORM} ..."
    echo -e "  ${YELLOW}Note:${RESET} First build on a QEMU-emulated platform takes ~30 min."
    echo ""

    # needed for --mount=type=cache; Docker >=23 enables this by default
    export DOCKER_BUILDKIT=1

    docker build \
        $_PFLAG \
        --progress=plain \
        -t "$IMAGE" \
        "$REPO_ROOT"

    log "Build complete."
fi

PASS=0; FAIL=0; SKIP=0
declare -a PASSED_TESTS=()
declare -a FAILED_TESTS=()
declare -a SKIPPED_TESTS=()

# run_test ID DESC EXPECT CMD... — expect: EXIT_0 | EMPTY | NON_EMPTY | grep-E pattern
run_test() {
    local id="$1" desc="$2" expect="$3"; shift 3
    local output exit_code=0

    printf "  ${BOLD}%-5s${RESET} %s ... " "$id" "$desc"
    if [[ "${TEST_TIMEOUT:-0}" -gt 0 ]]; then
        output="$(timeout --kill-after=15 "${TEST_TIMEOUT}" "$@" 2>&1)" || exit_code=$?
        if [[ $exit_code -eq 124 || $exit_code -eq 137 ]]; then
            echo -e "${YELLOW}TIMEOUT${RESET}  (>${TEST_TIMEOUT}s — killed)"
            (( FAIL++ )) || true
            FAILED_TESTS+=("$id: $desc  [timed out after ${TEST_TIMEOUT}s]")
            return
        fi
    else
        output="$("$@" 2>&1)" || exit_code=$?
    fi

    local result=PASS
    case "$expect" in
        EXIT_0)    [[ $exit_code -eq 0 ]] || result=FAIL ;;
        EMPTY)     [[ -z "$output" ]]      || result=FAIL ;;
        NON_EMPTY) [[ -n "$output" ]]      || result=FAIL ;;
        *)         echo "$output" | grep -qE "$expect" || result=FAIL ;;
    esac

    if [[ "$result" == PASS ]]; then
        echo -e "${GREEN}PASS${RESET}"
        (( PASS++ )) || true
        PASSED_TESTS+=("$id: $desc")
    else
        echo -e "${RED}FAIL${RESET}"
        echo -e "    ${GREY}expect : $expect${RESET}"
        echo -e "    ${GREY}output : $(echo "$output" | head -5 | sed 's/^/             /')${RESET}"
        (( FAIL++ )) || true
        FAILED_TESTS+=("$id: $desc")
    fi
}

run_test_sh() {
    local id="$1" desc="$2" expect="$3" script="$4"
    local _pflag=()
    [[ -n "$PLATFORM" ]] && _pflag=("--platform" "$PLATFORM")
    run_test "$id" "$desc" "$expect" \
        docker run --rm --stop-timeout 5 "${_pflag[@]}" --entrypoint sh "$IMAGE" -c "$script"
}

skip_test() {
    printf "  ${BOLD}%-5s${RESET} %s ... ${GREY}SKIP${RESET}  %s\n" "$1" "$2" "$3"
    (( SKIP++ )) || true
    SKIPPED_TESTS+=("$1: $2")
}

if $RUN_A; then
    divider "Section A — Image Metadata (T01–T08)"

    run_test T01 "Image exists locally" EXIT_0 \
        docker image inspect "$IMAGE"

    printf "  ${BOLD}%-5s${RESET} %s ... " "T02" "Image size < 80 MB"
    _sz=$(docker image inspect "$IMAGE" --format '{{.Size}}' 2>/dev/null || echo 0)
    if (( _sz < 83886080 )); then
        echo -e "${GREEN}PASS${RESET}  ($(( _sz / 1048576 )) MB)"
        (( PASS++ )) || true; PASSED_TESTS+=("T02: Image size < 80 MB")
    else
        echo -e "${RED}FAIL${RESET}  ($(( _sz / 1048576 )) MB — expected < 80 MB)"
        (( FAIL++ )) || true; FAILED_TESTS+=("T02: Image size < 80 MB")
    fi

    run_test T03 "Entrypoint is [\"snort\"]" '^\["snort"\]$' \
        docker image inspect "$IMAGE" --format '{{json .Config.Entrypoint}}'

    run_test T04 "Default CMD is [\"--version\"]" '^\["--version"\]$' \
        docker image inspect "$IMAGE" --format '{{json .Config.Cmd}}'

    run_test T05 "Running user is snorty (non-root)" 'snorty' \
        docker image inspect "$IMAGE" --format '{{.Config.User}}'

    run_test T06 "LD_LIBRARY_PATH set correctly" 'LD_LIBRARY_PATH=/usr/local/lib:/snort3/lib' \
        docker image inspect "$IMAGE" --format '{{json .Config.Env}}'

    run_test T07 "PATH includes /snort3/bin" '/snort3/bin' \
        docker image inspect "$IMAGE" --format '{{json .Config.Env}}'

    run_test T08 "Volume mounts declared" '/var/log/snort' \
        docker image inspect "$IMAGE" --format '{{json .Config.Volumes}}'
else
    divider "Section A — Image Metadata (T01–T08)  [SKIPPED]"
    for _id in T01 T02 T03 T04 T05 T06 T07 T08; do
        skip_test "$_id" "Image metadata" "section A not selected"
    done
fi

if $RUN_B; then
    divider "Section B — Binary and Library Presence (T09–T24)"

    run_test T09 "snort --version succeeds" 'Snort\+\+' \
        docker run --rm ${PLATFORM:+--platform $PLATFORM} "$IMAGE" --version

    run_test_sh T10 "snort binary in /snort3/bin" '/snort3/bin/snort' \
        'ls /snort3/bin/snort'

    if [[ "$PLATFORM" == *ppc64le* || "$PLATFORM" == *s390x* || "$PLATFORM" == *riscv64* ]]; then
        skip_test T11 "libluajit-5.1 present" "LuaJIT has no upstream support for $PLATFORM"
    else
        run_test_sh T11 "libluajit-5.1 present (source-built, CVE-free)" 'libluajit' \
            'ls /usr/local/lib/libluajit-5.1.so* 2>/dev/null'
    fi

    run_test_sh T12 "libdaq.so present" 'libdaq' \
        'ls /usr/local/lib/libdaq.so* 2>/dev/null'

    run_test_sh T13 "DAQ pcap module present" 'daq_pcap\.so' \
        'ls /usr/local/lib/daq/daq_pcap.so'

    run_test_sh T14 "DAQ dump module present" 'daq_dump\.so' \
        'ls /usr/local/lib/daq/daq_dump.so'

    run_test_sh T15 "Snort dynamic plugins directory exists" NON_EMPTY \
        'ls /snort3/lib/snort/ 2>/dev/null'

    run_test_sh T16 "Default snort.lua config present" 'snort\.lua' \
        'ls /snort3/etc/snort/snort.lua'

    run_test_sh T17 "libssl runtime library present" NON_EMPTY \
        'find /usr/lib /lib -name "libssl.so*" 2>/dev/null | head -1'

    run_test_sh T18 "libpcap runtime library present" NON_EMPTY \
        'find /usr/lib /lib -name "libpcap.so*" 2>/dev/null | head -1'

    run_test_sh T19 "libcrypto runtime library present" NON_EMPTY \
        'find /usr/lib /lib -name "libcrypto.so*" 2>/dev/null | head -1'

    run_test_sh T20 "snort binary is dynamically linked" '\.so' \
        'ldd /snort3/bin/snort 2>&1'

    if [[ "$PLATFORM" == *ppc64le* || "$PLATFORM" == *s390x* || "$PLATFORM" == *riscv64* ]]; then
        skip_test T21 "snort links against libluajit" "LuaJIT not built on $PLATFORM"
    else
        run_test_sh T21 "snort links against libluajit" 'luajit' \
            'ldd /snort3/bin/snort 2>/dev/null'
    fi

    run_test_sh T22 "snort links against libdaq" 'libdaq' \
        'ldd /snort3/bin/snort 2>/dev/null'

    run_test_sh T23 "snort links against libpcap" 'libpcap' \
        'ldd /snort3/bin/snort 2>/dev/null'

    printf "  ${BOLD}%-5s${RESET} %s ... " "T24" "No missing shared libraries"
    _missing=$(docker run --rm --entrypoint sh "$IMAGE" -c \
        'ldd /snort3/bin/snort 2>&1 | grep "not found" | wc -l' 2>/dev/null || echo 99)
    if [[ "${_missing// /}" == "0" ]]; then
        echo -e "${GREEN}PASS${RESET}"
        (( PASS++ )) || true; PASSED_TESTS+=("T24: No missing shared libraries")
    else
        echo -e "${RED}FAIL${RESET}  ($_missing unresolved libraries)"
        (( FAIL++ )) || true; FAILED_TESTS+=("T24: No missing shared libraries")
    fi
else
    divider "Section B — Binary and Library Presence (T09–T24)  [SKIPPED]"
    for _id in T09 T10 T11 T12 T13 T14 T15 T16 T17 T18 T19 T20 T21 T22 T23 T24; do
        skip_test "$_id" "Binary/library check" "section B not selected"
    done
fi

if $RUN_C; then
    divider "Section C — Functional Tests (T25–T36)"

    run_test T25 "Config validation -T passes" 'successfully validated' \
        docker run --rm ${PLATFORM:+--platform $PLATFORM} "$IMAGE" -c /snort3/etc/snort/snort.lua -T

    run_test T26 "Version string contains '3.'" '3\.' \
        docker run --rm ${PLATFORM:+--platform $PLATFORM} "$IMAGE" --version

    run_test_sh T27 "DAQ module list includes pcap" 'pcap' \
        'snort --daq-list 2>&1'

    run_test_sh T28 "Plugin list returns output" NON_EMPTY \
        'snort --plugin-path /snort3/lib/snort --list-plugins 2>&1 | head -5'

    _PCAP='
printf "\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00" > /tmp/t.pcap
printf "\x00\x28\x99\x65\x00\x00\x00\x00\x2a\x00\x00\x00\x2a\x00\x00\x00" >> /tmp/t.pcap
printf "\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x00" >> /tmp/t.pcap
printf "\x45\x00\x00\x1c\x00\x01\x00\x00\x40\x01\xf8\x3a\xc0\xa8\x01\x64\x08\x08\x08\x08" >> /tmp/t.pcap
printf "\x08\x00\xf7\xff\x00\x01\x00\x01" >> /tmp/t.pcap
'
    run_test_sh T29 "Pcap replay processes 1 packet" 'received:.*[1-9]|analyzed:.*[1-9]' \
        "${_PCAP}snort -c /snort3/etc/snort/snort.lua -r /tmp/t.pcap -k none 2>&1"

    run_test_sh T30 "Custom ICMP rule fires on replay" 'T30-ICMP' \
        "${_PCAP}
mkdir -p /tmp/rules
echo 'alert icmp any any -> any any (msg:\"T30-ICMP\"; sid:9000001; rev:1;)' > /tmp/rules/test.rules
snort -c /snort3/etc/snort/snort.lua --rule-path /tmp/rules -r /tmp/t.pcap -k none -A cmg 2>&1"

    run_test_sh T31 "Custom TCP rule config validates cleanly" 'successfully validated' \
        'mkdir -p /tmp/rules
echo "alert tcp any any -> any 80 (msg:\"T31-HTTP\"; sid:9000002; rev:1;)" > /tmp/rules/test.rules
snort -c /snort3/etc/snort/snort.lua --rule-path /tmp/rules -T 2>&1'

    run_test_sh T32 "Alert written to fast log file" 'T32-FAST' \
        "${_PCAP}
mkdir -p /tmp/rules /tmp/logs
echo 'alert icmp any any -> any any (msg:\"T32-FAST\"; sid:9000003; rev:1;)' > /tmp/rules/test.rules
snort -c /snort3/etc/snort/snort.lua --rule-path /tmp/rules \
      -r /tmp/t.pcap -k none -A fast -l /tmp/logs 2>&1
cat /tmp/logs/alert_fast 2>/dev/null"

    run_test_sh T33 "Container process runs as non-root (snorty)" 'snorty' \
        'id'

    printf "  ${BOLD}%-5s${RESET} %s ... " "T34" "/var/log/snort volume writable by snorty"
    # Named volume so Docker inherits image ownership; avoids WSL2 host /tmp permission issues
    docker volume create snort-t34 &>/dev/null
    _out=$(timeout --kill-after=15 "${TEST_TIMEOUT:-60}" \
        docker run --rm --stop-timeout 5 ${PLATFORM:+--platform $PLATFORM} \
        -v snort-t34:/var/log/snort \
        --entrypoint sh "$IMAGE" -c 'touch /var/log/snort/probe.txt && echo OK' 2>&1) || true
    docker volume rm snort-t34 &>/dev/null
    if echo "$_out" | grep -q "OK"; then
        echo -e "${GREEN}PASS${RESET}"
        (( PASS++ )) || true; PASSED_TESTS+=("T34: /var/log/snort volume writable by snorty")
    else
        echo -e "${RED}FAIL${RESET}  ($_out)"
        (( FAIL++ )) || true; FAILED_TESTS+=("T34: /var/log/snort volume writable by snorty")
    fi

    echo "# T35 test rule" > /tmp/t35-rule.txt
    run_test T35 "/snort3/etc/rules read-only volume readable" 'T35 test rule' \
        docker run --rm --stop-timeout 5 ${PLATFORM:+--platform $PLATFORM} \
            -v /tmp/t35-rule.txt:/snort3/etc/rules/local.rules:ro \
            --entrypoint sh "$IMAGE" \
            -c 'cat /snort3/etc/rules/local.rules'
    rm -f /tmp/t35-rule.txt

    printf "  ${BOLD}%-5s${RESET} %s ... " "T36" "Consecutive --version calls identical"
    # grep Snort++ line specifically to avoid Docker platform-mismatch warnings on stderr
    _v1=$(docker run --rm ${PLATFORM:+--platform $PLATFORM} "$IMAGE" --version 2>&1 | grep 'Snort++') || true
    _v2=$(docker run --rm ${PLATFORM:+--platform $PLATFORM} "$IMAGE" --version 2>&1 | grep 'Snort++') || true
    if [[ "$_v1" == "$_v2" && -n "$_v1" ]]; then
        echo -e "${GREEN}PASS${RESET}"
        (( PASS++ )) || true; PASSED_TESTS+=("T36: Consecutive --version calls identical")
    else
        echo -e "${RED}FAIL${RESET}  (outputs differ)"
        (( FAIL++ )) || true; FAILED_TESTS+=("T36: Consecutive --version calls identical")
    fi
else
    divider "Section C — Functional Tests (T25–T36)  [SKIPPED]"
    for _id in T25 T26 T27 T28 T29 T30 T31 T32 T33 T34 T35 T36; do
        skip_test "$_id" "Functional test" "section C not selected"
    done
fi

if $RUN_D; then
    divider "Section D — Live Interface (T37)"
    run_test T37 "Config validation with live NIC ($OPT_IFACE)" 'successfully validated' \
        docker run --rm --network host \
            --cap-add NET_ADMIN --cap-add NET_RAW \
            "$IMAGE" -c /snort3/etc/snort/snort.lua -i "$OPT_IFACE" -T
else
    divider "Section D — Live Interface (T37)  [SKIPPED]"
    skip_test T37 "Live interface config validation" "section D not selected (use --live to enable)"
fi

if $RUN_E; then
    divider "Section E — Trivy Security Scan (T38–T40)"

    if ! command -v trivy &>/dev/null; then
        log "Trivy not found — installing automatically..."

        _os="$(uname -s | tr '[:upper:]' '[:lower:]')"
        _arch="$(uname -m)"
        _trivy_ok=true

        case "$_arch" in
            x86_64)        _arch="64bit" ;;
            aarch64|arm64) _arch="ARM64" ;;
            armv7l)        _arch="ARM" ;;
            *)
                echo -e "  ${YELLOW}WARNING${RESET}: unsupported arch '$_arch' for Trivy auto-install."
                echo -e "  Install manually: https://trivy.dev/latest/getting-started/installation/"
                _trivy_ok=false ;;
        esac

        if $_trivy_ok; then
            _ver="$(curl -fsSL \
                https://api.github.com/repos/aquasecurity/trivy/releases/latest \
                | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')" || _ver=""

            if [[ -z "$_ver" ]]; then
                echo -e "  ${RED}ERROR${RESET}: Could not fetch latest Trivy version." >&2
                _trivy_ok=false
            else
                _tmp="$(mktemp -d)"
                trap 'rm -rf "$_tmp"' EXIT

                if [[ "$_os" == "linux" ]]; then
                    _pkg="trivy_${_ver}_Linux-${_arch}.tar.gz"
                    curl -fsSL \
                        "https://github.com/aquasecurity/trivy/releases/download/v${_ver}/${_pkg}" \
                        -o "$_tmp/$_pkg"
                    tar -xzf "$_tmp/$_pkg" -C "$_tmp"
                elif [[ "$_os" == "darwin" ]]; then
                    if command -v brew &>/dev/null; then
                        brew install trivy
                    else
                        _pkg="trivy_${_ver}_macOS-${_arch}.tar.gz"
                        curl -fsSL \
                            "https://github.com/aquasecurity/trivy/releases/download/v${_ver}/${_pkg}" \
                            -o "$_tmp/$_pkg"
                        tar -xzf "$_tmp/$_pkg" -C "$_tmp"
                    fi
                fi

                if [[ -f "$_tmp/trivy" ]]; then
                    if command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
                        sudo install -m 755 "$_tmp/trivy" /usr/local/bin/trivy
                    else
                        mkdir -p "$HOME/.local/bin"
                        install -m 755 "$_tmp/trivy" "$HOME/.local/bin/trivy"
                        export PATH="$HOME/.local/bin:$PATH"
                    fi
                fi

                command -v trivy &>/dev/null \
                    && log "Trivy $(trivy --version | head -1) installed." \
                    || { echo -e "  ${RED}ERROR${RESET}: Trivy install failed." >&2; _trivy_ok=false; }
            fi
        fi

        if ! $_trivy_ok; then
            for _id in T38 T39 T40; do
                skip_test "$_id" "Trivy scan" "trivy could not be installed"
            done
            _trivy_ok=false
        fi
    else
        log "Trivy available: $(trivy --version | head -1)"
        _trivy_ok=true
    fi

    if ${_trivy_ok:-true} && command -v trivy &>/dev/null; then
        run_test T38 "Zero CRITICAL vulnerabilities" EXIT_0 \
            trivy image --severity CRITICAL --scanners vuln --exit-code 1 --quiet "$IMAGE"

        run_test T39 "Zero HIGH vulnerabilities" EXIT_0 \
            trivy image --severity HIGH --scanners vuln --exit-code 1 --quiet "$IMAGE"

        run_test T40 "No embedded secrets or credentials" EXIT_0 \
            trivy image --scanners secret --exit-code 1 --quiet "$IMAGE"
    fi
else
    divider "Section E — Trivy Security Scan (T38–T40)  [SKIPPED]"
    for _id in T38 T39 T40; do
        skip_test "$_id" "Trivy scan" "section E not selected (use --skip-trivy to exclude)"
    done
fi

divider "Test Summary"
TOTAL=$(( PASS + FAIL + SKIP ))

_sections_run=""
$RUN_A && _sections_run+=" A"
$RUN_B && _sections_run+=" B"
$RUN_C && _sections_run+=" C"
$RUN_D && _sections_run+=" D"
$RUN_E && _sections_run+=" E"

echo ""
echo -e "  Platform : ${BOLD}${PLATFORM:-native}${RESET}"
echo -e "  Image    : ${BOLD}${IMAGE}${RESET}"
echo -e "  Sections :${BOLD}${_sections_run}${RESET}"
echo -e "  Total    : ${BOLD}${TOTAL}${RESET}  (passed: ${PASS}  failed: ${FAIL}  skipped: ${SKIP})"
echo ""

if [[ ${#PASSED_TESTS[@]} -gt 0 ]]; then
    echo -e "  ${GREEN}${BOLD}Passed (${PASS}):${RESET}"
    for _t in "${PASSED_TESTS[@]}"; do
        echo -e "    ${GREEN}✔${RESET}  $_t"
    done
    echo ""
fi

if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
    echo -e "  ${RED}${BOLD}Failed (${FAIL}):${RESET}"
    for _t in "${FAILED_TESTS[@]}"; do
        echo -e "    ${RED}✘${RESET}  $_t"
    done
    echo ""
fi

if [[ ${#SKIPPED_TESTS[@]} -gt 0 ]]; then
    echo -e "  ${GREY}${BOLD}Skipped (${SKIP}):${RESET}"
    for _t in "${SKIPPED_TESTS[@]}"; do
        echo -e "    ${GREY}–${RESET}  $_t"
    done
    echo ""
fi

if [[ $FAIL -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}All run tests passed.${RESET}"
    echo ""
    exit 0
else
    echo -e "  ${RED}${BOLD}$FAIL test(s) failed.${RESET}"
    echo ""
    exit 1
fi
