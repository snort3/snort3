#!/bin/sh
# Convenience wrapper for easily viewing/setting options that
# the project's CMake scripts will recognize

set -e
command="$0 $*"

# check for `cmake` command
type cmake > /dev/null 2>&1 || {
    echo "\
This package requires CMake, please install it first, then you may
use this configure script to access CMake equivalent functionality.\
" >&2;
    exit 1;
}

usage="\
Usage: $0 [OPTION]... [VAR=VALUE]...

        --builddir=   The build directory
        --generator=  run cmake --help for a list of generators
        --prefix=     Snort++ installation prefix

Optional Features:
    --disable-FEATURE       do not include FEATURE (same as --enable-FEATURE=no)
    --enable-FEATURE[=ARG]  include FEATURE [ARG=yes]
    --enable-code-coverage  Whether to enable code coverage support
    --enable-hardened-build Detect and use compile-time hardening options
    --enable-pie            Attempt to produce a position-independent executable
    --disable-safec         do not use libsafec bounds checking  even if available
    --disable-static-ips-actions
                            do not include ips actions in binary
    --disable-static-inspectors
                            do not include inspectors in binary
    --disable-static-loggers
                            do not include loggers in binary
    --disable-static-ips-options
                            do not include ips options in binary
    --disable-static-search-engines
                            do not include search engines in binary
    --disable-static-codecs do not include codecs in binary
    --enable-shell          enable command line shell support
    --enable-large-pcap     enable support for pcaps larger than 2 GB
    --enable-stdlog         use file descriptor 3 instead of stdout for alerts
    --enable-tsc-clock      use timestamp counter register clock (x86 only)
    --enable-debug-msgs     enable debug printing options (bugreports and
                            developers only)
    --enable-debug          enable debugging options (bugreports and developers
                            only)
    --disable-gdb           disable gdb debugging information
    --enable-gprof-profile  enable gprof profiling options (developers only)
    --disable-snort-profiler
                            disable snort performance profiling (cpu and memory) (developers only)
    --enable-deep-profiling
                            enabled detailed snort performance profiling (developers only)
    --disable-memory-manager
                            disable snort memory manager (developers only)
    --disable-corefiles     prevent Snort from generating core files
    --enable-address-sanitizer
                            enable address sanitizer support
    --enable-thread-sanitizer
                            enable thread sanitizer support
    --enable-ub-sanitizer
                            enable undefined behavior sanitizer support
    --enable-tcmalloc
                            enable using tcmalloc for dynamic memory management
    --enable-appid-third-party
                            enable third party appid
    --enable-unit-tests     build unit tests
    --enable-piglet         build piglet test harness
    --disable-static-daq    link static DAQ modules
    --disable-html-docs     don't create the HTML documentation
    --disable-pdf-docs      don't create the PDF documentation
    --disable-text-docs     don't create the TEXT documentation
    --disable-docs          don't create documentation

Optional Packages:
    --with-PACKAGE[=ARG]    use PACKAGE [ARG=yes]
    --without-PACKAGE       do not use PACKAGE (same as --with-PACKAGE=no)
    --with-pcap-includes=DIR
                            libpcap include directory
    --with-pcap-libraries=DIR
                            libpcap library directory
    --with-luajit-includes=DIR
                            luajit include directory
    --with-luajit-libraries=DIR
                            luajit library directory
    --with-pcre-includes=DIR
                            libpcre include directory
    --with-pcre-libraries=DIR
                            libpcre library directory
    --with-dnet-includes=DIR
                            libdnet include directory
    --with-dnet-libraries=DIR
                            libdnet library directory
    --with-daq-includes=DIR DAQ include directory
    --with-daq-libraries=DIR
                            DAQ library directory
    --with-openssl=DIR      openssl installation root directory
    --with-hyperscan-includes=DIR
                            libhs include directory
    --with-hyperscan-libraries=DIR
                            libhs library directory
    --with-flatbuffers-includes=DIR
                            flatbuffers include directory
    --with-flatbuffers-libraries=DIR
                            flatbuffers library directory
    --with-uuid-includes=DIR
                            libuuid include directory
    --with-uuid-libraries=DIR
                            libuuid library directory

Some influential environment variables:
    SIGNAL_SNORT_RELOAD=<value>
                set the SIGNAL_SNORT_RELOAD value
    SIGNAL_SNORT_DUMP_STATS<value>
                set the SIGNAL_SNORT_DUMP_STATS value
    SIGNAL_SNORT_ROTATE_STATS<value>
                set the SIGNAL_SNORT_ROTATE_STATS value
    SIGNAL_SNORT_READ_ATTR_TBL<value>
                set the SIGNAL_SNORT_READ_ATTR_TBL value
"

sourcedir="$( cd "$( dirname "$0" )" && pwd )"

# Function to append a CMake cache entry definition to the
# CMakeCacheEntries variable
#   $1 is the cache entry variable name
#   $2 is the cache entry variable type
#   $3 is the cache entry variable value
append_cache_entry () {
    CMakeCacheEntries="$CMakeCacheEntries -D $1:$2=$3"
}

# set defaults
builddir=build
prefix=/usr/local/snort
CMakeCacheEntries=""
append_cache_entry CMAKE_INSTALL_PREFIX PATH   $prefix


# parse arguments
while [ $# -ne 0 ]; do
    case "$1" in
        -*=*) optarg=`echo "$1" | sed 's/[-_a-zA-Z0-9]*=//'` ;;
        *) optarg= ;;
    esac

    case "$1" in
        --help|-h)
            echo "${usage}" 1>&2
            exit 1
            ;;
        --builddir=*)
            builddir=$optarg
            ;;
        --define=*)
            CMakeCacheEntries="$CMakeCacheEntries -D$optarg"
            ;;
        --generator=*)
            CMakeGenerator="$optarg"
            ;;
        --prefix=*)
            prefix=$optarg
            append_cache_entry CMAKE_INSTALL_PREFIX PATH $optarg
            ;;
        --enable-code-coverage)
            append_cache_entry ENABLE_CODE_COVERAGE     BOOL true
            ;;
        --disable-code-coverage)
            append_cache_entry ENABLE_CODE_COVERAGE     BOOL false
            ;;
        --enable-hardened-build)
            append_cache_entry ENABLE_HARDENED_BUILD    BOOL true
            ;;
        --disable-hardened-build)
            append_cache_entry ENABLE_HARDENED_BUILD    BOOL false
            ;;
        --enable-pie)
            append_cache_entry ENABLE_PIE               BOOL true
            ;;
        --disable-pie)
            append_cache_entry ENABLE_PIE               BOOL false
            ;;
        --disable-safec)
            append_cache_entry ENABLE_SAFEC             BOOL false
            ;;
        --enable-safec)
            append_cache_entry ENABLE_SAFEC             BOOL true
            ;;
        --disable-static-ips-actions)
            append_cache_entry STATIC_IPS_ACTIONS       BOOL false
            ;;
        --enable-static-ips-actions)
            append_cache_entry STATIC_IPS_ACTIONS       BOOL true
            ;;
        --disable-static-inspectors)
            append_cache_entry STATIC_INSPECTORS        BOOL false
            ;;
        --enable-static-inspectors)
            append_cache_entry STATIC_INSPECTORS        BOOL true
            ;;
        --disable-static-loggers)
            append_cache_entry STATIC_LOGGERS           BOOL false
            ;;
        --enable-static-loggers)
            append_cache_entry STATIC_LOGGERS           BOOL true
            ;;
        --disable-static-ips-options)
            append_cache_entry STATIC_IPS_OPTIONS       BOOL false
            ;;
        --enable-static-ips-options)
            append_cache_entry STATIC_IPS_OPTIONS       BOOL true
            ;;
        --disable-static-search-engines)
            append_cache_entry STATIC_SEARCH_ENGINES    BOOL false
            ;;
        --enable-static-search-engines)
            append_cache_entry STATIC_SEARCH_ENGINES    BOOL true
            ;;
        --disable-static-codecs)
            append_cache_entry STATIC_CODECS            BOOL false
            ;;
        --enable-static-codecs)
            append_cache_entry STATIC_CODECS            BOOL true
            ;;
        --enable-shell)
            append_cache_entry ENABLE_SHELL             BOOL true
            ;;
        --disable-shell)
            append_cache_entry ENABLE_SHELL             BOOL false
            ;;
        --enable-large-pcap)
            append_cache_entry ENABLE_LARGE_PCAP        BOOL true
            ;;
        --enable-stdlog)
            append_cache_entry ENABLE_STDLOG            BOOL true
            ;;
        --enable-tsc-clock)
            append_cache_entry ENABLE_TSC_CLOCK         BOOL true
            ;;
        --disable-snort-profiler)
            append_cache_entry DISABLE_SNORT_PROFILER   BOOL true
            ;;
        --enable-deep-profiling)
            append_cache_entry ENABLE_DEEP_PROFILING    BOOL true
            ;;
        --disable-memory-manager)
            append_cache_entry DISABLE_MEMORY_MANAGER   BOOL true
            ;;
        --disable-large-pcap)
            append_cache_entry ENABLE_LARGE_PCAP        BOOL false
            ;;
        --enable-debug-msgs)
            append_cache_entry ENABLE_DEBUG_MSGS        BOOL true
            ;;
        --disable-debug-msgs)
            append_cache_entry ENABLE_DEBUG_MSGS        BOOL false
            ;;
        --enable-debug)
            append_cache_entry ENABLE_DEBUG             BOOL true
            ;;
        --disable-debug)
            append_cache_entry ENABLE_DEBUG             BOOL false
            ;;
        --enable-gdb)
            append_cache_entry ENABLE_GDB               BOOL true
            ;;
        --disable-gdb)
            append_cache_entry ENABLE_GDB               BOOL false
            ;;
        --enable-gprof-profile)
            append_cache_entry ENABLE_PROFILE           BOOL true
            ;;
        --disable-gprof-profile)
            append_cache_entry ENABLE_PROFILE           BOOL false
            ;;
        --disable-corefiles)
            append_cache_entry ENABLE_COREFILES         BOOL false
            ;;
        --enable-corefiles)
            append_cache_entry ENABLE_COREFILES         BOOL true
            ;;
        --enable-address-sanitizer)
            append_cache_entry ENABLE_ADDRESS_SANITIZER BOOL true
            ;;
        --disable-address-sanitizer)
            append_cache_entry ENABLE_ADDRESS_SANITIZER BOOL false
            ;;
        --enable-thread-sanitizer)
            append_cache_entry ENABLE_THREAD_SANITIZER  BOOL true
            ;;
        --disable-thread-sanitizer)
            append_cache_entry ENABLE_THREAD_SANITIZER  BOOL false
            ;;
        --enable-ub-sanitizer)
            append_cache_entry ENABLE_UB_SANITIZER      BOOL true
            ;;
        --disable-ub-sanitizer)
            append_cache_entry ENABLE_UB_SANITIZER      BOOL false
            ;;
        --enable-tcmalloc)
            append_cache_entry ENABLE_TCMALLOC          BOOL true
            ;;
        --disable-tcmalloc)
            append_cache_entry ENABLE_TCMALLOC          BOOL false
            ;;
        --enable-appid-third-party)
            append_cache_entry ENABLE_APPID_THIRD_PARTY BOOL true
            ;;
        --enable-unit-tests)
            append_cache_entry ENABLE_UNIT_TESTS        BOOL true
            ;;
        --disable-unit-tests)
            append_cache_entry ENABLE_UNIT_TESTS        BOOL false
            ;;
        --enable-piglet)
            append_cache_entry ENABLE_PIGLET            BOOL true
            ;;
        --disable-piglet)
            append_cache_entry ENABLE_PIGLET            BOOL false
            ;;
        --disable-static-daq)
            append_cache_entry ENABLE_STATIC_DAQ        BOOL false
            ;;
        --enable-static-daq)
            append_cache_entry ENABLE_STATIC_DAQ        BOOL true
            ;;
        --disable-html-docs)
            append_cache_entry MAKE_HTML_DOC            BOOL false
            ;;
        --enable-html-docs)
            append_cache_entry MAKE_HTML_DOC            BOOL true
            ;;
        --disable-pdf-docs)
            append_cache_entry MAKE_PDF_DOC             BOOL false
            ;;
        --enable-pdf-docs)
            append_cache_entry MAKE_PDF_DOC             BOOL true
            ;;
        --disable-text-docs)
            append_cache_entry MAKE_TEXT_DOC            BOOL false
            ;;
        --enable-text-docs)
            append_cache_entry MAKE_TEXT_DOC            BOOL true
            ;;
        --disable-docs)
            append_cache_entry MAKE_DOC                 BOOL false
            ;;
        --enable-docs)
            append_cache_entry MAKE_DOC                 BOOL true
            ;;
        --with-pcap-includes=*)
            append_cache_entry PCAP_INCLUDE_DIR_HINT PATH $optarg
            ;;
        --with-pcap-libraries=*)
            append_cache_entry PCAP_LIBRARIES_DIR_HINT PATH $optarg
            ;;
        --with-luajit-includes=*)
            append_cache_entry LUAJIT_INCLUDE_DIR_HINT PATH $optarg
            ;;
        --with-luajit-libraries=*)
            append_cache_entry LUAJIT_LIBRARIES_DIR_HINT PATH $optarg
            ;;
        --with-pcre-includes=*)
            append_cache_entry PCRE_INCLUDE_DIR_HINT PATH $optarg
            ;;
        --with-pcre-libraries=*)
            append_cache_entry PCRE_LIBRARIES_DIR_HINT PATH $optarg
            ;;
        --with-dnet-includes=*)
            append_cache_entry DNET_INCLUDE_DIR_HINT PATH $optarg
            ;;
        --with-dnet-libraries=*)
            append_cache_entry DNET_LIBRARIES_DIR_HINT PATH $optarg
            ;;
        --with-daq-includes=*)
            append_cache_entry DAQ_INCLUDE_DIR_HINT PATH $optarg
            ;;
        --with-daq-libraries=*)
            append_cache_entry DAQ_LIBRARIES_DIR_HINT PATH $optarg
            ;;
        --with-openssl=*)
            append_cache_entry OPENSSL_ROOT_DIR PATH $optarg
            ;;
        --with-hyperscan-includes=*)
            append_cache_entry HS_INCLUDE_DIR PATH $optarg
            ;;
        --with-hyperscan-libraries=*)
            append_cache_entry HS_LIBRARIES_DIR PATH $optarg
            ;;
        --with-flatbuffers-includes=*)
            append_cache_entry FLATBUFFERS_INCLUDE_DIR_HINT PATH $optarg
            ;;
        --with-flatbuffers-libraries=*)
            append_cache_entry FLATBUFFERS_LIBRARIES_DIR_HINT PATH $optarg
            ;;
        --with-uuid-includes=*)
            append_cache_entry UUID_INCLUDE_DIR_HINT PATH $optarg
            ;;
        --with-uuid-libraries=*)
            append_cache_entry UUID_LIBRARIES_DIR_HINT PATH $optarg
            ;;
        SIGNAL_SNORT_RELOAD=*)
            append_cache_entry SIGNAL_SNORT_RELOAD STRING $optarg
            ;;
        SIGNAL_SNORT_DUMP_STATS=*)
            append_cache_entry SIGNAL_SNORT_DUMP_STATS STRING $optarg
            ;;
        SIGNAL_SNORT_ROTATE_STATS=*)
            append_cache_entry SIGNAL_SNORT_ROTATE_STATS STRING $optarg
            ;;
        SIGNAL_SNORT_READ_ATTR_TBL=*)
            append_cache_entry SIGNAL_SNORT_READ_ATTR_TBL STRING $optarg
            ;;
        *)
            echo "Invalid option '$1'.  Try $0 --help to see available options."
            exit 1
            ;;
    esac
    shift
done

if [ -d $builddir ]; then
    # If build directory exists, check if it has a CMake cache
    if [ -f $builddir/CMakeCache.txt ]; then
        # If the CMake cache exists, delete it so that this configuration
        # is not tainted by a previous one
        rm -f $builddir/CMakeCache.txt
    fi
else
    # Create build directory
    mkdir -p $builddir
fi

echo "Build Directory : $builddir"
echo "Source Directory: $sourcedir"
cd $builddir

[ "$CMakeGenerator" ] && gen="-G $CMakeGenerator"

cmake $gen \
    -DCMAKE_CXX_FLAGS:STRING="$CXXFLAGS $CPPFLAGS" \
    -DCMAKE_C_FLAGS:STRING="$CFLAGS $CPPFLAGS" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    $CMakeCacheEntries $sourcedir

echo "# This is the command used to configure this build" > config.status
echo $command >> config.status
chmod u+x config.status

