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
    --disable-static-ips-actions    do not include ips actions in binary
    --disable-static-inspectors    do not include inspectors in binary
    --disable-static-loggers    do not include loggers in binary
    --disable-static-ips-options    do not include ips options in binary
    --disable-static-search-engines    do not include search engines in binary
    --disable-static-codecs    do not include codecs in binary
    --disable-static-piglets   do not include piglets in binary
    --enable-valgrind        Only use if you are testing with valgrind.
    --enable-shell           enable command line shell support
    --enable-linux-smp-stats Enable statistics reporting through proc
    --enable-debug-msgs      Enable debug printing options (bugreports and developers only)
    --enable-large-pcap      Enable support for pcaps larger than 2 GB
    --enable-debug           Enable debugging options (bugreports and developers only)
    --enable-gdb             Enable gdb debugging information
    --enable-gprof-profile   Enable gprof profiling options (developers only)
    --disable-corefiles      Prevent Snort from generating core files
    --enable-unit-tests      Build unit tests
    --enable-piglet          Build piglet test capability
    --disable-static-daq     Link static DAQ modules.

Optional Packages:
    --with-PACKAGE[=ARG]    use PACKAGE [ARG=yes]
    --without-PACKAGE       do not use PACKAGE (same as --with-PACKAGE=no)
    --with-pic[=PKGS]       try to use only PIC/non-PIC objects [default=use
                            both]
    --with-gnu-ld           assume the C compiler uses GNU ld [default=no]
    --with-sysroot=DIR Search for dependent libraries within DIR
                          (or the compiler's sysroot if not specified).
    --with-pcap-includes=DIR    libpcap include directory
    --with-pcap-libraries=DIR   libpcap library directory
    --with-luajit-includes=DIR    luajit include directory
    --with-luajit-libraries=DIR   luajit library directory
    --with-pcre-includes=DIR    libpcre include directory
    --with-pcre-libraries=DIR   libpcre library directory
    --with-openssl-includes=DIR    openssl include directory
    --with-openssl-library=LIB   openssl library library - NOT THE DIRECTORY
    --with-crypto-library=LIB   openssl crypto library - NOT THE DIRECTORY
    --with-dnet-includes=DIR       libdnet include directory
    --with-dnet-libraries=DIR      libdnet library directory
    --with-daq-includes=DIR        DAQ include directory
    --with-daq-libraries=DIR       DAQ library directory

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

check_and_append_cache_entry() {
    if [ -f $3 ]; then
        append_cache_entry $1 $2 $3
    else 
        echo ""
        echo "the $1 variable, which is specified using a --with-* options,"
        echo "requires an absolute path to the library.  Could not stat the"
        echo "the library:"
        echo "    $3"
        echo ""
        exit 1
    fi
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
        --generator=*)
            CMakeGenerator="$optarg"
            ;;
        --prefix=*)
            prefix=$optarg
            append_cache_entry CMAKE_INSTALL_PREFIX PATH $optarg
            ;;
        --disable-static-codecs)
            append_cache_entry STATIC_CODECS       BOOL   false
            ;;
        --enable-static-codecs)
            append_cache_entry STATIC_CODECS       BOOL   true
            ;;
        --disable-static-inspectors)
            append_cache_entry STATIC_INSPECTORS    BOOL   false
            ;;
        --enable-static-inspectors)
            append_cache_entry STATIC_INSPECTORS    BOOL   true
            ;;
        --disable-static-loggers)
            append_cache_entry STATIC_LOGGERS       BOOL   false
            ;;
        --enable-static-loggers)
            append_cache_entry STATIC_LOGGERS       BOOL   true
            ;;
        --disable-static-ips-options)
            append_cache_entry STATIC_IPS_OPTIONS    BOOL   false
            ;;
        --enable-static-ips-actions)
            append_cache_entry STATIC_IPS_ACTIONS    BOOL   true
            ;;
        --disable-static-ips-actions)
            append_cache_entry STATIC_IPS_ACTIONS    BOOL   false
            ;;
        --enable-static-ips-options)
            append_cache_entry STATIC_IPS_OPTIONS    BOOL   true
            ;;
        --disable-static-search-engines)
            append_cache_entry STATIC_SEARCH_ENGINES       BOOL   false
            ;;
        --enable-static-search-engines)
            append_cache_entry STATIC_SEARCH_ENGINES       BOOL   true
            ;;
        --disable-static-piglets)
            append_cache_entry STATIC_PIGLETS       BOOL   false
            ;;
        --enable-static-piglets)
            append_cache_entry STATIC_PIGLETS       BOOL   true
            ;;
        --disable-static-daq)
            append_cache_entry ENABLE_STATIC_DAQ    BOOL   false
            ;;
        --enable-static-daq)
            append_cache_entry ENABLE_STATIC_DAQ    BOOL   true
            ;;
        --disable-linux-smp-stats)
            append_cache_entry ENABLE_LINUX_SMP_STATS    BOOL   false
            ;;
        --enable-linux-smp-stats)
            append_cache_entry ENABLE_LINUX_SMP_STATS    BOOL   true
            ;;
        --disable-pthread)
            append_cache_entry ENABLE_PTHREAD    BOOL   false
            ;;
        --enable-pthread)
            append_cache_entry ENABLE_PTHREAD    BOOL   true
            ;;
        --disable-debug-msgs)
            append_cache_entry ENABLE_DEBUG_MSGS    BOOL   false
            ;;
        --enable-debug-msgs)
            append_cache_entry ENABLE_DEBUG_MSGS    BOOL   true
            ;;
        --disable-gdb)
            append_cache_entry ENABLE_GDB    BOOL   false
            ;;
        --enable-gdb)
            append_cache_entry ENABLE_GDB    BOOL   true
            ;;
        --disable-gprof-profile)
            append_cache_entry ENABLE_PROFILE    BOOL   false
            ;;
        --enable-gprof-profile)
            append_cache_entry ENABLE_PROFILE    BOOL   true
            ;;
        --disable-debug)
            append_cache_entry ENABLE_DEBUG    BOOL   false
            ;;
        --enable-debug)
            append_cache_entry ENABLE_DEBUG    BOOL   true
            ;;
        --disable-corefiles)
            append_cache_entry ENABLE_COREFILES    BOOL   false
            ;;
        --enable-corefiles)
            append_cache_entry ENABLE_COREFILES    BOOL   true
            ;;
        --disable-large-pcap)
            append_cache_entry ENABLE_LARGE_PCAP    BOOL   false
            ;;
        --enable-large-pcap)
            append_cache_entry ENABLE_LARGE_PCAP    BOOL   true
            ;;
        --enable-shell)
            append_cache_entry ENABLE_SHELL    BOOL   true
            ;;
        --disable-shell)
            append_cache_entry ENABLE_SHELL    BOOL   false
            ;;
        --disable-unit-tests)
            append_cache_entry BUILD_UNIT_TESTS    BOOL   false
            ;;
        --enable-unit-tests)
            append_cache_entry BUILD_UNIT_TESTS    BOOL   true
            ;;
        --disable-piglet)
            append_cache_entry BUILD_PIGLET    BOOL   false
            ;;
        --enable-piglet)
            append_cache_entry BUILD_PIGLET    BOOL   true
            ;;
        --disable-html-docs)
            append_cache_entry MAKE_HTML_DOC    BOOL   false
            ;;
        --enable-html-docs)
            append_cache_entry MAKE_HTML_DOC    BOOL   true
            ;;
        --disable-pdf-docs)
            append_cache_entry MAKE_PDF_DOC    BOOL   false
            ;;
        --enable-pdf-docs)
            append_cache_entry MAKE_PDF_DOC    BOOL   true
            ;;
        --with-openssl-includes=*)
            append_cache_entry OPENSSL_INCLUDE_DIR PATH $optarg
            ;;
        --with-openssl-library=*)
            check_and_append_cache_entry OPENSSL_SSL_LIBRARY FILEPATH $optarg
            ;;
        --with-crypto-library=*)
            check_and_append_cache_entry OPENSSL_CRYPTO_LIBRARY FILEPATH $optarg
            ;;
        --with-pcap-includes=*)
            append_cache_entry PCAP_INCLUDE_DIR PATH $optarg
            ;;
        --with-pcap-libraries=*)
            append_cache_entry PCAP_LIBRARIES_DIR PATH $optarg
            ;;
        --with-luajit-includes=*)
            append_cache_entry LUAJIT_INCLUDE_DIR PATH $optarg
            ;;
        --with-luajit-libraries=*)
            append_cache_entry LUAJIT_LIBRARIES_DIR PATH $optarg
            ;;
        --with-pcre-includes=*)
            append_cache_entry PCRE_INCLUDE_DIR PATH $optarg
            ;;
        --with-pcre-libraries=*)
            append_cache_entry PCRE_LIBRARIES_DIR PATH $optarg
            ;;
        --with-dnet-includes=*)
            append_cache_entry DNET_INCLUDE_DIR PATH $optarg
            ;;
        --with-dnet-libraries=*)
            append_cache_entry DNET_LIBRARIES_DIR PATH $optarg
            ;;
        --with-daq-includes=*)
            append_cache_entry DAQ_INCLUDE_DIR PATH $optarg
            ;;
        --with-daq-libraries=*)
            append_cache_entry DAQ_LIBRARIES_DIR PATH $optarg
            ;;
#  Currently unsupported
#        --with-intel-soft-cpm-includes=*)
#            append_cache_entry INTEL_SOFT_CPM_INCLUDE_DIR PATH $optarg
#            ;;
#        --with-intel-soft-cpm-libraries=*)
#            append_cache_entry INTEL_SOFT_CPM_LIBRARIES_DIR PATH $optarg
#            ;;
        --with-flex=*)
            append_cache_entry FLEX_EXECUTABLE PATH $optarg
            ;;
        --with-bison=*)
            append_cache_entry BISON_EXECUTABLE PATH $optarg
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

gen=""
[ "$CMakeGenerator" ] && gen+=" -G $CMakeGenerator"

cmake $gen \
    -DCOMPILE_DEFINITIONS:STRING="$CPPFLAGS" \
    -DCMAKE_CXX_FLAGS:STRING="$CXXFLAGS $CPPFLAGS" \
    -DCMAKE_C_FLAGS:STRING="$CFLAGS $CPPFLAGS" \
    $CMakeCacheEntries $sourcedir

echo "# This is the command used to configure this build" > config.status
echo $command >> config.status
chmod u+x config.status

