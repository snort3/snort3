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

  Build Options:
    --builddir=DIR         place build files in directory [build]
    --generator=GENERATOR  CMake generator to use (see cmake --help)

  Installation Directories:
    --prefix=PREFIX        installation directory [/usr/local/bro]
    --conf-files-dir=PATH  config files installation directory [PREFIX/etc]

    Optional Features:
      --disable-option-checking  ignore unrecognized --enable/--with options
      --disable-FEATURE       do not include FEATURE (same as --enable-FEATURE=no)
      --enable-FEATURE[=ARG]  include FEATURE [ARG=yes]
      --enable-silent-rules   less verbose build output (undo: \"make V=1\")
      --disable-silent-rules  verbose build output (undo: \"make V=0\")
      --enable-shared[=PKGS]  build shared libraries [default=yes]
      --enable-static[=PKGS]  build static libraries [default=yes]
      --enable-fast-install[=PKGS]
                              optimize for fast installation [default=yes]
      --enable-dependency-tracking
                              do not reject slow dependency extractors
      --disable-dependency-tracking
                              speeds up one-time build
      --disable-libtool-lock  avoid locking (might break parallel builds)
      --disable-static-inspectors    do not include inspectors in binary
      --disable-static-loggers    do not include loggers in binary
      --disable-static-ips-options    do not include ips options in binary
      --disable-static-search-engines    do not include search engines in binary
      --disable-static-codecs  do not include codecs in binary
      --enable-control-socket  Enable the control socket (Linux only)
      --enable-side-channel    Enable the side channel (Linux only)
      --enable-valgrind        Only use if you are testing with valgrind.
      --disable-ppm            Disable packet/rule performance monitor
      --enable-ppm-test        Enable packet/rule performance monitor for readback
      --disable-perfprofiling  Disable preprocessor and rule performance profiling
      --enable-linux-smp-stats Enable statistics reporting through proc
      --enable-inline-init-failopen  Enable Fail Open during initialization for Inline Mode (adds pthread support implicitly)
      --disable-pthread        Disable pthread support
      --enable-debug-msgs      Enable debug printing options (bugreports and developers only)
      --enable-debug           Enable debugging options (bugreports and developers only)
      --enable-gdb             Enable gdb debugging information
      --enable-profile         Enable profiling options (developers only)
      --enable-sourcefire      Enable Sourcefire specific build options, encompasing --enable-perfprofiling and --enable-ppm
      --disable-corefiles      Prevent Snort from generating core files
      --enable-ha              Enable high-availability state sharing
      --enable-non-ether-decoders  Enable non Ethernet decoders.
      --enable-intel-soft-cpm  Enable Intel Soft CPM support
      --enable-unit-tests      Build unit tests
      --enable-large-pcap      Enable support for pcaps larger than 2 GB
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
      --with-openssl-libraries=DIR   openssl library directory
      --with-dnet-includes=DIR       libdnet include directory
      --with-dnet-libraries=DIR      libdnet library directory
      --with-daq-includes=DIR        DAQ include directory
      --with-daq-libraries=DIR       DAQ library directory
      --with-intel-soft-cpm-includes=DIR      Intel Soft CPM include directory
      --with-intel-soft-cpm-libraries=DIR     Intel Soft CPM library directory

    Some influential environment variables:
      CC          C compiler command
      CFLAGS      C compiler flags
      LDFLAGS     linker flags, e.g. -L<lib dir> if you have libraries in a
                  nonstandard directory <lib dir>
      LIBS        libraries to pass to the linker, e.g. -l<library>
      CPPFLAGS    (Objective) C/C++ preprocessor flags, e.g. -I<include dir> if
                  you have headers in a nonstandard directory <include dir>
      CPP         C preprocessor
      CXX         C++ compiler command
      CXXFLAGS    C++ compiler flags
      CXXCPP      C++ preprocessor
      SIGNAL_SNORT_RELOAD
                  set the SIGNAL_SNORT_RELOAD value
      SIGNAL_SNORT_DUMP_STATS
                  set the SIGNAL_SNORT_DUMP_STATS value
      SIGNAL_SNORT_ROTATE_STATS
                  set the SIGNAL_SNORT_ROTATE_STATS value
      SIGNAL_SNORT_READ_ATTR_TBL
                  set the SIGNAL_SNORT_READ_ATTR_TBL value

    Use these variables to override the choices made by \`configure' or to help
    it to find libraries and programs with nonstandard names/locations.

    Report bugs to the package provider.
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
        --disable-static-ips-option)
            append_cache_entry STATIC_IPS_OPTIONS    BOOL   false
            ;;
        --enable-static-ips-option)
            append_cache_entry STATIC_IPS_OPTIONS    BOOL   true
            ;;
        --disable-static-search-engines)
            append_cache_entry STATIC_SEARCH_ENGINES       BOOL   false
            ;;
        --enable-static-search-engines)
            append_cache_entry STATIC_SEARCH_ENGINES       BOOL   true
            ;;
        --disable-control-socket)
            append_cache_entry BUILD_CONTROL_SOCKET    BOOL   false
            ;;
        --enable-control-socket)
            append_cache_entry BUILD_CONTROL_SOCKET    BOOL   true
            ;;
        --disable-side-channel)
            append_cache_entry BUILD_SIDE_CHANNEL       BOOL   false
            ;;
        --enable-side-channel)
            append_cache_entry BUILD_SIDE_CHANNEL       BOOL   true
            ;;
        --disable-static-daq)
            append_cache_entry ENABLE_STATIC_DAQ    BOOL   false
            ;;
        --enable-static-daq)
            append_cache_entry ENABLE_STATIC_DAQ    BOOL   true
            ;;
        --disable-valgrind)
            append_cache_entry ENABLE_VALGRIND       BOOL   false
            ;;
        --enable-valgrind)
            append_cache_entry ENABLE_VALGRIND       BOOL   true
            ;;
        --disable-ppm)
            append_cache_entry ENABLE_PPM    BOOL   false
            ;;
        --enable-ppm)
            append_cache_entry ENABLE_PPM    BOOL   true
            ;;
        --disable-ppm-test)
            append_cache_entry ENABLE_PPM    BOOL   false
            ;;
        --enable-ppm-test)
            append_cache_entry ENABLE_PPM    BOOL   true
            ;;
        --disable-perfprofiling)
            append_cache_entry ENABLE_PERFPROFILING    BOOL   false
            ;;
        --enable-perfprofiling)
            append_cache_entry ENABLE_PERFPROFILING    BOOL   true
            ;;
        --disable-linux-smp-stats)
            append_cache_entry ENABLE_INLINE_INIT_FAILOPEN    BOOL   false
            ;;
        --enable-linux-smp-stats)
            append_cache_entry ENABLE_INLINE_INIT_FAILOPEN    BOOL   true
            ;;
        --disable-pthread)
            append_cache_entry ENABLE_PTHREAD    BOOL   false
            ;;
        --enable-pthread)
            append_cache_entry ENABLE_PTHREAD    BOOL   true
            ;;
        --disable-debug_msgs)
            append_cache_entry ENABLE_DEBUG_MSGS    BOOL   false
            ;;
        --enable-debug_msgs)
            append_cache_entry ENABLE_DEBUG_MSGS    BOOL   true
            ;;
        --disable-gdb)
            append_cache_entry ENABLE_GDB    BOOL   false
            ;;
        --enable-gdb)
            append_cache_entry ENABLE_GDB    BOOL   true
            ;;
        --disable-profile)
            append_cache_entry ENABLE_PROFILE    BOOL   false
            ;;
        --enable-profile)
            append_cache_entry ENABLE_PROFILE    BOOL   true
            ;;
        --disable-sourcefire)
            append_cache_entry ENABLE_SOURCEFIRE    BOOL   false
            ;;
        --enable-sourcefire)
            append_cache_entry ENABLE_SOURCEFIRE    BOOL   true
            ;;
        --disable-debug)
            append_cache_entry ENABLE_COREFILES    BOOL   false
            ;;
        --enable-debug)
            append_cache_entry ENABLE_COREFILES    BOOL   true
            ;;
        --disable-ha)
            append_cache_entry BUILD_HA    BOOL   false
            ;;
        --enable-ha)
            append_cache_entry BUILD_HA    BOOL   true
            ;;
        --disable-large-pcap)
            append_cache_entry ENABLE_LARGE_PCAP    BOOL   false
            ;;
        --enable-large-pcap)
            append_cache_entry ENABLE_LARGE_PCAP    BOOL   true
            ;;
        --disable-intel-soft-cpm)
            append_cache_entry HAVE_INTEL_SOFT_CPM    BOOL   false
            ;;
        --enable-intel-soft-cpm)
            append_cache_entry HAVE_INTEL_SOFT_CPM    BOOL   true
            ;;
        --disable-side-channel)
            append_cache_entry BUILD_SIDE_CHANNEL    BOOL   false
            ;;
        --enable-side-channel)
            append_cache_entry BUILD_SIDE_CHANNEL    BOOL   true
            ;;
        --disable-unit-tests)
            append_cache_entry BUILD_UNIT_TESTS    BOOL   false
            ;;
        --enable-unit-tests)
            append_cache_entry BUILD_UNIT_TESTS    BOOL   true
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
        --with-openssl-libraries=*)
            check_and_append_cache_entry OPENSSL_SSL_LIBRARY FILEPATH $optarg
            ;;
        --with-crypto-libraries=*)
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

if [ -n "$CMakeGenerator" ]; then
    cmake -G "$CMakeGenerator" $CMakeCacheEntries $sourcedir
else
    cmake $CMakeCacheEntries $sourcedir
fi

echo "# This is the command used to configure this build" > config.status
echo $command >> config.status
chmod u+x config.status
