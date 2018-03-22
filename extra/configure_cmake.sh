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
    --enable-debug          enable debugging options (bugreports and developers
                            only)
    --disable-gdb           disable gdb debugging information
    --enable-address-sanitizer
                            enable address sanitizer support
    --enable-thread-sanitizer
                            enable thread sanitizer support
    --enable-ub-sanitizer
                            enable undefined behavior sanitizer support
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
            append_cache_entry ENABLE_UB_SANITIZER  BOOL true
            ;;
        --disable-ub-sanitizer)
            append_cache_entry ENABLE_UB_SANITIZER  BOOL false
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

