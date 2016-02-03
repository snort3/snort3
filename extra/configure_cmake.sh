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

    Optional Packages:
    --with-daq-includes=DIR        DAQ include directory
    --with-daq-libraries=DIR       DAQ library directory
    --with-luajit-includes=DIR    luajit include directory
    --with-luajit-libraries=DIR   luajit library directory
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
        --with-luajit-includes=*)
            append_cache_entry LUAJIT_INCLUDE_DIR PATH $optarg
            ;;
        --with-luajit-libraries=*)
            append_cache_entry LUAJIT_LIBRARIES_DIR PATH $optarg
            ;;
        --with-daq-includes=*)
            append_cache_entry DAQ_INCLUDE_DIR PATH $optarg
            ;;
        --with-daq-libraries=*)
            append_cache_entry DAQ_LIBRARIES_DIR PATH $optarg
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
