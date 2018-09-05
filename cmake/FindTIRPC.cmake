# FindTIRPC
# ---------
#
# Find the native TIRPC includes and library.
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# This module will set the following variables in your project:
#
# ``TIRPC_INCLUDE_DIRS``
#   where to find rpc.h, etc.
# ``TIRPC_LIBRARIES``
#   the libraries to link against to use TIRPC.
# ``TIRPC_VERSION``
#   the version of TIRPC found.
# ``TIRPC_FOUND``
#   true if the TIRPC headers and libraries were found.
#

find_package(PkgConfig QUIET)
pkg_check_modules(PC_TIRPC libtirpc)

find_path(TIRPC_INCLUDE_DIRS
    NAMES netconfig.h
    PATH_SUFFIXES tirpc
    HINTS ${PC_TIRPC_INCLUDE_DIRS}
)

find_library(TIRPC_LIBRARIES
    NAMES tirpc
    HINTS ${PC_TIRPC_LIBRARY_DIRS}
)

set(TIRPC_VERSION ${PC_TIRPC_VERSION})

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(TIRPC
    REQUIRED_VARS TIRPC_LIBRARIES TIRPC_INCLUDE_DIRS
    VERSION_VAR TIRPC_VERSION
)

mark_as_advanced(TIRPC_INCLUDE_DIRS TIRPC_LIBRARIES)
