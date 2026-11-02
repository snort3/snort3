# FindLibunwind
# ---------
#
# Find the libunwind includes and library.
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# This module will set the following variables in your project:
#
# ``LIBUNWIND_INCLUDE_DIRS``
#   where to find rpc.h, etc.
# ``LIBUNWIND_LIBRARIES``
#   the libraries to link against to use TIRPC.
# ``LIBUNWIND_VERSION``
#   the version of TIRPC found.
# ``LIBUNWIND_FOUND``
#   true if the TIRPC headers and libraries were found.
#

find_package(PkgConfig QUIET)
pkg_check_modules(PC_LIBUNWIND libunwind)

find_path(LIBUNWIND_INCLUDE_DIRS
    NAMES libunwind.h
    HINTS ${PC_LIBUNWIND_INCLUDE_DIRS}
)

if (APPLE AND LIBUNWIND_INCLUDE_DIRS)
    # On macOS, libunwind is part of libSystem — no standalone library to find.
    set(LIBUNWIND_LIBRARIES "" CACHE FILEPATH "libunwind is part of libSystem on macOS" FORCE)
else ()
    find_library(LIBUNWIND_LIBRARIES
        NAMES unwind
        HINTS ${PC_LIBUNWIND_LIBRARY_DIRS}
    )
endif ()

set(LIBUNWIND_VERSION ${PC_LIBUNWIND_VERSION})

include(FindPackageHandleStandardArgs)

if (APPLE)
    find_package_handle_standard_args(Libunwind
        REQUIRED_VARS LIBUNWIND_INCLUDE_DIRS
        VERSION_VAR LIBUNWIND_VERSION
    )
else ()
    find_package_handle_standard_args(Libunwind
        REQUIRED_VARS LIBUNWIND_LIBRARIES LIBUNWIND_INCLUDE_DIRS
        VERSION_VAR LIBUNWIND_VERSION
    )
endif ()

mark_as_advanced(LIBUNWIND_INCLUDE_DIRS LIBUNWIND_LIBRARIES)
