# - Find pcre2
# Find the native PCRE2 includes and library
#
#  PCRE2_INCLUDE_DIR - where to find pcre2.h, etc.
#  PCRE2_LIBRARIES    - List of libraries when using pcre2.
#  PCRE2_FOUND        - True if pcre2 found.

set(ERROR_MESSAGE
    "\n\tERROR!  Libpcre2 library not found.
    \tGet it from http://www.pcre.org\n"
)

find_package(PkgConfig)
pkg_check_modules(PC_PCRE2 libpcre2)

# Use PCRE2_INCLUDE_DIR_HINT and PCRE2_LIBRARIES_DIR_HINT from configure_cmake.sh as primary hints
# and then package config information after that.
find_path(PCRE2_INCLUDE_DIR pcre2.h
    HINTS ${PCRE2_INCLUDE_DIR_HINT} ${PC_PCRE2_INCLUDEDIR} ${PC_PCRE2_INCLUDE_DIRS})
find_library(PCRE2_LIBRARIES NAMES pcre2-8
    HINTS ${PCRE2_LIBRARIES_DIR_HINT} ${PC_PCRE2_LIBDIR} ${PC_PCRE2_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCRE2
    REQUIRED_VARS PCRE2_INCLUDE_DIR PCRE2_LIBRARIES
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)

mark_as_advanced(
    PCRE2_LIBRARIES
    PCRE2_INCLUDE_DIR
)
