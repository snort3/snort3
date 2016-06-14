# - Find pcre
# Find the native PCRE includes and library
#
#  PCRE_INCLUDE_DIR - where to find pcre.h, etc.
#  PCRE_LIBRARIES    - List of libraries when using pcre.
#  PCRE_FOUND        - True if pcre found.

set(ERROR_MESSAGE
    "\n\tERROR!  Libpcre library not found.
    \tGet it from http://www.pcre.org\n"
)

find_package(PkgConfig)
pkg_check_modules(PC_PCRE libpcre)

# Use PCRE_INCLUDE_DIR_HINT and PCRE_LIBRARIES_DIR_HINT from configure_cmake.sh as primary hints
# and then package config information after that.
find_path(PCRE_INCLUDE_DIR pcre.h
    HINTS ${PCRE_INCLUDE_DIR_HINT} ${PC_PCRE_INCLUDEDIR} ${PC_PCRE_INCLUDE_DIRS})
find_library(PCRE_LIBRARIES NAMES pcre
    HINTS ${PCRE_LIBRARIES_DIR_HINT} ${PC_PCRE_LIBDIR} ${PC_PCRE_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCRE
    REQUIRED_VARS PCRE_INCLUDE_DIR PCRE_LIBRARIES
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)

mark_as_advanced(
    PCRE_LIBRARIES 
    PCRE_INCLUDE_DIR
)
