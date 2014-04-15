# $Id$
#
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

find_path(PCRE_INCLUDE_DIR 
    NAMES pcre.h
)

find_library(PCRE_LIBRARIES 
    NAMES pcre
)


include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCRE
    REQUIRED_VARS PCRE_INCLUDE_DIR PCRE_LIBRARIES
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)

message(STATUS "MUST BE AT LEAST VERSION SIX")

message(STATUS "Create test to check PCRE version")



mark_as_advanced(
    PCRE_LIBRARIES 
    PCRE_INCLUDE_DIR
)
