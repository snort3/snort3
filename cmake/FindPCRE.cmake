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
    HINTS ${PCRE_LIBRARIES_DIR} # from ./configure_cmake.sh script
    NO_DEFAULT_PATH
    NO_CMAKE_ENVIRONMENT_PATH
)

find_library(PCRE_LIBRARIES
    NAMES pcre
)


include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCRE
    REQUIRED_VARS PCRE_INCLUDE_DIR PCRE_LIBRARIES
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)

set(bindir "${CMAKE_CURRENT_BINARY_DIR}/pcre_version")
set(srcfile "${CMAKE_CURRENT_LIST_DIR}/Pcre/check_pcre_version.cpp")

try_compile(VALID_PCRE_VERSION "${bindir}" "${srcfile}"
    CMAKE_FLAGS
        "-DLINK_LIBRARIES:STRING=${PCRE_LIBRARIES}"
        "-DINCLUDE_DIRECTORIES:STRING=${PCRE_INCLUDE_DIR}"
)


if(NOT VALID_PCRE_VERSION)
    # unset these variables to ensure we search for PCRE again
    unset(PCRE_FOUND CACHE)
    unset(PCRE_INCLUDE_DIR CACHE)
    unset(PCRE_LIBRARIES CACHE)
    message(FATAL_ERROR
        "\nERROR!  Libpcre library version >= 6.0 not found."
        " Get it from http://www.pcre.org\n\n"
    )
endif()


mark_as_advanced(
    PCRE_LIBRARIES 
    PCRE_INCLUDE_DIR
)
