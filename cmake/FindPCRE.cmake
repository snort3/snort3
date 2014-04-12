# $Id$
#
# - Find pcre
# Find the native PCRE includes and library
#
#  PCRE_INCLUDE_DIRS - where to find pcre.h, etc.
#  PCRE_LIBRARIES    - List of libraries when using pcre.
#  PCRE_FOUND        - True if pcre found.

set(ERROR_MESSAGE
    "\n\tERROR!  Libpcre library not found.
    \tGet it from http://www.pcre.org\n"
)

find_program(PCRE_CONFIG 
    NAMES pcre-config
    HINTS ENV PCRE_DIR
)



if (NOT PCRE_INCLUDE_DIRS)
    if(PCRE_CONFIG)
        execute_process(COMMAND ${PCRE_CONFIG} --cflags
            OUTPUT_VARIABLE PCRE_INCLUDE_DIRS
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )

    else(PCRE_CONFIG)
        find_path(PCRE_INCLUDE_DIRS 
            NAMES pcre.h
        )

    endif(PCRE_CONFIG)
endif(NOT PCRE_INCLUDE_DIRS)


if (NOT PCRE_LIBRARIES)
    if(PCRE_CONFIG)
        execute_process(COMMAND ${PCRE_CONFIG} --libs
            OUTPUT_VARIABLE PCRE_LIBRARIES
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )

    else(PCRE_CONFIG)
        find_path(PCRE_LIBRARIES 
            NAMES pcre
        )

    endif(PCRE_CONFIG)
endif(NOT PCRE_LIBRARIES)



include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCRE
    REQUIRED_VARS PCRE_LIBRARIES PCRE_INCLUDE_DIRS
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)



include (CheckLibraryExists)
check_library_exists(pcre pcre_compile ${PCRE_LIBRARIES} MIN_VERSION_SIX)

message(STATUS "MUST BE AT LEAST VERSION SIX")

message(STATUS "Create test to check PCRE version")



mark_as_advanced(
    PCRE_LIBRARIES 
    PCRE_INCLUDE_DIRS
)
unset(PCRE_CONFIG CACHE)
