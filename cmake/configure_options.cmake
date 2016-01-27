#
#
# This file converts cmake cache variables and command line options
# into compiler flags
#


# convert cmake options into compiler defines

set_project_compiler_defines_if_true (ENABLE_DEBUG_MSGS "DEBUG_MSGS")
set_project_compiler_defines_if_true (ENABLE_DEBUG "DEBUG")
set_project_compiler_defines_if_true (BUILD_HA "ENABLE_HA")
set_project_compiler_defines_if_true (ENABLE_LARGE_PCAP "_LARGEFILE_SOURCE")
set_project_compiler_defines_if_true (ENABLE_LARGE_PCAP "_FILE_OFFSET_BITS=64")



# convert cmake options into config.h defines


set_if_true (STATIC_INSPECTORS STATIC_INSPECTORS)
set_if_true (STATIC_SEARCH_ENGINES STATIC_SEARCH_ENGINES)
set_if_true (STATIC_LOGGERS STATIC_LOGGERS)
set_if_true (STATIC_IPS_ACTIONS STATIC_IPS_ACTIONS)
set_if_true (STATIC_IPS_OPTIONS STATIC_IPS_OPTIONS)
set_if_true (STATIC_CODECS STATIC_CODECS)
set_if_true (ENABLE_VALGRIND VALGRIND_TESTING)
set_if_true (BUILD_HA ENABLE_HA )
set_if_true (ENABLE_LINUX_SMP_STATS LINUX_SMP)
set_if_true (ENABLE_DEBUG DEBUG)
set_if_false (ENABLE_DEBUG NDEBUG)
set_if_false (ENABLE_COREFILES NOCOREFILE)
set_if_true (BUILD_SHELL BUILD_SHELL)
set_if_true (BUILD_SIDE_CHANNEL SIDE_CHANNEL)
set_if_true (BUILD_UNIT_TESTS UNIT_TEST)
set_if_true (BUILD_PIGLET PIGLET)
set_if_true (ENABLE_PROFILE PROFILE)
set_if_true (ENABLE_SHELL BUILD_SHELL)
set_if_true (BUILD_PIGLET PIGLET)
set_if_true (STATIC_PIGLETS STATIC_PIGLETS)


# convert cmake options into CXX flags
if(ENABLE_DEBUG)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
endif(ENABLE_DEBUG)

if (ENABLE_GDB)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -ggdb")
endif ()

if(ENABLE_PROFILE AND CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg")
endif()

if (BUILD_UNIT_TESTS)
    enable_testing()
endif()

# If not found, automatically set the cache to false
if (NOT ASCIIDOC_FOUND)
    get_property(MAKE_HTML_DOC_HELP_STRING CACHE "MAKE_HTML_DOC" PROPERTY HELPSTRING)
    set(MAKE_HTML_DOC "OFF" CACHE BOOL ${MAKE_HTML_DOC_HELP_STRING} FORCE)
endif()

if (NOT (DBLATEX_FOUND AND ASCIIDOC_FOUND))
    get_property(MAKE_PDF_DOC_HELP_STRING CACHE "MAKE_PDF_DOC" PROPERTY HELPSTRING)
    set(MAKE_PDF_DOC "OFF" CACHE BOOL ${MAKE_PDF_DOC_HELP_STRING} FORCE)
endif()

if (NOT (W3M_FOUND AND ASCIIDOC_FOUND))
    get_property(MAKE_TEXT_DOC_HELP_STRING CACHE "MAKE_TEXT_DOC" PROPERTY HELPSTRING)
    set(MAKE_TEXT_DOC "OFF" CACHE BOOL ${MAKE_TEXT_DOC_HELP_STRING} FORCE)
endif()



# If the user switches DAQS, search for the new, correct version
if(DEFINED STATIC_DAQ_PRREVIOUSLY_ENABLED)
    if(NOT (ENABLE_STATIC_DAQ STREQUAL STATIC_DAQ_PRREVIOUSLY_ENABLED))
        unset(DAQ_FOUND CACHE)
        unset(DAQ_INCLUDE_DIR)
        unset(DAQ_LIBRARY CACHE)
        unset(DAQ_LIBRARIES CACHE)
        set(STATIC_DAQ_PRREVIOUSLY_ENABLED "${ENABLE_STATIC_DAQ}" CACHE INTERNAL "save daq link type" FORCE)
        find_package(DAQ REQUIRED)
    endif()
else()
    set(STATIC_DAQ_PRREVIOUSLY_ENABLED "${ENABLE_STATIC_DAQ}" CACHE INTERNAL "save daq link type" FORCE)
endif()


SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g -Wall -Wextra -pedantic -Wformat")
SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wformat-security -Wno-deprecated-declarations")
