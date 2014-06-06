#
#
# This file converts cmake cache variables and command line options
# into compiler flags
#

if("${CMAKE_SYSTEM_NAME}" MATCHES "Linux")
    set(LINUX "YES")
endif("${CMAKE_SYSTEM_NAME}" MATCHES "Linux")

# FIX THIS!!
# Setting visibility options.  
IF(UNIX)
    IF(CMAKE_COMPILER_IS_GNUCC)
#         SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
#         SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden")
    ENDIF(CMAKE_COMPILER_IS_GNUCC)
ENDIF(UNIX)

set(INCLUDE_INSTALL_PATH "include/${CMAKE_PROJECT_NAME}")



# convert cmake options into compiler defines

set_project_compiler_defines_if_true( ENABLE_PERFPROFILING "PERF_PROFILING")
set_project_compiler_defines_if_true( ENABLE_DEBUG_MSGS "DEBUG_MSGS")
set_project_compiler_defines_if_true( ENABLE_DEBUG "DEBUG")
set_project_compiler_defines_if_true( ENABLE_SOURCEFIRE "PERF_PROFILING")
set_project_compiler_defines_if_true( BUILD_HA "ENABLE_HA")
set_project_compiler_defines_if_false(ENABLE_NON_ETHER_DECODERS "NO_NON_ETHER_DECODER")
set_project_compiler_defines_if_true( ENABLE_LARGE_PCAP "_LARGEFILE_SOURCE")
set_project_compiler_defines_if_true( ENABLE_LARGE_PCAP "_LARGEFILE64_SOURCE")
set_project_compiler_defines_if_true( ENABLE_LARGE_PCAP "_FILE_OFFSET_BITS=64")



# convert cmake options into config.h defines

set_if_true( STATIC_INSPECTORS STATIC_INSPECTORS )
set_if_true( STATIC_SEARCH_ENGINES STATIC_SEARCH_ENGINES )
set_if_true( STATIC_LOGGERS STATIC_LOGGERS )
set_if_true( STATIC_IPS_OPTIONS STATIC_IPS_OPTIONS )
set_if_true( STATIC_DECODERS STATIC_DECODERS )
set_if_true( BUILD_SIDE_CHANNEL SIDE_CHANNEL )
set_if_true( ENABLE_VALGRIND VALGRIND_TESTING )
set_if_true( ENABLE_PPM PPM_MGR )
set_if_true( ENABLE_PPM_TEST PPM_TEST )
set_if_true( ENABLE_PERFPROFILING PERF_PROFILING )
set_if_true( BUILD_HA ENABLE_HA )
set_if_true( ENABLE_LINUX_SMP_STATS LINUX_SMP )
set_if_true( ENABLE_DEBUG DEBUG )
set_if_false(ENABLE_DEBUG NDEBUG )
set_if_true( ENABLE_SOURCEFIRE SOURCEFIRE )
set_if_true( ENABLE_SOURCEFIRE PPM_MGR )
set_if_true( ENABLE_SOURCEFIRE PERF_PROFILING )
set_if_false(ENABLE_COREFILES NOCOREFILE )
set_if_false(ENABLE_NON_ETHER_DECODERS NO_NON_ETHER_DECODER )
set_if_true( HAVE_INTEL_SOFT_CPM INTEL_SOFT_CPM )
set_if_true( BUILD_UNIT_TESTS UNIT_TEST )
set_if_true( ENABLE_PROFILE PROFILE)


if(LINUX AND BUILD_CONTROL_SOCKET)
    add_definitions("-DCONTROL_SOCKET")
    message(WARNING "The control socket is only supported on Linux systems.")
    message(STATUS "Building the control socket.")
endif(LINUX AND BUILD_CONTROL_SOCKET)



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

# sanity checks to re-check and set all necesssary variables

if (NOT ASCIIDOC_FOUND)
    get_property(MAKE_HTML_DOC_HELP_STRING CACHE "MAKE_HTML_DOC" PROPERTY HELPSTRING)
    set(MAKE_HTML_DOC "OFF" CACHE BOOL ${MAKE_HTML_DOC_HELP_STRING})
endif()

if (NOT DBLATEX_FOUND)
    get_property(MAKE_PDF_DOC_HELP_STRING CACHE "MAKE_PDF_DOC" PROPERTY HELPSTRING)
    set(MAKE_PDF_DOC "OFF" CACHE BOOL ${MAKE_PDF_DOC_HELP_STRING})
endif()

if ("${CMAKE_GENERATOR}" MATCHES "Xcode")
    get_property(MAKE_HTML_DOC_HELP_STRING CACHE "MAKE_HTML_DOC" PROPERTY HELPSTRING)
    set(MAKE_HTML_DOC "OFF" CACHE BOOL ${MAKE_HTML_DOC_HELP_STRING})
    get_property(MAKE_PDF_DOC_HELP_STRING CACHE "MAKE_PDF_DOC" PROPERTY HELPSTRING)
    set(MAKE_PDF_DOC "OFF" CACHE BOOL ${MAKE_PDF_DOC_HELP_STRING})

endif()


# This code resets the DAQ libraries so cmake will now search for the static/shared DAQ library
if(DEFINED STATIC_DAQ_PRREVIOUSLY_ENABLED)
    if(NOT (ENABLE-STATIC_DAQ STREQUAL STATIC_DAQ_PRREVIOUSLY_ENABLED))
        unset(DAQ_FOUND CACHE)
        unset(DAQ_LIBRARY CACHE)
        unset(DAQ_LIBRARIES CACHE)
        set(STATIC_DAQ_PRREVIOUSLY_ENABLED "${ENABLE_STATIC_DAQ}" CACHE INTERNAL "save daq link type" FORCE)
    endif()
else()
    set(STATIC_DAQ_PRREVIOUSLY_ENABLED "${ENABLE_STATIC_DAQ}" CACHE INTERNAL "save daq link type" FORCE)
endif()

