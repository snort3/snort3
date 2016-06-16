#
#  Locate DAQ library
#  This module defines
#  DAQ_FOUND, if false, do not try to link to Lua
# 
#  DAQ_FOUND - system has libdaq
#  DAQ_INCLUDE_DIR - the libdaq include directory
#  DAQ_LIBRARIES - the libraries needed to use libdaq
#

set (ERROR_MESSAGE 
    "
    ERROR! Cannot find LibDAQ.  Go get it from 
    http://snort.org/snort-downloads or use the --with-daq-*
    options if you have it installed in an unusual place.\n\n"
)

find_path(DAQ_INCLUDE_DIR
    NAMES daq.h
    HINTS ${DAQ_INCLUDE_DIR_HINT}
    NO_SYSTEM_ENVIRONMENT_PATH
)

# find any static libraries
if (ENABLE_STATIC_DAQ)
    execute_process(
        COMMAND daq-modules-config --static --libs
        OUTPUT_VARIABLE DAQ_STATIC_LIBRARIES
        RESULT_VARIABLE result
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    # This will be false if the exit status was 0 and true if the binary was not found
    if (result)
        message(SEND_ERROR 
        "
        ERROR! Cannot find LibDAQ's static libraries!  Make sure the binary
        file `daq-modules-config` is in your path.\n\n")
    endif()

    set(DAQ_LIB daq_static)
else()
    set(DAQ_LIB daq)
    set(DAQ_STATIC_LIBRARIES)
endif()

find_library(DAQ_LIBRARY
    NAMES ${DAQ_LIB}
    HINTS ${DAQ_LIBRARIES_DIR_HINT}     # user-specified path in ./configure_cmake.sh
    DOC "DAQ library directory"
)

set(DAQ_LIBRARIES ${DAQ_LIBRARY} ${DAQ_STATIC_LIBRARIES})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DAQ
    REQUIRED_VARS DAQ_LIBRARY DAQ_LIBRARIES DAQ_INCLUDE_DIR
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)

mark_as_advanced(
    DAQ_INCLUDE_DIR
    DAQ_LIBRARY 
    DAQ_LIBRARIES 
)
