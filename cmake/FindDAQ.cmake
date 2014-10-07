#
#
#  Locate DAQ library
#  This module defines
#  DAQ_FOUND, if false, do not try to link to Lua
# 
#  DAQ_FOUND - system has the daq
#  DAQ_INCLUDE_DIR - the daqs include directory
#  DAQ_LIBRARIES - the libraries needed to use the daq
#
## Copied from default CMake FindLua51.cmake



set (ERROR_MESSAGE 
    "
    ERROR!  cannot find the DAQ.  Go get it from 
    http://snort.org/snort-downloads or use the --with-daq-*
    options if you have it installed inn an unusual place.  You can
    also set the DAQ_DIR environment variablet to the daqs root installation directory\n\n"
)



find_path(DAQ_INCLUDE_DIR
    NAMES daq.h
    HINTS ENV DAQ_DIR
    PATH_SUFFIXES daq
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
        message(FATAL_ERROR "

        ERROR!  cannot find the DAQs static libraries!  make sure the binary
        file `daq-modules-config` is in your path, or specific the daqs path 
        with the --with-daq-root=<dir>
        
        ")
    endif()

    set(DAQ_LIB daq_static)
else()
    set(DAQ_LIB daq)
    set(DAQ_STATIC_LIBRARIES)
endif()


find_library(DAQ_LIBRARY
    NAMES  ${DAQ_LIB}
    HINTS ${DAQ_LIBRARIES_DIR} # user specified path in ./configure_cmake.sh
    DOC "DAQ library directory"
    NO_DEFAULT_PATH
    NO_CMAKE_ENVIRONMENT_PATH
)

find_library(DAQ_LIBRARY
    NAMES  ${DAQ_LIB}
    HINTS  ENV DAQ_DIR
    PATH_SUFFIXES daq
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
