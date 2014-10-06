#
#
#  Locate DAQ library
#  This module defines
#  DAQ_FOUND, if false, do not try to link to Lua
# 
#  SNORT_FOUND - system has the daq
#  SNORT_INCLUDE_DIR - the daqs include directory
#
## Copied from default CMake FindLua51.cmake


set(ERROR_MESSAGE
    "
    Unable to find Snort!!! Either
    
    1)  manually set the cmake variable SNORT_INCLUDE_DIR,

    2)  run cmake with the following argument
          -DSNORT_INCLUDE_DIR:PATH=/full/path/to/snort/include/dir

    3)  set the environment variable SNORT_DIR

    "
)


find_path (SNORT_INCLUDE_DIR
    NAMES main/snort_types.h
    HINTS ENV SNORT_DIR
    PATH_SUFFIXES snort
)


include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SNORT
    REQUIRED_VARS SNORT_INCLUDE_DIR
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)



mark_as_advanced(
    SNORT_INCLUDE_DIR
)


