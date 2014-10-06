#
#
#  Locate DAQ library
#  This module defines
#  DAQ_FOUND, if false, do not try to link to Lua
# 
#  SNORT_FOUND - Found Snort
#  SNORT_INCLUDE_DIR - Snort include directory
#

set(ERROR_MESSAGE
    "
    Unable to find Snort!!! Either
    
    1)  manually set the cmake variable SNORT_INCLUDE_DIR,

    2)  run cmake with the following argument
          -DSNORT_INCLUDE_DIR:PATH=/full/path/to/snort/include/dir

    3)  set the environment variable SNORT_DIR

    4)  install pkg-config and add snort.pc to the PKG_CONFIG_PATH
            environment variable.

    "
)


find_path (SNORT_INCLUDE_DIR
    NAMES main/snort_types.h
    HINTS ENV SNORT_DIR
    PATH_SUFFIXES snort include/snort
)

if (NOT SNORT_INCLUDE_DIR)
    find_package(PkgConfig QUIET)

    if (PKG_CONFIG_FOUND)
        pkg_check_modules(SNORT_PKG_MODULE snort)
        message(STATUS "snort_FOUND == ${snort_FOUND}")
        message(STATUS "SNORT_PKG_MODULE_FOUND == ${SNORT_PKG_MODULE_FOUND}")

        if (SNORT_PKG_MODULE_FOUND)
            set(SNORT_INCLUDE_DIR "${SNORT_PKG_MODULE_INCLUDE_DIRS}")
        endif (SNORT_PKG_MODULE_FOUND)

        message(STATUS "snort include dirs ${SNORT_PKG_MODULE_INCLUDE_DIRS}")
    endif (PKG_CONFIG_FOUND)
endif (NOT SNORT_INCLUDE_DIR)


include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SNORT
    REQUIRED_VARS SNORT_INCLUDE_DIR
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)



mark_as_advanced(
    SNORT_INCLUDE_DIR
)


