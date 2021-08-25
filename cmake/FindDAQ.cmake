#[=======================================================================[.rst:
FindDAQ
-------

Locate LibDAQ include paths and library as well as static DAQ module libraries

This module defines:

::

  DAQ_FOUND - system has libdaq
  DAQ_INCLUDE_DIR - the libdaq include directory
  DAQ_LIBRARIES - the libraries needed to use libdaq
  DAQ_STATIC_MODULES - the static DAQ modules available
  DAQ_STATIC_MODULE_LIBS - the set of additional libraries required by the available static DAQ modules
#]=======================================================================]

find_package(PkgConfig)
pkg_check_modules(PC_DAQ libdaq>=3.0.5)

# Use DAQ_INCLUDE_DIR_HINT and DAQ_LIBRARIES_DIR_HINT from configure_cmake.sh as primary hints
# and then package config information after that.
find_path(DAQ_INCLUDE_DIR
    NAMES daq.h
    HINTS ${DAQ_INCLUDE_DIR_HINT} ${PC_DAQ_INCLUDEDIR} ${PC_DAQ_INCLUDE_DIRS}
    NO_SYSTEM_ENVIRONMENT_PATH
)
find_library(DAQ_LIBRARIES
    NAMES daq
    HINTS ${DAQ_LIBRARIES_DIR_HINT} ${PC_DAQ_LIBDIR} ${PC_DAQ_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DAQ
    REQUIRED_VARS DAQ_LIBRARIES DAQ_INCLUDE_DIR
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)

mark_as_advanced(
    DAQ_INCLUDE_DIR
    DAQ_LIBRARIES
)

if (PKG_CONFIG_EXECUTABLE AND ENABLE_STATIC_DAQ)
    execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} --list-all
                    OUTPUT_VARIABLE _pkgconfig_list_result
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REGEX MATCHALL "libdaq_static_[^ ]+" AVAILABLE_STATIC_MODULES ${_pkgconfig_list_result})
    list(REMOVE_DUPLICATES AVAILABLE_STATIC_MODULES)
    foreach (STATIC_MODULE IN LISTS AVAILABLE_STATIC_MODULES)
        string(REGEX REPLACE "^libdaq_static_" "" MODULE_NAME ${STATIC_MODULE})
        list(APPEND DAQ_STATIC_MODULES ${MODULE_NAME})
        pkg_check_modules(PC_${STATIC_MODULE} ${STATIC_MODULE})
        foreach (STATIC_MODULE_LIBNAME IN LISTS PC_${STATIC_MODULE}_LIBRARIES)
            find_library(STATIC_MODULE_LIB
                NAMES ${STATIC_MODULE_LIBNAME}
                HINTS ${PC_${STATIC_MODULE}_LIBRARY_DIRS})
            if (STATIC_MODULE_LIB)
                list(APPEND DAQ_STATIC_MODULE_LIBS ${STATIC_MODULE_LIB})
                unset(STATIC_MODULE_LIB CACHE)
            endif()
        endforeach()
    endforeach()
    if (DAQ_STATIC_MODULE_LIBS)
        list(REMOVE_DUPLICATES DAQ_STATIC_MODULE_LIBS)
        set(DAQ_STATIC_MODULE_LIBS ${DAQ_STATIC_MODULE_LIBS} CACHE INTERNAL "Static DAQ module libraries")
    endif()
    if (DAQ_STATIC_MODULES)
        list(SORT DAQ_STATIC_MODULES)
        set(DAQ_STATIC_MODULES ${DAQ_STATIC_MODULES} CACHE INTERNAL "Static DAQ modules")
    endif()
endif()
