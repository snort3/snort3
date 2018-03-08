#
#
#  Library containing all of the information regarding specific platforms, and their specific libraries.
# 


# APPLE is defined by Cmake
if (APPLE)
    set(CMAKE_MACOSX_RPATH OFF)
endif()

set (CMAKE_SKIP_RPATH ON)

if (${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
    set(GNUCXX_MINVER "4.8.1")
    message(STATUS "g++ version ${CMAKE_CXX_COMPILER_VERSION}")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS GNUCXX_MINVER)
        message(FATAL_ERROR "A minimum of g++ ${GNUCXX_MINVER} is required for C++11 support")
    endif()
endif()


# the Clang compiler on MacOS X may need the c++ library explicitly specified
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")

        find_library(CLANG_CXX_LIBRARY 
            NAMES c++
        )
    endif()
endif()

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

CHECK_C_COMPILER_FLAG(-fvisibility=hidden HAS_C_HIDDEN)
if (HAS_C_HIDDEN)
    set(EXTRA_C_FLAGS "${EXTRA_C_FLAGS} -fvisibility=hidden")
    set(HAVE_VISIBILITY 1)
endif()

CHECK_CXX_COMPILER_FLAG(-fvisibility=hidden HAS_CXX_HIDDEN)
if (HAS_CXX_HIDDEN)
    set(EXTRA_CXX_FLAGS "${EXTRA_CXX_FLAGS} -fvisibility=hidden")
    set(HAVE_VISIBILITY 1)
endif()

