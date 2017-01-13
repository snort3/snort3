#
#
#  Library containing all of the information regarding specific platforms, and their specific libraries.
# 


# APPLE is defined by Cmake
if (APPLE)
    set(CMAKE_MACOSX_RPATH OFF)
endif()

set (CMAKE_SKIP_RPATH ON)


if(${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS "4.8")
        message(FATAL_ERROR "G++ version 4.8 or greater required")
    endif()
endif()


# the Clang compiler on MacOS X may need the c++ library explicityly specified
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")

        find_library(CLANG_CXX_LIBRARY 
            NAMES c++
        )
    endif()
endif()


include(CheckCXXCompilerFlag)

set (CMAKE_REQUIRED_FLAGS "-fvisibility=hidden")
check_cxx_compiler_flag (${CMAKE_REQUIRED_FLAGS} HAVE_VISIBILITY)
if (HAVE_VISIBILITY)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_REQUIRED_FLAGS}")
endif ()
unset(CMAKE_REQUIRED_FLAGS)
