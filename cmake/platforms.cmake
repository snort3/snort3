#
#
#  Library containing all of the information regarding specific platforms, and their specific libraries.
# 


# TODO:  Either make a macro or a  of platforms and loop over them.

if (${CMAKE_SYSTEM_NAME} MATCHES "aix")
    set(AIX "1")
endif ()

if (${CMAKE_SYSTEM_NAME} MATCHES "bsdi")
    set(BSDI "1")
endif ()

if (${CMAKE_SYSTEM_NAME} MATCHES "freebsd")
    set(FREEBSD "1")
endif ()

if (${CMAKE_SYSTEM_NAME} MATCHES "hpux")
    set(HPUX "1")
endif ()

if (${CMAKE_SYSTEM_NAME} MATCHES "linux")
    set(LINUX "1")
endif ()

if("${CMAKE_SYSTEM_NAME}" MATCHES "Linux")
    set(LINUX "1")
endif("${CMAKE_SYSTEM_NAME}" MATCHES "Linux")

if (${CMAKE_SYSTEM_NAME} MATCHES "openbsd")
    set(OPENBSD "1")
endif ()

if (${CMAKE_SYSTEM_NAME} MATCHES "osf")
    set(OSF1 "1")
endif ()

if (${CMAKE_SYSTEM_NAME} MATCHES "sgi-irix")
    set(IRIX "1")
endif ()

if (${CMAKE_SYSTEM_NAME} MATCHES "solaris")
    set(SOLARIS "1")
endif ()

if (${CMAKE_SYSTEM_NAME} MATCHES "sunos")
    set(SUNOS "1")
endif ()

if (${CMAKE_SYSTEM_NAME} MATCHES "tru64")
    set(OSF1 "1")
endif ()

# APPLE is defined by Cmake
if (APPLE)
    set(MACOS 1)
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

# More MacOS X fun
set(CMAKE_REQUIRED_FLAGS "-Wl,-undefined,dynamic_lookup")
check_cxx_compiler_flag(${CMAKE_REQUIRED_FLAGS} HAVE_DYNAMIC_LOOKUP)
if(HAVE_DYNAMIC_LOOKUP)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${CMAKE_REQUIRED_FLAGS}")
endif()
unset (CMAKE_REQUIRED_FLAGS)


set (CMAKE_REQUIRED_FLAGS "-Wl,-export-dynamic")
check_cxx_compiler_flag (${CMAKE_REQUIRED_FLAGS} HAVE_EXPORT_DYNAMIC)
if (HAVE_EXPORT_DYNAMIC)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${CMAKE_REQUIRED_FLAGS}")
endif ()
unset(CMAKE_REQUIRED_FLAGS)


set (CMAKE_REQUIRED_FLAGS "-Wl,-shared")
check_cxx_compiler_flag (${CMAKE_REQUIRED_FLAGS} HAVE_SHARED)
if (HAVE_SHARED)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${CMAKE_REQUIRED_FLAGS}")
endif ()
unset(CMAKE_REQUIRED_FLAGS)

set (CMAKE_REQUIRED_FLAGS "-fvisibility=hidden")
check_cxx_compiler_flag (${CMAKE_REQUIRED_FLAGS} HAVE_VISIBILITY)
if (HAVE_VISIBILITY)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_REQUIRED_FLAGS}")
endif ()
unset(CMAKE_REQUIRED_FLAGS)
