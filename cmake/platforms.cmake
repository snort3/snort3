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
    set(LINUX "YES")
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


include(CheckCXXCompilerFlag)


# the Clang compiler on MacOS X may need the c++ library explicityly specified
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")


    set(CMAKE_REQUIRED_FLAGS "-Wl,-undefined -Wl,dynamic_lookup")
    check_cxx_compiler_flag("" HAVE_DYNAMIC_LOOKUP)
    if(HAVE_DYNAMIC_LOOKUP)
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -undefined dynamic_lookup")
    endif()
    set (CMAKE_REQUIRED_FLAGS "")


    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")

        find_library(CLANG_CXX_LIBRARY 
            NAMES c++
        )
    endif()
endif()

set (CMAKE_REQUIRED_FLAGS "-Wl,-export-dynamic")
check_cxx_compiler_flag ("" HAVE_EXPORT_DYNAMIC)
if (HAVE_EXPORT_DYNAMIC)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -export-dynamic")
endif ()


unset(CMAKE_REQUIRED_FLAGS)
