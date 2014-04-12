#  Taken from 
#  some code https://github.com/bro/cmake/blob/master/FindPCAP.cmake
#
#
# - Try to find libpcap include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(PCAP)
#
# Variables defined by this module:
#
#  PCAP_FOUND                System has libpcap, include and library dirs found
#  PCAP_INCLUDE_DIRS          The libpcap include directories.
#  PCAP_LIBRARIES            The libpcap library (possibly includes a thread
#                            library e.g. required by pf_ring's libpcap)
#  HAVE_LIBPFRING              If a found version of libpcap supports PF_RING


set(ERROR_MESSAGE
    "
    ERROR!  Libpcap library/headers (libpcap.a (or .so)/pcap.h)
    not found, go get it from http://www.tcpdump.org
    or use the --with-pcap-* options, if you have it installed
    in unusual place.  Also check if your libpcap depends on another
    shared library that may be installed in an unusual place"
)

find_program(PCAP_CONFIG 
    NAMES pcap-config
    HINTS ENV PCAP_DIR
)

if(NOT PCAP_INCLUDE_DIRS)
    if (PCAP_CONFIG)
        EXECUTE_PROCESS(COMMAND ${PCAP_CONFIG} --cflags
            OUTPUT_VARIABLE PCAP_INCLUDE_DIRS
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )

    else()   
        find_path(PCAP_INCLUDE_DIRS
            NAMES pcap.h
        )

    endif()
endif()


if(NOT PCAP_LIBRARIES)
    if (PCAP_CONFIG)
        EXECUTE_PROCESS(
            COMMAND pcap-config --libs
            RESULT_VARIABLE exit_code
            OUTPUT_VARIABLE PCAP_LIBRARIES
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )

    else()

        find_library(PCAP_LIBRARIES 
            NAMES pcap
        )
    endif()


    set (PCAP_LIBRARIES "${PCAP_LIBRARIES}" CACHE PATH "libpcap library directory")
endif()


#  foo to ensure PCAP compiles

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP
    REQUIRED_VARS PCAP_LIBRARIES PCAP_INCLUDE_DIRS
    FAIL_MESSAGE ${ERROR_MESSAGE}
)


include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARIES})
check_c_source_compiles("int main() { return 0; }" PCAP_LINKS_SOLO)
set(CMAKE_REQUIRED_LIBRARIES)


# check if linking against libpcap also needs to link against a thread library
if (NOT PCAP_LINKS_SOLO)
    find_package(Threads)
    if (THREADS_FOUND)
        set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
        check_c_source_compiles("int main() { return 0; }" PCAP_NEEDS_THREADS)
        set(CMAKE_REQUIRED_LIBRARIES)
    endif ()
    if (THREADS_FOUND AND PCAP_NEEDS_THREADS)
        set(_tmp ${PCAP_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
        list(REMOVE_DUPLICATES _tmp)
        set(PCAP_LIBRARIES ${_tmp}
            CACHE STRING "Libraries needed to link against libpcap" FORCE)
    else ()
        message(FATAL_ERROR "Couldn't determine how to link against libpcap")
    endif ()
endif ()

include(CheckFunctionExists)
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARIES})
check_function_exists(pcap_get_pfring_id HAVE_LIBPFRING)
set(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(
    PCAP_INCLUDE_DIRS
    PCAP_LIBRARIES
)
unset(PCAP_CONFIG CACHE)
