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
#  PCAP_INCLUDE_DIR          The libpcap include directories.
#  PCAP_LIBRARIES            The libpcap library


set(ERROR_MESSAGE
    "
    ERROR!  Libpcap library/headers (libpcap.a (or .so)/pcap.h)
    not found, go get it from http://www.tcpdump.org
    or use the --with-pcap-* options, if you have it installed
    in unusual place.  Also check if your libpcap depends on another
    shared library that may be installed in an unusual place"
)



find_path(PCAP_INCLUDE_DIR
    NAMES pcap.h
)

# call find_library twice. First search custom path, then search standard paths
find_library(PCAP_LIBRARIES 
    NAMES pcap
    HINTS ${PCAP_LIBRARIES_DIR} # user specified option in ./configure_cmake.sh
    NO_DEFAULT_PATH
    NO_CMAKE_ENVIRONMENT_PATH
)
find_library(PCAP_LIBRARIES 
    NAMES pcap
)


#  foo to ensure PCAP compiles

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP
    REQUIRED_VARS PCAP_LIBRARIES PCAP_INCLUDE_DIR
    FAIL_MESSAGE ${ERROR_MESSAGE}
)


include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARIES})
check_c_source_compiles("int main() { return 0; }" PCAP_LINKS_SOLO)
set(CMAKE_REQUIRED_LIBRARIES)


# check if linking against libpcap also needs to link against a thread and/or SFBPF library
if (NOT PCAP_LINKS_SOLO)
    find_package(Threads)
    if (THREADS_FOUND)
        set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
        check_c_source_compiles("int main() { return 0; }" PCAP_NEEDS_THREADS_ONLY)
        if (PCAP_NEEDS_THREADS_ONLY)
            set(PCAP_EXTRA_LIBS ${CMAKE_THREAD_LIBS_INIT})
        endif ()
        set(CMAKE_REQUIRED_LIBRARIES)
    endif ()

    find_package(SFBPF)
    if (NOT PCAP_NEEDS_THREADS AND SFBPF_FOUND)
        set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARIES} ${SFBPF_LIBRARIES})
        check_c_source_compiles("int main() { return 0; }" PCAP_NEEDS_SFBPF_ONLY)
        if (PCAP_NEEDS_SFBPF_ONLY)
            set(PCAP_EXTRA_LIBS ${SFBPF_LIBRARIES})
        endif ()
        set(CMAKE_REQUIRED_LIBRARIES)
    endif ()

    if (NOT (PCAP_NEEDS_THREADS_ONLY OR PCAP_NEEDS_SFBPF_ONLY) AND THREADS_FOUND AND SFBPF_FOUND)
        set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARIES} ${SFBPF_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
        check_c_source_compiles("int main() { return 0; }" PCAP_NEEDS_SFBPF_AND_THREADS)
        if (PCAP_NEEDS_SFBPF_AND_THREADS)
            set(PCAP_EXTRA_LIBS ${SFBPF_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
        endif ()
    endif ()

    if (PCAP_EXTRA_LIBS)
        set(_tmp ${PCAP_LIBRARIES} ${PCAP_EXTRA_LIBS})
        list(REMOVE_DUPLICATES _tmp)
        set(PCAP_LIBRARIES ${_tmp}
            CACHE STRING "Libraries needed to link against libpcap" FORCE)
    else ()
        message(SEND_ERROR "Couldn't determine how to link against libpcap")
    endif ()
endif ()

mark_as_advanced(
    PCAP_INCLUDE_DIR
    PCAP_LIBRARIES
)
unset(PCAP_CONFIG CACHE)
