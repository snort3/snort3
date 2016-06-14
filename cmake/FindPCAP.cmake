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
        message(SEND_ERROR "Couldn't determine how to link against libpcap")
    endif ()
endif ()

mark_as_advanced(
    PCAP_INCLUDE_DIR
    PCAP_LIBRARIES
)
unset(PCAP_CONFIG CACHE)
