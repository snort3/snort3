cmake_minimum_required ( VERSION 2.8.11 )
project( snort_extra CXX C )

set (EXTRA_VERSION_MAJOR 1)
set (EXTRA_VERSION_MINOR 0)
set (EXTRA_VERSION_BUILD 0-a4)

set (AUTOTOOL_FILES "autom4te.cache;m4;configure.ac;Makefile.am")

set (CPACK_GENERATOR TGZ)
set (CPACK_PACKAGE_NAME "snort_extra")
set (CPACK_PACKAGE_VENDOR "Cisco")
set (CPACK_PACKAGE_VERSION_MAJOR "${EXTRA_VERSION_MAJOR}")
set (CPACK_PACKAGE_VERSION_MINOR "${EXTRA_VERSION_MINOR}")
set (CPACK_PACKAGE_VERSION_PATCH "${EXTRA_VERSION_BUILD}")
set (CPACK_PACKAGE_ICON "${CMAKE_SOURCE_DIR}/doc/images/snort.png")
set (CPACK_PACKAGE_INSTALL_DIRECTORY "snort")
set (CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set (CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README")
set (CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
set (CPACK_SOURCE_IGNORE_FILES "${AUTOTOOL_FILES}")
set (CPACK_SOURCE_GENERATOR TGZ)

include(CPack)

set ( C_FLAGS "" CACHE STRING "" )
set ( CXX_FLAGS "" CACHE STRING "" )

set ( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS}" CACHE STRING "" FORCE )
set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_FLAGS}" CACHE STRING "" FORCE )

execute_process (
    COMMAND pkg-config --variable=cpp_opts snort
    OUTPUT_VARIABLE CPP_OPTS
)
string ( REGEX REPLACE "[\r\n]" " " CPP_OPTS "${CPP_OPTS}" )
separate_arguments ( CPP_OPTS )

foreach ( OPT ${CPP_OPTS} )
    execute_process (
        COMMAND pkg-config --variable=${OPT}_CPPFLAGS snort
        OUTPUT_VARIABLE CPPFLAGS
    )

    string ( REGEX REPLACE "[\r\n]" " " CPPFLAGS "${CPPFLAGS}" )
    set ( ${OPT}_CPPFLAGS "${CPPFLAGS}" CACHE STRING "" )

    set ( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${${OPT}_CPPFLAGS}" CACHE STRING "" FORCE )
    set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${${OPT}_CPPFLAGS}" CACHE STRING "" FORCE )
endforeach ( OPT )

execute_process (
    COMMAND pkg-config --variable=cpp_opts_other snort
    OUTPUT_VARIABLE CPP_OPTS_OTHER
)
string ( REGEX REPLACE "[\r\n]" " " CPP_OPTS_OTHER "${CPP_OPTS_OTHER}" )
separate_arguments ( CPP_OPTS_OTHER )

foreach ( OPT ${CPP_OPTS_OTHER} )
    execute_process (
        COMMAND pkg-config --variable=${OPT}_CPPFLAGS snort
        OUTPUT_VARIABLE CPPFLAGS
    )

    string ( REGEX REPLACE "[\r\n]" " " CPPFLAGS "${CPPFLAGS}" )
    set ( ${OPT}_CPPFLAGS "${CPPFLAGS}" CACHE STRING "" )
endforeach ( OPT )

add_subdirectory ( src )
