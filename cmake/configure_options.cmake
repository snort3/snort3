# map cmake options to compiler defines and do miscellaneous further configuration work
# cmake options are defined in cmake/create_options.cmake

# features

set ( SHELL ${ENABLE_SHELL} )
set ( UNIT_TEST ${ENABLE_UNIT_TESTS} )
set ( PIGLET ${ENABLE_PIGLET} )

if ( NOT ENABLE_COREFILES )
    set ( NOCOREFILE ON )
endif ( NOT ENABLE_COREFILES )

set ( _LARGEFILE_SOURCE ${ENABLE_LARGE_PCAP} )

if ( ENABLE_LARGE_PCAP )
    set ( _FILE_OFFSET_BITS 64 )
endif ( ENABLE_LARGE_PCAP )

# documentation

if ( NOT ASCIIDOC_FOUND )
    get_property ( MAKE_HTML_DOC_HELP_STRING CACHE "MAKE_HTML_DOC" PROPERTY HELPSTRING )
    set ( MAKE_HTML_DOC OFF CACHE BOOL ${MAKE_HTML_DOC_HELP_STRING} FORCE )
endif()

if ( NOT (DBLATEX_FOUND AND ASCIIDOC_FOUND) )
    get_property ( MAKE_PDF_DOC_HELP_STRING CACHE "MAKE_PDF_DOC" PROPERTY HELPSTRING )
    set ( MAKE_PDF_DOC OFF CACHE BOOL ${MAKE_PDF_DOC_HELP_STRING} FORCE )
endif()

if ( NOT (W3M_FOUND AND ASCIIDOC_FOUND) )
    get_property ( MAKE_TEXT_DOC_HELP_STRING CACHE "MAKE_TEXT_DOC" PROPERTY HELPSTRING )
    set ( MAKE_TEXT_DOC OFF CACHE BOOL ${MAKE_TEXT_DOC_HELP_STRING} FORCE )
endif()

# debugging

set ( DEBUG_MSGS ${ENABLE_DEBUG_MSGS} )

set ( DEBUG ${ENABLE_DEBUG} )
if ( ENABLE_DEBUG )
    set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g" )
endif ( ENABLE_DEBUG )

if ( ENABLE_GDB )
    set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -ggdb" )
endif ( ENABLE_GDB )

if ( ENABLE_PROFILE AND CMAKE_COMPILER_IS_GNUCXX )
    set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg" )
endif ( ENABLE_PROFILE AND CMAKE_COMPILER_IS_GNUCXX )

if ( ENABLE_ADDRESS_SANITIZER )
    set ( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer" )
    set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer" )
endif ( ENABLE_ADDRESS_SANITIZER )

if ( ENABLE_CODE_COVERAGE )
    set ( CMAKE_CPP_FLAGS "${CMAKE_CPP_FLAGS} -DNDEBUG" )
    set ( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g -fprofile-arcs -ftest-coverage" )
    set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g -fprofile-arcs -ftest-coverage" )

    if ( "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" )
        set ( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lgcov" )
    endif ()
endif ( ENABLE_CODE_COVERAGE )

