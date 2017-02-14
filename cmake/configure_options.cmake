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
set ( USE_TSC_CLOCK ${ENABLE_TSC_CLOCK} )

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

# security

if ( ENABLE_HARDENED_BUILD )

    check_cxx_compiler_flag ( "-Wdate-time" HAS_WDATE_TIME_CPPFLAG )
    if ( HAS_WDATE_TIME_CPPFLAG )
        set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wdate-time" )
    endif ()

    check_cxx_compiler_flag ( "-D_FORTIFY_SOURCE=2" HAS_FORTIFY_SOURCE_2_CPPFLAG )
    if ( HAS_FORTIFY_SOURCE_2_CPPFLAG )
        set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_FORTIFY_SOURCE=2" )
    endif ()

    check_cxx_compiler_flag ( "-fstack-protector-strong" HAS_FSTACK_PROTECTOR_STRONG_CXXFLAG )
    if ( HAS_FSTACK_PROTECTOR_STRONG_CXXFLAG )
        set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong" )
    endif ()

    check_cxx_compiler_flag ( "-Wformat" HAS_WFORMAT_CXXFLAG )
    if ( HAS_WFORMAT_CXXFLAG )
        set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wformat" )
    endif ()

    check_cxx_compiler_flag ( "-Werror=format-security" HAS_WERROR_FORMAT_SECURITY_CXXFLAG )
    if ( HAS_WERROR_FORMAT_SECURITY_CXXFLAG )
        set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror=format-security" )
    endif ()

    set ( CMAKE_REQUIRED_FLAGS "-Wl,-z,relro" )
    check_cxx_compiler_flag ( "" HAS_ZRELRO_LDFLAG )
    if ( HAS_ZRELRO_LDFLAG )
        set ( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro" )
        set ( CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -Wl,-z,relro" )
    endif ()
    unset ( CMAKE_REQUIRED_FLAGS )

    set ( CMAKE_REQUIRED_FLAGS "-Wl,-z,now" )
    check_cxx_compiler_flag ( "-Wl,-z,now" HAS_ZNOW_LDFLAG )
    if ( HAS_ZNOW_LDFLAG )
        set ( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,now" )
        set ( CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -Wl,-z,now" )
    endif ()
    unset ( CMAKE_REQUIRED_FLAGS )

endif ( ENABLE_HARDENED_BUILD )

if ( ENABLE_PIE )
    check_cxx_compiler_flag ( "-fPIE -pie" HAS_PIE_SUPPORT )
    if ( HAS_PIE_SUPPORT )
        set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE" )
        set ( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fPIE -pie" )
        set ( CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -fPIE -pie" )
    endif ()
endif ( ENABLE_PIE )

if ( ENABLE_SAFEC )
    set(ENABLE_SAFEC "1")
endif ( ENABLE_SAFEC )

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
    set ( SANITIZER_FLAGS "-fsanitize=address -fno-omit-frame-pointer" )

    set ( CMAKE_REQUIRED_FLAGS "${SANITIZER_LDFLAGS} -fsanitize=address" )
    check_cxx_compiler_flag ( "${SANITIZER_FLAGS}" HAS_SANITIZE_ADDRESS_LDFLAG )
    if ( HAS_SANITIZE_ADDRESS_LDFLAG )
        set ( SANITIZER_LDFLAGS "${SANITIZER_LDFLAGS} -fsanitize=address" )
    endif ()
    unset ( CMAKE_REQUIRED_FLAGS )

    set ( CMAKE_REQUIRED_FLAGS "${SANITIZER_LDFLAGS} -static-libasan" )
    check_cxx_compiler_flag ( "${SANITIZER_FLAGS}" HAS_STATIC_LIBASAN_LDFLAG )
    if ( HAS_STATIC_LIBASAN_LDFLAG )
        set ( SANITIZER_LDFLAGS "${SANITIZER_LDFLAGS} -static-libasan" )
    endif ()
    unset ( CMAKE_REQUIRED_FLAGS )
endif ( ENABLE_ADDRESS_SANITIZER )

if ( ENABLE_THREAD_SANITIZER )
    set ( SANITIZER_CXXFLAGS "-fsanitize=thread -fno-omit-frame-pointer" )

    set ( CMAKE_REQUIRED_FLAGS "${SANITIZER_LDFLAGS} -fsanitize=thread" )
    check_cxx_compiler_flag ( "${SANITIZER_CXXFLAGS}" HAS_SANITIZE_THREAD_LDFLAG )
    if ( HAS_SANITIZE_THREAD_LDFLAG )
        set ( SANITIZER_LDFLAGS "${SANITIZER_LDFLAGS} -fsanitize=thread" )
    endif ()
    unset ( CMAKE_REQUIRED_FLAGS )

    set ( CMAKE_REQUIRED_FLAGS "${SANITIZER_LDFLAGS} -static-libtsan" )
    check_cxx_compiler_flag ( "${SANITIZER_CXXFLAGS}" HAS_STATIC_LIBTSAN_LDFLAG )
    if ( HAS_STATIC_LIBTSAN_LDFLAG )
        set ( SANITIZER_LDFLAGS "${SANITIZER_LDFLAGS} -static-libtsan" )
    endif ()
    unset ( CMAKE_REQUIRED_FLAGS )
endif ( ENABLE_THREAD_SANITIZER )

if ( ENABLE_CODE_COVERAGE )
    set ( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g -fprofile-arcs -ftest-coverage" )
    set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g -fprofile-arcs -ftest-coverage" )

    if ( "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" )
        set ( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lgcov" )
    endif ()
endif ( ENABLE_CODE_COVERAGE )

