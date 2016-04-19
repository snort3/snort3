# creating pkg-config module.  these will all be substituted into snort.pc

unset ( CPPDEFS )

# some ugly hacks to tease out defines that snort headers depend on.
# these need to match in order to build dynamic snort plugins using pkgconfig
# FIXIT-H J we need a better system to manage these exported defines. In the meantime,
# any definitions that are depended on by installed snort headers need to end up in CPPDEFS

get_directory_property( TMP_DEFS DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} COMPILE_DEFINITIONS)

if ( WORDS_MUSTALIGN )
    list ( APPEND TMP_DEFS "WORDS_MUSTALIGN" )
endif ()

if ( BUILD_PIGLET )
    list ( APPEND TMP_DEFS "PIGLET" )
endif ()

if ( BUILD_SHELL )
    list ( APPEND TMP_DEFS "BUILD_SHELL" )
endif ()

if ( NOT ENABLE_COREFILES )
    list ( APPEND TMP_DEFS "NOCOREFILE" )
endif ()

if ( BUILD_UNIT_TESTS )
    list ( APPEND TMP_DEFS "UNIT_TEST" )
endif ()

if ( HAVE_LZMA )
    list ( APPEND TMP_DEFS "HAVE_LZMA" )
endif ()

# attach -D to each define
foreach ( def ${TMP_DEFS} )
    if ( NOT ${def} MATCHES "HAVE_CONFIG_H" )
        if ( NOT ${def} MATCHES "restrict" )
            set ( CPPDEFS "${CPPDEFS} -D${def}" )
        endif ()
    endif ()
endforeach  ( def )

# set pkgconfig vars

set(prefix "${CMAKE_INSTALL_PREFIX}")
set(exec_prefix "\${prefix}")
set(bindir "\${exec_prefix}/bin")
set(libdir "\${exec_prefix}/snort")
set(includedir "\${prefix}/include")
set(datarootdir "\${prefix}/share")
set(datadir "\${datarootdir}")
set(mandir "\${datarootdir}/info")
set(infodir "\${datarootdir}/info")

# create & install pkgconfig file

configure_file(
    "${CMAKE_SOURCE_DIR}/snort.pc.in"
    "${CMAKE_BINARY_DIR}/snort.pc"
    @ONLY
)

install (FILES ${CMAKE_BINARY_DIR}/snort.pc
    DESTINATION "lib/pkgconfig/"
)
