# creating pkg-config module.  these will all be substituted into snort.pc

# set pkgconfig vars

set(prefix "${CMAKE_INSTALL_PREFIX}")
set(exec_prefix "\${prefix}")
set(bindir "\${exec_prefix}/bin")
set(libdir "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
set(includedir "\${prefix}/include")
set(datarootdir "\${prefix}/share")
set(datadir "\${datarootdir}")
set(mandir "\${datarootdir}/man")
set(infodir "\${datarootdir}/info")

if(DAQ_INCLUDE_DIR)
    set(DAQ_CPPFLAGS "-I${DAQ_INCLUDE_DIR}")
endif()

if(DNET_INCLUDE_DIR)
    set(DNET_CPPFLAGS "-I${DNET_INCLUDE_DIR}")
endif()

if(FLATBUFFERS_INCLUDE_DIR)
    set(FLATBUFFERS_CPPFLAGS "-I${FLATBUFFERS_INCLUDE_DIR}")
endif()

if(HS_INCLUDE_DIR)
    set(HYPERSCAN_CPPFLAGS "-I${HS_INCLUDE_DIR}")
endif()

if(HWLOC_INCLUDE_DIR)
    set(HWLOC_CPPFLAGS "-I${HWLOC_INCLUDE_DIR}")
endif()

if(ICONV_INCLUDE_DIR)
    set(ICONV_CPPFLAGS "-I${ICONV_INCLUDE_DIR}")
endif()

if(LUAJIT_INCLUDE_DIR)
    set(LUAJIT_CPPFLAGS "-I${LUAJIT_INCLUDE_DIR}")
endif()

if(LZMA_INCLUDE_DIR)
    set(LZMA_CPPFLAGS "-I${LZMA_INCLUDE_DIR}")
endif()

if(OPENSSL_INCLUDE_DIR)
    set(OPENSSL_CPPFLAGS "-I${OPENSSL_INCLUDE_DIR}")
endif()

if(PCAP_INCLUDE_DIR)
    set(PCAP_CPPFLAGS "-I${PCAP_INCLUDE_DIR}")
endif()

if(PCRE_INCLUDE_DIR)
    set(PCRE_CPPFLAGS "-I${PCRE_INCLUDE_DIR}")
endif()

if(UUID_INCLUDE_DIR)
    set(UUID_CPPFLAGS "-I${UUID_INCLUDE_DIR}")
endif()

# create & install pkgconfig file

configure_file(
    "${CMAKE_SOURCE_DIR}/snort.pc.in"
    "${CMAKE_BINARY_DIR}/snort.pc"
    @ONLY
)

install (FILES ${CMAKE_BINARY_DIR}/snort.pc
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig/"
)
