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

if(DISABLE_MEMORY_MANAGER)
    set(NO_MEM_MGR_CPPFLAGS "-DNO_MEM_MGR")
endif()

if(DISABLE_SNORT_PROFILER)
    set(NO_PROFILER_CPPFLAGS "-DNO_PROFILER")
endif()

if(DNET_INCLUDE_DIR)
    set(DNET_CPPFLAGS "-I${DNET_INCLUDE_DIR}")
endif()

if(ENABLE_APPID_THIRD_PARTY)
    set(TP_APPID_CPPFLAGS "-DENABLE_APPID_THIRD_PARTY")
endif()

if(ENABLE_DEEP_PROFILING)
    set(DEEP_PROFILING_CPPFLAGS "-DDEEP_PROFILING")
endif()

if(ENABLE_TSC_CLOCK)
    set(TSC_CPPFLAGS "-DUSE_TSC_CLOCK")
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
