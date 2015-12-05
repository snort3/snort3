
# keeping track of external libraries seperately for use in pkg-config.
set(EXTERNAL_LIBRARIES
    ${DAQ_LIBRARIES}
    ${DNET_LIBRARIES}
    ${CLANG_CXX_LIBRARY}
    ${CMAKE_DL_LIBS}
    ${CMAKE_THREAD_LIBS_INIT} # GCC says we must link to the threads library
    ${LIBLZMA_LIBRARIES}
    ${LUAJIT_LIBRARIES}
    ${OPENSSL_LIBRARIES}
#    ${OPENSSL_CRYPTO_LIBRARY}  -- part of OPENSSL_LIBRARIES
    ${PCAP_LIBRARIES}
    ${PCRE_LIBRARIES}
    ${ZLIB_LIBRARIES}
    CACHE INTERNAL "external libraries" FORCE
)

set(EXTERNAL_INCLUDES
    ${DAQ_INCLUDE_DIR}
    ${DNET_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${PCAP_INCLUDE_DIR}
    ${PCRE_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIRS}
    CACHE INTERNAL "external INCLUDES" FORCE
)

if ( HS_FOUND )
    LIST(APPEND EXTERNAL_LIBRARIES ${HS_LIBRARIES})
    LIST(APPEND EXTERNAL_INCLUDES ${HS_INCLUDE_DIRS})
endif ()

include_directories(BEFORE ${LUAJIT_INCLUDE_DIR})
include_directories(AFTER ${EXTERNAL_INCLUDES})

# prepending all of these to ensure they are included before External Libs
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(BEFORE network_inspectors)

# Build options for specific libraries
# FIXIT is this needed?  see also
# STATIC_INSECTOR_LIBS in service_inspectors/CMakeLists.txt
if (STATIC_INSPECTORS)
    set (STATIC_INSPECTOR_LIBRARIES
        arp_spoof
        back_orifice
        dns
        ftp_telnet
        nhttp_inspect
        rpc_decode
        sip
        ssh
        wizard
    )
endif()


if (STATIC_CODECS)
    set (STATIC_CODEC_LIBRARIES
        link_codecs
        root_codecs
    )
endif()

if (BUILD_UNIT_TESTS)
    set( UNIT_TESTS_LIBRARIES catch_tests)
    add_subdirectory(catch)
endif (BUILD_UNIT_TESTS)

if (BUILD_PIGLET)
    set(PIGLET_LIBRARIES piglet piglet_plugins)
    add_subdirectory(piglet)
    add_subdirectory(piglet_plugins)
endif (BUILD_PIGLET)

if (ENABLE_PPM)
    set(PPM_LIBRARIES ppm)
    add_subdirectory(ppm)
endif (ENABLE_PPM)

#  The main Snort executableRA
add_executable( snort
    main.h
    main.cc
)

# order libs to avoid undefined symbols
# from gnu linker
target_link_libraries( snort
    ${UNIT_TESTS_LIBRARIES}
    managers
    loggers
    codecs
    ip_codecs
    misc_codecs
    ${STATIC_CODEC_LIBRARIES}
    network_inspectors
    service_inspectors
    ${STATIC_INSPECTOR_LIBRARIES}
    port_scan
    stream
    stream_base
    stream_ip
    stream_icmp
    stream_tcp
    stream_libtcp
    stream_udp
    stream_user
    stream_file
    file_api
    mime
    http_inspect
    imap
    pop
    smtp
    ssl
    ${PIGLET_LIBRARIES}
    ips_options
    search_engines
    target_based
    main
    parser
    flow
    control
    filter
    detection
    framework
    time
    ${PPM_LIBRARIES}
    profiler
    ips_actions
    events
    hash
    log
    packet_io
    helpers
    lua
    decompress
    sfip
    sfrt
    protocols
    ports
    utils
    ${EXTERNAL_LIBRARIES}
)

add_subdirectory(actions)
add_subdirectory(codecs)
add_subdirectory(control)
add_subdirectory(detection)
add_subdirectory(events)
add_subdirectory(file_api)
add_subdirectory(filters)
add_subdirectory(flow)
add_subdirectory(framework)
add_subdirectory(hash)
add_subdirectory(log)
add_subdirectory(main)
add_subdirectory(managers)
add_subdirectory(mime)
add_subdirectory(packet_io)
add_subdirectory(parser)
add_subdirectory(ports)
add_subdirectory(protocols)
add_subdirectory(sfip)
add_subdirectory(sfrt)
add_subdirectory(service_inspectors)
add_subdirectory(stream)
add_subdirectory(target_based)
add_subdirectory(time)
add_subdirectory(profiler)
add_subdirectory(utils)
add_subdirectory(helpers)
add_subdirectory(lua)
add_subdirectory(decompress)
add_subdirectory(ips_options)
add_subdirectory(loggers)
add_subdirectory(network_inspectors)
add_subdirectory(search_engines)


#  setting export properties
set_property(TARGET snort APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES
    ${LUAJIT_INCLUDE_DIR}
    ${EXTERNAL_INCLUDES}
    # The installed path '${INCLUDE_INSTALL_PATH}'' is added below with 'install (... snort ...)'
)

set_property(TARGET snort APPEND PROPERTY INTERFACE_COMPILE_OPTIONS "${CMAKE_CXX_FLAGS}")


install (TARGETS snort
    EXPORT snortexe
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION "${INCLUDE_INSTALL_PATH}"
)

install (EXPORT snortexe
    DESTINATION lib/snort
    FILE snort.cmake
)
