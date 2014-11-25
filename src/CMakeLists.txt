
# keeping track of external libraries seperately for use in pkg-config.
set(EXTERNAL_LIBRARIES
    ${LUAJIT_LIBRARIES}
    ${PCRE_LIBRARIES}
    ${PCAP_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${ZLIB_LIBRARIES}
#    ${OPENSSL_CRYPTO_LIBRARY}  -- part of OPENSSL_LIBRARIES
    ${DAQ_LIBRARIES}
    ${DNET_LIBRARIES}
    ${CLANG_CXX_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT} # GCC says we must link to the threads library
    ${CMAKE_DL_LIBS}
    CACHE INTERNAL "external libraries" FORCE
)

set(EXTERNAL_INCLUDES
    ${DAQ_INCLUDE_DIR}
    ${PCAP_INCLUDE_DIR}
    ${PCRE_INCLUDE_DIR}
    ${DNET_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIRS}
    CACHE INTERNAL "external INCLUDES" FORCE
)
include_directories(BEFORE ${LUAJIT_INCLUDE_DIR})
include_directories(AFTER ${EXTERNAL_INCLUDES})

# prepending all of these to ensure they are included before External Libs
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(BEFORE detection)
include_directories(BEFORE events)
include_directories(BEFORE framework)
include_directories(BEFORE hash)
include_directories(BEFORE log)
include_directories(BEFORE loggers)
include_directories(BEFORE main)
include_directories(BEFORE network_inspectors)
include_directories(BEFORE parser)
include_directories(BEFORE protocols)
include_directories(BEFORE sfip)
include_directories(BEFORE stream)
include_directories(BEFORE target_based)
include_directories(BEFORE time)
include_directories(BEFORE utils)



# Build options for specific librries
if (STATIC_INSPECTORS)
    set (STATIC_INSPECTOR_LIBRARIES
        arp_spoof
        back_orifice
        ftp_telnet
        nhttp_inspect
        rpc_decode
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
    set( UNIT_TESTS_LIBRARIES unit_tests)
    add_subdirectory(test)
endif (BUILD_UNIT_TESTS)


#  The main Snort executableRA
add_executable( snort
    main.h
    main.cc
)

target_link_libraries( snort
    main
    target_based
    log
    protocols
    framework
    normalize
    perf_monitor
    stream
    stream_base
    stream_ip
    stream_icmp
    stream_tcp
    stream_udp
    http_inspect
    flow
    parser
    file_api
    file
    control
    filter
    detection
    packet_io
    time
    events
    sfrt
    sfip
    hash
    utils
    network_inspectors
    search_engines
    helpers
    ips_options
    loggers
    service_inspectors
    stream
    ips_actions
    port_scan
    managers
    codecs
    ip_codecs
    misc_codecs
    ${STATIC_CODEC_LIBRARIES}
    ${STATIC_INSPECTOR_LIBRARIES}
    ${UNIT_TESTS_LIBRARIES}
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
add_subdirectory(packet_io)
add_subdirectory(parser)
add_subdirectory(protocols)
add_subdirectory(sfip)
add_subdirectory(sfrt)
add_subdirectory(service_inspectors)
add_subdirectory(stream)
add_subdirectory(target_based)
add_subdirectory(time)
add_subdirectory(utils)
add_subdirectory(helpers)
add_subdirectory(ips_options)
add_subdirectory(loggers)
add_subdirectory(network_inspectors)
add_subdirectory(search_engines)


install (TARGETS snort
    EXPORT snortexe
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION "${INCLUDE_INSTALL_PATH}"
)

install (EXPORT snortexe
    DESTINATION lib/snort
    FILE snort.cmake
)
