
# keeping track of external libraries seperately for use in pkg-config.
set(EXTERNAL_LIBRARIES
    ${DAQ_LIBRARIES}
    ${DNET_LIBRARIES}
    ${CLANG_CXX_LIBRARY}
    ${CMAKE_DL_LIBS}
    ${CMAKE_THREAD_LIBS_INIT} # GCC says we must link to the threads library
    ${HWLOC_LIBRARIES}
    ${LIBLZMA_LIBRARIES}
    ${LUAJIT_LIBRARIES}
    ${OPENSSL_CRYPTO_LIBRARY}
    ${PCAP_LIBRARIES}
    ${PCRE_LIBRARIES}
    ${SAFEC_LIBRARIES}
    ${SFBPF_LIBRARIES}
    ${ZLIB_LIBRARIES}
)

set(EXTERNAL_INCLUDES
    ${DAQ_INCLUDE_DIR}
    ${DNET_INCLUDE_DIR}
    ${HWLOC_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${PCAP_INCLUDE_DIR}
    ${PCRE_INCLUDE_DIR}
    ${SAFEC_INCLUDE_DIR}
    ${SFBPF_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIRS}
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

if (STATIC_CODECS)
    set (STATIC_CODEC_LIBRARIES
        link_codecs
        root_codecs
    )
endif()

if (ENABLE_UNIT_TESTS)
    enable_testing()
    set( UNIT_TESTS_LIBRARIES catch_tests)
    add_subdirectory(catch)
endif (ENABLE_UNIT_TESTS)

if ( ENABLE_PIGLET )
    set ( PIGLET_LIBRARIES piglet piglet_plugins )
    add_subdirectory ( piglet )
    add_subdirectory ( piglet_plugins )
endif ( ENABLE_PIGLET )

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
    main
    codecs
    loggers
    ip_codecs
    misc_codecs
    ${STATIC_CODEC_LIBRARIES}
    network_inspectors
    service_inspectors
# include only those with otherwise unresolved dependencies
    appid
    http_inspect
    sip
    reputation
    stream
    stream_base
    stream_ip
    stream_icmp
    stream_tcp
    stream_libtcp
    stream_udp
    stream_user
    stream_file
    stream_paf
    mime
    ips_options
    search_engines
    target_based
    ${PIGLET_LIBRARIES}
    codec_module
    memory
    host_tracker
    pub_sub
    parser
    flow
    side_channel
    connectors
    file_connector
    control
    filter
    detection
    framework
    file_api
    latency
    profiler
    time
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
add_subdirectory(latency)
add_subdirectory(log)
add_subdirectory(main)
add_subdirectory(managers)
add_subdirectory(memory)
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
add_subdirectory(host_tracker)
add_subdirectory(pub_sub)
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
add_subdirectory(side_channel)
add_subdirectory(connectors)


#  setting export properties
set_property(TARGET snort APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES
    ${LUAJIT_INCLUDE_DIR}
    ${EXTERNAL_INCLUDES}
    # The installed path '${INCLUDE_INSTALL_PATH}'' is added below with 'install (... snort ...)'
)

set_property(TARGET snort APPEND PROPERTY INTERFACE_COMPILE_OPTIONS "${CMAKE_CXX_FLAGS}")

set_target_properties(
    snort
    PROPERTIES
        LINK_FLAGS "${SANITIZER_LDFLAGS}"
)

install (TARGETS snort
    EXPORT snortexe
    RUNTIME DESTINATION bin
)

install (EXPORT snortexe
    DESTINATION lib/snort
    FILE snort.cmake
)
