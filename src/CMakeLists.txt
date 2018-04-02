
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
    ${UUID_LIBRARY}
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
    ${UUID_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIRS}
)

if ( FLATBUFFERS_FOUND )
    LIST(APPEND EXTERNAL_LIBRARIES ${FLATBUFFERS_LIBRARIES})
endif()

if ( HS_FOUND )
    LIST(APPEND EXTERNAL_LIBRARIES ${HS_LIBRARIES})
    LIST(APPEND EXTERNAL_INCLUDES ${HS_INCLUDE_DIRS})
endif ()

if ( ICONV_FOUND )
    LIST(APPEND EXTERNAL_LIBRARIES ${ICONV_LIBRARY})
    LIST(APPEND EXTERNAL_INCLUDES ${ICONV_INCLUDE_DIR})
endif ()

include_directories(BEFORE ${LUAJIT_INCLUDE_DIR})
include_directories(AFTER ${EXTERNAL_INCLUDES})

# prepending all of these to ensure they are included before External Libs
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(BEFORE network_inspectors)

if (ENABLE_UNIT_TESTS)
    enable_testing()
    set( UNIT_TESTS_LIBRARIES $<TARGET_OBJECTS:catch_tests>)
    add_subdirectory(catch)
endif (ENABLE_UNIT_TESTS)

if ( ENABLE_PIGLET )
    set ( PIGLET_LIBRARIES $<TARGET_OBJECTS:piglet> $<TARGET_OBJECTS:piglet_plugins> )
    add_subdirectory ( piglet )
    add_subdirectory ( piglet_plugins )
endif ( ENABLE_PIGLET )

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


# FIXIT-L Delegate building out the target objects list to subdirectories

#  The main Snort executable
add_executable( snort
    main.h
    main.cc
    $<TARGET_OBJECTS:codecs>
    $<TARGET_OBJECTS:connectors>
    $<TARGET_OBJECTS:control>
    $<TARGET_OBJECTS:decompress>
    $<TARGET_OBJECTS:detection>
    $<TARGET_OBJECTS:events>
    $<TARGET_OBJECTS:file_api>
    $<TARGET_OBJECTS:file_connector>
    $<TARGET_OBJECTS:filter>
    $<TARGET_OBJECTS:flow>
    $<TARGET_OBJECTS:framework>
    $<TARGET_OBJECTS:hash>
    $<TARGET_OBJECTS:helpers>
    $<TARGET_OBJECTS:host_tracker>
    $<TARGET_OBJECTS:ips_actions>
    $<TARGET_OBJECTS:ips_options>
    $<TARGET_OBJECTS:latency>
    $<TARGET_OBJECTS:log>
    $<TARGET_OBJECTS:loggers>
    $<TARGET_OBJECTS:lua>
    $<TARGET_OBJECTS:main>
    $<TARGET_OBJECTS:managers>
    $<TARGET_OBJECTS:memory>
    $<TARGET_OBJECTS:mime>
    $<TARGET_OBJECTS:network_inspectors>
    $<TARGET_OBJECTS:packet_io>
    $<TARGET_OBJECTS:parser>
    $<TARGET_OBJECTS:ports>
    $<TARGET_OBJECTS:profiler>
    $<TARGET_OBJECTS:protocols>
    $<TARGET_OBJECTS:pub_sub>
    $<TARGET_OBJECTS:search_engines>
    $<TARGET_OBJECTS:service_inspectors>
    $<TARGET_OBJECTS:sfip>
    $<TARGET_OBJECTS:sfrt>
    $<TARGET_OBJECTS:side_channel>
    $<TARGET_OBJECTS:stream>
    $<TARGET_OBJECTS:stream_base>
    $<TARGET_OBJECTS:stream_ip>
    $<TARGET_OBJECTS:stream_icmp>
    $<TARGET_OBJECTS:stream_libtcp>
    $<TARGET_OBJECTS:stream_tcp>
    $<TARGET_OBJECTS:stream_udp>
    $<TARGET_OBJECTS:stream_user>
    $<TARGET_OBJECTS:stream_file>
    $<TARGET_OBJECTS:stream_paf>
    $<TARGET_OBJECTS:target_based>
    $<TARGET_OBJECTS:tcp_connector>
    $<TARGET_OBJECTS:time>
    $<TARGET_OBJECTS:utils>
    ${PIGLET_LIBRARIES}
    ${STATIC_CODEC_PLUGINS}
    ${STATIC_NETWORK_INSPECTOR_PLUGINS}
    ${STATIC_SERVICE_INSPECTOR_PLUGINS}
    ${UNIT_TESTS_LIBRARIES}
)

#[[
message("
    STATIC_CODEC_PLUGINS = ${STATIC_CODEC_PLUGINS}
    STATIC_NETWORK_INSPECTOR_PLUGINS = ${STATIC_NETWORK_INSPECTOR_PLUGINS}
    STATIC_SERVICE_INSPECTOR_PLUGINS = ${STATIC_SERVICE_INSPECTOR_PLUGINS}
")
]]

target_link_libraries( snort
    ${EXTERNAL_LIBRARIES}
)

#  setting export properties
set_property(TARGET snort APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES
    ${LUAJIT_INCLUDE_DIR}
    ${EXTERNAL_INCLUDES}
    # The installed path '${INCLUDE_INSTALL_PATH}'' is added below with 'install (... snort ...)'
)

set_property(TARGET snort APPEND PROPERTY INTERFACE_COMPILE_OPTIONS "${CMAKE_CXX_FLAGS}")

set_property(TARGET snort PROPERTY ENABLE_EXPORTS 1)

install (TARGETS snort
    # EXPORT snortexe
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# FIXIT-L Restore CMake export information
#install (EXPORT snortexe
#    DESTINATION ${CMAKE_INSTALL_LIBDIR}/snort
#    FILE snort.cmake
#)
