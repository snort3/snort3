
# keeping track of external libraries seperately for use in pkg-config.
set(EXTERNAL_LIBRARIES
    ${DAQ_LIBRARIES}
    ${DNET_LIBRARIES}
    ${CLANG_CXX_LIBRARY}
    ${CMAKE_DL_LIBS}
    ${CMAKE_THREAD_LIBS_INIT} # GCC says we must link to the threads library
    ${HWLOC_LIBRARIES}
    ${LUAJIT_LIBRARIES}
    ${OPENSSL_CRYPTO_LIBRARY}
    ${PCAP_LIBRARIES}
    ${PCRE2_LIBRARIES}
    ${ZLIB_LIBRARIES}
)

set(EXTERNAL_INCLUDES
    ${DAQ_INCLUDE_DIR}
    ${DNET_INCLUDE_DIR}
    ${FLEX_INCLUDES}
    ${HWLOC_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${PCAP_INCLUDE_DIR}
    ${PCRE2_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIRS}
)

if ( ENABLE_STATIC_DAQ )
    LIST(APPEND EXTERNAL_LIBRARIES ${DAQ_STATIC_MODULE_LIBS})
endif ()

if ( HAVE_ATOMIC )
    LIST(APPEND EXTERNAL_LIBRARIES ${ATOMIC_LIBRARIES})
endif()

if ( HAVE_HYPERSCAN )
    LIST(APPEND EXTERNAL_LIBRARIES ${HS_LIBRARIES})
    LIST(APPEND EXTERNAL_INCLUDES ${HS_INCLUDE_DIRS})
endif ()

if ( HAVE_ICONV )
    LIST(APPEND EXTERNAL_LIBRARIES ${ICONV_LIBRARY})
    LIST(APPEND EXTERNAL_INCLUDES ${ICONV_INCLUDE_DIR})
endif ()

if ( HAVE_LIBUNWIND )
    LIST(APPEND EXTERNAL_LIBRARIES ${LIBUNWIND_LIBRARIES})
    LIST(APPEND EXTERNAL_INCLUDES ${LIBUNWIND_INCLUDE_DIRS})
endif ()

if ( HAVE_LZMA )
    LIST(APPEND EXTERNAL_LIBRARIES ${LIBLZMA_LIBRARIES})
endif()

if ( HAVE_NUMA )
    LIST(APPEND EXTERNAL_INCLUDES ${NUMA_INCLUDE_DIRS})
    LIST(APPEND EXTERNAL_LIBRARIES ${NUMA_LIBRARIES})
endif()

if ( HAVE_SAFEC )
    LIST(APPEND EXTERNAL_LIBRARIES ${SAFEC_LIBRARIES})
    LIST(APPEND EXTERNAL_INCLUDES ${SAFEC_INCLUDE_DIR})
endif ()

if ( HAVE_UUID )
    LIST(APPEND EXTERNAL_LIBRARIES ${UUID_LIBRARY})
    LIST(APPEND EXTERNAL_INCLUDES ${UUID_INCLUDE_DIR})
endif ()

if ( USE_TIRPC )
    LIST(APPEND EXTERNAL_LIBRARIES ${TIRPC_LIBRARIES})
    LIST(APPEND EXTERNAL_INCLUDES ${TIRPC_INCLUDE_DIRS})
endif ()

if ( HAVE_LIBML )
    LIST(APPEND EXTERNAL_LIBRARIES ${ML_LIBRARIES})
    LIST(APPEND EXTERNAL_INCLUDES ${ML_INCLUDE_DIRS})
endif ()

include_directories(BEFORE ${LUAJIT_INCLUDE_DIR})
include_directories(AFTER ${EXTERNAL_INCLUDES})

# prepending all of these to ensure they are included before External Libs
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(BEFORE network_inspectors)

if ( ENABLE_UNIT_TESTS )
    enable_testing()
endif ( ENABLE_UNIT_TESTS )

if ( ENABLE_UNIT_TESTS OR ENABLE_BENCHMARK_TESTS )
    set( UNIT_TESTS_LIBRARIES $<TARGET_OBJECTS:catch_tests>)
    add_subdirectory(catch)
endif ( ENABLE_UNIT_TESTS OR ENABLE_BENCHMARK_TESTS )

add_subdirectory(actions)
add_subdirectory(codecs)
add_subdirectory(control)
add_subdirectory(detection)
add_subdirectory(dump_config)
add_subdirectory(events)
add_subdirectory(file_api)
add_subdirectory(filters)
add_subdirectory(flow)
add_subdirectory(framework)
add_subdirectory(hash)
add_subdirectory(js_norm)
add_subdirectory(latency)
add_subdirectory(log)
add_subdirectory(main)
add_subdirectory(managers)
add_subdirectory(memory)
add_subdirectory(mime)
add_subdirectory(packet_io)
add_subdirectory(parser)
add_subdirectory(payload_injector)
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
add_subdirectory(trace)
add_subdirectory(utils)
add_subdirectory(helpers)
add_subdirectory(lua)
add_subdirectory(decompress)
add_subdirectory(ips_options)
add_subdirectory(loggers)
add_subdirectory(network_inspectors)
add_subdirectory(policy_selectors)
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
    $<TARGET_OBJECTS:dump_config>
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
    $<TARGET_OBJECTS:js_norm>
    $<TARGET_OBJECTS:latency>
    $<TARGET_OBJECTS:log>
    $<TARGET_OBJECTS:loggers>
    $<TARGET_OBJECTS:lua>
    $<TARGET_OBJECTS:main>
    $<TARGET_OBJECTS:managers>
    $<TARGET_OBJECTS:memory>
    $<TARGET_OBJECTS:mime>
    $<TARGET_OBJECTS:network_inspectors>
    $<TARGET_OBJECTS:policy_selectors>
    $<TARGET_OBJECTS:packet_io>
    $<TARGET_OBJECTS:parser>
    $<TARGET_OBJECTS:payload_injector>
    $<TARGET_OBJECTS:ports>
    $<TARGET_OBJECTS:profiler>
    $<TARGET_OBJECTS:protocols>
    $<TARGET_OBJECTS:pub_sub>
    $<TARGET_OBJECTS:search_engines>
    $<TARGET_OBJECTS:service_inspectors>
    $<TARGET_OBJECTS:sfip>
    $<TARGET_OBJECTS:sfrt>
    $<TARGET_OBJECTS:side_channel>
    $<TARGET_OBJECTS:std_connector>
    $<TARGET_OBJECTS:stream>
    $<TARGET_OBJECTS:stream_base>
    $<TARGET_OBJECTS:stream_ip>
    $<TARGET_OBJECTS:stream_icmp>
    $<TARGET_OBJECTS:stream_tcp>
    $<TARGET_OBJECTS:stream_udp>
    $<TARGET_OBJECTS:stream_user>
    $<TARGET_OBJECTS:stream_file>
    $<TARGET_OBJECTS:stream_paf>
    $<TARGET_OBJECTS:target_based>
    $<TARGET_OBJECTS:tcp_connector>
    $<TARGET_OBJECTS:unixdomain_connector>
    $<TARGET_OBJECTS:time>
    $<TARGET_OBJECTS:trace>
    $<TARGET_OBJECTS:utils>
    ${STATIC_CODEC_PLUGINS}
    ${STATIC_NETWORK_INSPECTOR_PLUGINS}
    ${STATIC_SERVICE_INSPECTOR_PLUGINS}
    ${STATIC_POLICY_SELECTOR_PLUGINS}
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
    ${EXTRA_LIBRARIES}
)

# Solaris requires libnsl and libsocket for various network-related library functions
if ( CMAKE_SYSTEM_NAME STREQUAL SunOS )
    target_link_libraries(snort nsl socket)
endif ()

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
