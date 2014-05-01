
# include directories should match configure.ac::AM_CPPFLAGS

include_directories(${DAQ_INCLUDE_DIR})
include_directories(${PCAP_INCLUDE_DIR})
include_directories(${PCRE_INCLUDE_DIR})
include_directories(BEFORE ${LUAJIT_INCLUDE_DIR})
include_directories(${DNET_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(detection)
include_directories(events)
include_directories(framework)
include_directories(hash)
include_directories(log)
include_directories(loggers)
include_directories(main)
include_directories(network_inspectors)
include_directories(parser)
include_directories(protocols)
include_directories(sfip)
include_directories(target_based)
include_directories(time)
include_directories(utils)

add_executable(snort
    main.h
    main.cc
)

if (STATIC_INSPECTORS)
    set (STATIC_INSPECTOR_LIBRARIES
        arp_spoof
        port_scan
        back_orifice
        ftp_telnet
        rpc_decode
    )
endif(STATIC_INSPECTORS)

if (BUILD_UNIT_TESTS)
    set( UNIT_TESTS_LIBRARIES test)
    add_subdirectory(test)
endif( BUILD_UNIT_TESTS)

if (BUILD_SIDE_CHANNEL)
    set( SIDE_CHANNEL_LIBRARIES sidechannel sscm)
    add_subdirectory(side_channel)
endif (BUILD_SIDE_CHANNEL)

set_default_visibility_compile_flag(snort)
target_link_libraries(snort
    main
    target_based
    log
    protocols
    framework
    defrag
    normalize
    perf_monitor
    stream
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
    mempool
    network_inspectors
    search_engines
    helpers
    ips_options
    loggers
    service_inspectors
    stream_api
    actions
    managers
    codecs
    ${SIDE_CHANNEL_LIBRARIES}
    ${STATIC_INSPECTOR_LIBRARIES}
    ${UNIT_TESTS_LIBRARIES}
    ${PCRE_LIBRARIES}
    ${PCAP_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${ZLIB_LIBRARIES}
    ${DNET_LIBRARIES}
    ${OPENSSL_CRYPTO_LIBRARY}
    ${LUAJIT_LIBRARIES}
    ${DAQ_LIBRARIES}
    ${DNET_LIBRARIES}
    c++
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
add_subdirectory(mempool)
add_subdirectory(packet_io)
add_subdirectory(parser)
add_subdirectory(protocols)
add_subdirectory(sfip)
add_subdirectory(sfrt)
add_subdirectory(service_inspectors)
add_subdirectory(target_based)
add_subdirectory(time)
add_subdirectory(utils)
add_subdirectory(helpers)
add_subdirectory(ips_options)
add_subdirectory(loggers)
add_subdirectory(network_inspectors)
add_subdirectory(search_engines)


install(TARGETS snort
    RUNTIME DESTINATION bin
)

##############################################################################
#
#  This is the documents seciton of the cmake file.  Yes, I hate that I am 
#  putting this stuff in the src directory instead of the doc directory,
#  but these files are dependent on the Snort executable.  Since complete
#  platform independence is the goal, these command need a file level
#  dependcy on snort, which means they need to be here
#
#  When creating new files, follow these directions
#       1) Copy an entire segment (include the set, add_custom_command, 
#           and add_custom_target pieces)
#       2) Change the ARGS to create the file you want
#       3) Add the file name to list of BUILT_SOURCES at the top of 
#           doc/CMakeLists.txt
#
##############################################################################



if (MAKE_PDF_DOC OR MAKE_HTML_DOC)


    set(TARGET_DIR ${CMAKE_BINARY_DIR})


    set(file builtin.txt)

    set(output ${TARGET_DIR}/${file})
    add_custom_command(
        OUTPUT ${output}
        COMMAND snort --markup --help-builtin > ${output}
        MAIN_DEPENDENCY snort
        COMMENT "Documents: building ${output}"
    )
    get_filename_component(file_name "${file}" NAME_WE)
    add_custom_target(doc_${file_name} ALL DEPENDS ${output} )


    set(file commands.txt)

    set(output ${TARGET_DIR}/${file})
    add_custom_command(
        OUTPUT ${output}
        COMMAND snort  --markup --help-commands > ${output}
        MAIN_DEPENDENCY snort
        COMMENT "Documents: building ${output}"
    )
    get_filename_component(file_name "${file}" NAME_WE)
    add_custom_target(doc_${file_name} ALL DEPENDS ${output} )



    set(file config.txt)

    set(output ${TARGET_DIR}/${file})
    add_custom_command(
        OUTPUT ${output}
        COMMAND snort --markup --help-config > ${output}
        MAIN_DEPENDENCY snort
        COMMENT "Documents: building ${output}"
    )
    get_filename_component(file_name "${file}" NAME_WE)
    add_custom_target(doc_${file_name} ALL DEPENDS ${output})


    set(file options.txt)

    set(output ${TARGET_DIR}/${file})
    add_custom_command(
        OUTPUT ${output}
        COMMAND snort --markup --help > ${output}
        MAIN_DEPENDENCY snort
        COMMENT "Documents: building ${output}"
    )
    get_filename_component(file_name "${file}" NAME_WE)
    add_custom_target(doc_${file_name} ALL DEPENDS ${output})


    set(file gids.txt)

    set(output ${TARGET_DIR}/${file})
    add_custom_command(
        OUTPUT ${output}
        COMMAND snort --markup --help-gids > ${output}
        MAIN_DEPENDENCY snort
        COMMENT "Documents: building ${output}"
    )
    get_filename_component(file_name "${file}" NAME_WE)
    add_custom_target(doc_${file_name} ALL DEPENDS ${output})
endif()
