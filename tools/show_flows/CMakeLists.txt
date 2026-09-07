
add_executable( show_flows
    show_flows.cc
)

target_include_directories( show_flows
    PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${PCAP_INCLUDE_DIR}
)
target_link_libraries( show_flows
    ${PCAP_LIBRARIES}
)

if (WIN32)
    target_link_libraries(show_flows ws2_32)
endif ()

install (TARGETS show_flows
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES README.show_flows
    DESTINATION "${CMAKE_INSTALL_DOCDIR}"
)
