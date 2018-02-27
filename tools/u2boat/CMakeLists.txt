
add_executable( u2boat
    u2boat.cc
)

target_include_directories( u2boat
    PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${PCAP_INCLUDE_DIR}
)
target_link_libraries( u2boat
    ${PCAP_LIBRARIES}
)

install (TARGETS u2boat
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES README.u2boat
    DESTINATION "${CMAKE_INSTALL_DOCDIR}"
)
