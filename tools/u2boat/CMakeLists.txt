
include_directories(${PROJECT_SOURCE_DIR}/src/loggers)

add_executable( u2boat
    u2boat.cc
    u2boat.h
)

target_link_libraries( u2boat
    ${PCAP_LIBRARIES}
)


install (TARGETS u2boat
    RUNTIME DESTINATION bin
)

install(FILES README.u2boat
    DESTINATION "${SNORT_DATA_DIR}"
)
