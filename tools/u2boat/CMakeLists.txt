include_directories(${PROJECT_SOURCE_DIR}/src/loggers)

add_executable( u2boat
    u2boat.cc
    u2boat.h
)

target_link_libraries( u2boat
    ${PCAP_LIBRARIES}
)

#add_compile_flags(u2boat ${AM_CFLAGS})

set( AM_CXXFLAGS ${AM_CXXFLAGS} ${EXTRA_INCL}]})

install (TARGETS u2boat
    RUNTIME DESTINATION bin
)

install(FILES README.u2boat
    DESTINATION ${SNORT_DATA_DIR}
)

