if ( FLATBUFFERS_FOUND )
    include_directories(${PROJECT_SOURCE_DIR}/src ${FLATBUFFERS_INCLUDE_DIR})

    add_executable( fbstreamer
        fbstreamer.cc
    )

    target_link_libraries( fbstreamer ${FLATBUFFERS_LIBRARIES} )

    install (TARGETS fbstreamer
        RUNTIME DESTINATION bin
    )
endif()

