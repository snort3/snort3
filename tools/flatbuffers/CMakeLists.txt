if ( FLATBUFFERS_FOUND )
    add_executable( fbstreamer
        fbstreamer.cc
    )

    target_include_directories( fbstreamer
        PRIVATE
        ${FLATBUFFERS_INCLUDE_DIR}
    )
    target_link_libraries( fbstreamer
        ${FLATBUFFERS_LIBRARIES}
    )

    install (TARGETS fbstreamer
        RUNTIME DESTINATION bin
    )
endif()

