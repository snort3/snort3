set (HOST_TRACKER_INCLUDES
    cache_allocator.h
    cache_interface.h
    host_cache.h
    host_cache_segmented.h
    host_tracker.h
)

add_library( host_tracker OBJECT
    ${HOST_TRACKER_INCLUDES}
    cache_allocator.cc
    host_cache.cc
    host_cache_module.cc
    host_cache_module.h
    host_cache_segmented.h
    host_tracker_module.cc
    host_tracker_module.h
    host_tracker.cc
)

add_subdirectory ( test )

install(FILES ${HOST_TRACKER_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/host_tracker"
)
