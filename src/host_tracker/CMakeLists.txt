add_library( host_tracker OBJECT
    host_cache.cc
    host_cache.h
    host_cache_module.cc
    host_cache_module.h
    host_tracker_module.cc
    host_tracker_module.h
    host_tracker.cc
    host_tracker.h
)

add_subdirectory ( test )
