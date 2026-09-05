if (NOT WIN32)
    add_subdirectory(mp_unix_transport)
endif()

add_library( mp_transports OBJECT
    mp_transports.cc
    mp_transports.h
)