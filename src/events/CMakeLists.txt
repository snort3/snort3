

set (INCLUDES
    event.h
    event_queue.h
)

add_library (events STATIC
    event.cc
    event_queue.cc 
    event_wrapper.cc 
    event_wrapper.h 
    codec_events.cc
    codec_events.h
    sfeventq.cc 
    sfeventq.h
    codec_events.cc
)

install (FILES ${INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/events"
)
