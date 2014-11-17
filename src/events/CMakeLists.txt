
set (INCLUDES
    event.h
    event_queue.h
)

add_library (events STATIC
    event.cc
    event_queue.cc 
    event_wrapper.cc 
    event_wrapper.h 
    sfeventq.cc 
    sfeventq.h
    ${INCLUDES}
)

install (FILES ${INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/events"
)
