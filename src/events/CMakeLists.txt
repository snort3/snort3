
set (INCLUDES
    event.h
    event_queue.h
)

add_library (events OBJECT
    event.cc
    event_queue.cc 
    sfeventq.cc 
    sfeventq.h
    ${INCLUDES}
)

install (FILES ${INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/events"
)
