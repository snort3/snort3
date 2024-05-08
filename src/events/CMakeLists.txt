
set (INCLUDES
    event.h
)

add_library (events OBJECT
    event.cc
    event_queue.cc
    event_queue.h
    sfeventq.cc
    sfeventq.h
    ${INCLUDES}
)

install (FILES ${INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/events"
)
