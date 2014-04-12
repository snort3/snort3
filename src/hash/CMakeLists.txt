
set (HASH_INCLUDES
    sfghash.h 
    sfxhash.h 
    sfhashfcn.h 
)

add_library( hash STATIC
    ${HASH_INCLUDES}
    sfghash.cc 
    sfhashfcn.cc 
    sfprimetable.cc 
    sfprimetable.h 
    sfxhash.cc 
    zhash.cc 
    zhash.h
)

install(FILES ${HASH_INCLUDES}
    DESTINATION "${CMAKE_PROJECT_NAME}/hash"
)


