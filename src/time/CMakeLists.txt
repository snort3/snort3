
set (TIME_INCLUDES
    cpuclock.h
    profiler.h
    ppm.h
)

add_library( time  STATIC
    packet_time.cc 
    packet_time.h 
    ppm.cc 
    ppm.h 
    ppm_module.cc
    ppm_module.h
    profiler.cc 
    periodic.cc 
    periodic.h 
    timersub.h
    ${TIME_INCLUDES}
)


install (FILES ${TIME_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/time"
)


