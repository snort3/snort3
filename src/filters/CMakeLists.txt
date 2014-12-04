
set (FILTER_INCLUDES
    sfrf.h 
)

add_library (filter STATIC
    detection_filter.cc
    detection_filter.h
    rate_filter.cc
    rate_filter.h
    sfthreshold.cc
    sfthreshold.h
    sfrf.cc
    sfthd.cc
    sfthd.h
    ${FILTER_INCLUDES}
)


install(FILES ${FILTER_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/filters"
)

