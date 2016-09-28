set ( TICS_INCLUDES
    tics_macro_enabler.h
    tics.h
)

ADD_LIBRARY ( tics STATIC
    tics_compile.cc
    tics_detect.cc
    ${TICS_INCLUDES}
)
