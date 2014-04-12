
set( FILE_LIST
    back_orifice.cc
)

if (STATIC_INSPECTORS)
    add_library( back_orifice STATIC ${FILE_LIST})

else ()
    add_shared_library(back_orifice inspectors ${FILE_LIST})

endif ()
