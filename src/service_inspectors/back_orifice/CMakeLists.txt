
set( FILE_LIST
    back_orifice.cc
)

if (STATIC_INSPECTORS)
    add_library( back_orifice OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(back_orifice inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)
