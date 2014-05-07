
set (FILE_LIST
    nhttp_inspect.cc
    nhttp_inspect.h
    nhttp_msgheader.cc
    nhttp_msgheader.h
    nhttp_headnorm.cc
    nhttp_headnorm.h
    nhttp_strtocode.cc
    nhttp_strtocode.h
    nhttp_api.cc
    nhttp_api.h
    nhttp_tables.cc
    nhttp_module.cc
    nhttp_module.h
    nhttp_testinput.cc
    nhttp_testinput.h
    nhttp_flowdata.cc
    nhttp_flowdata.h
    nhttp_scratchpad.h
    nhttp_enum.h
)

#if (STATIC_INSPECTORS)
    add_library(nhttp_inspect STATIC ${FILE_LIST})
#else()
#    add_shared_library(nhttp_inspect inspectors ${FILE_LIST})
#endif()
