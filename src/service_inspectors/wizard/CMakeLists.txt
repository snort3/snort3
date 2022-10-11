
set(FILE_LIST
    curses.cc
    curses.h
    magic.cc
    magic.h
    mms_curse.h
    s7commplus_curse.h
    hexes.cc
    spells.cc
    wizard.cc
    wiz_module.cc
    wiz_module.h
)

if (STATIC_INSPECTORS)
    add_library(wizard OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(wizard inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

add_catch_test(curses_test
    NO_TEST_SOURCE
    SOURCES
        curses.cc
)
