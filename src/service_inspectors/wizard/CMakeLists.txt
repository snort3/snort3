
set(FILE_LIST
    curses.cc
    curses.h
    magic.cc
    magic.h
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
