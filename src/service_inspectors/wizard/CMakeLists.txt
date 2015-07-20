
set(FILE_LIST
    magic.cc
    magic.h
    hexes.cc
    spells.cc
    wizard.cc
    wiz_module.cc
    wiz_module.h
)

if (STATIC_INSPECTORS)
    add_library(wizard STATIC ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_shared_library(wizard inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)
