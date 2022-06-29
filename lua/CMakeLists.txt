
set (LUA_SCRIPTS
    balanced.lua
    connectivity.lua
    file_magic.rules
    inline.lua
    max_detect.lua
    security.lua
    snort.lua
    snort_defaults.lua
    talos.lua
)

install (FILES ${LUA_SCRIPTS}
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/snort"
)
