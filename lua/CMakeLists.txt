
set (LUA_SCRIPTS
    file_magic.lua
    inline.lua
    snort.lua
    snort_defaults.lua
    talos.lua
)

install (FILES ${LUA_SCRIPTS}
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/snort"
)
