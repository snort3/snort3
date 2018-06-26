
set (LUA_SCRIPTS
    file_magic.lua
    inline.lua
    snort_defaults.lua
    talos.lua
)

configure_file(snort.lua.in
    snort.lua)

install (FILES ${LUA_SCRIPTS} ${CMAKE_CURRENT_BINARY_DIR}/snort.lua
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/snort"
)
