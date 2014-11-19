
set (LUA_SCRIPTS
    snort.lua
    snort_defaults.lua
    classification.lua
    reference.lua
)

install (FILES ${LUA_SCRIPTS}
    DESTINATION "conf"
)

set(ENV{LUA_PATH} "${CMAKE_INSTALL_PREFIX}/include/snort/lua/?.lua\;\;")
