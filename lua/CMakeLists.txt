
set (LUA_SCRIPTS
    snort.lua
    snort_defaults.lua
    sample.rules
)

install (FILES ${LUA_SCRIPTS}
    DESTINATION "etc/snort"
)
