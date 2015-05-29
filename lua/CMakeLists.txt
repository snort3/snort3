
set (LUA_SCRIPTS
    file_magic.lua
    snort.lua
    snort_defaults.lua
    sample.rules
)

install (FILES ${LUA_SCRIPTS}
    DESTINATION "etc/snort"
)
