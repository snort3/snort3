
set (LUA_SCRIPTS
    snort.lua
    snort_defaults.lua
    classification.lua
    reference.lua
    sample.rules
)

install (FILES ${LUA_SCRIPTS}
    DESTINATION "etc/snort"
)
