

set (LUA_SCRIPTS
    snort.lua
    classification.lua
    reference.lua
)

install (FILES ${EXTRA_DIST_BINARY_PATH}
    DESTINATION "conf"
)

