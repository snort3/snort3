
add_example_library(alert_ex loggers alert_ex.cc)

install (
    FILES alert.lua
    DESTINATION "${EX_INSTALL_PATH}/loggers"
)
