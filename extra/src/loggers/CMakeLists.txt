
add_example_library(alert_ex loggers alert_ex.cc)

install (
    FILES alert.lua
    LIBRARY DESTINATION "${EX_INSTALL_PATH}/loggers"
)
