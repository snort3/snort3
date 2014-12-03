
add_example_library(alert_ex loggers alert_ex.cc)

install (
    FILE alert.lua
    LIBRARY DESTINATION "${EX_INSTALL_PATH}/loggers"
)
