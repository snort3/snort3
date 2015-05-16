
add_example_library(alert_ex loggers alert_ex.cc)
add_example_library(log_user loggers log_user.cc)

install (
    FILES alert.lua
    DESTINATION "${EX_INSTALL_PATH}/loggers"
)
