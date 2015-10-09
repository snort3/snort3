
add_example_library(alert_ex loggers alert_ex.cc)
add_example_library(alert_unixsock loggers alert_unixsock.cc)
add_example_library(log_null loggers log_null.cc)

install (
    FILES alert.lua
    DESTINATION "${EX_INSTALL_PATH}/loggers"
)
