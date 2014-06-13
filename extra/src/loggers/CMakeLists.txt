

add_library(alert_ex SHARED
    alert_ex.cc
)

set_target_properties ( alert_ex
    PROPERTIES
    LINK_FLAGS "-export-dynamic -shared"
)

install (TARGETS alert_ex
    LIBRARY DESTINATION "${EX_INSTALL_PATH}/loggers"
)
