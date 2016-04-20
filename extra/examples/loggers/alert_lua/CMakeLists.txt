cmake_minimum_required ( VERSION 3.5.2 )
project ( alert_lua )

install (
    FILES alert.lua
    DESTINATION "lib/${CMAKE_PROJECT_NAME}/loggers"
)
