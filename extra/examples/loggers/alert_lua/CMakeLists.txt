cmake_minimum_required ( VERSION 2.8.11 )
project ( alert_lua )

install (
    FILES alert.lua
    DESTINATION "lib/${CMAKE_PROJECT_NAME}/loggers"
)
