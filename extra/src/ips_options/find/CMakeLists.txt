cmake_minimum_required ( VERSION 2.8.11 )
project ( find )

install (
    FILES find.lua
    DESTINATION "lib/${CMAKE_PROJECT_NAME}/ips_options"
)
