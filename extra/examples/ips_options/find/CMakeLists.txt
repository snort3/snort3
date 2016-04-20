cmake_minimum_required ( VERSION 3.5.2 )
project ( find )

install (
    FILES find.lua
    DESTINATION "lib/${CMAKE_PROJECT_NAME}/ips_options"
)
