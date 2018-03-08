cmake_minimum_required ( VERSION 3.4.3 )
project ( find )

install (
    FILES find.lua
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/${CMAKE_PROJECT_NAME}/ips_options"
)
