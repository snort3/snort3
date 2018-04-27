include(CheckIncludeFileCXX)

add_subdirectory ( codecs )
add_subdirectory ( daqs )
add_subdirectory ( inspectors )
add_subdirectory ( ips_options )
add_subdirectory ( loggers )
add_subdirectory ( search_engines )
add_subdirectory ( so_rules )

CHECK_INCLUDE_FILE_CXX( "${CMAKE_INSTALL_PREFIX}/include/snort/network_inspectors/appid/tp_appid_module_api.h" ENABLE_APPID_THIRD_PARTY ${CMAKE_CXX_FLAGS})

if ( ENABLE_APPID_THIRD_PARTY )
  add_subdirectory ( tp_appid )
endif()
