include_directories (${CMAKE_CURRENT_BINARY_DIR})

add_library (
    piglet STATIC

    piglet.cc
    piglet.h
    piglet_api.cc
    piglet_api.h
    piglet_manager.cc
    piglet_manager.h
    piglet_runner.cc
    piglet_runner.h
    piglet_utils.cc
    piglet_utils.h
)
