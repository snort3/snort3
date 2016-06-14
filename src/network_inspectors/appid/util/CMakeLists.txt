set ( UTIL_SOURCES
    common_util.h
    fw_avltree.cc
    fw_avltree.h
    ip_funcs.cc
    ip_funcs.h
    network_set.cc
    network_set.h
    output_file.cc
    output_file.h
    sfksearch.cc
    sfksearch.h
    sf_mlmp.cc
    sf_mlmp.h
    sf_multi_mpse.cc
    sf_multi_mpse.h
    sfutil.cc
    sfutil.h
    )

add_library ( appid_util STATIC
    ${UTIL_SOURCES}
)

target_include_directories ( appid_util PRIVATE ${APPID_INCLUDE_DIR} )

#  FIXIT-H: Add unit tests

#install (FILES ${UTIL_INCLUDES}
#    DESTINATION "${INCLUDE_INSTALL_PATH}/appid/util"
#)
