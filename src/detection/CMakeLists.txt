
set (DETECTION_INCLUDES
    detect.h
    detection_defines.h
    detection_util.h
    ips_context.h
    rule_option_types.h
    rules.h
    signature.h
    treenodes.h
)

add_library (detection STATIC
    ${DETECTION_INCLUDES}
    context_switcher.cc
    context_switcher.h
    detect.cc
    detection_options.cc
    detection_options.h
    detection_util.cc
    fp_config.cc
    fp_config.h
    fp_create.cc
    fp_create.h
    fp_detect.cc
    fp_detect.h
    fp_utils.cc
    fp_utils.h
    ips_context.cc
    pattern_match_data.h
    pcrm.cc
    pcrm.h
    service_map.cc
    service_map.h
    sfrim.cc
    sfrim.h
    signature.cc
    treenodes.cc
    tag.cc
    tag.h
)

target_link_libraries( detection
    framework
    managers
)

install(FILES ${DETECTION_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/detection"
)
