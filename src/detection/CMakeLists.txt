
set (DETECTION_INCLUDES
    detection_buf.h
    detection_engine.h
    extract.h
    ips_context.h
    ips_context_chain.h
    ips_context_data.h
    pattern_match_data.h
    rule_option_types.h
)

add_library (detection OBJECT
    ${DETECTION_INCLUDES}
    context_switcher.cc
    context_switcher.h
    detect.cc
    detect.h
    detection_continuation.h
    detection_engine.cc
    detection_module.cc
    detection_module.h
    detection_options.cc
    detection_options.h
    detect_trace.cc
    detect_trace.h
    event_trace.cc
    event_trace.h
    extract.cc
    fp_config.cc
    fp_config.h
    fp_create.cc
    fp_create.h
    fp_detect.cc
    fp_detect.h
    fp_utils.cc
    fp_utils.h
    ips_context.cc
    ips_context_chain.cc
    ips_context_data.cc
    pcrm.cc
    pcrm.h
    regex_offload.cc
    regex_offload.h
    rtn_checks.cc
    rtn_checks.h
    rules.cc
    rules.h
    service_map.cc
    service_map.h
    sfrim.cc
    sfrim.h
    signature.cc
    signature.h
    treenodes.cc
    treenodes.h
    tag.cc
    tag.h
)

install(FILES ${DETECTION_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/detection"
)
