
set ( LATENCY_SOURCES
    latency_config.h
    latency_rules.h
    latency_stats.h
    latency_timer.h
    latency_util.h
    latency_module.h
    latency_module.cc
    packet_latency.h
    packet_latency.cc
    packet_latency_config.h
    rule_latency_config.h
    rule_latency_state.h
    rule_latency.h
    rule_latency.cc
)

add_library ( latency OBJECT ${LATENCY_SOURCES} )

