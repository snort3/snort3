

add_library (parser STATIC 
    parser.cc 
    parser.h 
    parse_conf.cc 
    parse_conf.h 
    parse_rule.cc 
    parse_rule.h 
    parse_otn.cc 
    parse_otn.h 
    cmd_line.cc 
    cmd_line.h 
    config_file.cc 
    config_file.h 
    keywords.h 
    modules.cc
    modules.h
    ip_addr_set.cc
    ip_addr_set.h
    mstring.cc 
    mstring.h 
    vars.cc 
    vars.h
)

target_link_libraries(parser
    protocols
    time
    stream
)

