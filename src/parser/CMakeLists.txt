
add_library (parser STATIC 
    arg_list.cc 
    arg_list.h 
    parser.cc 
    parser.h 
    parse_byte_code.cc 
    parse_byte_code.h 
    parse_conf.cc 
    parse_conf.h 
    parse_ip.cc 
    parse_ip.h 
    parse_rule.cc 
    parse_rule.h 
    parse_stream.cc 
    parse_stream.h 
    cmd_line.cc 
    cmd_line.h 
    config_file.cc 
    config_file.h 
    keywords.h 
    mstring.cc 
    mstring.h 
    vars.cc 
    vars.h
)

target_link_libraries(parser
    protocols
    time
    stream
    codecs
)
